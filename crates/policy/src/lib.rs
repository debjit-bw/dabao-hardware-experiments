//! The device's signing policy. Runs in the verifier after the simulation and the ERC-7730
//! check; a transaction is signed only if both pass. See docs/policy.md.
//!
//! * The policy is part of the firmware (compiled from `policy/policy.json` by
//!   `dabao-host compile-policy`, embedded here), so a compromised host can't replace it.
//! * Rules, per chain: daily spending limits per asset (counters persisted in RRAM), a cap on
//!   the network fee, a cap on swap slippage, an address allowlist, and what to do with assets
//!   that have no limit. A chain without a policy is refused.
//! * "Spending" is what the simulation says leaves the sender: net losses per asset, plus every
//!   allowance the sender grants (at its full amount: an allowance is spending authority), plus
//!   the maximum network fee for ETH. Measured from effects, not from calldata, so a router or
//!   multicall can't hide it.
//! * Time: a day is `block.timestamp / 86400` of the block the host says comes next. Until the
//!   light client exists that timestamp is host-supplied (untrusted): a lying host can start a
//!   new "day" early. Documented, not solved.

use alloy_primitives::{Address, Bytes, U256, keccak256};
use alloy_rlp::{RlpDecodable, RlpEncodable};
use clear_sign::{
    check::{asset_label, format_amount},
    model::DescriptorSet,
};
use sim_types::{PolicyCheck, SimInput, SimResult, effect};

pub const POLICY_VERSION: u64 = 1;
/// Counters available (keystore app slots claimed by the verifier).
pub const MAX_LIMITS: usize = 32;
/// `max_slippage_bps` meaning "no limit".
pub const NO_SLIPPAGE_LIMIT: u64 = 10_000;

#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct Policy {
    pub version: u64,
    pub id: Bytes,
    pub chains: Vec<ChainPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct ChainPolicy {
    pub chain_id: u64,
    /// Max of `gas_limit x max fee per gas`, wei (0 = no cap).
    pub max_fee: U256,
    /// Max of (simulated - shown minimum) / simulated, basis points (10000 = no limit).
    pub max_slippage_bps: u64,
    /// Non-empty: `tx.to` and every address the user is shown must be on it (or the device).
    pub allowlist: Vec<Address>,
    /// Allow spending assets that have no daily limit (else refused).
    pub allow_unlimited_assets: bool,
    pub limits: Vec<Limit>,
}

#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct Limit {
    /// Zero = ETH.
    pub asset: Address,
    pub daily: U256,
}

impl Policy {
    /// `(global counter index, limit)` for every limit, in order.
    pub fn limits(&self) -> impl Iterator<Item = (usize, u64, &Limit)> {
        self.chains.iter().flat_map(|c| c.limits.iter().map(move |l| (c.chain_id, l))).enumerate().map(|(i, (c, l))| (i, c, l))
    }
}

/// The policy compiled into the firmware.
pub fn builtin() -> Policy {
    alloy_rlp::Decodable::decode(&mut &include_bytes!("../policy.bin")[..]).expect("embedded policy")
}

/// One daily-spending counter, persisted as one 32-byte keystore slot:
/// `"DPL1" || id (8) || day (u32 BE) || spent (u128 BE)`. `id` ties it to its (chain, asset):
/// a slot holding another limit's counter (policy changed) reads as a fresh counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Counter {
    pub id: [u8; 8],
    pub day: u32,
    pub spent: u128,
}

const MAGIC: &[u8; 4] = b"DPL1";

pub fn counter_id(chain_id: u64, asset: Address) -> [u8; 8] {
    let mut b = chain_id.to_be_bytes().to_vec();
    b.extend_from_slice(asset.as_slice());
    keccak256(&b)[..8].try_into().unwrap()
}

impl Counter {
    pub fn encode(&self) -> [u8; 32] {
        let mut s = [0u8; 32];
        s[..4].copy_from_slice(MAGIC);
        s[4..12].copy_from_slice(&self.id);
        s[12..16].copy_from_slice(&self.day.to_be_bytes());
        s[16..].copy_from_slice(&self.spent.to_be_bytes());
        s
    }

    /// The stored counter for `id`, or a fresh one (empty slot, or another limit's counter).
    pub fn decode(slot: &[u8; 32], id: [u8; 8]) -> Counter {
        if &slot[..4] != MAGIC || slot[4..12] != id {
            return Counter { id, day: 0, spent: 0 };
        }
        Counter {
            id,
            day: u32::from_be_bytes(slot[12..16].try_into().unwrap()),
            spent: u128::from_be_bytes(slot[16..].try_into().unwrap()),
        }
    }

    /// Spent on `day` (a counter from an earlier day counts as 0).
    pub fn spent_on(&self, day: u32) -> u128 {
        if self.day == day { self.spent } else { 0 }
    }
}

/// The policy's verdict, and the counters to persist *before* signing if it passes.
#[derive(Debug, Default)]
pub struct Outcome {
    pub check: PolicyCheck,
    pub updates: Vec<(usize, Counter)>,
}

fn bytes(s: String) -> Bytes {
    s.into_bytes().into()
}

/// Evaluate `input` / `sim` against `p`. `counters[i]` is the counter of the `i`-th limit
/// ([`Policy::limits`]); `tokens` formats amounts.
pub fn evaluate(p: &Policy, counters: &[Counter], tokens: &DescriptorSet, input: &SimInput, sim: &SimResult) -> Outcome {
    let mut v: Vec<String> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    let mut updates = Vec::new();
    let chain = input.chain_id;
    let tx = &input.tx;
    let me = tx.from;
    let amt = |a: Address, x: U256| format_amount(tokens, chain, a, x);
    let done = |v: Vec<String>, notes: Vec<String>, updates| Outcome {
        check: PolicyCheck { policy: p.id.clone(), violations: v.into_iter().map(bytes).collect(), notes: notes.into_iter().map(bytes).collect() },
        updates,
    };

    let Some(cp) = p.chains.iter().find(|c| c.chain_id == chain) else {
        v.push(format!("no policy for chain {chain}: refused"));
        return done(v, notes, updates);
    };
    if !sim.error.is_empty() {
        v.push("the simulation rejected the input".into());
        return done(v, notes, updates);
    }

    // network fee
    let max_fee = U256::from(tx.gas_limit) * U256::from(tx.gas_price);
    if !cp.max_fee.is_zero() && max_fee > cp.max_fee {
        v.push(format!("max network fee {} exceeds the policy's {}", amt(Address::ZERO, max_fee), amt(Address::ZERO, cp.max_fee)));
    }

    // allowlist
    if !cp.allowlist.is_empty() {
        let ok = |a: &Address| *a == me || cp.allowlist.contains(a);
        if !ok(&tx.to) {
            v.push(format!("{} is not on the allowlist", tx.to));
        }
        let mut seen = Vec::new();
        for a in &sim.clear_sign.addresses {
            if !ok(a) && *a != tx.to && !seen.contains(a) {
                v.push(format!("shown address {a} is not on the allowlist"));
                seen.push(*a);
            }
        }
    }

    // slippage
    for m in &sim.clear_sign.min_receive {
        if m.simulated.is_zero() {
            continue;
        }
        let bps = (m.simulated - m.shown) * U256::from(10_000) / m.simulated;
        if cp.max_slippage_bps < NO_SLIPPAGE_LIMIT && bps > U256::from(cp.max_slippage_bps) {
            v.push(format!(
                "slippage: minimum {} is {bps} bps below the simulated {} (policy max {} bps)",
                amt(m.asset, m.shown),
                amt(m.asset, m.simulated),
                cp.max_slippage_bps
            ));
        }
    }

    // spending: net losses, allowances granted (full amount), max fee for ETH
    let mut spend: Vec<(Address, U256)> = Vec::new();
    let mut add = |a: Address, x: U256| match spend.iter_mut().find(|(b, _)| *b == a) {
        Some((_, y)) => *y = y.saturating_add(x),
        None => spend.push((a, x)),
    };
    add(Address::ZERO, max_fee);
    for e in &sim.effects {
        match e.kind {
            effect::NET_LOSS if e.from == me => add(e.contract, e.amount),
            effect::ERC20_APPROVAL if e.from == me && !e.amount.is_zero() => add(e.contract, e.amount),
            effect::PERMIT2_APPROVAL if e.from == me && !e.amount.is_zero() && e.extra.len() >= 20 => {
                add(Address::from_slice(&e.extra[..20]), e.amount)
            }
            effect::NFT_TRANSFER | effect::ERC1155_TRANSFER if e.from == me && !cp.allow_unlimited_assets => {
                v.push(format!("NFT {} leaves the device's account: no limit covers NFTs", e.contract))
            }
            effect::NFT_APPROVAL | effect::APPROVAL_FOR_ALL if e.from == me && !e.amount.is_zero() && !cp.allow_unlimited_assets => {
                v.push(format!("NFT approval on {} to {}: no limit covers NFTs", e.contract, e.to))
            }
            _ => {}
        }
    }
    let day = (input.block.timestamp / 86_400) as u32;
    for (asset, x) in spend {
        let limit = p.limits().find(|(_, c, l)| *c == chain && l.asset == asset);
        let Some((i, _, l)) = limit else {
            if cp.allow_unlimited_assets {
                notes.push(format!("{}: no daily limit (allowed by the policy)", amt(asset, x)));
            } else {
                v.push(format!("spends {}, an asset with no daily limit in the policy", amt(asset, x)));
            }
            continue;
        };
        let c = counters.get(i).copied().unwrap_or(Counter { id: counter_id(chain, asset), day: 0, spent: 0 });
        let before = U256::from(c.spent_on(day));
        let after = before.saturating_add(x);
        if after > l.daily {
            v.push(format!(
                "daily limit: {} this tx + {} already today > {}",
                amt(asset, x),
                amt(asset, before),
                amt(asset, l.daily)
            ));
        } else {
            notes.push(format!("{}: {} this tx, {} of {} today", asset_label(tokens, chain, asset), amt(asset, x), amt(asset, after), amt(asset, l.daily)));
            // after <= daily < 2^128 (the compiler enforces it)
            updates.push((i, Counter { id: c.id, day, spent: after.to::<u128>() }));
        }
    }
    notes.push(format!("day {day} (from the host-supplied block time: untrusted until the light client)"));
    done(v, notes, updates)
}

/// The policy and today's counters as text (`dabao-host policy`).
pub fn describe(p: &Policy, counters: &[Counter], tokens: &DescriptorSet) -> Vec<String> {
    let mut out = vec![format!("policy '{}'", String::from_utf8_lossy(&p.id))];
    for cp in &p.chains {
        let amt = |a: Address, x: U256| format_amount(tokens, cp.chain_id, a, x);
        out.push(format!(
            "chain {}: max network fee {}; max slippage {}; allowlist {}; assets without a limit {}",
            cp.chain_id,
            if cp.max_fee.is_zero() { "none".into() } else { amt(Address::ZERO, cp.max_fee) },
            if cp.max_slippage_bps >= NO_SLIPPAGE_LIMIT { "none".into() } else { format!("{} bps", cp.max_slippage_bps) },
            if cp.allowlist.is_empty() { "off".into() } else { format!("{} addresses", cp.allowlist.len()) },
            if cp.allow_unlimited_assets { "allowed" } else { "refused" }
        ));
        for a in &cp.allowlist {
            out.push(format!("  allow {a}"));
        }
        for (i, _, l) in p.limits().filter(|(_, c, _)| *c == cp.chain_id) {
            let k = counters.get(i).copied().unwrap_or_default();
            out.push(format!("  daily limit {}: {} spent on day {}", amt(l.asset, l.daily), amt(l.asset, U256::from(k.spent)), k.day));
        }
    }
    out
}

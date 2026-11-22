//! The device's signing policy. Runs in the verifier after the simulation and the ERC-7730
//! check; a transaction is signed only if both pass. See docs/policy.md.
//!
//! * The policy is part of the firmware (compiled from `policy/policy.json` by
//!   `dabao-host compile-policy`, embedded here), so a compromised host can't replace it.
//! * Rules, per chain: daily spending limits per asset (counters persisted in RRAM), a cap on
//!   the network fee, a cap on swap slippage, which contracts may be called, who may receive,
//!   and what to do with assets that have no limit. A chain without a policy is refused.
//! * Being callable is not being a recipient: anyone can sweep what is left in a router. Swaps
//!   must pay out to the sender, and a called contract must not keep funds.
//! * "Spending" is what the simulation says leaves the sender: net losses per asset, plus every
//!   allowance the sender grants (at its full amount: an allowance is spending authority), plus
//!   the maximum network fee for ETH. Measured from effects, not from calldata, so a router or
//!   multicall can't hide it.
//! * Time: a day is `block.timestamp / 86400` of the simulated block, which the verifier
//!   requires to be the light-client-proven parent's timestamp + 12 s (signing is refused
//!   without that proof), so the clock is as trustworthy as the sync committee.

use alloy_primitives::{Address, Bytes, U256, keccak256};
use alloy_rlp::{RlpDecodable, RlpEncodable};
use clear_sign::{
    check::{asset_label, format_amount},
    model::DescriptorSet,
};
use sim_types::{PolicyCheck, SimInput, SimResult, effect};

pub const POLICY_VERSION: u64 = 2;
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
    /// May be called with calldata, and may be given allowances. Not recipients.
    pub contracts: Vec<Address>,
    /// May receive funds (as may the sender itself). Both lists empty: no address rules.
    pub recipients: Vec<Address>,
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

    // who may be called, and who may receive
    let swapped = sim.effects.iter().any(|e| e.kind == effect::POOL_SWAP);
    if !cp.contracts.is_empty() || !cp.recipients.is_empty() {
        let receives = |a: &Address| *a == me || cp.recipients.contains(a);
        // a callable contract may be named as a spender, if nothing is also sent to it
        let spender = |a: &Address| {
            cp.contracts.contains(a)
                && sim.effects.iter().any(|e| matches!(e.kind, effect::ERC20_APPROVAL | effect::PERMIT2_APPROVAL) && e.from == me && e.to == *a)
                && !sim.effects.iter().any(|e| e.kind == effect::ERC20_TRANSFER && e.to == *a)
        };
        if tx.data.is_empty() {
            if !receives(&tx.to) {
                v.push(format!("{} is not an allowed recipient", tx.to));
            }
        } else if !cp.contracts.contains(&tx.to) {
            v.push(format!("{} is not an allowed contract to call", tx.to));
        }
        let mut seen = Vec::new();
        for a in &sim.clear_sign.addresses {
            if tx.data.is_empty() && *a == tx.to {
                continue; // judged above
            }
            if !receives(a) && !spender(a) && !seen.contains(a) {
                v.push(format!("shown address {a} is not an allowed recipient"));
                seen.push(*a);
            }
        }
    }

    // swaps: one at a time and paid out to the sender, or the slippage rule has nothing to check
    if swapped {
        if sim.clear_sign.addresses != [me] {
            v.push("a swap must be a single swap whose only recipient is the sender".into());
        }
        if !sim.effects.iter().any(|e| e.kind == effect::NET_GAIN && e.from == me) {
            v.push("a swap must leave the sender with a gain to check slippage against".into());
        }
    }

    // a called contract must not keep funds (anyone can sweep a router); wrapping is the exception
    if !tx.data.is_empty() && tx.to != me {
        let wraps = sim.effects.iter().any(|e| e.kind == effect::WRAP && e.contract == tx.to);
        let mut kept: Vec<(Address, U256, U256)> = Vec::new(); // asset, received, sent on
        let mut tally = |asset: Address, got: U256, sent: U256| match kept.iter_mut().find(|k| k.0 == asset) {
            Some(k) => (k.1, k.2) = (k.1.saturating_add(got), k.2.saturating_add(sent)),
            None => kept.push((asset, got, sent)),
        };
        let none = U256::ZERO;
        for e in &sim.effects {
            match e.kind {
                effect::NATIVE_IN if e.to == tx.to && !wraps => tally(Address::ZERO, e.amount, none),
                effect::ERC20_TRANSFER => {
                    if e.to == tx.to {
                        tally(e.contract, e.amount, none);
                    }
                    if e.from == tx.to {
                        tally(e.contract, none, e.amount);
                    }
                }
                effect::WRAP if e.to == tx.to => tally(e.contract, e.amount, none),
                effect::UNWRAP if e.from == tx.to => tally(e.contract, none, e.amount),
                _ => {}
            }
        }
        for (asset, got, sent) in kept {
            if got > sent {
                v.push(format!("the called contract {} keeps {}", tx.to, amt(asset, got - sent)));
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

    if swapped && cp.max_slippage_bps < NO_SLIPPAGE_LIMIT {
        for m in &sim.clear_sign.max_spend {
            let bps = m.shown.saturating_sub(m.simulated).saturating_mul(U256::from(10_000)) / m.shown.max(U256::from(1));
            if bps > U256::from(cp.max_slippage_bps) {
                v.push(format!(
                    "slippage: maximum {} is {bps} bps above the simulated {} (policy max {} bps)",
                    amt(m.asset, m.shown),
                    amt(m.asset, m.simulated),
                    cp.max_slippage_bps
                ));
            }
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
    notes.push(format!("day {day} (block time follows the parent header: trusted once the light client proved it)"));
    done(v, notes, updates)
}

/// The policy and today's counters as text (`dabao-host policy`).
pub fn describe(p: &Policy, counters: &[Counter], tokens: &DescriptorSet) -> Vec<String> {
    let mut out = vec![format!("policy '{}'", String::from_utf8_lossy(&p.id))];
    for cp in &p.chains {
        let amt = |a: Address, x: U256| format_amount(tokens, cp.chain_id, a, x);
        out.push(format!(
            "chain {}: max network fee {}; max slippage {}; addresses: {}; assets without a limit {}",
            cp.chain_id,
            if cp.max_fee.is_zero() { "none".into() } else { amt(Address::ZERO, cp.max_fee) },
            if cp.max_slippage_bps >= NO_SLIPPAGE_LIMIT { "none".into() } else { format!("{} bps", cp.max_slippage_bps) },
            if cp.contracts.is_empty() && cp.recipients.is_empty() { "off".into() } else { format!("{} contracts, {} recipients", cp.contracts.len(), cp.recipients.len()) },
            if cp.allow_unlimited_assets { "allowed" } else { "refused" }
        ));
        for a in &cp.contracts {
            out.push(format!("  may call    {a}"));
        }
        for a in &cp.recipients {
            out.push(format!("  may receive {a}"));
        }
        for (i, _, l) in p.limits().filter(|(_, c, _)| *c == cp.chain_id) {
            let k = counters.get(i).copied().unwrap_or_default();
            out.push(format!("  daily limit {}: {} spent on day {}", amt(l.asset, l.daily), amt(l.asset, U256::from(k.spent)), k.day));
        }
    }
    out
}

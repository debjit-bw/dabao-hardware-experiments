//! Effects inspector v0: normalise a simulation's logs and state changes into [`Effect`]s.
//!
//! Subset (see `sim_types::effect`): ETH in/out per account (net of gas), gas fee, ERC-20
//! Transfer/Approval, ERC-721 Transfer/Approval, ApprovalForAll, ERC-1155 TransferSingle,
//! Permit2 Approval/Permit, OwnershipTransferred, EIP-1967 Upgraded/AdminChanged, WETH-style
//! Deposit/Withdrawal, Uniswap V2/V3 Swap (and V2 Sync as pure bookkeeping), plus the sender's
//! net gain/loss per asset.
//!
//! Rule that makes a subset safe: a contract whose storage changed but which emitted none of
//! the recognised events is reported as `UNEXPLAINED_STORAGE`. Unknown or malformed events are
//! not recognised, so they end up there too. Nothing is dropped silently.
//!
//! Limits (documented in docs/effects-inspector.md): events are what the executed contract
//! *claims*; a contract that emits a recognised event and also writes unrelated storage is not
//! flagged, and a fake event with no storage change is reported as if real. No call tree yet
//! (delegatecall), no code changes (EIP-7702, selfdestruct).

use std::collections::BTreeSet;

use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use sim_types::{Effect, SimBlock, SimLog, SimResult, SimTx, effect};

fn sig(s: &str) -> B256 {
    keccak256(s.as_bytes())
}

fn topic_addr(t: &B256) -> Address {
    Address::from_word(*t)
}

fn word(data: &[u8], i: usize) -> Option<U256> {
    data.get(32 * i..32 * i + 32).map(U256::from_be_slice)
}

fn word_addr(data: &[u8], i: usize) -> Option<Address> {
    data.get(32 * i + 12..32 * i + 32).map(Address::from_slice)
}

fn fx(kind: u8, contract: Address, from: Address, to: Address, amount: U256, extra: Bytes) -> Effect {
    Effect { kind, contract, from, to, amount, extra }
}

/// EIP-7708 (Amsterdam): every ETH movement also emits `Transfer(from, to, amount)` from this
/// system address. ETH moves are already derived from balance deltas, so these logs are
/// bookkeeping, never an ERC-20 transfer of a "token" at this address.
const ETH_TRANSFER_LOG_ADDRESS: Address = alloy_primitives::address!("0xfffffffffffffffffffffffffffffffffffffffe");

/// One log -> an effect, if it is one of the recognised, well-formed events.
fn from_log(l: &SimLog) -> Option<Effect> {
    if l.address == ETH_TRANSFER_LOG_ADDRESS {
        return None;
    }
    let t = &l.topics;
    let d = &l.data[..];
    let c = l.address;
    let z = Address::ZERO;
    let topic0 = *t.first()?;
    let n = t.len();
    if topic0 == sig("Transfer(address,address,uint256)") {
        return match (n, d.len()) {
            (3, 32) => Some(fx(effect::ERC20_TRANSFER, c, topic_addr(&t[1]), topic_addr(&t[2]), word(d, 0)?, Bytes::new())),
            (4, 0) => Some(fx(effect::NFT_TRANSFER, c, topic_addr(&t[1]), topic_addr(&t[2]), U256::from_be_bytes(t[3].0), Bytes::new())),
            _ => None,
        };
    }
    if topic0 == sig("Approval(address,address,uint256)") {
        return match (n, d.len()) {
            (3, 32) => Some(fx(effect::ERC20_APPROVAL, c, topic_addr(&t[1]), topic_addr(&t[2]), word(d, 0)?, Bytes::new())),
            (4, 0) => Some(fx(effect::NFT_APPROVAL, c, topic_addr(&t[1]), topic_addr(&t[2]), U256::from_be_bytes(t[3].0), Bytes::new())),
            _ => None,
        };
    }
    if topic0 == sig("ApprovalForAll(address,address,bool)") && n == 3 && d.len() == 32 {
        let on = word(d, 0)?;
        if on > U256::from(1) {
            return None;
        }
        return Some(fx(effect::APPROVAL_FOR_ALL, c, topic_addr(&t[1]), topic_addr(&t[2]), on, Bytes::new()));
    }
    if topic0 == sig("TransferSingle(address,address,address,uint256,uint256)") && n == 4 && d.len() == 64 {
        let id = word(d, 0)?;
        return Some(fx(
            effect::ERC1155_TRANSFER,
            c,
            topic_addr(&t[2]),
            topic_addr(&t[3]),
            word(d, 1)?,
            Bytes::copy_from_slice(&id.to_be_bytes::<32>()),
        ));
    }
    // Permit2: owner, token, spender indexed; amount (uint160), expiration (uint48) [, nonce]
    let permit2_approval = topic0 == sig("Approval(address,address,address,uint160,uint48)") && d.len() == 64;
    let permit2_permit = topic0 == sig("Permit(address,address,address,uint160,uint48,uint48)") && d.len() == 96;
    if (permit2_approval || permit2_permit) && n == 4 {
        let amount = word(d, 0)?;
        let expiration = word(d, 1)?;
        if amount >= (U256::from(1) << 160) || expiration >= (U256::from(1) << 48) {
            return None;
        }
        let mut extra = topic_addr(&t[2]).to_vec();
        extra.extend_from_slice(&expiration.to_be_bytes::<32>()[26..]);
        return Some(fx(effect::PERMIT2_APPROVAL, c, topic_addr(&t[1]), topic_addr(&t[3]), amount, extra.into()));
    }
    if topic0 == sig("OwnershipTransferred(address,address)") && n == 3 && d.is_empty() {
        return Some(fx(effect::OWNERSHIP_TRANSFER, c, topic_addr(&t[1]), topic_addr(&t[2]), U256::ZERO, Bytes::new()));
    }
    if topic0 == sig("Upgraded(address)") && n == 2 && d.is_empty() {
        return Some(fx(effect::PROXY_UPGRADE, c, z, topic_addr(&t[1]), U256::ZERO, Bytes::new()));
    }
    if topic0 == sig("AdminChanged(address,address)") && n == 1 && d.len() == 64 {
        return Some(fx(effect::PROXY_ADMIN_CHANGE, c, word_addr(d, 0)?, word_addr(d, 1)?, U256::ZERO, Bytes::new()));
    }
    if topic0 == sig("Deposit(address,uint256)") && n == 2 && d.len() == 32 {
        return Some(fx(effect::WRAP, c, z, topic_addr(&t[1]), word(d, 0)?, Bytes::new()));
    }
    if topic0 == sig("Withdrawal(address,uint256)") && n == 2 && d.len() == 32 {
        return Some(fx(effect::UNWRAP, c, topic_addr(&t[1]), z, word(d, 0)?, Bytes::new()));
    }
    // Uniswap V2: Swap(sender indexed, amount0In, amount1In, amount0Out, amount1Out, to indexed)
    if topic0 == sig("Swap(address,uint256,uint256,uint256,uint256,address)") && n == 3 && d.len() == 128 {
        return Some(fx(effect::POOL_SWAP, c, topic_addr(&t[1]), topic_addr(&t[2]), U256::ZERO, Bytes::copy_from_slice(d)));
    }
    // Uniswap V3: Swap(sender indexed, recipient indexed, amount0, amount1, sqrtPriceX96, liquidity, tick)
    if topic0 == sig("Swap(address,address,int256,int256,uint160,uint128,int24)") && n == 3 && d.len() == 160 {
        return Some(fx(effect::POOL_SWAP, c, topic_addr(&t[1]), topic_addr(&t[2]), U256::ZERO, Bytes::copy_from_slice(d)));
    }
    None
}

/// Uniswap V2 `Sync(uint112,uint112)`: reserve bookkeeping that accompanies every V2 swap /
/// mint / burn. Counts as explaining the pair's storage but is no effect of its own.
fn is_bookkeeping(l: &SimLog) -> bool {
    l.topics.len() == 1 && l.topics[0] == sig("Sync(uint112,uint112)") && l.data.len() == 64
}

/// The sender's net gain (+) / loss (-) per asset (zero address = ETH, gas excluded).
fn net_for(sender: Address, effects: &[Effect]) -> Vec<Effect> {
    use std::collections::BTreeMap;
    let mut net: BTreeMap<Address, (U256, U256)> = BTreeMap::new(); // asset -> (gained, lost)
    let mut add = |asset: Address, gain: bool, amount: U256| {
        let e = net.entry(asset).or_insert((U256::ZERO, U256::ZERO));
        if gain { e.0 += amount } else { e.1 += amount }
    };
    for e in effects {
        match e.kind {
            effect::NATIVE_IN if e.to == sender => add(Address::ZERO, true, e.amount),
            effect::NATIVE_OUT if e.from == sender => add(Address::ZERO, false, e.amount),
            effect::ERC20_TRANSFER => {
                if e.to == sender {
                    add(e.contract, true, e.amount);
                }
                if e.from == sender {
                    add(e.contract, false, e.amount);
                }
            }
            effect::WRAP if e.to == sender => add(e.contract, true, e.amount),
            effect::UNWRAP if e.from == sender => add(e.contract, false, e.amount),
            _ => {}
        }
    }
    let z = Address::ZERO;
    net.into_iter()
        .filter_map(|(asset, (g, l))| match g.cmp(&l) {
            std::cmp::Ordering::Greater => Some(fx(effect::NET_GAIN, asset, sender, z, g - l, Bytes::new())),
            std::cmp::Ordering::Less => Some(fx(effect::NET_LOSS, asset, sender, z, l - g, Bytes::new())),
            std::cmp::Ordering::Equal => None,
        })
        .collect()
}

/// All effects of a simulated `tx` in `block`, from `r.logs` and `r.changes`.
pub fn effects(tx: &SimTx, block: &SimBlock, r: &SimResult) -> Vec<Effect> {
    let z = Address::ZERO;
    let mut out = Vec::new();

    // gas: the sender pays gas_used * gas_price; the block beneficiary receives the tip
    let gas = U256::from(r.gas_used);
    let fee = gas * U256::from(tx.gas_price);
    let tip = gas * U256::from(tx.gas_price.saturating_sub(block.basefee as u128));
    out.push(fx(effect::GAS_FEE, z, tx.from, z, fee, Bytes::new()));

    // ETH moves: per-account balance delta, net of the fee (sender) and the tip (beneficiary)
    for c in &r.changes {
        let mut gained = c.balance_after;
        let mut lost = c.balance_before;
        if c.address == tx.from {
            gained += fee;
        }
        if c.address == block.beneficiary {
            lost += tip;
        }
        if gained > lost {
            out.push(fx(effect::NATIVE_IN, z, z, c.address, gained - lost, Bytes::new()));
        } else if lost > gained {
            out.push(fx(effect::NATIVE_OUT, z, c.address, z, lost - gained, Bytes::new()));
        }
    }

    // events
    let mut explained: BTreeSet<Address> = BTreeSet::new();
    for l in &r.logs {
        if let Some(e) = from_log(l) {
            explained.insert(l.address);
            out.push(e);
        } else if is_bookkeeping(l) {
            explained.insert(l.address);
        }
    }

    // storage changes no recognised event accounts for
    for c in &r.changes {
        if !c.slots.is_empty() && !explained.contains(&c.address) {
            out.push(fx(effect::UNEXPLAINED_STORAGE, c.address, z, z, U256::from(c.slots.len()), Bytes::new()));
        }
    }

    // what the sender ends up with, per asset
    let net = net_for(tx.from, &out);
    out.extend(net);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;
    use sim_types::{SimChange, SlotChange};

    const A: Address = address!("0x00000000000000000000000000000000000000aa");
    const B: Address = address!("0x00000000000000000000000000000000000000bb");
    const T: Address = address!("0x00000000000000000000000000000000000000cc");
    const COINBASE: Address = address!("0x00000000000000000000000000000000000000ee");

    fn tx(value: u64) -> SimTx {
        SimTx { from: A, to: T, nonce: 0, gas_limit: 100_000, gas_price: 12, value: U256::from(value), data: Bytes::new() }
    }
    fn block() -> SimBlock {
        SimBlock { number: 1, timestamp: 1, basefee: 10, gas_limit: 30_000_000, beneficiary: COINBASE, prevrandao: B256::ZERO }
    }
    fn t(a: Address) -> B256 {
        a.into_word()
    }
    fn w(x: u64) -> Vec<u8> {
        U256::from(x).to_be_bytes::<32>().to_vec()
    }
    fn log(address: Address, topics: Vec<B256>, data: Vec<u8>) -> SimLog {
        SimLog { address, topics, data: data.into() }
    }
    fn change(address: Address, before: u64, after: u64, slots: usize) -> SimChange {
        SimChange {
            address,
            balance_before: U256::from(before),
            balance_after: U256::from(after),
            nonce_before: 0,
            nonce_after: 0,
            slots: (0..slots).map(|i| SlotChange { slot: U256::from(i), before: U256::ZERO, after: U256::from(1) }).collect(),
        }
    }
    fn result(gas_used: u64, logs: Vec<SimLog>, changes: Vec<SimChange>) -> SimResult {
        SimResult { success: true, gas_used, logs, changes, ..Default::default() }
    }
    fn kinds(e: &[Effect]) -> Vec<u8> {
        e.iter().map(|e| e.kind).collect()
    }

    #[test]
    fn eth_transfer_is_native_out_in_and_gas() {
        // A sends 1000 wei to B; gas 21000 @ 12 (basefee 10, tip 2)
        let fee = 21_000 * 12;
        let tip = 21_000 * 2;
        let r = result(21_000, vec![], vec![
            change(A, 1_000_000, 1_000_000 - 1000 - fee, 0),
            change(B, 0, 1000, 0),
            change(COINBASE, 5, 5 + tip, 0),
        ]);
        let e = effects(&tx(1000), &block(), &r);
        assert_eq!(kinds(&e), vec![effect::GAS_FEE, effect::NATIVE_OUT, effect::NATIVE_IN, effect::NET_LOSS]);
        assert_eq!((e[3].contract, e[3].amount), (Address::ZERO, U256::from(1000))); // sender: -1000 wei net of gas
        assert_eq!(e[0].amount, U256::from(fee));
        assert_eq!((e[1].from, e[1].amount), (A, U256::from(1000)));
        assert_eq!((e[2].to, e[2].amount), (B, U256::from(1000)));
    }

    #[test]
    fn erc20_transfer_and_approval() {
        let r = result(50_000, vec![
            log(T, vec![sig("Transfer(address,address,uint256)"), t(A), t(B)], w(7)),
            log(T, vec![sig("Approval(address,address,uint256)"), t(A), t(B)], w(9)),
        ], vec![change(T, 0, 0, 3)]);
        let e = effects(&tx(0), &block(), &r);
        assert_eq!(kinds(&e), vec![effect::GAS_FEE, effect::ERC20_TRANSFER, effect::ERC20_APPROVAL, effect::NET_LOSS]);
        assert_eq!((e[3].contract, e[3].amount), (T, U256::from(7)));
        assert_eq!((e[1].contract, e[1].from, e[1].to, e[1].amount), (T, A, B, U256::from(7)));
        assert_eq!((e[2].from, e[2].to, e[2].amount), (A, B, U256::from(9)));
    }

    #[test]
    fn nft_events() {
        let id = B256::from(U256::from(42));
        let r = result(1, vec![
            log(T, vec![sig("Transfer(address,address,uint256)"), t(A), t(B), id], vec![]),
            log(T, vec![sig("Approval(address,address,uint256)"), t(A), t(B), id], vec![]),
            log(T, vec![sig("ApprovalForAll(address,address,bool)"), t(A), t(B)], w(1)),
            log(T, vec![sig("TransferSingle(address,address,address,uint256,uint256)"), t(B), t(A), t(B)], [w(5), w(3)].concat()),
        ], vec![]);
        let e = effects(&tx(0), &block(), &r);
        assert_eq!(kinds(&e)[1..], [effect::NFT_TRANSFER, effect::NFT_APPROVAL, effect::APPROVAL_FOR_ALL, effect::ERC1155_TRANSFER]);
        assert_eq!(e[1].amount, U256::from(42));
        assert_eq!(e[3].amount, U256::from(1));
        assert_eq!((e[4].from, e[4].to, e[4].amount), (A, B, U256::from(3)));
        assert_eq!(U256::from_be_slice(&e[4].extra), U256::from(5));
    }

    #[test]
    fn permit2_and_authority_events() {
        let r = result(1, vec![
            log(T, vec![sig("Approval(address,address,address,uint160,uint48)"), t(A), t(B), t(COINBASE)], [w(100), w(1_700_000_000)].concat()),
            log(T, vec![sig("OwnershipTransferred(address,address)"), t(A), t(B)], vec![]),
            log(T, vec![sig("Upgraded(address)"), t(B)], vec![]),
            log(T, vec![sig("AdminChanged(address,address)")], [t(A).to_vec(), t(B).to_vec()].concat()),
        ], vec![]);
        let e = effects(&tx(0), &block(), &r);
        assert_eq!(kinds(&e)[1..], [effect::PERMIT2_APPROVAL, effect::OWNERSHIP_TRANSFER, effect::PROXY_UPGRADE, effect::PROXY_ADMIN_CHANGE]);
        let p = &e[1];
        assert_eq!((p.from, p.to, p.amount), (A, COINBASE, U256::from(100)));
        assert_eq!(&p.extra[..20], B.as_slice()); // token
        assert_eq!(U256::from_be_slice(&p.extra[20..]), U256::from(1_700_000_000u64));
        assert_eq!((e[2].from, e[2].to), (A, B));
        assert_eq!(e[3].to, B);
        assert_eq!((e[4].from, e[4].to), (A, B));
    }

    #[test]
    fn silent_storage_writes_are_unexplained() {
        // T changes 2 slots with no event; an unknown event doesn't count as an explanation
        let r = result(1, vec![log(T, vec![sig("Minted(address,uint256)"), t(A)], w(1))], vec![change(T, 0, 0, 2)]);
        let e = effects(&tx(0), &block(), &r);
        assert_eq!(kinds(&e), vec![effect::GAS_FEE, effect::UNEXPLAINED_STORAGE]);
        assert_eq!((e[1].contract, e[1].amount), (T, U256::from(2)));
    }

    #[test]
    fn swap_bookkeeping_and_sender_net() {
        // V2 swap paid in ETH: A wraps 100 into WETH (W), pair P sends 250 of token T to A
        let w_ = address!("0x00000000000000000000000000000000000000a1");
        let p = address!("0x00000000000000000000000000000000000000a2");
        let r = result(1, vec![
            log(w_, vec![sig("Deposit(address,uint256)"), t(B)], w(100)),
            log(w_, vec![sig("Transfer(address,address,uint256)"), t(B), t(p)], w(100)),
            log(T, vec![sig("Transfer(address,address,uint256)"), t(p), t(A)], w(250)),
            log(p, vec![sig("Sync(uint112,uint112)")], [w(1), w(2)].concat()),
            log(p, vec![sig("Swap(address,uint256,uint256,uint256,uint256,address)"), t(B), t(A)], [w(100), w(0), w(0), w(250)].concat()),
        ], vec![change(A, 1_000_000, 1_000_000 - 100 - 12, 0), change(w_, 0, 100, 2), change(T, 0, 0, 2), change(p, 0, 0, 3)]);
        let e = effects(&tx(100), &block(), &r);
        let k = kinds(&e);
        assert!(!k.contains(&effect::UNEXPLAINED_STORAGE), "pool / WETH storage should be explained: {k:?}");
        assert!(k.contains(&effect::WRAP) && k.contains(&effect::POOL_SWAP));
        let net: Vec<_> = e.iter().filter(|e| matches!(e.kind, effect::NET_GAIN | effect::NET_LOSS)).map(|e| (e.kind, e.contract, e.amount)).collect();
        assert_eq!(net, vec![(effect::NET_LOSS, Address::ZERO, U256::from(100)), (effect::NET_GAIN, T, U256::from(250))]);
    }

    #[test]
    fn eip7708_eth_transfer_logs_are_not_tokens() {
        // Amsterdam: a plain ETH transfer of 1000 also logs Transfer(A, B, 1000) from 0xff..fe
        let sys = address!("0xfffffffffffffffffffffffffffffffffffffffe");
        let r = result(21_000, vec![log(sys, vec![sig("Transfer(address,address,uint256)"), t(A), t(B)], w(1000))], vec![
            change(A, 1_000_000, 1_000_000 - 1000 - 21_000 * 12, 0),
            change(B, 0, 1000, 0),
        ]);
        let e = effects(&tx(1000), &block(), &r);
        assert_eq!(kinds(&e), vec![effect::GAS_FEE, effect::NATIVE_OUT, effect::NATIVE_IN, effect::NET_LOSS]);
        assert_eq!(e[3].contract, Address::ZERO); // an ETH loss, not a token at 0xff..fe
    }

    #[test]
    fn malformed_events_are_not_recognised() {
        // right signature, wrong shape: must not be trusted as a Transfer
        let r = result(1, vec![
            log(T, vec![sig("Transfer(address,address,uint256)"), t(A), t(B)], vec![1, 2, 3]),
            log(T, vec![sig("ApprovalForAll(address,address,bool)"), t(A), t(B)], w(2)),
        ], vec![change(T, 0, 0, 1)]);
        let e = effects(&tx(0), &block(), &r);
        assert_eq!(kinds(&e), vec![effect::GAS_FEE, effect::UNEXPLAINED_STORAGE]);
    }
}

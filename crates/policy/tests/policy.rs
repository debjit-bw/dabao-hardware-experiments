//! The signing policy on real Sepolia transactions the Dabao signed (crates/xous-evm/fixtures),
//! with the firmware's policy and with small crafted policies.
use alloy_primitives::{Address, Bytes, U256, address};
use policy::{ChainPolicy, Counter, Limit, Outcome, Policy, counter_id, evaluate};
use sim_types::{Effect, SimInput, SimResult, effect};

const SEPOLIA: u64 = 11_155_111;
const WETH: Address = address!("0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14");
const USDC: Address = address!("0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238");
const ROUTER: Address = address!("0x3bFA4769FB09eefC5a80d6E87c3B9C650f7Ae48E");
const DEAD: Address = address!("0x000000000000000000000000000000000000dEaD");

fn sim(fixture: &[u8]) -> (SimInput, SimResult) {
    let input: SimInput = alloy_rlp::Decodable::decode(&mut &fixture[..]).unwrap();
    let mut r = xous_evm::sim::simulate(fixture).unwrap();
    r.clear_sign = clear_sign::check(&clear_sign::builtin(), input.chain_id, &input.tx, r.success, &r.effects);
    (input, r)
}

fn eval(p: &Policy, counters: &[Counter], input: &SimInput, r: &SimResult) -> Outcome {
    evaluate(p, counters, &clear_sign::builtin(), input, r)
}

fn text(o: &Outcome) -> String {
    let s = |v: &[Bytes]| v.iter().map(|b| String::from_utf8_lossy(b).to_string()).collect::<Vec<_>>();
    format!("violations {:?} notes {:?}", s(&o.check.violations), s(&o.check.notes))
}

fn eth(x: &str) -> U256 {
    // "0.005" -> wei
    let (i, f) = x.split_once('.').unwrap_or((x, ""));
    format!("{i}{f:0<18}").parse().unwrap()
}

/// A Sepolia policy with these ETH / WETH daily limits, no fee / slippage cap, no address rules.
fn small(eth_daily: &str, weth_daily: Option<&str>) -> Policy {
    let mut limits = vec![Limit { asset: Address::ZERO, daily: eth(eth_daily) }];
    if let Some(w) = weth_daily {
        limits.push(Limit { asset: WETH, daily: eth(w) });
    }
    Policy {
        version: 1,
        id: Bytes::from_static(b"test"),
        chains: vec![ChainPolicy { chain_id: SEPOLIA, max_fee: U256::ZERO, max_slippage_bps: 10_000, contracts: vec![], recipients: vec![], allow_unlimited_assets: false, limits }],
    }
}

fn fresh(p: &Policy) -> Vec<Counter> {
    p.limits().map(|(_, c, l)| Counter { id: counter_id(c, l.asset), day: 0, spent: 0 }).collect()
}

fn apply(counters: &mut [Counter], o: &Outcome) {
    for (i, c) in &o.updates {
        counters[*i] = *c;
    }
}

#[test]
fn firmware_policy_passes_the_board_eth_send_and_counts_it() {
    let p = policy::builtin();
    let (input, r) = sim(include_bytes!("../../xous-evm/fixtures/sepolia-eth-send.rlp"));
    let o = eval(&p, &fresh(&p), &input, &r);
    eprintln!("{}", text(&o));
    assert!(o.check.violations.is_empty(), "{}", text(&o));
    // value + max fee is recorded against ETH, for today
    let (i, c) = o.updates[0];
    assert_eq!(i, 0);
    let max_fee = U256::from(input.tx.gas_limit) * U256::from(input.tx.gas_price);
    assert_eq!(U256::from(c.spent), eth("0.001") + max_fee);
    assert_eq!(c.day as u64, input.block.timestamp / 86_400);
}

#[test]
fn daily_limit_accumulates_and_resets_the_next_day() {
    // 0.001 ETH + ~0.00003 max fee per send; limit 0.0025 -> two pass, the third is refused
    let p = small("0.0025", None);
    let (mut input, r) = sim(include_bytes!("../../xous-evm/fixtures/sepolia-eth-send.rlp"));
    let mut counters = fresh(&p);
    for n in 0..2 {
        let o = eval(&p, &counters, &input, &r);
        assert!(o.check.violations.is_empty(), "send {n}: {}", text(&o));
        apply(&mut counters, &o);
    }
    let o = eval(&p, &counters, &input, &r);
    assert!(text(&o).contains("daily limit"), "{}", text(&o));
    assert!(o.updates.is_empty(), "nothing recorded for a refused tx");
    input.block.timestamp += 86_400; // the next day
    let o = eval(&p, &counters, &input, &r);
    assert!(o.check.violations.is_empty(), "{}", text(&o));
}

#[test]
fn chain_without_a_policy_is_refused() {
    let (input, r) = sim(include_bytes!("../../xous-evm/fixtures/weth-transfer.rlp")); // mainnet
    let o = eval(&policy::builtin(), &[], &input, &r);
    assert!(text(&o).contains("no policy for chain 1"), "{}", text(&o));
}

#[test]
fn asset_without_a_limit_is_refused() {
    // a WETH transfer under a policy with only an ETH limit
    let (input, r) = sim(include_bytes!("../../xous-evm/fixtures/sepolia-weth-transfer.rlp"));
    let o = eval(&small("1", None), &[], &input, &r);
    assert!(text(&o).contains("no daily limit"), "{}", text(&o));
    let o = eval(&small("1", Some("0.01")), &fresh(&small("1", Some("0.01"))), &input, &r);
    assert!(o.check.violations.is_empty(), "{}", text(&o));
    let o = eval(&small("1", Some("0.0005")), &fresh(&small("1", Some("0.0005"))), &input, &r);
    assert!(text(&o).contains("daily limit"), "0.001 WETH > 0.0005: {}", text(&o));
}

#[test]
fn slippage_cap_refuses_a_loose_minimum() {
    // the board's swap: minimum is 10.32% below the simulation; the firmware policy allows 3%
    let (input, r) = sim(include_bytes!("../../xous-evm/fixtures/sepolia-swap.rlp"));
    let o = eval(&policy::builtin(), &fresh(&policy::builtin()), &input, &r);
    assert!(text(&o).contains("slippage: minimum 0.000252 USDC is 1032 bps"), "{}", text(&o));
    // with a 15% cap it passes, and spends ETH (value + fee), nothing else
    let mut p = policy::builtin();
    p.chains[0].max_slippage_bps = 1_500;
    let o = eval(&p, &fresh(&p), &input, &r);
    assert!(o.check.violations.is_empty(), "{}", text(&o));
    assert_eq!(o.updates.len(), 1);
}

#[test]
fn address_rules_and_fee_cap() {
    let (input, r) = sim(include_bytes!("../../xous-evm/fixtures/sepolia-eth-send.rlp"));
    let mut p = small("1", None);
    p.chains[0].contracts = vec![ROUTER, WETH];
    let o = eval(&p, &fresh(&p), &input, &r);
    assert!(text(&o).contains(&format!("{DEAD} is not an allowed recipient")), "{}", text(&o));
    p.chains[0].recipients.push(DEAD);
    assert!(eval(&p, &fresh(&p), &input, &r).check.violations.is_empty());
    p.chains[0].max_fee = eth("0.00001");
    let o = eval(&p, &fresh(&p), &input, &r);
    assert!(text(&o).contains("max network fee"), "{}", text(&o));
}

#[test]
fn allowances_count_as_spending() {
    // an unlimited WETH approval is refused by any finite limit, even with no tokens moving
    let (input, mut r) = sim(include_bytes!("../../xous-evm/fixtures/sepolia-weth-transfer.rlp"));
    let me = input.tx.from;
    r.effects.retain(|e| e.kind == effect::GAS_FEE);
    r.effects.push(Effect { kind: effect::ERC20_APPROVAL, contract: WETH, from: me, to: ROUTER, amount: U256::MAX, extra: Bytes::new() });
    let p = small("1", Some("0.01"));
    let o = eval(&p, &fresh(&p), &input, &r);
    assert!(text(&o).contains("daily limit") && text(&o).contains("WETH"), "{}", text(&o));
    // and an NFT operator approval has no limit to fit in
    r.effects.retain(|e| e.kind == effect::GAS_FEE);
    r.effects.push(Effect { kind: effect::APPROVAL_FOR_ALL, contract: USDC, from: me, to: ROUTER, amount: U256::from(1), extra: Bytes::new() });
    assert!(text(&eval(&p, &fresh(&p), &input, &r)).contains("NFT approval"));
}

#[test]
fn counter_slots_round_trip_and_reject_other_limits() {
    let id = counter_id(SEPOLIA, WETH);
    let c = Counter { id, day: 20_414, spent: 123_456_789 };
    assert_eq!(Counter::decode(&c.encode(), id), c);
    // the same slot read for another limit (policy changed) is a fresh counter
    let other = counter_id(SEPOLIA, USDC);
    assert_eq!(Counter::decode(&c.encode(), other), Counter { id: other, day: 0, spent: 0 });
    // an empty slot too
    assert_eq!(Counter::decode(&[0; 32], id).spent, 0);
    assert_eq!(c.spent_on(20_414), 123_456_789);
    assert_eq!(c.spent_on(20_415), 0);
}

fn swap_under_a_loose_cap() -> (Policy, SimInput, SimResult) {
    let mut p = policy::builtin();
    p.chains[0].max_slippage_bps = 1_500;
    let (input, r) = sim(include_bytes!("../../xous-evm/fixtures/sepolia-swap.rlp"));
    assert!(eval(&p, &fresh(&p), &input, &r).check.violations.is_empty(), "the honest swap passes");
    (p, input, r)
}

#[test]
fn a_router_is_not_a_recipient() {
    // swap output left in the router: no gain to the sender, sweepable by anyone
    let (p, input, mut r) = swap_under_a_loose_cap();
    r.effects.retain(|e| e.kind != effect::NET_GAIN);
    r.clear_sign.addresses = vec![ROUTER];
    r.clear_sign.min_receive.clear();
    let t = text(&eval(&p, &fresh(&p), &input, &r));
    assert!(t.contains("not an allowed recipient") && t.contains("only recipient is the sender") && t.contains("a gain"), "{t}");
    // an allowed recipient can't take swap output either
    r.clear_sign.addresses = vec![DEAD];
    assert!(text(&eval(&p, &fresh(&p), &input, &r)).contains("only recipient is the sender"));
}

#[test]
fn funds_left_in_the_called_contract_are_refused() {
    let (p, input, r) = swap_under_a_loose_cap();
    for (kind, contract) in [(effect::NATIVE_IN, Address::ZERO), (effect::ERC20_TRANSFER, USDC), (effect::WRAP, WETH)] {
        let mut x = r.clone();
        x.effects.push(Effect { kind, contract, from: Address::ZERO, to: ROUTER, amount: U256::from(5), extra: Bytes::new() });
        assert!(text(&eval(&p, &fresh(&p), &input, &x)).contains("keeps"), "kind {kind}");
    }
}

#[test]
fn a_second_swap_and_a_loose_maximum_are_refused() {
    let (p, input, r) = swap_under_a_loose_cap();
    let mut two = r.clone();
    two.clear_sign.addresses = vec![input.tx.from, input.tx.from];
    assert!(text(&eval(&p, &fresh(&p), &input, &two)).contains("single swap"));
    let mut loose = r.clone();
    loose.clear_sign.max_spend.push(sim_types::MaxSpend { asset: WETH, shown: U256::from(200), simulated: U256::from(100) });
    assert!(text(&eval(&p, &fresh(&p), &input, &loose)).contains("maximum"));
}

#[test]
fn plain_eth_to_a_callable_contract_is_refused() {
    let (mut input, mut r) = sim(include_bytes!("../../xous-evm/fixtures/sepolia-eth-send.rlp"));
    input.tx.to = ROUTER;
    r.clear_sign.addresses = vec![ROUTER];
    let p = policy::builtin();
    assert!(text(&eval(&p, &fresh(&p), &input, &r)).contains("not an allowed recipient"));
}

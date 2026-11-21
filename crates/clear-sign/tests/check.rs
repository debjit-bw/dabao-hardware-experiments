//! The ERC-7730 check on real mainnet transactions (fixtures from crates/xous-evm/fixtures),
//! and on crafted effects that a shown display must not hide.
use alloy_primitives::{Address, Bytes, U256, address};
use sim_types::{ClearSign, Effect, SimInput, SimTx, effect};

const WETH: Address = address!("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2");
const ROUTER: Address = address!("0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45");

fn run(fixture: &[u8]) -> (SimInput, ClearSign) {
    let input: SimInput = alloy_rlp::Decodable::decode(&mut &fixture[..]).unwrap();
    let r = xous_evm::sim::simulate(fixture).expect("simulates");
    let c = clear_sign::check(&clear_sign::builtin(), input.chain_id, &input.tx, r.success, &r.effects);
    (input, c)
}

fn show(c: &ClearSign) -> String {
    let f: Vec<String> = c.fields.iter().map(|f| format!("{}={}", String::from_utf8_lossy(&f.label), String::from_utf8_lossy(&f.value))).collect();
    let v: Vec<String> = c.violations.iter().map(|v| String::from_utf8_lossy(v).to_string()).collect();
    let w: Vec<String> = c.warnings.iter().map(|v| String::from_utf8_lossy(v).to_string()).collect();
    format!("[{}] intent '{}' fields {f:?} violations {v:?} warnings {w:?}", String::from_utf8_lossy(&c.descriptor), String::from_utf8_lossy(&c.intent))
}

#[test]
fn weth_transfer_passes() {
    let (_, c) = run(include_bytes!("../../xous-evm/fixtures/weth-transfer.rlp"));
    eprintln!("{}", show(&c));
    assert_eq!(c.descriptor.as_ref(), b"WETH9 (dabao-hackathon)");
    assert!(c.violations.is_empty(), "{}", show(&c));
    assert_eq!(c.intent.as_ref(), b"Send");
}

#[test]
fn swap_exact_input_single_passes() {
    // SwapRouter02.exactInputSingle paid with ETH: the loss is tx.value, which is always shown
    let (_, c) = run(include_bytes!("../../xous-evm/fixtures/uniswap-swap.rlp"));
    eprintln!("{}", show(&c));
    assert_eq!(c.descriptor.as_ref(), b"Uniswap v3 Router 2");
    assert!(c.violations.is_empty(), "{}", show(&c));
    // this real mainnet swap set amountOutMinimum = 0: signable, but warned about
    assert_eq!(c.warnings.len(), 1, "{}", show(&c));
    assert!(String::from_utf8_lossy(&c.warnings[0]).starts_with("'Minimum to Receive' is 0"), "{}", show(&c));
}

#[test]
fn amounts_use_the_trusted_token_list() {
    use clear_sign::check::format_units;
    assert_eq!(format_units(U256::from(1_500_000u64), 6), "1.5");
    assert_eq!(format_units(U256::from(252u64), 6), "0.000252");
    assert_eq!(format_units(U256::from(10u64).pow(U256::from(18)), 18), "1");
    assert_eq!(format_units(U256::ZERO, 18), "0");
    assert_eq!(format_units(U256::from(123u64), 0), "123");
    let set = clear_sign::builtin();
    let usdc = address!("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
    let f = |chain, a| clear_sign::check::format_amount(&set, chain, a, U256::from(2_500_000u64));
    assert_eq!(f(1, usdc), "2.5 USDC");
    assert_eq!(f(1, Address::ZERO), "0.0000000000025 ETH");
    // the same address on another chain is not that token
    assert_eq!(f(11155111, usdc), format!("2500000 raw units of unlisted token {usdc}"));
}

#[test]
fn swap_inside_multicall_passes() {
    // the exact mainnet replay: multicall(deadline, [exactInputSingle]); the registry has no
    // multicall format, our extension checks the inner call
    let (_, c) = run(include_bytes!("../../xous-evm/fixtures/uniswap-swap-replay.rlp"));
    eprintln!("{}", show(&c));
    assert!(c.violations.is_empty(), "{}", show(&c));
    assert!(String::from_utf8_lossy(&c.intent).starts_with("multicall: swap"));
}

// ---- crafted cases: what the display must not hide ------------------------------------------

fn tx(to: Address, data: Vec<u8>, value: u64) -> SimTx {
    SimTx { from: address!("0x00000000000000000000000000000000000000aa"), to, nonce: 0, gas_limit: 100_000, gas_price: 1, value: U256::from(value), data: data.into(), max_priority_fee_per_gas: None }
}
fn fx(kind: u8, contract: Address, from: Address, to: Address, amount: u64) -> Effect {
    Effect { kind, contract, from, to, amount: U256::from(amount), extra: Bytes::new() }
}
/// WETH transfer(dst, wad) calldata
fn weth_transfer(dst: Address, wad: u64) -> Vec<u8> {
    let mut d = vec![0xa9, 0x05, 0x9c, 0xbb];
    d.extend_from_slice(&[0u8; 12]);
    d.extend_from_slice(dst.as_slice());
    d.extend_from_slice(&U256::from(wad).to_be_bytes::<32>());
    d
}
fn check(t: &SimTx, effects: &[Effect]) -> ClearSign {
    clear_sign::check(&clear_sign::builtin(), 1, t, true, effects)
}

#[test]
fn hidden_loss_is_refused() {
    // shows "Send 5 WETH", but the sender loses 50
    let me = address!("0x00000000000000000000000000000000000000aa");
    let bob = address!("0x00000000000000000000000000000000000000bb");
    let t = tx(WETH, weth_transfer(bob, 5), 0);
    let ok = check(&t, &[fx(effect::NET_LOSS, WETH, me, Address::ZERO, 5)]);
    assert!(ok.violations.is_empty(), "{}", show(&ok));
    let bad = check(&t, &[fx(effect::NET_LOSS, WETH, me, Address::ZERO, 50)]);
    assert!(show(&bad).contains("hidden loss"), "{}", show(&bad));
    // and losing a different token than the one shown
    let other = address!("0x00000000000000000000000000000000000000cc");
    let bad2 = check(&t, &[fx(effect::NET_LOSS, other, me, Address::ZERO, 1)]);
    assert!(show(&bad2).contains("hidden loss"), "{}", show(&bad2));
    // ETH leaving beyond tx.value
    let bad3 = check(&t, &[fx(effect::NET_LOSS, Address::ZERO, me, Address::ZERO, 1)]);
    assert!(show(&bad3).contains("hidden loss"), "{}", show(&bad3));
}

#[test]
fn hidden_approval_is_refused() {
    // a "transfer" that also grants an allowance to someone not shown
    let me = address!("0x00000000000000000000000000000000000000aa");
    let bob = address!("0x00000000000000000000000000000000000000bb");
    let thief = address!("0x00000000000000000000000000000000000000ee");
    let t = tx(WETH, weth_transfer(bob, 5), 0);
    let bad = check(&t, &[fx(effect::ERC20_APPROVAL, WETH, me, thief, 1_000_000)]);
    assert!(show(&bad).contains("hidden approval"), "{}", show(&bad));
    let bad = check(&t, &[fx(effect::APPROVAL_FOR_ALL, address!("0x00000000000000000000000000000000000000dd"), me, thief, 1)]);
    assert!(show(&bad).contains("hidden approval"), "{}", show(&bad));
    // an approval to the *shown* recipient, larger than the shown amount, is still refused
    let bad = check(&t, &[fx(effect::ERC20_APPROVAL, WETH, me, bob, 6)]);
    assert!(show(&bad).contains("exceeds"), "{}", show(&bad));
}

#[test]
fn authority_change_and_unexplained_storage_are_refused() {
    let me = address!("0x00000000000000000000000000000000000000aa");
    let bob = address!("0x00000000000000000000000000000000000000bb");
    let t = tx(WETH, weth_transfer(bob, 5), 0);
    let c = address!("0x00000000000000000000000000000000000000c1");
    let bad = check(&t, &[fx(effect::OWNERSHIP_TRANSFER, c, me, address!("0x00000000000000000000000000000000000000ee"), 0)]);
    assert!(show(&bad).contains("hidden authority"), "{}", show(&bad));
    let bad = check(&t, &[fx(effect::UNEXPLAINED_STORAGE, c, Address::ZERO, Address::ZERO, 3)]);
    assert!(show(&bad).contains("unexplained"), "{}", show(&bad));
}

#[test]
fn blind_signing_is_refused() {
    // a contract with no descriptor
    let usdc = address!("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
    let c = check(&tx(usdc, weth_transfer(Address::ZERO, 1), 0), &[]);
    assert!(show(&c).contains("blind signing refused"), "{}", show(&c));
    // a known contract, unknown function
    let c = check(&tx(ROUTER, vec![0xde, 0xad, 0xbe, 0xef, 0, 0], 0), &[]);
    assert!(show(&c).contains("blind signing refused"), "{}", show(&c));
    // a multicall with an inner call that has no format
    let mut mc = vec![0xac, 0x96, 0x50, 0xd8]; // multicall(bytes[])
    let inner: Vec<u8> = vec![0xde, 0xad, 0xbe, 0xef];
    use alloy_dyn_abi::DynSolValue;
    mc.extend(DynSolValue::Tuple(vec![DynSolValue::Array(vec![DynSolValue::Bytes(inner)])]).abi_encode_params());
    let c = check(&tx(ROUTER, mc, 0), &[]);
    assert!(show(&c).contains("has no format"), "{}", show(&c));
    // plain ETH transfers are fine (value and recipient always shown)
    let me = address!("0x00000000000000000000000000000000000000aa");
    let c = check(&tx(usdc, vec![], 7), &[fx(effect::NET_LOSS, Address::ZERO, me, Address::ZERO, 7)]);
    assert!(c.violations.is_empty(), "{}", show(&c));
}

#[test]
fn revert_is_refused() {
    let t = tx(WETH, weth_transfer(Address::ZERO, 1), 0);
    let c = clear_sign::check(&clear_sign::builtin(), 1, &t, false, &[]);
    assert!(show(&c).contains("reverts"), "{}", show(&c));
}

#[test]
fn sepolia_transactions_pass() {
    // the three txs the Dabao signed on Sepolia (Amsterdam, EIP-7708 ETH logs)
    for (name, f) in [
        ("eth send", &include_bytes!("../../xous-evm/fixtures/sepolia-eth-send.rlp")[..]),
        ("weth deposit", &include_bytes!("../../xous-evm/fixtures/sepolia-weth-deposit.rlp")[..]),
        ("weth transfer", &include_bytes!("../../xous-evm/fixtures/sepolia-weth-transfer.rlp")[..]),
    ] {
        let (_, c) = run(f);
        eprintln!("{name}: {}", show(&c));
        assert!(!c.descriptor.is_empty() && c.violations.is_empty(), "{name}: {}", show(&c));
    }
}

#[test]
fn sepolia_swaps_signed_by_the_board_pass() {
    // two Uniswap swaps (1e10 wei ETH -> USDC) the Dabao signed on Sepolia, replayed on their
    // parent state; the second is wrapped in multicall(deadline, [exactInputSingle])
    for (name, f, intent) in [
        ("exactInputSingle", &include_bytes!("../../xous-evm/fixtures/sepolia-swap.rlp")[..], "swap"),
        ("multicall", &include_bytes!("../../xous-evm/fixtures/sepolia-swap-multicall.rlp")[..], "multicall: swap"),
    ] {
        let (_, c) = run(f);
        assert!(c.violations.is_empty(), "{name}: {}", show(&c));
        assert_eq!(String::from_utf8_lossy(&c.intent), intent, "{name}");
        assert!(show(&c).contains("Minimum to Receive=0.000252 USDC (simulated: 0.000281 USDC, 10.32% lower)"), "{name}: {}", show(&c));
        assert!(c.warnings.is_empty(), "{name}: 90% of the quote is not a loose limit");
    }
}

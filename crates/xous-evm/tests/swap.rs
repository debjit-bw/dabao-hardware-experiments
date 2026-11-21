//! A real Uniswap SwapRouter02 swap (host: `dabao-host build ... --find-swap`), re-done on
//! mainnet block 26463980. Checks the effects inspector's view of a swap.
use sim_types::effect;
use xous_evm::sim::simulate;

const SWAP: &[u8] = include_bytes!("../fixtures/uniswap-swap.rlp");

fn name(k: u8) -> &'static str {
    match k {
        effect::NATIVE_OUT => "NATIVE_OUT",
        effect::NATIVE_IN => "NATIVE_IN",
        effect::GAS_FEE => "GAS_FEE",
        effect::ERC20_TRANSFER => "ERC20_TRANSFER",
        effect::ERC20_APPROVAL => "ERC20_APPROVAL",
        effect::UNEXPLAINED_STORAGE => "UNEXPLAINED_STORAGE",
        effect::WRAP => "WRAP",
        effect::POOL_SWAP => "POOL_SWAP",
        effect::NET_GAIN => "NET_GAIN",
        effect::NET_LOSS => "NET_LOSS",
        _ => "other",
    }
}

#[test]
fn print_swap_effects() {
    let r = simulate(SWAP).expect("simulates");
    eprintln!("success={} gas={} logs={}", r.success, r.gas_used, r.logs.len());
    for l in &r.logs {
        eprintln!("  log {} topic0={:?} ntopics={} data={}B", l.address, l.topics.first(), l.topics.len(), l.data.len());
    }
    for e in &r.effects {
        eprintln!("  effect {:<20} contract={} from={} to={} amount={}", name(e.kind), e.contract, e.from, e.to, e.amount);
    }
}

#[test]
fn swap_effects_are_fully_explained() {
    use alloy_primitives::{Address, U256, address};
    let input: sim_types::SimInput = alloy_rlp::Decodable::decode(&mut &SWAP[..]).unwrap();
    let r = simulate(SWAP).expect("simulates");
    assert!(r.success);
    let k: Vec<u8> = r.effects.iter().map(|e| e.kind).collect();
    assert!(!k.contains(&effect::UNEXPLAINED_STORAGE), "unexplained storage left: {k:?}");
    assert!(k.contains(&effect::POOL_SWAP));
    // the sender: pays exactly tx.value in ETH (gas separate), gains some of the output token
    let sender = input.tx.from;
    let net: Vec<_> = r.effects.iter().filter(|e| matches!(e.kind, effect::NET_GAIN | effect::NET_LOSS)).collect();
    assert_eq!(net.len(), 2, "{net:?}");
    assert!(net.iter().all(|e| e.from == sender));
    let eth = net.iter().find(|e| e.contract == Address::ZERO).expect("ETH leg");
    assert_eq!((eth.kind, eth.amount), (effect::NET_LOSS, input.tx.value));
    let tok = net.iter().find(|e| e.contract != Address::ZERO).expect("token leg");
    assert_eq!(tok.kind, effect::NET_GAIN);
    assert_eq!(tok.contract, address!("0xcccCCCcCCC33D538DBC2EE4fEab0a7A1FF4e8A94"));
    assert!(tok.amount > U256::ZERO);
}

/// A swap replayed exactly as mined (block 26464010 tx 0x38c2…da1a on its parent state; built
/// with `dabao-host build --find-swap` against an RPC with a 128-block proof window). At build
/// time the host checked: status, gas used (124255) and all 3 logs identical to the receipt.
const REPLAY: &[u8] = include_bytes!("../fixtures/uniswap-swap-replay.rlp");

#[test]
fn replayed_swap_matches_chain_and_is_explained() {
    let r = simulate(REPLAY).expect("simulates");
    assert!(r.success);
    assert_eq!(r.gas_used, 124_255, "gas used on chain");
    assert_eq!(r.logs.len(), 3);
    for e in &r.effects {
        eprintln!("  replay effect {:<20} contract={} from={} to={} amount={}", name(e.kind), e.contract, e.from, e.to, e.amount);
    }
    let k: Vec<u8> = r.effects.iter().map(|e| e.kind).collect();
    assert!(!k.contains(&effect::UNEXPLAINED_STORAGE), "unexplained storage left: {k:?}");
    assert!(k.contains(&effect::POOL_SWAP));
    assert!(k.contains(&effect::NET_GAIN) && k.contains(&effect::NET_LOSS));
}

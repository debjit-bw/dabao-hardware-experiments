//! The mainnet WETH transfer fixture (host/witness-gen, block 26463239): expected effects,
//! and fail-closed behaviour when the witness is incomplete or the state root is wrong.
use alloy_primitives::{U256, address, b256};
use alloy_rlp::Decodable as _;
use xous_evm::sim::{simulate, simulate_with};

const WETH_TRANSFER: &[u8] = include_bytes!("../fixtures/weth-transfer.rlp");
const WETH: alloy_primitives::Address = address!("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2");
/// keccak256("Transfer(address,address,uint256)")
const TRANSFER: alloy_primitives::B256 =
    b256!("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef");

#[test]
fn weth_transfer_effects() {
    let r = simulate(WETH_TRANSFER).expect("simulates");
    assert!(r.success);
    assert_eq!(r.gas_used, 34218);
    assert_eq!(r.output.as_ref(), U256::from(1).to_be_bytes::<32>().as_slice()); // returns true
    assert_eq!(r.logs.len(), 1);
    assert_eq!(r.logs[0].address, WETH);
    assert_eq!(r.logs[0].topics[0], TRANSFER);
    assert_eq!(U256::from_be_slice(&r.logs[0].data), U256::from(1));
    let weth = r.changes.iter().find(|c| c.address == WETH).expect("WETH touched");
    assert_eq!(weth.slots.len(), 2); // balanceOf[from] -1, balanceOf[0xdEaD] +1
    let delta: Vec<_> = weth.slots.iter().map(|s| (s.before, s.after)).collect();
    assert!(delta.iter().any(|(b, a)| *a + U256::from(1) == *b));
    assert!(delta.iter().any(|(b, a)| *b + U256::from(1) == *a));

    // effects: the gas fee, one ERC-20 transfer of 1 unit to 0x..dEaD, and the sender's net
    // loss of 1 WETH; nothing unexplained (WETH's writes are explained by its Transfer event)
    use sim_types::effect;
    let kinds: Vec<u8> = r.effects.iter().map(|e| e.kind).collect();
    assert_eq!(kinds, vec![effect::GAS_FEE, effect::ERC20_TRANSFER, effect::NET_LOSS]);
    let t = &r.effects[1];
    assert_eq!((t.contract, t.to, t.amount), (WETH, address!("0x000000000000000000000000000000000000dEaD"), U256::from(1)));
    let n = &r.effects[2];
    assert_eq!((n.contract, n.amount), (WETH, U256::from(1)));
}

#[test]
fn missing_witness_node_never_changes_the_result() {
    // The host over-fetches (e.g. the 0x..dEaD account proof, which the EVM never reads), so
    // some nodes are unneeded. The safety property: dropping any node either fails, or yields
    // exactly the full-witness result. It must never silently produce a different outcome.
    let full = simulate(WETH_TRANSFER).expect("simulates");
    let input: sim_types::SimInput = alloy_rlp::Decodable::decode(&mut &WETH_TRANSFER[..]).unwrap();
    let n = input.state.len();
    let (mut rejected, mut unneeded) = (0, 0);
    for i in 0..n {
        match simulate_with(WETH_TRANSFER, |inp| {
            inp.state.remove(i);
        }) {
            Err(_) => rejected += 1,
            Ok(r) => {
                assert_eq!(r, full, "dropping witness node {i} of {n} changed the result");
                unneeded += 1;
            }
        }
    }
    eprintln!("{n} nodes: {rejected} needed (dropping one fails), {unneeded} unneeded");
    assert!(rejected > 0);
}

#[test]
fn wrong_state_root_is_rejected() {
    use alloy_consensus::Header;
    let r = simulate_with(WETH_TRANSFER, |inp| {
        let mut h = Header::decode(&mut &inp.parent_header[..]).unwrap();
        h.state_root.0[0] ^= 1;
        inp.parent_header = alloy_rlp::encode(&h).into();
    });
    assert!(r.is_err(), "wrong state root still simulated: {r:?}");
}

#[test]
fn tampered_witness_node_is_rejected() {
    // change one byte in every node in turn: the node no longer hashes to its parent's link,
    // so it is unreachable. Same property as dropping it: fail, or identical result.
    let full = simulate(WETH_TRANSFER).expect("simulates");
    let input: sim_types::SimInput = alloy_rlp::Decodable::decode(&mut &WETH_TRANSFER[..]).unwrap();
    for i in 0..input.state.len() {
        if let Ok(r) = simulate_with(WETH_TRANSFER, |inp| {
            let mut node = inp.state[i].to_vec();
            let last = node.len() - 1;
            node[last] ^= 1;
            inp.state[i] = node.into();
        }) {
            assert_eq!(r, full, "tampering with witness node {i} changed the result");
        }
    }
}

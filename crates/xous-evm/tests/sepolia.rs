//! Three transactions the Dabao signed and broadcast on Sepolia (Amsterdam active), replayed on
//! their parent state (`dabao-host build --replay <hash> --chain sepolia`). Expected values are
//! from the on-chain receipts: the device's EVM must reproduce them exactly.
use sim_types::effect;
use xous_evm::sim::simulate;

fn kinds(r: &sim_types::SimResult) -> Vec<u8> {
    r.effects.iter().map(|e| e.kind).collect()
}

#[test]
fn eth_send_matches_chain() {
    // 0x5faa4fe5…2112: 0.001 ETH to 0x…dEaD; Amsterdam logs it (EIP-7708)
    let r = simulate(include_bytes!("../fixtures/sepolia-eth-send.rlp")).unwrap();
    assert!(r.success);
    assert_eq!(r.gas_used, 21_000);
    assert_eq!(r.logs.len(), 1, "EIP-7708 ETH transfer log");
    assert_eq!(kinds(&r), vec![effect::GAS_FEE, effect::NATIVE_IN, effect::NATIVE_OUT, effect::NET_LOSS]);
}

#[test]
fn weth_deposit_matches_chain() {
    // 0x4ccc8235…45c7: deposit() with 0.002 ETH; EIP-8037 state gas makes it 133,058
    let r = simulate(include_bytes!("../fixtures/sepolia-weth-deposit.rlp")).unwrap();
    assert!(r.success);
    assert_eq!(r.gas_used, 133_058);
    assert_eq!(r.logs.len(), 2, "EIP-7708 ETH log + WETH Deposit");
    assert!(kinds(&r).contains(&effect::WRAP));
    assert!(!kinds(&r).contains(&effect::UNEXPLAINED_STORAGE));
}

#[test]
fn weth_transfer_matches_chain() {
    // 0x275f3946…6e2f: transfer(0x…dEaD, 0.001 WETH)
    let r = simulate(include_bytes!("../fixtures/sepolia-weth-transfer.rlp")).unwrap();
    assert!(r.success);
    assert_eq!(r.gas_used, 42_678);
    assert_eq!(r.logs.len(), 1);
    assert_eq!(kinds(&r), vec![effect::GAS_FEE, effect::ERC20_TRANSFER, effect::NET_LOSS]);
}

#[test]
fn swaps_match_chain() {
    // gas from the receipts; the first swap creates the sender's USDC balance (EIP-8037 state gas)
    for (f, gas) in [
        (&include_bytes!("../fixtures/sepolia-swap.rlp")[..], 252_708u64),
        (&include_bytes!("../fixtures/sepolia-swap-multicall.rlp")[..], 157_878),
    ] {
        let r = simulate(f).unwrap();
        assert!(r.success);
        assert_eq!(r.gas_used, gas);
        assert_eq!(r.logs.len(), 6);
        assert!(!kinds(&r).contains(&effect::UNEXPLAINED_STORAGE));
        assert!(kinds(&r).contains(&effect::POOL_SWAP));
    }
}

#[test]
fn eip1559_pays_basefee_plus_tip_not_the_cap() {
    // the same ETH send as an EIP-1559 tx: cap 100 gwei, tip 1 gwei. The sender must be
    // charged gas_used * (basefee + tip), the beneficiary gets only the tip, and the ETH moved
    // is still exactly the value (no hidden loss from the fee cap).
    let raw = include_bytes!("../fixtures/sepolia-eth-send.rlp");
    let mut basefee = 0u64;
    let tip = 1_000_000_000u128;
    let r = xous_evm::sim::simulate_with(raw, |i| {
        basefee = i.block.basefee;
        i.tx.gas_price = 100_000_000_000;
        i.tx.max_priority_fee_per_gas = Some(tip);
    })
    .unwrap();
    assert!(r.success);
    let fee = r.effects.iter().find(|e| e.kind == effect::GAS_FEE).unwrap();
    assert_eq!(fee.amount, alloy_primitives::U256::from(21_000u128 * (basefee as u128 + tip)));
    let net = r.effects.iter().find(|e| e.kind == effect::NET_LOSS).unwrap();
    assert_eq!(net.amount, alloy_primitives::U256::from(10u64.pow(15)), "0.001 ETH, gas excluded");
    assert!(!kinds(&r).contains(&effect::UNEXPLAINED_STORAGE));

    // and the RLP stays compatible: the legacy fixture decodes with no tip
    let legacy: sim_types::SimInput = alloy_rlp::Decodable::decode(&mut &raw[..]).unwrap();
    assert_eq!(legacy.tx.max_priority_fee_per_gas, None);
    let mut t = legacy.tx.clone();
    t.max_priority_fee_per_gas = Some(tip);
    let back: sim_types::SimTx = alloy_rlp::Decodable::decode(&mut &alloy_rlp::encode(&t)[..]).unwrap();
    assert_eq!(back, t);
}

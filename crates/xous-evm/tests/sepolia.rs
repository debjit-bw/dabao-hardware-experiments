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

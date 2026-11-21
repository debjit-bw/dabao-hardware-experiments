//! A SYNTHETIC SimInput for testing the sign path: a tiny state trie where `from` holds
//! 1 ETH, and a plain 0.01 ETH transfer from it. The trie, its proofs and the header are real
//! and consistent (the device verifies them like any other), but the state root is made up:
//! this is not mainnet state. Use it to exercise approve -> sign; use `build` for real state.

use alloy::consensus::{EMPTY_ROOT_HASH, Header};
use alloy_primitives::{Address, B256, Bytes, U256, address, keccak256};
use alloy_trie::{HashBuilder, KECCAK_EMPTY, Nibbles, TrieAccount, proof::ProofRetainer};
use anyhow::Result;
use sim_types::{SimBlock, SimInput, SimTx};

const RECIPIENT: Address = address!("0x000000000000000000000000000000000000bEEF");
const BENEFICIARY: Address = address!("0x4838B106FCe9647Bdf1E7877BF73cE8B0BAD5f97");

pub fn build(from: Address, out: &str, data: Bytes) -> Result<()> {
    let funded = TrieAccount {
        nonce: 0,
        balance: U256::from(10u128.pow(18)),
        storage_root: EMPTY_ROOT_HASH,
        code_hash: KECCAK_EMPTY,
    };
    // the trie holds only `from`; recipient and beneficiary are proven absent
    let targets: Vec<Nibbles> = [from, RECIPIENT, BENEFICIARY].iter().map(|a| Nibbles::unpack(keccak256(a))).collect();
    let mut hb = HashBuilder::default().with_proof_retainer(ProofRetainer::new(targets));
    hb.add_leaf(Nibbles::unpack(keccak256(from)), &alloy_rlp::encode(funded));
    let state_root = hb.root();
    let state: Vec<Bytes> = hb.take_proof_nodes().into_nodes_sorted().into_iter().map(|(_, n)| n).collect();

    let basefee = 1_000_000_000u64; // 1 gwei
    let parent = Header {
        state_root,
        number: 26_463_239,
        timestamp: 1_795_000_000, // after Osaka on mainnet's schedule
        gas_limit: 45_000_000,
        base_fee_per_gas: Some(basefee),
        beneficiary: BENEFICIARY,
        ..Default::default()
    };
    let input = SimInput {
        chain_id: 1,
        parent_header: alloy_rlp::encode(&parent).into(),
        block: SimBlock {
            number: parent.number + 1,
            timestamp: parent.timestamp + 12,
            basefee,
            gas_limit: parent.gas_limit,
            beneficiary: BENEFICIARY,
            prevrandao: B256::ZERO,
        },
        tx: SimTx {
            from,
            to: RECIPIENT,
            nonce: 0,
            gas_limit: if data.is_empty() { 21_000 } else { 100_000 },
            gas_price: basefee as u128,
            value: U256::from(10u128.pow(16)), // 0.01 ETH
            data: data.clone(),
        },
        state,
        codes: vec![],
        keys: vec![Bytes::copy_from_slice(from.as_slice())],
    };
    let bytes = alloy_rlp::encode(&input);
    std::fs::write(out, &bytes)?;
    println!(
        "SYNTHETIC state (not mainnet): {from} holds 1 ETH, state root {state_root}; tx: 0.01 ETH to {RECIPIENT} \
         with {} B calldata, {} trie nodes -> {out} ({} B)",
        data.len(),
        input.state.len(),
        bytes.len()
    );
    Ok(())
}

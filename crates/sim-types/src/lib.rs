//! Wire format for "simulate one transaction against a witness".
//!
//! The host fetches `eth_getProof` data for every account and slot the
//! transaction touches and packs the proof nodes into the same shape as
//! `ExecutionWitness { state, codes, keys, headers }`. The device trusts
//! nothing in here except what it can check: every trie node is verified
//! against the state root of `parent_header`, and (later) that header is
//! checked against a trusted head from the light client.
#![no_std]
extern crate alloc;

use alloc::vec::Vec;
use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_rlp::{RlpDecodable, RlpEncodable};

/// One transaction to simulate on top of the post-state of `parent_header`.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct SimInput {
    pub chain_id: u64,
    /// RLP-encoded header of the block whose post-state we execute on. Its
    /// `state_root` is the pre-state root; its hash serves BLOCKHASH(number).
    pub parent_header: Bytes,
    /// Environment of the (hypothetical) next block.
    pub block: SimBlock,
    pub tx: SimTx,
    /// RLP trie nodes (account and storage proofs), as `ExecutionWitness::state`.
    pub state: Vec<Bytes>,
    /// Contract bytecodes, as `ExecutionWitness::codes`.
    pub codes: Vec<Bytes>,
    /// Address and slot preimages, as `ExecutionWitness::keys`.
    pub keys: Vec<Bytes>,
}

#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct SimBlock {
    pub number: u64,
    pub timestamp: u64,
    pub basefee: u64,
    pub gas_limit: u64,
    pub beneficiary: Address,
    pub prevrandao: B256,
}

#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct SimTx {
    pub from: Address,
    pub to: Address,
    pub nonce: u64,
    pub gas_limit: u64,
    pub gas_price: u128,
    pub value: U256,
    pub data: Bytes,
}

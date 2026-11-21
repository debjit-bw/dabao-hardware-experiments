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

/// Result of a simulation, as returned by the verifier. `error` non-empty means the input
/// was rejected (decode failure, witness doesn't match the state root, missing witness data,
/// invalid tx); then the other fields are meaningless.
#[derive(Debug, Clone, Default, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct SimResult {
    pub error: Bytes,
    pub success: bool,
    pub gas_used: u64,
    pub output: Bytes,
    pub logs: Vec<SimLog>,
    pub changes: Vec<SimChange>,
    /// Verifier-side cost of this request.
    pub micros: u64,
    pub peak_heap: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct SimLog {
    pub address: Address,
    pub topics: Vec<B256>,
    pub data: Bytes,
}

/// A touched account: balance before/after and every storage slot whose value changed.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct SimChange {
    pub address: Address,
    pub balance_before: U256,
    pub balance_after: U256,
    pub nonce_before: u64,
    pub nonce_after: u64,
    pub slots: Vec<SlotChange>,
}

#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct SlotChange {
    pub slot: U256,
    pub before: U256,
    pub after: U256,
}

/// Verifier -> signer: a transaction the verifier simulated and approved. The signer builds
/// and signs exactly this (EIP-155 legacy, `gas_price` as simulated); it never signs a hash
/// it didn't compute itself.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct SignJob {
    pub chain_id: u64,
    pub tx: SimTx,
}

/// Reply to `wire::TYPE_SIGN`: the simulation, and either a refusal or the signed tx.
#[derive(Debug, Clone, Default, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct SignResult {
    pub sim: SimResult,
    /// Non-empty: not signed, and why (simulation error, revert, policy).
    pub refused: Bytes,
    /// EIP-2718 encoding of the signed tx (legacy: plain RLP), ready for eth_sendRawTransaction.
    pub signed_tx: Bytes,
    /// This device's signing address.
    pub signer: Address,
}

/// Host <-> device framing (same envelope as eth-burner): `length (u32 BE) || type || message`;
/// `length` counts `type || message`. Over USB HID it is cut into 64-byte reports, zero-padded.
pub mod wire {
    /// Largest `type || message` accepted (the frame is buffered whole in the transport).
    pub const MAX_LEN: usize = 256 * 1024;
    /// message: RLP `SimInput`; reply: RLP `SimResult`.
    pub const TYPE_SIMULATE: u8 = 0x10;
    /// message: empty; reply: UTF-8 version string.
    pub const TYPE_VERSION: u8 = 0x11;
    /// message: RLP `SimInput`; reply: RLP `SignResult` (simulated, policy-checked, signed).
    pub const TYPE_SIGN: u8 = 0x12;
    /// message: empty; reply: the device's 20-byte signing address.
    pub const TYPE_ADDRESS: u8 = 0x13;
    /// reply only: UTF-8 error from the transport (bad frame, unknown type, verifier down).
    pub const TYPE_ERROR: u8 = 0x7f;

    pub fn encode_frame(ty: u8, message: &[u8]) -> alloc::vec::Vec<u8> {
        let mut out = alloc::vec::Vec::with_capacity(5 + message.len());
        out.extend_from_slice(&(message.len() as u32 + 1).to_be_bytes());
        out.push(ty);
        out.extend_from_slice(message);
        out
    }

    /// Length announced by a prefix, if acceptable.
    pub fn frame_len(prefix: [u8; 4]) -> Option<usize> {
        match u32::from_be_bytes(prefix) as usize {
            0 => None,
            n if n > MAX_LEN => None,
            n => Some(n),
        }
    }
}

/// Xous IPC. All calls lend a buffer; the reply is written into it (`valid` = reply length).
///
/// Transport -> verifier, on `VERIFIER_SERVER_NAME` (one connection):
/// `OP_SIMULATE` (RLP `SimInput` -> RLP `SimResult`), `OP_SIGN` (RLP `SimInput` -> RLP
/// `SignResult`), `OP_ADDRESS` (-> 20-byte address, or empty while no signer is attached).
///
/// Signer -> verifier, on `SIGNER_CHANNEL_NAME` (one connection). The signer has no server of
/// its own, so nothing can send it requests: it lends `OP_SIGNER_WAIT` (its 20-byte address)
/// and blocks until the verifier returns it holding an RLP `SignJob`; then it lends
/// `OP_SIGNER_RESULT` holding the EIP-2718 signed tx (empty if it refused).
pub mod ipc {
    pub const VERIFIER_SERVER_NAME: &str = "_EVM verifier_";
    pub const SIGNER_CHANNEL_NAME: &str = "_EVM verifier signer channel_";
    pub const OP_SIMULATE: usize = 1;
    pub const OP_SIGN: usize = 2;
    pub const OP_ADDRESS: usize = 3;
    pub const OP_SIGNER_WAIT: usize = 10;
    pub const OP_SIGNER_RESULT: usize = 11;
}

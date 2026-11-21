//! Simulate one transaction against a verified witness (stage 3).
//!
//! 1. Decode `SimInput`; hash the parent header; its `state_root` is the pre-state root.
//! 2. `tries::zeth::SparseState::new` indexes witness nodes by keccak hash and rebuilds the
//!    trie from that root, so only nodes that hash-link to the root are ever read.
//! 3. revm executes the tx over a `Database` backed by that trie. Any account, slot or code
//!    the witness doesn't cover is a database *error* (fail closed), never "empty".

use std::collections::BTreeMap;

use alloy_consensus::Header;
use alloy_primitives::{Address, B256, Bytes, U256, map::B256IndexMap};
use alloy_rlp::Decodable;
use revm::{
    Context, ExecuteEvm, MainBuilder, MainContext,
    bytecode::Bytecode,
    context::{BlockEnv, TxEnv},
    database_interface::Database,
    primitives::TxKind,
    state::AccountInfo,
};
use sim_types::{SimChange, SimInput, SimLog, SimResult, SlotChange};
use stateless::ExecutionWitness;
use tries::{StatelessTrie, WitnessDbError, zeth::SparseState};

/// revm database over the verified trie. Mirrors `stateless`'s crate-private `WitnessDatabase`.
struct WitnessDb<'a> {
    trie: &'a SparseState,
    bytecode: B256IndexMap<Bytes>,
    block_hashes: BTreeMap<u64, B256>,
}

impl Database for WitnessDb<'_> {
    type Error = WitnessDbError;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        Ok(self.trie.account(address)?.map(|a| AccountInfo {
            balance: a.balance,
            nonce: a.nonce,
            code_hash: a.code_hash,
            code: None,
            account_id: None,
        }))
    }

    fn storage(&mut self, address: Address, slot: U256) -> Result<U256, Self::Error> {
        self.trie.storage(address, slot)
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.bytecode
            .get(&code_hash)
            .map(|c| Bytecode::new_raw(c.clone()))
            .ok_or_else(|| WitnessDbError::TrieWitness(format!("bytecode {code_hash} not in witness")))
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        self.block_hashes.get(&number).copied().ok_or(WitnessDbError::StateNotFound(number))
    }
}

/// Simulate the RLP `SimInput` in `raw`. Err = input rejected (fail closed).
pub fn simulate(raw: &[u8]) -> Result<SimResult, String> {
    simulate_with(raw, |_| {})
}

/// Like `simulate`, but lets a test tamper with the decoded input first.
pub fn simulate_with(raw: &[u8], tamper: impl FnOnce(&mut SimInput)) -> Result<SimResult, String> {
    simulate_opts(raw, tamper, &Options::default()).map(|(r, _)| r)
}

/// How to run the transaction.
#[derive(Default)]
pub struct Options {
    /// Run `tx` as a call *made by a contract* (a Safe executing its inner call): no EIP-3607
    /// sender-has-code rejection, no nonce check, no base fee (gas price 0: the Safe's executor
    /// pays the gas, not the Safe). Value and storage effects are exactly those of the call.
    pub as_contract: bool,
    /// Storage slots to read from the verified pre-state, returned in order (e.g. a Safe's
    /// owners and nonce). A slot the witness doesn't cover rejects the input (fail closed).
    pub reads: Vec<(Address, U256)>,
}

/// `simulate` with [`Options`]; returns the result and the pre-state `reads`.
pub fn simulate_opts(raw: &[u8], tamper: impl FnOnce(&mut SimInput), opts: &Options) -> Result<(SimResult, Vec<U256>), String> {
    let mut input = SimInput::decode(&mut &raw[..]).map_err(|e| format!("decode SimInput: {e}"))?;
    tamper(&mut input);
    let parent = Header::decode(&mut &input.parent_header[..]).map_err(|e| format!("decode header: {e}"))?;

    let witness = ExecutionWitness {
        state: input.state,
        codes: input.codes,
        keys: input.keys,
        headers: vec![input.parent_header.clone()],
    };
    let (trie, bytecode) =
        SparseState::new(witness, parent.state_root).map_err(|e| format!("witness vs state root: {e}"))?;
    let reads = opts
        .reads
        .iter()
        .map(|(a, slot)| trie.storage(*a, *slot).map_err(|e| format!("witness lacks {a} slot {slot:#x}: {e}")))
        .collect::<Result<Vec<U256>, String>>()?;
    if opts.as_contract {
        input.tx.gas_price = 0;
        input.tx.max_priority_fee_per_gas = None;
    }
    let db = WitnessDb {
        trie: &trie,
        bytecode,
        block_hashes: BTreeMap::from([(parent.number, parent.hash_slow())]),
    };

    let spec = crate::chainspec::spec_for(input.chain_id).ok_or_else(|| format!("chain {} not supported", input.chain_id))?;
    let spec_id = alloy_evm::spec_by_timestamp_and_block_number(&*spec, input.block.timestamp, input.block.number);
    let b = &input.block;
    let block = BlockEnv {
        number: U256::from(b.number),
        timestamp: U256::from(b.timestamp),
        basefee: b.basefee,
        gas_limit: b.gas_limit,
        beneficiary: b.beneficiary,
        prevrandao: Some(b.prevrandao),
        ..Default::default()
    };
    let t = &input.tx;
    let tx = TxEnv::builder()
        .caller(t.from)
        .kind(TxKind::Call(t.to))
        .nonce(t.nonce)
        .gas_limit(t.gas_limit)
        .gas_price(t.gas_price)
        .gas_priority_fee(t.max_priority_fee_per_gas)
        .tx_type(Some(if t.max_priority_fee_per_gas.is_some() { 2 } else { 0 }))
        .value(t.value)
        .data(t.data.clone())
        .chain_id(Some(input.chain_id))
        .build()
        .map_err(|e| format!("tx env: {e:?}"))?;

    let mut evm = Context::mainnet()
        .with_db(db)
        .with_block(block)
        .modify_cfg_chained(|cfg| {
            cfg.chain_id = input.chain_id;
            cfg.set_spec_and_mainnet_gas_params(spec_id);
            if opts.as_contract {
                cfg.disable_eip3607 = true;
                cfg.disable_nonce_check = true;
                cfg.disable_base_fee = true;
            }
        })
        .build_mainnet();
    let out = evm.transact(tx).map_err(|e| format!("execution: {e:?}"))?;

    let mut changes: Vec<SimChange> = out
        .state
        .iter()
        .filter(|(_, acc)| acc.is_touched())
        .map(|(addr, acc)| {
            let mut slots: Vec<SlotChange> = acc
                .storage
                .iter()
                .filter(|(_, s)| s.is_changed())
                .map(|(k, s)| SlotChange { slot: *k, before: s.original_value(), after: s.present_value() })
                .collect();
            slots.sort_by_key(|c| c.slot);
            SimChange {
                address: *addr,
                balance_before: acc.original_info().balance,
                balance_after: acc.info.balance,
                nonce_before: acc.original_info().nonce,
                nonce_after: acc.info.nonce,
                slots,
            }
        })
        .collect();
    changes.sort_by_key(|c| c.address);
    let logs = out
        .result
        .logs()
        .iter()
        .map(|l| SimLog { address: l.address, topics: l.topics().to_vec(), data: l.data.data.clone() })
        .collect();
    let mut r = SimResult {
        error: Bytes::new(),
        success: out.result.is_success(),
        gas_used: out.result.tx_gas_used(),
        output: out.result.output().cloned().unwrap_or_default(),
        logs,
        changes,
        micros: 0,
        peak_heap: 0,
        effects: Vec::new(),
        clear_sign: Default::default(),
        policy: Default::default(),
    };
    r.effects = crate::effects::effects(&input.tx, &input.block, &r);
    Ok((r, reads))
}

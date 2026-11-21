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
use sim_types::SimInput;
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

/// What the simulation did, for logging (the effects inspector comes later).
#[derive(Debug)]
pub struct SimReport {
    pub success: bool,
    pub gas_used: u64,
    pub output: Bytes,
    pub logs: usize,
    /// (address, balance before -> after, changed slots)
    pub changes: Vec<(Address, U256, U256, usize)>,
}

pub fn simulate(raw: &[u8]) -> Result<SimReport, String> {
    simulate_with(raw, |_| {})
}

/// Like `simulate`, but lets a test tamper with the decoded input first.
pub fn simulate_with(raw: &[u8], tamper: impl FnOnce(&mut SimInput)) -> Result<SimReport, String> {
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
    let db = WitnessDb {
        trie: &trie,
        bytecode,
        block_hashes: BTreeMap::from([(parent.number, parent.hash_slow())]),
    };

    let spec = crate::chainspec::mainnet_no_alloc();
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
        })
        .build_mainnet();
    let out = evm.transact(tx).map_err(|e| format!("execution: {e:?}"))?;

    let mut changes: Vec<_> = out
        .state
        .iter()
        .filter(|(_, acc)| acc.is_touched())
        .map(|(addr, acc)| {
            let changed = acc.storage.values().filter(|s| s.is_changed()).count();
            (*addr, acc.original_info().balance, acc.info.balance, changed)
        })
        .collect();
    changes.sort();
    Ok(SimReport {
        success: out.result.is_success(),
        gas_used: out.result.tx_gas_used(),
        output: out.result.output().cloned().unwrap_or_default(),
        logs: out.result.logs().len(),
        changes,
    })
}

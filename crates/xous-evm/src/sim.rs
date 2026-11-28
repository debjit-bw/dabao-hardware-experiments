//! Simulate one transaction against a verified witness (stage 3).
//!
//! 1. Decode `SimInput`; hash the parent header; its `state_root` is the pre-state root.
//! 2. `tries::zeth::SparseState::new` indexes witness nodes by keccak hash and rebuilds the
//!    trie from that root, so only nodes that hash-link to the root are ever read.
//! 3. revm executes the tx over a `Database` backed by that trie. Any account, slot or code
//!    the witness doesn't cover is a database *error* (fail closed), never "empty".

use std::{cell::RefCell, collections::BTreeMap};

use alloy_consensus::Header;
use alloy_primitives::{Address, B256, Bytes, U256, map::B256IndexMap};
use alloy_rlp::Decodable;
use revm::{
    Context, ExecuteCommitEvm, ExecuteEvm, MainContext,
    bytecode::Bytecode,
    context::{BlockEnv, Evm, TxEnv},
    context_interface::local::FrameStack,
    database::CacheDB,
    database_interface::DatabaseRef,
    handler::{EthFrame, EthPrecompiles, MainnetEvm, instructions::EthInstructions},
    interpreter::interpreter::EthInterpreter,
    primitives::TxKind,
    state::AccountInfo,
};
use sim_types::{SimChange, SimInput, SimLog, SimResult, SlotChange};
use stateless::ExecutionWitness;
use tries::{StatelessTrie, WitnessDbError, zeth::SparseState};

/// revm database over the verified trie. Mirrors `stateless`'s crate-private `WitnessDatabase`.
struct WitnessDb<'a> {
    trie: &'a SparseState,
    /// Each code is moved out when first asked for: `CacheDB` keeps the analysed copy, and the
    /// board can't afford both. (Asked again, it would fail closed as "not in witness".)
    bytecode: RefCell<B256IndexMap<Bytes>>,
    block_hashes: BTreeMap<u64, B256>,
}

impl DatabaseRef for WitnessDb<'_> {
    type Error = WitnessDbError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        Ok(self.trie.account(address)?.map(|a| AccountInfo {
            balance: a.balance,
            nonce: a.nonce,
            code_hash: a.code_hash,
            code: None,
            account_id: None,
        }))
    }

    fn storage_ref(&self, address: Address, slot: U256) -> Result<U256, Self::Error> {
        self.trie.storage(address, slot)
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.bytecode
            .borrow_mut()
            .swap_remove(&code_hash)
            .map(Bytecode::new_raw)
            .ok_or_else(|| WitnessDbError::TrieWitness(format!("bytecode {code_hash} not in witness")))
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
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
    /// Accounts whose code hash to read from the verified pre-state (zero if no account).
    pub code_hashes: Vec<Address>,
}

/// Values read from the verified pre-state, per [`Options`].
#[derive(Debug, Default, Clone)]
pub struct Reads {
    pub slots: Vec<U256>,
    pub code_hashes: Vec<B256>,
}

/// The state a follow-up call runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum At {
    /// Before the transaction. Only possible before the first [`At::Post`] call.
    Pre,
    /// After the transaction and any earlier [`At::Post`] calls.
    Post,
}

/// A follow-up call from `tx.from` (a view, gas price 0, no nonce check): `(state, to, calldata) -> (success, output)`.
pub type PostCall<'a> = dyn FnMut(At, Address, Vec<u8>) -> Result<(bool, Bytes), String> + 'a;

/// `simulate` with [`Options`]; returns the result and the pre-state `reads`.
pub fn simulate_opts(raw: &[u8], tamper: impl FnOnce(&mut SimInput), opts: &Options) -> Result<(SimResult, Vec<U256>), String> {
    simulate_then(raw, tamper, opts, |_, _, _| ()).map(|(r, reads, ())| (r, reads.slots))
}

/// `simulate_opts`, then `then(result, reads, call)` with `call` running follow-up calls on the
/// post-state: e.g. the Safe postcondition the device appends to a co-signed call.
pub fn simulate_then<R>(
    raw: &[u8],
    tamper: impl FnOnce(&mut SimInput),
    opts: &Options,
    then: impl FnOnce(&mut SimResult, &Reads, &mut PostCall) -> R,
) -> Result<(SimResult, Reads, R), String> {
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
    let code_hashes = opts
        .code_hashes
        .iter()
        .map(|a| trie.account(*a).map(|x| x.map(|x| x.code_hash).unwrap_or_default()).map_err(|e| format!("witness lacks account {a}: {e}")))
        .collect::<Result<Vec<B256>, String>>()?;
    let reads = Reads { slots: reads, code_hashes };
    if opts.as_contract {
        input.tx.gas_price = 0;
        input.tx.max_priority_fee_per_gas = None;
    }
    let db = CacheDB::new(WitnessDb {
        trie: &trie,
        bytecode: RefCell::new(bytecode),
        block_hashes: BTreeMap::from([(parent.number, parent.hash_slow())]),
    });

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

    let ctx = Context::mainnet()
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
        });
    // As `build_mainnet`, except the frame stack. That preallocates 8 call frames with a 32 KiB
    // EVM stack each (256 KiB, an eighth of the board's RAM); replacing it afterwards still
    // spikes. Empty, it allocates one per call depth actually reached.
    let mut evm: MainnetEvm<_> = Evm {
        ctx,
        inspector: (),
        instruction: EthInstructions::new_mainnet_with_spec(spec_id),
        precompiles: EthPrecompiles::new(spec_id),
        frame_stack: FrameStack::<EthFrame<EthInterpreter>>::new(),
    };
    let out = evm.transact(tx).map_err(|e| format!("execution: {e:?}"))?;
    let state = out.state;

    let mut changes: Vec<SimChange> = state
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
        header_check: Default::default(),
    };
    r.effects = crate::effects::effects(&input.tx, &input.block, &r);

    // the transaction is committed by the first Post call, so Pre calls can still see the pre-state
    let mut uncommitted = Some(state);
    let (from, chain_id, as_contract) = (input.tx.from, input.chain_id, opts.as_contract);
    let mut call = |at: At, to: Address, data: Vec<u8>| -> Result<(bool, Bytes), String> {
        if !as_contract {
            // a sender's follow-up calls are views run at gas price 0, after its own transaction
            evm.ctx.cfg.disable_nonce_check = true;
            evm.ctx.cfg.disable_base_fee = true;
        }
        match at {
            At::Pre if uncommitted.is_none() => return Err("pre-state calls must come before post-state calls".into()),
            At::Pre => {}
            At::Post => {
                if let Some(state) = uncommitted.take() {
                    evm.commit(state);
                }
            }
        }
        let tx = TxEnv::builder()
            .caller(from)
            .kind(TxKind::Call(to))
            .gas_limit(2_000_000)
            .gas_price(0)
            .tx_type(Some(0))
            .data(data.into())
            .chain_id(Some(chain_id))
            .build()
            .map_err(|e| format!("tx env: {e:?}"))?;
        let out = evm.transact(tx).map_err(|e| format!("follow-up call: {e:?}"))?;
        if at == At::Post {
            evm.commit(out.state);
        }
        Ok((out.result.is_success(), out.result.output().cloned().unwrap_or_default()))
    };
    let extra = then(&mut r, &reads, &mut call);
    Ok((r, reads, extra))
}

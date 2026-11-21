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

/// The transaction. `max_priority_fee_per_gas`: `None` = EIP-155 legacy at `gas_price`;
/// `Some(tip)` = EIP-1559 with `gas_price` as `max_fee_per_gas` (and an empty access list).
/// The trailing option keeps legacy encodings (and the fixtures) valid.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
#[rlp(trailing)]
pub struct SimTx {
    pub from: Address,
    pub to: Address,
    pub nonce: u64,
    pub gas_limit: u64,
    pub gas_price: u128,
    pub value: U256,
    pub data: Bytes,
    pub max_priority_fee_per_gas: Option<u128>,
}

impl SimTx {
    /// What one unit of gas costs the sender in a block with `basefee`.
    pub fn effective_gas_price(&self, basefee: u64) -> u128 {
        match self.max_priority_fee_per_gas {
            None => self.gas_price,
            Some(tip) => self.gas_price.min(basefee as u128 + tip),
        }
    }
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
    /// Normalised effects (see [`effect`]), computed on the device from `logs` and `changes`.
    pub effects: Vec<Effect>,
    /// The ERC-7730 clear-signing check (filled in by the verifier).
    pub clear_sign: ClearSign,
    /// The device's signing policy (filled in by the verifier).
    pub policy: PolicyCheck,
}

/// Result of the signing policy (`crates/policy`). Signing requires `violations` empty.
#[derive(Debug, Clone, Default, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct PolicyCheck {
    /// Id of the policy compiled into the firmware.
    pub policy: Bytes,
    pub violations: Vec<Bytes>,
    /// What the policy checked and what it would record (e.g. today's spending).
    pub notes: Vec<Bytes>,
}

/// Reply to `wire::TYPE_POLICY`: the policy in force and its counters, as text.
#[derive(Debug, Clone, Default, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct PolicyStatus {
    pub policy: Bytes,
    pub lines: Vec<Bytes>,
}

/// Result of the ERC-7730 check: what the user is shown, and every effect it doesn't explain.
/// Signing requires `descriptor` non-empty and `violations` empty.
#[derive(Debug, Clone, Default, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct ClearSign {
    /// Id of the matched descriptor (empty: none matched).
    pub descriptor: Bytes,
    pub intent: Bytes,
    pub fields: Vec<ShownField>,
    /// Human-readable reasons not to sign (empty: every effect is explained).
    pub violations: Vec<Bytes>,
    /// Things the user should know that don't block signing (e.g. no slippage protection).
    pub warnings: Vec<Bytes>,
    /// Every address the user is shown (recipients, spenders, beneficiaries), for the policy.
    pub addresses: Vec<Address>,
    /// Shown amounts of assets the sender gains that are below what the simulation gains
    /// (swap minimums), for the policy's slippage limit.
    pub min_receive: Vec<MinReceive>,
}

#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct MinReceive {
    /// The asset (zero = ETH).
    pub asset: Address,
    /// The shown minimum.
    pub shown: U256,
    /// What the simulation actually gains.
    pub simulated: U256,
}

#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct ShownField {
    pub label: Bytes,
    pub value: Bytes,
}

/// One normalised effect of a simulated transaction. `kind` is one of the [`effect`]
/// constants; the meaning of the other fields depends on it (documented there).
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct Effect {
    pub kind: u8,
    /// The contract the effect is about (token, collection, Permit2, proxy...); zero for ETH.
    pub contract: Address,
    pub from: Address,
    pub to: Address,
    pub amount: U256,
    /// Kind-specific extra data (see [`effect`]).
    pub extra: Bytes,
}

/// Effect kinds. Anything not recognised is reported as `UNEXPLAINED_STORAGE`, never dropped.
pub mod effect {
    /// ETH leaving `from` (net of gas), `amount` wei.
    pub const NATIVE_OUT: u8 = 1;
    /// ETH arriving at `to` (net of the block reward), `amount` wei.
    pub const NATIVE_IN: u8 = 2;
    /// Gas paid by `from`: `amount` = gas_used * gas_price wei.
    pub const GAS_FEE: u8 = 3;
    /// ERC-20 `Transfer` from `contract`: `from` -> `to`, `amount` units.
    pub const ERC20_TRANSFER: u8 = 4;
    /// ERC-20 `Approval` on `contract`: owner `from`, spender `to`, allowance `amount`.
    pub const ERC20_APPROVAL: u8 = 5;
    /// ERC-721 `Transfer` on `contract`: `from` -> `to`, token id `amount`.
    pub const NFT_TRANSFER: u8 = 6;
    /// ERC-721 `Approval` on `contract`: owner `from`, approved `to`, token id `amount`.
    pub const NFT_APPROVAL: u8 = 7;
    /// `ApprovalForAll` on `contract`: owner `from`, operator `to`, `amount` = 1 (granted) / 0.
    pub const APPROVAL_FOR_ALL: u8 = 8;
    /// ERC-1155 `TransferSingle` on `contract`: `from` -> `to`, `amount` units;
    /// `extra` = token id (32 bytes BE).
    pub const ERC1155_TRANSFER: u8 = 9;
    /// Permit2 `Approval` or `Permit`: owner `from`, spender `to`, `amount`;
    /// `extra` = token (20 bytes) || expiration (u48, 6 bytes BE). `contract` = Permit2.
    pub const PERMIT2_APPROVAL: u8 = 10;
    /// `OwnershipTransferred` on `contract`: previous owner `from` -> new owner `to`.
    pub const OWNERSHIP_TRANSFER: u8 = 11;
    /// EIP-1967 `Upgraded` on proxy `contract`: new implementation `to`.
    pub const PROXY_UPGRADE: u8 = 12;
    /// EIP-1967 `AdminChanged` on proxy `contract`: previous admin `from` -> new admin `to`.
    pub const PROXY_ADMIN_CHANGE: u8 = 13;
    /// `contract`'s storage changed but it emitted no recognised event: `amount` = number of
    /// changed slots. Covers unknown events, silent balance moves, anything outside the subset.
    pub const UNEXPLAINED_STORAGE: u8 = 14;
    /// WETH-style `Deposit` on `contract`: `amount` ETH wrapped, credited to `to`.
    pub const WRAP: u8 = 15;
    /// WETH-style `Withdrawal` on `contract`: `amount` unwrapped, debited from `from`.
    pub const UNWRAP: u8 = 16;
    /// Uniswap V2 or V3 `Swap` on pool `contract`: initiator `from`, recipient `to`;
    /// `extra` = the event data (V2: 4 words amount0In, amount1In, amount0Out, amount1Out;
    /// V3: 5 words int256 amount0, int256 amount1, sqrtPriceX96, liquidity, tick).
    pub const POOL_SWAP: u8 = 17;
    /// Summary for the tx sender (`from`): net gain of asset `contract` (zero = ETH, gas
    /// excluded), `amount` units, summed over the ETH moves and token transfer/wrap effects.
    pub const NET_GAIN: u8 = 18;
    /// Summary for the tx sender: net loss of asset `contract`, as `NET_GAIN`.
    pub const NET_LOSS: u8 = 19;
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
/// and signs exactly this; it never signs a hash it didn't compute itself.
/// * `kind` [`SignJob::TX`]: the device's own transaction (EIP-155 legacy or EIP-1559, fees as
///   simulated).
/// * `kind` [`SignJob::SAFE`]: a Safe transaction: Safe `tx.from` calls `tx.to` with
///   `tx.value` / `tx.data` (operation CALL, no gas refund parameters) at Safe nonce
///   `safe_nonce`; the signer computes [`safe::tx_hash`] and returns a 65-byte owner signature.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct SignJob {
    pub chain_id: u64,
    pub tx: SimTx,
    pub kind: u8,
    pub safe_nonce: U256,
}

impl SignJob {
    pub const TX: u8 = 0;
    pub const SAFE: u8 = 1;
}

/// Safe (v1.4.1) co-signing: storage layout and the SafeTx EIP-712 hash, shared by the verifier
/// (which reads the Safe's state from the verified witness) and the signer (which computes the
/// hash it signs).
pub mod safe {
    use alloy_primitives::{Address, B256, U256, address, b256, keccak256};

    /// Safe 1.4.1 singletons (canonical deployments: same address on every chain). A proxy
    /// whose singleton is anything else is not a Safe we know how to reason about.
    pub const SINGLETONS: [Address; 2] = [
        address!("0x41675C099F32341bf84BFc5382aF534df5C7461a"), // Safe
        address!("0x29fcB43b46531BcA003ddC8FCB67FFE91900C762"), // SafeL2
    ];
    /// Storage (Singleton, ModuleManager, OwnerManager, Safe): slot 0 singleton, 1 modules
    /// mapping, 2 owners mapping, 3 ownerCount, 4 threshold, 5 nonce.
    pub const SLOT_SINGLETON: U256 = U256::ZERO;
    pub const SLOT_THRESHOLD: U256 = U256::from_limbs([4, 0, 0, 0]);
    pub const SLOT_NONCE: U256 = U256::from_limbs([5, 0, 0, 0]);
    /// `keccak256("guard_manager.guard.address")`
    pub const SLOT_GUARD: B256 = b256!("0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8");
    const SENTINEL: Address = address!("0x0000000000000000000000000000000000000001");

    fn mapping_slot(key: Address, slot: u64) -> U256 {
        let mut b = [0u8; 64];
        b[12..32].copy_from_slice(key.as_slice());
        b[56..].copy_from_slice(&slot.to_be_bytes());
        U256::from_be_bytes(keccak256(b).0)
    }

    /// `owners[a]`: non-zero iff `a` is an owner (the linked list's next pointer).
    pub fn owner_slot(a: Address) -> U256 {
        mapping_slot(a, 2)
    }

    /// `modules[SENTINEL]`: equals SENTINEL iff no module is enabled.
    pub fn modules_head_slot() -> U256 {
        mapping_slot(SENTINEL, 1)
    }

    /// The slots the verifier reads (in this order) to check a Safe before co-signing.
    pub fn slots(device: Address) -> [U256; 6] {
        [SLOT_SINGLETON, SLOT_THRESHOLD, SLOT_NONCE, owner_slot(device), modules_head_slot(), U256::from_be_bytes(SLOT_GUARD.0)]
    }

    /// The Safe's configuration, from [`slots`].
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct State {
        pub singleton: Address,
        pub threshold: U256,
        pub nonce: U256,
        pub device_is_owner: bool,
        pub modules: bool,
        pub guard: Address,
    }

    impl State {
        pub fn from_slots(v: &[U256; 6]) -> State {
            let addr = |x: U256| Address::from_word(B256::from(x));
            State {
                singleton: addr(v[0]),
                threshold: v[1],
                nonce: v[2],
                device_is_owner: !v[3].is_zero(),
                modules: addr(v[4]) != SENTINEL,
                guard: addr(v[5]),
            }
        }

        /// Reasons the device's signature would not be a real check on this Safe.
        pub fn problems(&self) -> alloc::vec::Vec<alloc::string::String> {
            use alloc::format;
            let mut p = alloc::vec::Vec::new();
            if !SINGLETONS.contains(&self.singleton) {
                p.push(format!("not a known Safe 1.4.1 (singleton {})", self.singleton));
            }
            if !self.device_is_owner {
                p.push("this device is not an owner of the Safe".into());
            }
            if self.threshold < U256::from(2) {
                p.push(format!("threshold {} < 2: other owners don't need this device", self.threshold));
            }
            if self.modules {
                p.push("the Safe has modules enabled (they can move funds without owner signatures)".into());
            }
            if !self.guard.is_zero() {
                p.push(format!("the Safe has a transaction guard ({}) this device doesn't know", self.guard));
            }
            p
        }
    }

    /// `keccak256("EIP712Domain(uint256 chainId,address verifyingContract)")`
    const DOMAIN_TYPEHASH: B256 = b256!("0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218");
    /// `keccak256("SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)")`
    const SAFE_TX_TYPEHASH: B256 = b256!("0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8");

    fn word_addr(a: Address) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(a.as_slice());
        w
    }

    /// The EIP-712 SafeTx hash owners sign: operation CALL, safeTxGas = baseGas = gasPrice = 0,
    /// gasToken = refundReceiver = 0 (no gas refunds paid from the Safe).
    pub fn tx_hash(chain_id: u64, safe: Address, to: Address, value: U256, data: &[u8], nonce: U256) -> B256 {
        let mut d = alloc::vec::Vec::with_capacity(96);
        d.extend_from_slice(DOMAIN_TYPEHASH.as_slice());
        d.extend_from_slice(&U256::from(chain_id).to_be_bytes::<32>());
        d.extend_from_slice(&word_addr(safe));
        let domain = keccak256(&d);
        let mut s = alloc::vec::Vec::with_capacity(352);
        s.extend_from_slice(SAFE_TX_TYPEHASH.as_slice());
        s.extend_from_slice(&word_addr(to));
        s.extend_from_slice(&value.to_be_bytes::<32>());
        s.extend_from_slice(keccak256(data).as_slice());
        s.extend_from_slice(&[0u8; 32]); // operation CALL
        s.extend_from_slice(&[0u8; 32 * 3]); // safeTxGas, baseGas, gasPrice
        s.extend_from_slice(&[0u8; 32 * 2]); // gasToken, refundReceiver
        s.extend_from_slice(&nonce.to_be_bytes::<32>());
        let st = keccak256(&s);
        let mut m = alloc::vec::Vec::with_capacity(66);
        m.extend_from_slice(&[0x19, 0x01]);
        m.extend_from_slice(domain.as_slice());
        m.extend_from_slice(st.as_slice());
        keccak256(&m)
    }
}

/// Reply to `wire::TYPE_SIGN`: the simulation, and either a refusal or the signed tx.
#[derive(Debug, Clone, Default, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct SignResult {
    pub sim: SimResult,
    /// Non-empty: not signed, and why (simulation error, revert, policy).
    pub refused: Bytes,
    /// EIP-2718 encoding of the signed tx (legacy: plain RLP; EIP-1559: 0x02 || RLP), ready for eth_sendRawTransaction.
    pub signed_tx: Bytes,
    /// This device's signing address.
    pub signer: Address,
}

/// Reply to `wire::TYPE_STATUS`: the verifier's memory budget.
#[derive(Debug, Clone, Default, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct DeviceStatus {
    /// Free physical RAM, bytes; 0 = not measured (Xous maps memory lazily, so the verifier
    /// can't probe it safely; kept for a future kernel-side query).
    pub free_ram_at_boot: u64,
    /// The verifier's heap cap, bytes.
    pub heap_limit: u64,
    /// Largest `SimInput` the verifier accepts, bytes (from the memory model).
    pub max_input: u64,
    /// The signer's address, if attached (empty otherwise).
    pub signer: Bytes,
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
    /// message: empty; reply: RLP `DeviceStatus`.
    pub const TYPE_STATUS: u8 = 0x14;
    /// message: empty; reply: RLP `PolicyStatus`.
    pub const TYPE_POLICY: u8 = 0x15;
    /// message: RLP `SimInput` whose `tx.from` is a Safe (the Safe's inner call; gas fields
    /// ignored: the executor pays); reply: RLP `SignResult` with `signed_tx` = the device's
    /// 65-byte owner signature (r || s || v, v = 27/28) over the SafeTx hash.
    pub const TYPE_SAFE_SIGN: u8 = 0x16;
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
    /// -> RLP `DeviceStatus`.
    pub const OP_STATUS: usize = 4;
    /// -> RLP `PolicyStatus`.
    pub const OP_POLICY: usize = 5;
    /// RLP `SimInput` (Safe inner call) -> RLP `SignResult` (65-byte Safe owner signature).
    pub const OP_SAFE_SIGN: usize = 6;
    pub const OP_SIGNER_WAIT: usize = 10;
    pub const OP_SIGNER_RESULT: usize = 11;
}

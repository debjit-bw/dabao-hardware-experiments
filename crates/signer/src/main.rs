//! Process 3: the signer. The only process that touches the private key, and the only one
//! that maps the RRAM slots (it runs as PID 3 in place of the keystore).
//!
//! * Its only server is the slot server for the verifier's persistent state
//!   (`ipc::SLOTS_SERVER_NAME`): it answers only the process holding this boot's random token,
//!   and only for `ipc::VERIFIER_SLOTS`, never the key's slots. Nothing can send it signing
//!   requests: it connects to the verifier's private signer channel and blocks in
//!   `OP_SIGNER_WAIT` until the verifier hands it a `SignJob` (a transaction the verifier
//!   simulated and approved). The token travels in that first `OP_SIGNER_WAIT`.
//! * It builds the transaction (EIP-155 legacy or EIP-1559, empty access list) and its signing
//!   hash itself from those fields,
//!   checks the job is for its own address, signs with k256 and returns the EIP-2718 bytes.
//! * The key: 32 bytes from the chip TRNG on first boot, kept in two RRAM app slots
//!   (key, then a header written last); emulator: a host file.

mod store;

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, B256, Signature, TxKind, keccak256};
use k256::ecdsa::SigningKey;
use sim_types::{SignJob, ipc};

fn address_of(key: &SigningKey) -> Address {
    let point = key.verifying_key().to_encoded_point(false);
    Address::from_slice(&keccak256(&point.as_bytes()[1..])[12..])
}

/// Sign `job` (EIP-155 legacy, or EIP-1559 when it has a priority fee), or refuse.
fn sign(key: &SigningKey, me: Address, job: &SignJob) -> Result<Vec<u8>, String> {
    if job.kind == SignJob::TX && job.tx.from != me {
        return Err(format!("job is for {}, not this device ({me})", job.tx.from));
    }
    let t = &job.tx;
    let sign_hash = |hash: B256| -> Result<Signature, String> {
        let (sig, recid) = key.sign_prehash_recoverable(hash.as_slice()).map_err(|e| format!("sign: {e}"))?;
        let (r, s) = sig.split_bytes();
        Ok(Signature::from_scalars_and_parity(B256::from_slice(&r), B256::from_slice(&s), recid.is_y_odd()))
    };
    if job.kind == SignJob::SAFE {
        return Err("Safe calls are co-signed only wrapped in the postcondition (SAFE_MULTISEND)".into());
    }
    if job.kind == SignJob::SAFE_MULTISEND {
        // co-sign a Safe transaction: the SafeTx hash, computed here from the approved fields.
        // DELEGATECALL runs code as the Safe, so only to the pinned MultiSendCallOnly, with a
        // batch of exactly [begin, call, check].
        use sim_types::safe;
        let calls = safe::multisend_decode(&t.data).ok_or("not a MultiSendCallOnly batch of CALLs")?;
        let own = |c: &safe::Call, selector: [u8; 4]| c.to == safe::POSTCONDITION && c.value.is_zero() && c.data.starts_with(&selector);
        let shaped = matches!(&calls[..], [begin, call, check]
            if own(begin, safe::BEGIN_SELECTOR) && own(check, safe::CHECK_SELECTOR) && call.to != safe::POSTCONDITION && call.to != t.from);
        if t.to != safe::MULTISEND_CALL_ONLY || !t.value.is_zero() || !shaped {
            return Err("DELEGATECALL only to MultiSendCallOnly: [begin, call, check]".into());
        }
        let hash = safe::tx_hash_op(job.chain_id, t.from, t.to, t.value, &t.data, job.safe_nonce, 1);
        let sig = sign_hash(hash)?;
        let mut out = sig.r().to_be_bytes::<32>().to_vec();
        out.extend_from_slice(&sig.s().to_be_bytes::<32>());
        out.push(27 + sig.v() as u8); // Safe: v 27/28 = ECDSA over the hash itself
        return Ok(out);
    }
    if job.kind != SignJob::TX {
        return Err(format!("unknown job kind {}", job.kind));
    }
    let signed = match t.max_priority_fee_per_gas {
        None => {
            let tx = TxLegacy {
                chain_id: Some(job.chain_id),
                nonce: t.nonce,
                gas_price: t.gas_price,
                gas_limit: t.gas_limit,
                to: TxKind::Call(t.to),
                value: t.value,
                input: t.data.clone(),
            };
            let sig = sign_hash(tx.signature_hash())?;
            TxEnvelope::Legacy(tx.into_signed(sig))
        }
        Some(tip) => {
            if tip > t.gas_price {
                return Err(format!("priority fee {tip} above max fee {}", t.gas_price));
            }
            let tx = TxEip1559 {
                chain_id: job.chain_id,
                nonce: t.nonce,
                gas_limit: t.gas_limit,
                max_fee_per_gas: t.gas_price,
                max_priority_fee_per_gas: tip,
                to: TxKind::Call(t.to),
                value: t.value,
                access_list: Default::default(),
                input: t.data.clone(),
            };
            let sig = sign_hash(tx.signature_hash())?;
            TxEnvelope::Eip1559(tx.into_signed(sig))
        }
    };
    Ok(signed.encoded_2718())
}

/// Lend `buf[..len]` to the verifier with `op`; returns the reply bytes.
fn call(cid: xous::CID, op: usize, payload: &[u8], cap: usize) -> Vec<u8> {
    let mut range = xous::map_memory(None, None, cap, xous::MemoryFlags::R | xous::MemoryFlags::W).expect("OOM");
    unsafe { range.as_slice_mut::<u8>()[..payload.len()].copy_from_slice(payload) };
    let r = xous::send_message(cid, xous::Message::new_lend_mut(op, range, None, xous::MemorySize::new(payload.len())));
    let out = match r {
        Ok(xous::Result::MemoryReturned(_, Some(valid))) => unsafe { range.as_slice::<u8>()[..valid.get().min(cap)].to_vec() },
        _ => Vec::new(),
    };
    xous::unmap_memory(range).ok();
    out
}

/// The address this build must find in the slots, if built with `DABAO_SIGNER_ADDRESS` set.
/// Then the signer never creates a key, and refuses to run with any other.
const EXPECTED_ADDRESS: Option<&str> = option_env!("DABAO_SIGNER_ADDRESS");

#[cfg(all(target_os = "xous", not(feature = "board-dabao")))]
compile_error!("device builds of the signer need --features board-dabao");

/// Device: what the keystore did at boot that the image still needs. Hardware access to the
/// RRAM slots is ours only as PID 3, and the HAL leaves preemption off until someone (the
/// keystore, upstream) turns it on.
#[cfg(target_os = "xous")]
fn device_init(xns: &xous_names::XousNames) {
    let pid = xous::process::id();
    if pid != bao1x_hal::coreuser::TRUSTED_PID as u32 {
        panic!("the signer must run as PID {} (built with --trusted-service), not {pid}", bao1x_hal::coreuser::TRUSTED_PID);
    }
    let hal = xns.request_connection_blocking(bao1x_api::SERVER_NAME_BAO1X_HAL).expect("HAL");
    xous::send_message(hal, xous::Message::new_blocking_scalar(bao1x_api::HalOpcode::SetPreemptionState as usize, 1, 0, 0, 0))
        .expect("can't turn preemption on");
}

fn token_ok(got: &[u8], want: &[u8; ipc::SLOT_TOKEN_LEN]) -> bool {
    got.len() == want.len() && got.iter().zip(want).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

/// The verifier's persistent state. Serves `ipc::VERIFIER_SLOTS` only, only with the token,
/// and only to the first process that presented it.
fn serve_slots(sid: xous::SID, token: [u8; ipc::SLOT_TOKEN_LEN], slots: &mut impl store::Slots) -> ! {
    let mut client: Option<xous::PID> = None;
    loop {
        let mut msg = xous::receive_message(sid).unwrap();
        let op = msg.body.id();
        let sender = msg.sender.pid();
        let Some(mem) = msg.body.memory_message_mut() else { continue };
        let len = mem.valid.map(|v| v.get()).unwrap_or(0).min(mem.buf.len());
        let req = unsafe { &mem.buf.as_slice::<u8>()[..len] };
        let t = ipc::SLOT_TOKEN_LEN;
        let index = (len >= t + 4).then(|| u32::from_be_bytes(req[t..t + 4].try_into().unwrap()) as usize);
        let refuse = |why: &str| log::warn!("slot server: refused op {op} slot {index:?} from PID {:?}: {why}", sender.map(|p| p.get()));
        let mut answer: Option<Vec<u8>> = None;
        if len < t + 4 || !token_ok(&req[..t], &token) {
            refuse("bad token");
        } else if client.is_some() && client != sender {
            refuse("not the verifier");
        } else if !ipc::VERIFIER_SLOTS.contains(&index.unwrap()) {
            refuse("slot not served");
        } else {
            if client.is_none() {
                client = sender;
                log::info!("slot server: verifier is PID {:?}", sender.map(|p| p.get()));
            }
            let i = index.unwrap();
            answer = match (op, len - t - 4) {
                (ipc::OP_SLOT_READ, 0) => slots.read(i).map(|d| d.to_vec()),
                (ipc::OP_SLOT_WRITE, 32) => {
                    let d: store::Slot = req[t + 4..].try_into().unwrap();
                    slots.write(i, &d).then(|| vec![1])
                }
                _ => {
                    refuse("bad request");
                    None
                }
            };
        }
        let out = answer.unwrap_or_default();
        unsafe { mem.buf.as_slice_mut::<u8>()[..out.len()].copy_from_slice(&out) };
        mem.valid = xous::MemorySize::new(out.len());
    }
}

fn main() -> ! {
    log_server::init_wait().unwrap();
    log::set_max_level(log::LevelFilter::Info);
    let xns = xous_names::XousNames::new().unwrap();
    #[cfg(target_os = "xous")]
    device_init(&xns);

    let mut slots = store::open();
    let key = store::load_or_create_key(&mut slots, EXPECTED_ADDRESS.is_some());
    let me = address_of(&key);
    if let Some(want) = EXPECTED_ADDRESS {
        if !want.eq_ignore_ascii_case(&me.to_string()) {
            panic!("the slots hold {me}, but this build expects {want}; refusing to run");
        }
    }
    log::info!("signer {}, PID {}, address {me}", env!("CARGO_PKG_VERSION"), xous::process::id());

    let mut token = [0u8; ipc::SLOT_TOKEN_LEN];
    getrandom::getrandom(&mut token).expect("TRNG");
    // unlimited connections: a process that connects first gains nothing without the token
    let slots_sid = xns.register_name(ipc::SLOTS_SERVER_NAME, None).expect("can't register slot server");

    std::thread::spawn(move || {
        let xns = xous_names::XousNames::new().unwrap();
        let cid = xns.request_connection_blocking(ipc::SIGNER_CHANNEL_NAME).expect("verifier signer channel");
        let mut hello = me.to_vec();
        hello.extend_from_slice(&token);
        loop {
            // blocks until the verifier has an approved transaction for us
            let job_bytes = call(cid, ipc::OP_SIGNER_WAIT, &hello, 64 * 1024);
            let reply = match alloy_rlp::Decodable::decode(&mut &job_bytes[..]) {
                Ok(job) => match sign(&key, me, &job) {
                    Ok(raw) => {
                        if job.kind == SignJob::SAFE_MULTISEND {
                            log::info!("co-signed Safe {} nonce {} to {}", job.tx.from, job.safe_nonce, job.tx.to);
                        } else {
                            log::info!("signed nonce {} to {} ({} B)", job.tx.nonce, job.tx.to, raw.len());
                        }
                        raw
                    }
                    Err(e) => {
                        log::warn!("refused: {e}");
                        Vec::new()
                    }
                },
                Err(e) => {
                    log::warn!("bad job from verifier: {e}");
                    Vec::new()
                }
            };
            call(cid, ipc::OP_SIGNER_RESULT, &reply, 4096);
        }
    });
    serve_slots(slots_sid, token, &mut slots)
}

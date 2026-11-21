//! Process 3 of 3: the signer. The only process that touches the private key.
//!
//! * It has no server: nothing can send it requests. It connects to the verifier's private
//!   signer channel and blocks in `OP_SIGNER_WAIT` until the verifier hands it a `SignJob`
//!   (a transaction the verifier simulated and approved).
//! * It builds the EIP-155 legacy transaction and its signing hash itself from those fields,
//!   checks the job is for its own address, signs with k256 and returns the EIP-2718 bytes.
//! * The key: 32 bytes from the chip TRNG on first boot, kept in two keystore app slots
//!   (key, then a header written last); emulator: a host file.

mod store;

use alloy_consensus::{SignableTransaction, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, B256, Signature, TxKind, keccak256};
use k256::ecdsa::SigningKey;
use sim_types::{SignJob, ipc};

fn address_of(key: &SigningKey) -> Address {
    let point = key.verifying_key().to_encoded_point(false);
    Address::from_slice(&keccak256(&point.as_bytes()[1..])[12..])
}

/// Sign `job` as an EIP-155 legacy tx, or refuse (empty result).
fn sign(key: &SigningKey, me: Address, job: &SignJob) -> Result<Vec<u8>, String> {
    if job.tx.from != me {
        return Err(format!("job is for {}, not this device ({me})", job.tx.from));
    }
    let tx = TxLegacy {
        chain_id: Some(job.chain_id),
        nonce: job.tx.nonce,
        gas_price: job.tx.gas_price,
        gas_limit: job.tx.gas_limit,
        to: TxKind::Call(job.tx.to),
        value: job.tx.value,
        input: job.tx.data.clone(),
    };
    let hash = tx.signature_hash();
    let (sig, recid) = key.sign_prehash_recoverable(hash.as_slice()).map_err(|e| format!("sign: {e}"))?;
    let (r, s) = sig.split_bytes();
    let signature = Signature::from_scalars_and_parity(B256::from_slice(&r), B256::from_slice(&s), recid.is_y_odd());
    let signed = TxEnvelope::Legacy(tx.into_signed(signature));
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

fn main() -> ! {
    log_server::init_wait().unwrap();
    log::set_max_level(log::LevelFilter::Info);

    let key = store::load_or_create_key();
    let me = address_of(&key);
    log::info!("signer {}, PID {}, address {me}", env!("CARGO_PKG_VERSION"), xous::process::id());

    let xns = xous_names::XousNames::new().unwrap();
    let cid = xns.request_connection_blocking(ipc::SIGNER_CHANNEL_NAME).expect("verifier signer channel");
    loop {
        // blocks until the verifier has an approved transaction for us
        let job_bytes = call(cid, ipc::OP_SIGNER_WAIT, me.as_slice(), 64 * 1024);
        let reply = match alloy_rlp::Decodable::decode(&mut &job_bytes[..]) {
            Ok(job) => match sign(&key, me, &job) {
                Ok(raw) => {
                    log::info!("signed nonce {} to {} ({} B)", job.tx.nonce, job.tx.to, raw.len());
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
}

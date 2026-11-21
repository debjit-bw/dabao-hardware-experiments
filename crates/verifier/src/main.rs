//! Process 2 of 3: the verifier. Owns witness verification and EVM simulation (and, next,
//! the effects inspector, ERC-7730 check and policy). Trusts nothing it receives: every
//! request comes from the untrusted transport, and every byte of state is checked against
//! the state root before use.
//!
//! IPC (see `sim_types::ipc`): the transport's server (one connection) answers OP_SIMULATE,
//! OP_SIGN and OP_ADDRESS; a second server (one connection), served by its own thread, is the
//! signer's channel. Only transactions that pass `approve` are handed to the signer.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicUsize, Ordering::Relaxed},
    time::Instant,
};

use std::sync::{
    Arc, Mutex,
    mpsc::{Receiver, Sender, channel},
};

use alloy_primitives::Address;
use sim_types::{SignJob, SignResult, SimInput, SimResult, ipc};

/// Counts live and peak heap bytes (Xous has no allocator statistics).
struct Counting;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(l) };
        if !p.is_null() {
            PEAK.fetch_max(LIVE.fetch_add(l.size(), Relaxed) + l.size(), Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) };
        LIVE.fetch_sub(l.size(), Relaxed);
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn error_result(e: impl Into<String>) -> SimResult {
    SimResult { error: e.into().into_bytes().into(), ..Default::default() }
}

/// Simulate `input`, with this request's time and peak heap filled in.
fn run(input: &[u8]) -> SimResult {
    let base = LIVE.load(Relaxed);
    PEAK.store(base, Relaxed);
    let start = Instant::now();
    let mut r = xous_evm::sim::simulate(input).unwrap_or_else(error_result);
    r.micros = start.elapsed().as_micros() as u64;
    r.peak_heap = (PEAK.load(Relaxed) - base) as u64;
    r
}

/// The signing policy. PLACEHOLDER until the effects inspector / ERC-7730 / policy engine:
/// sign only if the simulation succeeded, the tx doesn't revert, and it is sent from this
/// device's address on mainnet (the only chain the simulator's spec covers).
fn approve(input: &SimInput, sim: &SimResult, signer: Address) -> Result<(), String> {
    if !sim.error.is_empty() {
        return Err(format!("simulation rejected the input: {}", String::from_utf8_lossy(&sim.error)));
    }
    if !sim.success {
        return Err("the transaction reverts".into());
    }
    if input.tx.from != signer {
        return Err(format!("tx is from {}, not this device ({signer})", input.tx.from));
    }
    if input.chain_id != 1 {
        return Err(format!("chain {} not supported (mainnet only)", input.chain_id));
    }
    Ok(())
}

/// The signer's channel, served by its own thread. The signer parks an `OP_SIGNER_WAIT`
/// message here; a job from the main thread fills it, then the signer's `OP_SIGNER_RESULT`
/// comes back on the same server and is passed back.
struct SignerLink {
    address: Arc<Mutex<Option<Address>>>,
    jobs: Sender<SignJob>,
    results: Mutex<Receiver<Vec<u8>>>,
}

fn start_signer_channel(xns: &xous_names::XousNames) -> SignerLink {
    let sid = xns.register_name(ipc::SIGNER_CHANNEL_NAME, Some(1)).expect("can't register signer channel");
    let address = Arc::new(Mutex::new(None));
    let (jobs, job_rx) = channel::<SignJob>();
    let (result_tx, results) = channel::<Vec<u8>>();
    let addr = address.clone();
    std::thread::spawn(move || {
        loop {
            // 1. the signer parks OP_SIGNER_WAIT (with its address)
            let mut wait = xous::receive_message(sid).unwrap();
            if wait.body.id() != ipc::OP_SIGNER_WAIT {
                log::warn!("signer channel: expected OP_SIGNER_WAIT, got {}", wait.body.id());
                continue;
            }
            let Some(mem) = wait.body.memory_message_mut() else { continue };
            let len = mem.valid.map(|v| v.get()).unwrap_or(0).min(mem.buf.len());
            let a = unsafe { &mem.buf.as_slice::<u8>()[..len] };
            if a.len() != 20 {
                log::warn!("signer channel: bad address length {}", a.len());
                continue;
            }
            let a = Address::from_slice(a);
            {
                let mut cur = addr.lock().unwrap();
                match *cur {
                    None => {
                        log::info!("signer attached: {a}");
                        *cur = Some(a);
                    }
                    Some(prev) if prev != a => {
                        log::error!("signer channel: address changed {prev} -> {a}; refusing");
                        continue;
                    }
                    _ => {}
                }
            }
            // 2. hold it until there is an approved job, then return it with the job
            let job = job_rx.recv().expect("main thread gone");
            let out = alloy_rlp::encode(&job);
            let cap = mem.buf.len();
            if out.len() > cap {
                log::error!("job ({} B) larger than the signer's buffer ({cap} B)", out.len());
                result_tx.send(Vec::new()).ok();
                continue;
            }
            unsafe { mem.buf.as_slice_mut::<u8>()[..out.len()].copy_from_slice(&out) };
            mem.valid = xous::MemorySize::new(out.len());
            drop(wait); // wakes the signer
            // 3. the signer's answer
            let mut res = xous::receive_message(sid).unwrap();
            let res_op = res.body.id();
            let signed = match res.body.memory_message_mut() {
                Some(m) if res_op == ipc::OP_SIGNER_RESULT => {
                    let len = m.valid.map(|v| v.get()).unwrap_or(0).min(m.buf.len());
                    unsafe { m.buf.as_slice::<u8>()[..len].to_vec() }
                }
                _ => {
                    log::warn!("signer channel: expected OP_SIGNER_RESULT, got {res_op}");
                    Vec::new()
                }
            };
            result_tx.send(signed).ok();
        }
    });
    SignerLink { address, jobs, results: Mutex::new(results) }
}

impl SignerLink {
    fn address(&self) -> Option<Address> {
        *self.address.lock().unwrap()
    }

    fn sign(&self, job: SignJob) -> Vec<u8> {
        if self.jobs.send(job).is_err() {
            return Vec::new();
        }
        self.results.lock().unwrap().recv().unwrap_or_default()
    }
}

/// Simulate, check the policy, and (if approved) have the signer sign.
fn sign_request(raw: &[u8], signer: &SignerLink) -> SignResult {
    let sim = run(raw);
    let mut out = SignResult { sim, ..Default::default() };
    let Some(me) = signer.address() else {
        out.refused = b"no signer attached".to_vec().into();
        return out;
    };
    out.signer = me;
    let input: SimInput = match alloy_rlp::Decodable::decode(&mut &raw[..]) {
        Ok(i) => i,
        Err(e) => {
            out.refused = format!("decode: {e}").into_bytes().into();
            return out;
        }
    };
    if let Err(e) = approve(&input, &out.sim, me) {
        log::info!("verifier: refused to sign: {e}");
        out.refused = e.into_bytes().into();
        return out;
    }
    let signed = signer.sign(SignJob { chain_id: input.chain_id, tx: input.tx });
    if signed.is_empty() {
        out.refused = b"the signer refused".to_vec().into();
    } else {
        log::info!("verifier: approved and signed ({} B)", signed.len());
        out.signed_tx = signed.into();
    }
    out
}

/// Write `out` into the lent buffer (or an error if it doesn't fit) and set `valid`.
fn reply(mem: &mut xous::MemoryMessage, out: Vec<u8>, too_big: impl FnOnce(usize, usize) -> Vec<u8>) {
    let cap = mem.buf.len();
    let out = if out.len() > cap { too_big(out.len(), cap) } else { out };
    unsafe { mem.buf.as_slice_mut::<u8>()[..out.len()].copy_from_slice(&out) };
    mem.valid = xous::MemorySize::new(out.len());
}

/// Xous caps each process's heap at 512 KiB by default (kernel `services.rs`, unless built with
/// `big-heap`). Simulating a Uniswap swap needs ~0.7-0.9 MB, so the verifier raises its own cap
/// (`AdjustProcessLimit` acts on the calling process; pddb does the same). Physical SRAM is
/// 2 MiB shared by everything, so this is not unlimited.
const HEAP_LIMIT: usize = 1536 * 1024;

fn raise_heap_limit() {
    use xous::{Limits, SysCall, rsyscall};
    let cur = match rsyscall(SysCall::AdjustProcessLimit(Limits::HeapMaximum as usize, 0, HEAP_LIMIT)) {
        Ok(xous::Result::Scalar2(1, cur)) => cur,
        other => {
            log::error!("can't read the heap limit: {other:?}");
            return;
        }
    };
    match rsyscall(SysCall::AdjustProcessLimit(Limits::HeapMaximum as usize, cur, HEAP_LIMIT)) {
        Ok(xous::Result::Scalar2(1, new)) => log::info!("heap limit {} KiB -> {} KiB", cur / 1024, new / 1024),
        other => log::error!("can't raise the heap limit: {other:?}"),
    }
}

fn main() -> ! {
    log_server::init_wait().unwrap();
    log::set_max_level(log::LevelFilter::Info);
    raise_heap_limit();
    let xns = xous_names::XousNames::new().unwrap();
    let signer = start_signer_channel(&xns);
    let sid = xns.register_name(ipc::VERIFIER_SERVER_NAME, Some(1)).expect("can't register verifier");
    log::info!("verifier {} ready, PID {}", env!("CARGO_PKG_VERSION"), xous::process::id());

    loop {
        let mut msg = xous::receive_message(sid).unwrap();
        let op = msg.body.id();
        let Some(mem) = msg.body.memory_message_mut() else {
            log::warn!("verifier: opcode {op} without a mutable buffer");
            continue;
        };
        let len = mem.valid.map(|v| v.get()).unwrap_or(0).min(mem.buf.len());
        match op {
            ipc::OP_SIMULATE => {
                // safety: the kernel mapped the buffer for us; we only read the first `len` bytes
                let result = run(unsafe { &mem.buf.as_slice::<u8>()[..len] });
                log_result(&result);
                reply(mem, alloy_rlp::encode(&result), |n, cap| {
                    alloy_rlp::encode(&error_result(format!("result ({n} B) larger than buffer ({cap} B)")))
                });
            }
            ipc::OP_SIGN => {
                let raw = unsafe { mem.buf.as_slice::<u8>()[..len].to_vec() };
                let result = sign_request(&raw, &signer);
                log_result(&result.sim);
                reply(mem, alloy_rlp::encode(&result), |n, cap| {
                    let r = SignResult {
                        refused: format!("result ({n} B) larger than buffer ({cap} B)").into_bytes().into(),
                        ..Default::default()
                    };
                    alloy_rlp::encode(&r)
                });
            }
            ipc::OP_ADDRESS => {
                let a = signer.address().map(|a| a.to_vec()).unwrap_or_default();
                reply(mem, a, |_, _| Vec::new());
            }
            _ => log::warn!("verifier: unknown opcode {op}"),
        }
        // dropping `msg` returns the buffer to the transport with the new `valid`
    }
}

fn log_result(result: &SimResult) {
    if !result.error.is_empty() {
        log::info!("verifier: rejected: {}", String::from_utf8_lossy(&result.error));
    } else {
        log::info!(
            "verifier: success={} gas={} logs={} changes={} {} us, peak heap {} B",
            result.success,
            result.gas_used,
            result.logs.len(),
            result.changes.len(),
            result.micros,
            result.peak_heap
        );
    }
}

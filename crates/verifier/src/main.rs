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

mod counters;
mod lc;
mod slots;

use alloy_primitives::Address;
use counters::Counters;
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

/// Simulate `input`, with this request's time and peak heap filled in, then run the ERC-7730
/// check and the policy. Returns the result and the policy counters to persist if it is signed.
/// Inputs whose estimated peak memory doesn't fit are rejected up front: running out of memory
/// aborts the verifier, which would leave the device stuck until RESET.
fn run(input: &[u8], counters: &Counters, lc: &lc::LightClient) -> (SimResult, Vec<(usize, policy::Counter)>) {
    let r = run_as(input, counters, lc, None);
    (r.sim, r.updates)
}

/// The light-client check of `inp`'s parent header: proven canonical by the sync committee, and
/// the simulated block follows it (so the block time the policy uses is trusted too). Returns
/// the attested beacon slot.
fn header_check(inp: &SimInput, lc: &lc::LightClient) -> Result<u64, String> {
    let Some(p) = &inp.lc else {
        return Err("no light-client proof: the host-supplied parent header is not trusted".into());
    };
    let slot = lc.check(p, alloy_primitives::keccak256(&inp.parent_header))?;
    let parent = <alloy_consensus::Header as alloy_rlp::Decodable>::decode(&mut &inp.parent_header[..]).map_err(|e| format!("parent header: {e}"))?;
    if inp.block.number != parent.number + 1 || inp.block.timestamp != parent.timestamp + 12 {
        return Err(format!(
            "simulated block {} at {} does not follow the verified parent {} at {}",
            inp.block.number, inp.block.timestamp, parent.number, parent.timestamp
        ));
    }
    Ok(slot)
}

/// One verifier run: the simulation with the 7730 check and policy filled in, the policy
/// counters to persist if it is signed, the Safe's verified configuration, the attested beacon
/// slot, and (Safe co-signing) the postcondition to wrap the call in.
#[derive(Default)]
struct Run {
    sim: SimResult,
    updates: Vec<(usize, policy::Counter)>,
    safe: Option<sim_types::safe::State>,
    slot: Option<u64>,
    post: Option<Result<xous_evm::postcondition::Postcondition, String>>,
}

/// `run`; with `safe_owner = Some(device)`, `tx.from` is a Safe: the call is simulated as made
/// by the Safe, its configuration is read from the verified pre-state, and the postcondition is
/// built and checked on the simulated post-state.
fn run_as(input: &[u8], counters: &Counters, lc: &lc::LightClient, safe_owner: Option<Address>) -> Run {
    let max = MAX_INPUT;
    if input.len() > max {
        let e = error_result(format!(
            "input too large for this device: {} B > {max} B (estimated peak {} KB)",
            input.len(),
            estimated_peak(input.len()) / 1024
        ));
        return Run { sim: e, ..Default::default() };
    }
    let base = LIVE.load(Relaxed);
    PEAK.store(base, Relaxed);
    let start = Instant::now();
    let mut inp = match <SimInput as alloy_rlp::Decodable>::decode(&mut &input[..]) {
        Ok(inp) => inp,
        Err(e) => return Run { sim: error_result(format!("decode SimInput: {e}")), ..Default::default() },
    };
    let verified = header_check(&inp, lc);
    // the simulation decodes its own copy: drop the witness here, so it isn't in RAM twice
    inp.state = Vec::new();
    inp.codes = Vec::new();
    inp.keys = Vec::new();
    let mut opts = xous_evm::sim::Options::default();
    if let Some(device) = safe_owner {
        opts.as_contract = true;
        opts.reads = sim_types::safe::slots(device).iter().map(|s| (inp.tx.from, *s)).collect();
        opts.code_hashes = xous_evm::postcondition::CODE_HASH_ACCOUNTS.to_vec();
    }
    // the policy's limited assets on this chain are always in the postcondition
    let limited: Vec<Address> =
        POLICY.chains.iter().filter(|c| c.chain_id == inp.chain_id).flat_map(|c| c.limits.iter().map(|l| l.asset)).collect();
    let res = xous_evm::sim::simulate_then(input, |_| {}, &opts, |r, reads, call| {
        // ERC-7730: what the user would be shown vs what the simulation did
        r.clear_sign = clear_sign::check(&DESCRIPTORS, inp.chain_id, &inp.tx, r.success, &r.effects);
        // the device's own policy: limits, fee, slippage, allowlist
        let out = policy::evaluate(&POLICY, &counters.values, &DESCRIPTORS, &inp, r);
        r.policy = out.check;
        if !counters.ok() {
            r.policy.violations.push(b"policy counters unreadable: can't enforce spending limits".to_vec().into());
        }
        let post = safe_owner.filter(|_| r.success && reads.slots.len() == 6).map(|device| {
            let threshold = reads.slots[1];
            xous_evm::postcondition::build(r, &inp.tx, device, threshold, &reads.code_hashes, &limited, call)
        });
        (out.updates, post)
    });
    let mut run = match res {
        Ok((sim, reads, (updates, post))) => {
            let safe = (safe_owner.is_some() && reads.slots.len() == 6)
                .then(|| sim_types::safe::State::from_slots(&reads.slots.clone().try_into().unwrap()));
            Run { sim, updates, safe, slot: None, post }
        }
        Err(e) => Run { sim: error_result(e), ..Default::default() },
    };
    match verified {
        Ok(slot) => run.slot = Some(slot),
        Err(e) => run.sim.header_check = e.into_bytes().into(),
    }
    run.sim.micros = start.elapsed().as_micros() as u64;
    run.sim.peak_heap = (PEAK.load(Relaxed) - base) as u64;
    run
}

/// The signing policy compiled into the firmware (crates/policy/policy.bin).
static POLICY: std::sync::LazyLock<policy::Policy> = std::sync::LazyLock::new(policy::builtin);

/// ERC-7730 descriptors compiled into the firmware (crates/clear-sign/descriptors.bin).
static DESCRIPTORS: std::sync::LazyLock<clear_sign::model::DescriptorSet> = std::sync::LazyLock::new(clear_sign::builtin);

/// Sign only if the simulation succeeded, the ERC-7730 check matched a descriptor and found
/// every effect explained by what the user is shown, the policy passed, and the tx is sent
/// from this device's address on a chain the simulator has a spec for (mainnet, Sepolia).
fn approve(input: &SimInput, sim: &SimResult, signer: Address, safe: Option<&sim_types::safe::State>) -> Result<(), String> {
    if !sim.error.is_empty() {
        return Err(format!("simulation rejected the input: {}", String::from_utf8_lossy(&sim.error)));
    }
    if !sim.success {
        return Err("the transaction reverts".into());
    }
    let cs = &sim.clear_sign;
    if cs.descriptor.is_empty() || !cs.violations.is_empty() {
        let why: Vec<String> = cs.violations.iter().map(|v| String::from_utf8_lossy(v).to_string()).collect();
        return Err(format!("ERC-7730 check failed: {}", if why.is_empty() { "no descriptor matched".into() } else { why.join("; ") }));
    }
    if !sim.header_check.is_empty() {
        return Err(format!("light client: {}", String::from_utf8_lossy(&sim.header_check)));
    }
    if !sim.policy.violations.is_empty() {
        let why: Vec<String> = sim.policy.violations.iter().map(|v| String::from_utf8_lossy(v).to_string()).collect();
        return Err(format!("policy: {}", why.join("; ")));
    }
    match safe {
        None if input.tx.from != signer => return Err(format!("tx is from {}, not this device ({signer})", input.tx.from)),
        None => {}
        Some(st) => {
            let p = st.problems();
            if !p.is_empty() {
                return Err(format!("Safe {}: {}", input.tx.from, p.join("; ")));
            }
        }
    }
    if !matches!(input.chain_id, 1 | 11155111) {
        return Err(format!("chain {} not supported (mainnet and Sepolia only)", input.chain_id));
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
/// `safe`: co-sign a Safe transaction (`tx.from` = the Safe) instead of signing our own.
fn sign_request(raw: &[u8], signer: &SignerLink, counters: &mut Counters, lc: &mut lc::LightClient, safe: bool) -> SignResult {
    let Some(me) = signer.address() else {
        return SignResult { refused: b"no signer attached".to_vec().into(), ..Default::default() };
    };
    let Run { sim, updates, safe: safe_state, slot, post } = run_as(raw, counters, lc, safe.then_some(me));
    let mut out = SignResult { sim, ..Default::default() };
    out.signer = me;
    let input: SimInput = match alloy_rlp::Decodable::decode(&mut &raw[..]) {
        Ok(i) => i,
        Err(e) => {
            out.refused = format!("decode: {e}").into_bytes().into();
            return out;
        }
    };
    if let Err(e) = approve(&input, &out.sim, me, safe_state.as_ref()) {
        log::info!("verifier: refused to sign: {e}");
        out.refused = e.into_bytes().into();
        return out;
    }
    // a Safe call is co-signed only wrapped in its postcondition
    let post = match (safe, post) {
        (false, _) => None,
        (true, Some(Ok(p))) => Some(p),
        (true, Some(Err(e))) => {
            out.refused = format!("postcondition: {e}").into_bytes().into();
            return out;
        }
        (true, None) => {
            out.refused = b"Safe state not verified".to_vec().into();
            return out;
        }
    };
    // record the spending before signing: a crash after this over-counts, never under-counts
    if let Err(e) = counters.commit(&updates) {
        log::error!("verifier: {e}");
        out.refused = e.into_bytes().into();
        return out;
    }
    // and never accept an older header again
    if !slot.is_some_and(|s| lc.ratchet(s)) {
        out.refused = b"can't persist the light client's highest slot".to_vec().into();
        return out;
    }
    let job = match (&safe_state, &post) {
        // the Safe nonce comes from the verified state, not from the host; the SafeTx is the
        // DELEGATECALL to MultiSendCallOnly: [the simulated call, the postcondition]
        (Some(st), Some(p)) => {
            out.safe_data = p.safe_data.clone().into();
            let tx = sim_types::SimTx {
                to: sim_types::safe::MULTISEND_CALL_ONLY,
                value: Default::default(),
                data: p.safe_data.clone().into(),
                ..input.tx
            };
            SignJob { chain_id: input.chain_id, tx, kind: SignJob::SAFE_MULTISEND, safe_nonce: st.nonce }
        }
        (None, None) => SignJob { chain_id: input.chain_id, tx: input.tx, kind: SignJob::TX, safe_nonce: Default::default() },
        _ => {
            out.refused = b"internal: Safe state and postcondition disagree".to_vec().into();
            return out;
        }
    };
    let signed = signer.sign(job);
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

/// Memory model for one simulation, fitted to board measurements (peak heap: WETH transfer
/// 23 KB -> 420 KB, swap 94 KB -> 594 KB, swap 131 KB -> 699-714 KB, i.e. ~330 KB + 2.8 x
/// input) and padded: estimate = BASE + FACTOR x input. Used only to report the estimate.
const MODEL_BASE: usize = 350 * 1024;
const MODEL_FACTOR_X10: usize = 35; // 3.5 x

/// Largest `SimInput` accepted: just above the largest input measured to work on the board
/// (131 KB swap, 714 KB peak heap). Physical RAM (2 MiB SRAM, shared) is the real limit, and it
/// can't be measured from here: `map_memory` maps lazily (a 4 MiB probe succeeds on a 2 MiB
/// chip) and touching pages to find the limit would kill this process when RAM runs out.
/// Running out of memory mid-request aborts the verifier and wedges the device until RESET, so
/// we refuse instead. Raise only after measuring a larger input on the board.
const MAX_INPUT: usize = 140 * 1024;

fn estimated_peak(input_len: usize) -> usize {
    MODEL_BASE + input_len * MODEL_FACTOR_X10 / 10
}

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
    // claim and load the policy counters before registering the server (before any host input)
    let mut counters = Counters::open(&POLICY);
    let mut lc = lc::LightClient::open();
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
                let (result, _) = run(unsafe { &mem.buf.as_slice::<u8>()[..len] }, &counters, &lc);
                log_result(&result);
                reply(mem, alloy_rlp::encode(&result), |n, cap| {
                    alloy_rlp::encode(&error_result(format!("result ({n} B) larger than buffer ({cap} B)")))
                });
            }
            ipc::OP_SIGN | ipc::OP_SAFE_SIGN => {
                // borrowed, not copied: a copy would keep the whole witness in RAM twice
                let result = sign_request(unsafe { &mem.buf.as_slice::<u8>()[..len] }, &signer, &mut counters, &mut lc, op == ipc::OP_SAFE_SIGN);
                log_result(&result.sim);
                reply(mem, alloy_rlp::encode(&result), |n, cap| {
                    let r = SignResult {
                        refused: format!("result ({n} B) larger than buffer ({cap} B)").into_bytes().into(),
                        ..Default::default()
                    };
                    alloy_rlp::encode(&r)
                });
            }
            ipc::OP_STATUS => {
                let st = sim_types::DeviceStatus {
                    free_ram_at_boot: 0, // not measurable (see MAX_INPUT)
                    heap_limit: HEAP_LIMIT as u64,
                    max_input: MAX_INPUT as u64,
                    signer: signer.address().map(|a| a.to_vec()).unwrap_or_default().into(),
                };
                reply(mem, alloy_rlp::encode(&st), |_, _| Vec::new());
            }
            ipc::OP_LC_COMMITTEE | ipc::OP_LC_UPDATE | ipc::OP_LC_STATUS => {
                let msg = unsafe { &mem.buf.as_slice::<u8>()[..len] };
                let st = match op {
                    ipc::OP_LC_COMMITTEE => match alloy_rlp::Decodable::decode(&mut &msg[..]) {
                        Ok(c) => lc.load(&c),
                        Err(e) => lc.status(format!("decode committee: {e}")),
                    },
                    ipc::OP_LC_UPDATE => match alloy_rlp::Decodable::decode(&mut &msg[..]) {
                        Ok(u) => lc.update(&u),
                        Err(e) => lc.status(format!("decode update: {e}")),
                    },
                    _ => lc.status(""),
                };
                reply(mem, alloy_rlp::encode(&st), |_, _| Vec::new());
            }
            ipc::OP_POLICY => {
                let mut lines = policy::describe(&POLICY, &counters.values, &DESCRIPTORS);
                if !counters.ok() {
                    lines.push("COUNTERS UNREADABLE: signing disabled".into());
                }
                let st = sim_types::PolicyStatus {
                    policy: POLICY.id.clone(),
                    lines: lines.into_iter().map(|l| l.into_bytes().into()).collect(),
                };
                reply(mem, alloy_rlp::encode(&st), |_, _| Vec::new());
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

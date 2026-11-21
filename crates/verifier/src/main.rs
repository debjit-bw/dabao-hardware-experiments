//! Process 2 of 3: the verifier. Owns witness verification and EVM simulation (and, next,
//! the effects inspector, ERC-7730 check and policy). Trusts nothing it receives: every
//! request comes from the untrusted transport, and every byte of state is checked against
//! the state root before use.
//!
//! IPC: `sim_types::ipc::OP_SIMULATE`, a lent buffer holding RLP `SimInput` (`valid` = its
//! length). The reply RLP `SimResult` is written into the same buffer (`valid` = its length).
//! Only one connection is accepted (the transport).

use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicUsize, Ordering::Relaxed},
    time::Instant,
};

use sim_types::{SimResult, ipc};

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

fn main() -> ! {
    log_server::init_wait().unwrap();
    log::set_max_level(log::LevelFilter::Info);
    let xns = xous_names::XousNames::new().unwrap();
    let sid = xns.register_name(ipc::VERIFIER_SERVER_NAME, Some(1)).expect("can't register verifier");
    log::info!("verifier {} ready, PID {}", env!("CARGO_PKG_VERSION"), xous::process::id());

    loop {
        let mut msg = xous::receive_message(sid).unwrap();
        if msg.body.id() != ipc::OP_SIMULATE {
            log::warn!("verifier: unknown opcode {}", msg.body.id());
            continue;
        }
        let Some(mem) = msg.body.memory_message_mut() else {
            log::warn!("verifier: OP_SIMULATE without a mutable buffer");
            continue;
        };
        let cap = mem.buf.len();
        let len = mem.valid.map(|v| v.get()).unwrap_or(0).min(cap);
        let result = {
            // safety: the kernel mapped `cap` bytes for us; we only read the first `len`
            let input = unsafe { &mem.buf.as_slice::<u8>()[..len] };
            run(input)
        };
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
        let mut out = alloy_rlp::encode(&result);
        if out.len() > cap {
            out = alloy_rlp::encode(&error_result(format!("result ({} B) larger than buffer ({cap} B)", out.len())));
        }
        // safety: as above; `out.len() <= cap` (an error result is tiny)
        unsafe { mem.buf.as_slice_mut::<u8>()[..out.len()].copy_from_slice(&out) };
        mem.valid = xous::MemorySize::new(out.len());
        // dropping `msg` returns the buffer to the transport with the new `valid`
    }
}

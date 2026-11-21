//! Engine spike: run reth stateless block validation (witness verification +
//! revm execution) inside a Xous process and measure it.
//!
//! Stage 2: the upstream guest program (`stateless_validator_reth::run_stateless_guest`,
//! SSZ in / SSZ out) on the release smoke fixture from paradigmxyz/stateless,
//! compared byte-for-byte against the expected output. Reports wall time and
//! peak heap.

use xous_evm::sim;

use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicUsize, Ordering::Relaxed},
    time::Instant,
};

/// Counts live and peak heap bytes. Xous has no allocator statistics, and peak
/// heap is what decides whether a block fits in 2 MiB of SRAM.
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

const SMOKE_IN: &[u8] = include_bytes!("../fixtures/guest-smoke.in.ssz");
const SMOKE_OUT: &[u8] = include_bytes!("../fixtures/guest-smoke.out.ssz");
/// Stage 3: WETH transfer(0x..dEaD, 1) on mainnet state; see host/witness-gen.
const WETH_TRANSFER: &[u8] = include_bytes!("../../xous-evm/fixtures/weth-transfer.rlp");

/// Runs `f`, returning its result, wall time and peak heap above the starting level.
fn measure<T>(f: impl FnOnce() -> T) -> (T, std::time::Duration, usize) {
    let base = LIVE.load(Relaxed);
    PEAK.store(base, Relaxed);
    let start = Instant::now();
    let r = f();
    (r, start.elapsed(), PEAK.load(Relaxed) - base)
}

fn main() {
    log_server::init_wait().unwrap();
    log::set_max_level(log::LevelFilter::Info);
    log::info!("engine-spike, PID {}", xous::process::id());
    // Give USB time to enumerate and the host time to open the serial port: log lines
    // mirrored to USB before a listener exists are dropped.
    std::thread::sleep(std::time::Duration::from_secs(10));

    let (out, elapsed, peak) = measure(|| stateless_validator_reth::guest::run_stateless_guest(SMOKE_IN));

    // Stage 3: simulate the WETH transfer; then the same input with one trie node removed,
    // which must fail (a missing proof must never read as an empty account or zero slot).
    let (sim, sim_t, sim_peak) = measure(|| sim::simulate(WETH_TRANSFER));
    let sim_line = match &sim {
        Ok(r) => format!(
            "success={} gas_used={} output={} logs={} changes={}",
            r.success, r.gas_used, r.output, r.logs.len(), r.changes.len()
        ),
        Err(e) => format!("ERROR {e}"),
    };
    let missing = sim::simulate_with(WETH_TRANSFER, |i| {
        i.state.pop();
    });
    let missing_line = match &missing {
        Ok(r) => format!("UNEXPECTED SUCCESS (fail-open!) success={} gas={}", r.success, r.gas_used),
        Err(e) => format!("rejected as expected: {e}"),
    };

    // StatelessValidationResult SSZ: new_payload_request_root (32) | successful_validation (1) | ...
    let valid = out.get(32) == Some(&1);
    let matches = out == SMOKE_OUT;
    // Repeat forever so a late-attaching serial console still sees the result.
    loop {
        log::info!(
            "smoke: successful_validation={valid} output_matches_expected={matches} time={elapsed:?} peak_heap={peak} B (input {} B)",
            SMOKE_IN.len()
        );
        if !matches {
            log::error!("output {out:02x?}\nexpected {SMOKE_OUT:02x?}");
        }
        log::info!("weth-transfer: {sim_line} time={sim_t:?} peak_heap={sim_peak} B (input {} B)", WETH_TRANSFER.len());
        log::info!("weth-transfer minus one witness node: {missing_line}");
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}

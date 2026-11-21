//! Engine spike: run reth stateless block validation (witness verification +
//! revm execution) inside a Xous process and measure it.
//!
//! Stage 2: the upstream guest program (`stateless_validator_reth::run_stateless_guest`,
//! SSZ in / SSZ out) on the release smoke fixture from paradigmxyz/stateless,
//! compared byte-for-byte against the expected output. Reports wall time and
//! peak heap.

#[allow(dead_code)] // mainnet spec for the later simulate-a-tx path; unused by the guest path
mod chainspec;

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

fn main() {
    log_server::init_wait().unwrap();
    log::set_max_level(log::LevelFilter::Info);
    log::info!("engine-spike, PID {}", xous::process::id());
    // Give USB time to enumerate and the host time to open the serial port: log lines
    // mirrored to USB before a listener exists are dropped.
    std::thread::sleep(std::time::Duration::from_secs(10));

    let base = LIVE.load(Relaxed);
    PEAK.store(base, Relaxed);
    let start = Instant::now();
    let out = stateless_validator_reth::guest::run_stateless_guest(SMOKE_IN);
    let elapsed = start.elapsed();
    let peak = PEAK.load(Relaxed) - base;

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
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}

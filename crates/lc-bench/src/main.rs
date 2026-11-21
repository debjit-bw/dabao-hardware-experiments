//! Light-client benchmark: verify the recorded Sepolia finality update (494/512 signers) on
//! the chip, timing each step, then repeat with a tampered header (must fail). Results are
//! logged every 10 s so a late-attaching USB console still sees them.

use std::time::Instant;

use light_client::{Committee, Fixture, signing_root, verify_sync_aggregate};

const FIXTURE: &[u8] = include_bytes!("../../light-client/fixtures/sepolia-finality.rlp");

fn main() {
    log_server::init_wait().unwrap();
    log::set_max_level(log::LevelFilter::Info);
    log::info!("lc-bench, PID {}", xous::process::id());
    std::thread::sleep(std::time::Duration::from_secs(10));

    let start = Instant::now();
    let now = || start.elapsed().as_micros() as u64;
    let f: Fixture = alloy_rlp::Decodable::decode(&mut &FIXTURE[..]).expect("fixture");
    let t0 = now();
    let c = Committee::from_compressed(&f.pubkeys).expect("committee");
    let decompress = now() - t0;
    let t1 = now();
    let root = signing_root(&f.header, f.signature_slot);
    let ssz = now() - t1;
    let ok = verify_sync_aggregate(&c, &f.bits, &f.signature, root, &now);
    let mut bad = f.header.clone();
    bad.state_root.0[0] ^= 1;
    let t2 = now();
    let tampered = verify_sync_aggregate(&c, &f.bits, &f.signature, signing_root(&bad, f.signature_slot), &now);
    let tampered_us = now() - t2;
    let summary = format!(
        "LC RESULT slot {}: {}; decompress+subgroup-check 512 keys {} ms; SSZ+domain {} us; {}; tampered header: {} ({} ms)",
        f.header.slot,
        if ok.is_ok() { "VERIFIED" } else { "FAILED" },
        decompress / 1000,
        ssz,
        match &ok {
            Ok(t) => format!(
                "aggregate {} ms, hash-to-G2 {} ms, signature decompress {} ms, pairing check {} ms, total verify {} ms",
                t.aggregate_us / 1000,
                t.hash_to_curve_us / 1000,
                t.signature_us / 1000,
                t.pairing_us / 1000,
                (t.aggregate_us + t.hash_to_curve_us + t.signature_us + t.pairing_us) / 1000
            ),
            Err(e) => e.clone(),
        },
        if tampered.is_err() { "rejected" } else { "ACCEPTED?!" },
        tampered_us / 1000
    );
    loop {
        log::info!("{summary}");
        std::thread::sleep(std::time::Duration::from_secs(10));
    }
}

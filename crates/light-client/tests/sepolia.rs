//! A real Sepolia finality update (slot 11630016, Gloas), recorded with `dabao-host lc-fixture`.
use light_client::{Committee, Fixture, signing_root, verify_sync_aggregate};

fn fixture() -> Fixture {
    alloy_rlp::Decodable::decode(&mut &include_bytes!("../fixtures/sepolia-finality.rlp")[..]).unwrap()
}

fn now() -> u64 {
    0
}

#[test]
fn real_sync_aggregate_verifies() {
    let f = fixture();
    let c = Committee::from_compressed(&f.pubkeys).unwrap();
    verify_sync_aggregate(&c, &f.bits, &f.signature, signing_root(&f.header, f.signature_slot), &now).unwrap();
}

#[test]
fn tampered_header_or_bits_fail() {
    let f = fixture();
    let c = Committee::from_compressed(&f.pubkeys).unwrap();
    let mut h = f.header.clone();
    h.state_root.0[0] ^= 1; // a different state root: not what the committee signed
    assert!(verify_sync_aggregate(&c, &f.bits, &f.signature, signing_root(&h, f.signature_slot), &now).is_err());
    // claim one more participant than actually signed: the aggregate key no longer matches
    let mut bits = f.bits.to_vec();
    let i = (0..512).find(|i| bits[i / 8] >> (i % 8) & 1 == 0).unwrap();
    bits[i / 8] |= 1 << (i % 8);
    assert!(verify_sync_aggregate(&c, &bits, &f.signature, signing_root(&f.header, f.signature_slot), &now).is_err());
    // too few signers
    assert!(verify_sync_aggregate(&c, &[0xff; 40], &f.signature, signing_root(&f.header, f.signature_slot), &now).unwrap_err().contains("2/3"));
}

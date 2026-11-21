//! The light-client protocol on real Sepolia data (`dabao-host lc-fixtures`): the anchor's
//! committee, the hand-off from period 1418 to 1419, and a header proof.
use alloy_primitives::B256;
use light_client::{Committee, anchor, committee_root, verify_header_proof, verify_update};
use sim_types::lc::{Committee as Keys, CommitteeUpdate, HeaderProof};

fn de<T: alloy_rlp::Decodable>(b: &[u8]) -> T {
    T::decode(&mut &b[..]).unwrap()
}
fn now() -> u64 {
    0
}
fn c1418() -> Keys {
    de(include_bytes!("../fixtures/committee-1418.rlp"))
}
fn c1419() -> Keys {
    de(include_bytes!("../fixtures/committee-1419.rlp"))
}

#[test]
fn anchor_committee_matches_and_others_dont() {
    let k = c1419();
    assert_eq!(committee_root(&k.pubkeys, &k.aggregate).unwrap(), anchor::COMMITTEE_ROOT);
    assert!(Committee::load(&k, anchor::COMMITTEE_ROOT).is_ok());
    // the previous period's keys don't hash to the anchor: refused
    assert!(Committee::load(&c1418(), anchor::COMMITTEE_ROOT).is_err());
    // one swapped key: refused
    let mut bad = c1419();
    bad.pubkeys.swap(0, 1);
    assert!(Committee::load(&bad, anchor::COMMITTEE_ROOT).is_err());
}

#[test]
fn handoff_1418_to_1419_verifies_and_lands_on_the_anchor() {
    let k = c1418();
    let c = Committee::load(&k, committee_root(&k.pubkeys, &k.aggregate).unwrap()).unwrap();
    let u: CommitteeUpdate = de(include_bytes!("../fixtures/update-1418.rlp"));
    // independent check: the hand-off arrives exactly at the anchor's committee
    assert_eq!(verify_update(&c, &u, &now).unwrap(), anchor::COMMITTEE_ROOT);
    // a forged next committee (one key changed) fails the state branch
    let mut f = u.clone();
    f.next.pubkeys[7] = f.next.pubkeys[8].clone();
    assert!(verify_update(&c, &f, &now).unwrap_err().contains("not in the signed header's state"));
    // the wrong committee can't sign a hand-off
    let wrong = Committee::load(&c1419(), anchor::COMMITTEE_ROOT).unwrap();
    assert!(verify_update(&wrong, &u, &now).is_err());
}

#[test]
fn header_proof_verifies_and_binds_the_execution_hash() {
    let c = Committee::load(&c1419(), anchor::COMMITTEE_ROOT).unwrap();
    let p: HeaderProof = de(include_bytes!("../fixtures/header-proof.rlp"));
    verify_header_proof(&c, &p, &now).unwrap();
    let mut q = p.clone();
    q.execution_block_hash = B256::repeat_byte(0x42); // another block: not in the signed body
    assert!(verify_header_proof(&c, &q, &now).unwrap_err().contains("not in the signed header's body"));
}

//! The device's SafeTx hash and Safe configuration checks.
use alloy_primitives::{Address, U256, address, b256};
use sim_types::safe::{self, State};

#[test]
fn safe_tx_hash_matches_the_safe_contract() {
    // vector from Sepolia: SafeL2 1.4.1 singleton's own getTransactionHash(0x…dEaD, 12345,
    // 0xa9059cbb00, CALL, 0, 0, 0, 0, 0, nonce 7) (eth_call, 2026-11-22); the domain is the
    // contract's own address and the chain id
    let singleton = address!("0x29fcB43b46531BcA003ddC8FCB67FFE91900C762");
    let h = safe::tx_hash(11_155_111, singleton, address!("0x000000000000000000000000000000000000dEaD"), U256::from(12345), &[0xa9, 0x05, 0x9c, 0xbb, 0x00], U256::from(7));
    assert_eq!(h, b256!("0xf1a54a96efe1ba98cae868163b5717b5383dda21a1a323062ee40fe562e186a6"));
}

fn word(a: Address) -> U256 {
    U256::from_be_slice(a.as_slice())
}

#[test]
fn safe_configuration_checks() {
    let one = address!("0x0000000000000000000000000000000000000001");
    let good = [word(safe::SINGLETONS[1]), U256::from(2), U256::from(3), word(one), word(one), U256::ZERO];
    let st = State::from_slots(&good);
    assert!(st.problems().is_empty(), "{:?}", st.problems());
    assert_eq!(st.nonce, U256::from(3));
    let bad = |i: usize, v: U256| {
        let mut s = good;
        s[i] = v;
        State::from_slots(&s).problems().join("; ")
    };
    assert!(bad(0, U256::from(0xbad)).contains("not a known Safe"));
    assert!(bad(1, U256::from(1)).contains("threshold 1"));
    assert!(bad(3, U256::ZERO).contains("not an owner"));
    assert!(bad(4, U256::from(0x1234)).contains("modules"));
    assert!(bad(5, U256::from(0x1234)).contains("guard"));
}

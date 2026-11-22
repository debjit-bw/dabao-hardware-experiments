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

// Reference encodings from `cast calldata`; the hash from the live Sepolia Safe's own
// getTransactionHash(MultiSendCallOnly, 0, <ms>, operation 1, 0, 0, 0, 0, 0, nonce 7).
mod postcondition {
    use alloy_primitives::{Address, U256, address, b256, hex};
    use sim_types::safe::*;

    const DEVICE: Address = address!("0x7813e1C142086D37060Be2335ff9Dd4EA4a2F986");
    const SAFE: Address = address!("0x265871a72567419AE2f799a1288271C09B589fd9");
    const WETH: Address = address!("0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14");
    const MS: &str = "0x8d80ff0a0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000005700000000000000000000000000000000000000dead00000000000000000000000000000000000000000000000000000000000000640000000000000000000000000000000000000000000000000000000000000002abcd000000000000000000";

    #[test]
    fn check_and_balances_calldata() {
        let assets = [Address::ZERO, WETH];
        let deltas = [U256::ZERO.wrapping_sub(U256::from(5)), U256::from(2)];
        assert_eq!(hex::encode_prefixed(check_calldata(DEVICE, U256::from(2), 9999, &assets, &deltas)), "0x64e17fcd0000000000000000000000007813e1c142086d37060be2335ff9dd4ea4a2f9860000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000270f00000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000fff9976782d46cc05630d1f6ebab18b2324d6b140000000000000000000000000000000000000000000000000000000000000002fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb0000000000000000000000000000000000000000000000000000000000000002");
        assert_eq!(hex::encode_prefixed(verify_calldata(DEVICE, U256::from(2), 9999, &assets, &[U256::from(7), U256::from(8)], &deltas)), "0x8ff52cc10000000000000000000000007813e1c142086d37060be2335ff9dd4ea4a2f9860000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000270f00000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000120000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000fff9976782d46cc05630d1f6ebab18b2324d6b140000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000700000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000002fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb0000000000000000000000000000000000000000000000000000000000000002");
        assert_eq!(hex::encode_prefixed(begin_calldata(&assets)), "0xd3102a62000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000fff9976782d46cc05630d1f6ebab18b2324d6b14");
        let b = balances_calldata(SAFE, &[Address::ZERO]);
        assert_eq!(hex::encode_prefixed(b), "0xd3e5ca87000000000000000000000000265871a72567419ae2f799a1288271c09b589fd9000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000");
    }

    #[test]
    fn multisend_roundtrip_and_hash() {
        let call = Call { to: address!("0x000000000000000000000000000000000000dEaD"), value: U256::from(100), data: vec![0xab, 0xcd] };
        let ms = multisend_calldata(core::slice::from_ref(&call));
        assert_eq!(hex::encode_prefixed(&ms), MS);
        assert_eq!(multisend_decode(&ms), Some(vec![call.clone()]));
        let two = multisend_calldata(&[call.clone(), Call { to: POSTCONDITION, value: U256::ZERO, data: vec![1; 40] }]);
        assert_eq!(multisend_decode(&two).unwrap().len(), 2);
        assert!(multisend_decode(&ms[..ms.len() - 1]).is_none());
        let mut bad = ms.clone();
        bad[68] = 1; // a DELEGATECALL inside the batch
        assert!(multisend_decode(&bad).is_none());
        assert_eq!(
            tx_hash_op(11155111, SAFE, MULTISEND_CALL_ONLY, U256::ZERO, &ms, U256::from(7), 1),
            b256!("0x912da396ece5b2b1c3b32eecee6b0575c40902841a4394efc67289554aaca08b")
        );
    }

    #[test]
    fn uint_array() {
        let mut out = vec![0u8; 128];
        out[31] = 32;
        out[63] = 2;
        out[95] = 7;
        out[127] = 9;
        assert_eq!(decode_uint_array(&out), Some(vec![U256::from(7), U256::from(9)]));
        assert!(decode_uint_array(&out[..96]).is_none());
    }
}

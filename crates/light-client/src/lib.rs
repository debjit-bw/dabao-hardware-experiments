//! Sync-committee light client pieces (Ethereum consensus spec, Altair onward), for Sepolia.
//!
//! A sync committee of 512 validators signs each beacon block header with an aggregate BLS
//! signature. Verifying one header = SSZ `hash_tree_root` of the header, the signing domain
//! (fork version at the signature slot, genesis validators root), aggregating the
//! participants' public keys, hashing the signing root to G2, and one pairing check:
//! `e(agg_pk, H(m)) == e(g1, sig)`.
//!
//! BLS12-381 is arkworks (`ark-bls12-381`), which revm's EIP-2537 precompiles already pull
//! into the firmware; no C dependencies.

use alloy_primitives::{B256, Bytes};
use alloy_rlp::{RlpDecodable, RlpEncodable};
use ark_bls12_381::{Bls12_381, G1Affine, G1Projective, G2Affine, G2Projective, g2};
use ark_ec::{
    AffineRepr, CurveGroup,
    hashing::{HashToCurve, curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher},
    pairing::Pairing,
};
use ark_ff::{Zero, field_hashers::DefaultFieldHasher};
use ark_serialize::CanonicalDeserialize;
use sha2::{Digest, Sha256};

pub const SYNC_COMMITTEE_SIZE: usize = 512;
pub const SLOTS_PER_EPOCH: u64 = 32;
pub const EPOCHS_PER_SYNC_COMMITTEE_PERIOD: u64 = 256;
pub const DOMAIN_SYNC_COMMITTEE: [u8; 4] = [7, 0, 0, 0];
/// Ethereum's BLS ciphersuite (proof-of-possession scheme, signatures in G2).
pub const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Sepolia: genesis validators root and fork schedule (epoch, version), from the beacon API's
/// /eth/v1/beacon/genesis and /eth/v1/config/fork_schedule (2026-11-22).
pub mod sepolia {
    use alloy_primitives::{B256, b256};
    pub const GENESIS_VALIDATORS_ROOT: B256 = b256!("0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078");
    pub const FORKS: [(u64, [u8; 4]); 8] = [
        (0, [0x90, 0, 0, 0x69]),
        (50, [0x90, 0, 0, 0x70]),      // Altair
        (100, [0x90, 0, 0, 0x71]),     // Bellatrix
        (56832, [0x90, 0, 0, 0x72]),   // Capella
        (132608, [0x90, 0, 0, 0x73]),  // Deneb
        (222464, [0x90, 0, 0, 0x74]),  // Electra
        (272640, [0x90, 0, 0, 0x75]),  // Fulu
        (353024, [0x90, 0, 0, 0x76]),  // Gloas
    ];

    pub fn fork_version(epoch: u64) -> [u8; 4] {
        FORKS.iter().rev().find(|(e, _)| *e <= epoch).map(|(_, v)| *v).unwrap()
    }
}

fn sha(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(a);
    h.update(b);
    h.finalize().into()
}

fn u64_leaf(x: u64) -> [u8; 32] {
    let mut l = [0u8; 32];
    l[..8].copy_from_slice(&x.to_le_bytes());
    l
}

/// `BeaconBlockHeader` (phase0 container, unchanged since).
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct BeaconHeader {
    pub slot: u64,
    pub proposer_index: u64,
    pub parent_root: B256,
    pub state_root: B256,
    pub body_root: B256,
}

impl BeaconHeader {
    /// SSZ `hash_tree_root`: 5 fields padded to 8 leaves.
    pub fn hash_tree_root(&self) -> B256 {
        let z = [0u8; 32];
        let l = [u64_leaf(self.slot), u64_leaf(self.proposer_index), self.parent_root.0, self.state_root.0, self.body_root.0, z, z, z];
        let a = [sha(&l[0], &l[1]), sha(&l[2], &l[3]), sha(&l[4], &l[5]), sha(&l[6], &l[7])];
        let b = [sha(&a[0], &a[1]), sha(&a[2], &a[3])];
        B256::from(sha(&b[0], &b[1]))
    }
}

/// `compute_domain(DOMAIN_SYNC_COMMITTEE, fork_version, genesis_validators_root)`.
pub fn sync_committee_domain(fork_version: [u8; 4], genesis_validators_root: B256) -> [u8; 32] {
    let mut v = [0u8; 32];
    v[..4].copy_from_slice(&fork_version);
    let fork_data_root = sha(&v, genesis_validators_root.as_slice());
    let mut d = [0u8; 32];
    d[..4].copy_from_slice(&DOMAIN_SYNC_COMMITTEE);
    d[4..].copy_from_slice(&fork_data_root[..28]);
    d
}

/// The signing root the committee signs at `signature_slot` for `header` (Sepolia).
pub fn signing_root(header: &BeaconHeader, signature_slot: u64) -> B256 {
    // the spec takes the fork at the epoch of signature_slot - 1
    let epoch = signature_slot.max(1).saturating_sub(1) / SLOTS_PER_EPOCH;
    let domain = sync_committee_domain(sepolia::fork_version(epoch), sepolia::GENESIS_VALIDATORS_ROOT);
    B256::from(sha(header.hash_tree_root().as_slice(), &domain))
}

pub fn period(slot: u64) -> u64 {
    slot / SLOTS_PER_EPOCH / EPOCHS_PER_SYNC_COMMITTEE_PERIOD
}

/// A sync committee's public keys, decompressed and subgroup-checked once (then reusable for
/// every header of the period, ~27 h on Ethereum).
pub struct Committee {
    pub pubkeys: Vec<G1Affine>,
}

impl Committee {
    pub fn from_compressed(keys: &[Bytes]) -> Result<Committee, String> {
        if keys.len() != SYNC_COMMITTEE_SIZE {
            return Err(format!("{} keys, expected {SYNC_COMMITTEE_SIZE}", keys.len()));
        }
        let pubkeys = keys
            .iter()
            .enumerate()
            .map(|(i, k)| G1Affine::deserialize_compressed(&k[..]).map_err(|e| format!("pubkey {i}: {e}")))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Committee { pubkeys })
    }
}

/// Participants in an SSZ `Bitvector[512]` (bit i = byte i/8, bit i%8).
pub fn participants(bits: &[u8]) -> Vec<usize> {
    (0..SYNC_COMMITTEE_SIZE).filter(|i| bits.get(i / 8).is_some_and(|b| b >> (i % 8) & 1 == 1)).collect()
}

/// Timings of one verification, microseconds.
#[derive(Debug, Default, Clone, Copy)]
pub struct Timing {
    pub aggregate_us: u64,
    pub hash_to_curve_us: u64,
    pub signature_us: u64,
    pub pairing_us: u64,
}

/// Verify the committee's aggregate `signature` (96-byte compressed G2) over `root` by the
/// participants in `bits`. Requires a 2/3 supermajority (what the spec requires to update the
/// finalized header). `now` is a microsecond clock for the timings.
pub fn verify_sync_aggregate(c: &Committee, bits: &[u8], signature: &[u8], root: B256, now: &dyn Fn() -> u64) -> Result<Timing, String> {
    let mut t = Timing::default();
    let who = participants(bits);
    if who.len() * 3 < SYNC_COMMITTEE_SIZE * 2 {
        return Err(format!("only {} of {SYNC_COMMITTEE_SIZE} signed (< 2/3)", who.len()));
    }
    let t0 = now();
    let agg: G1Projective = who.iter().map(|&i| c.pubkeys[i]).fold(G1Projective::zero(), |acc, p| acc + p);
    let agg = agg.into_affine();
    let t1 = now();
    t.aggregate_us = t1 - t0;
    let hasher = MapToCurveBasedHasher::<G2Projective, DefaultFieldHasher<Sha256, 128>, WBMap<g2::Config>>::new(DST).map_err(|e| format!("hasher: {e}"))?;
    let h: G2Affine = hasher.hash(root.as_slice()).map_err(|e| format!("hash to curve: {e}"))?;
    let t2 = now();
    t.hash_to_curve_us = t2 - t1;
    let sig = G2Affine::deserialize_compressed(signature).map_err(|e| format!("signature: {e}"))?;
    let t3 = now();
    t.signature_us = t3 - t2;
    // e(agg, H(m)) * e(-g1, sig) == 1
    let ok = Bls12_381::multi_pairing([agg, -G1Affine::generator()], [h, sig]).is_zero();
    t.pairing_us = now() - t3;
    if ok { Ok(t) } else { Err("sync committee signature does not verify".into()) }
}

/// A recorded light-client update for tests and the on-device benchmark.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct Fixture {
    pub header: BeaconHeader,
    pub signature_slot: u64,
    pub bits: Bytes,
    pub signature: Bytes,
    /// The committee of `period(signature_slot)`, 48-byte compressed keys.
    pub pubkeys: Vec<Bytes>,
    /// The execution block hash the update's `execution_branch` links to the header's body.
    pub execution_block_hash: B256,
}

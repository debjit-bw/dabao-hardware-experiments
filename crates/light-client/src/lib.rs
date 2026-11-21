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
pub use sim_types::lc::{BeaconHeader, CommitteeUpdate, HeaderProof, Signed};
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

/// SSZ `hash_tree_root` of a `BeaconBlockHeader`: 5 fields padded to 8 leaves.
pub fn header_root(h: &BeaconHeader) -> B256 {
    let z = [0u8; 32];
    let l = [u64_leaf(h.slot), u64_leaf(h.proposer_index), h.parent_root.0, h.state_root.0, h.body_root.0, z, z, z];
    let a = [sha(&l[0], &l[1]), sha(&l[2], &l[3]), sha(&l[4], &l[5]), sha(&l[6], &l[7])];
    let b = [sha(&a[0], &a[1]), sha(&a[2], &a[3])];
    B256::from(sha(&b[0], &b[1]))
}

/// Generalized indices (Gloas; measured on real Sepolia proofs, 2026-11-22):
/// `current_sync_committee` / `next_sync_committee` in `BeaconState`, the execution block
/// hash in `BeaconBlockBody`.
pub const GINDEX_CURRENT_SYNC_COMMITTEE: u64 = 2945;
pub const GINDEX_NEXT_SYNC_COMMITTEE: u64 = 2946;
pub const GINDEX_EXECUTION_BLOCK_HASH: u64 = 2856;
/// The gindices above hold from Gloas on.
pub const GLOAS_EPOCH: u64 = 353_024;

/// SSZ Merkle branch: does `leaf` at generalized index `gindex` hash up to `root`?
pub fn verify_branch(leaf: B256, branch: &[B256], gindex: u64, root: B256) -> bool {
    let depth = 63 - gindex.leading_zeros() as usize;
    if branch.len() != depth {
        return false;
    }
    let mut v = leaf.0;
    for (i, s) in branch.iter().enumerate() {
        v = if gindex >> i & 1 == 1 { sha(s.as_slice(), &v) } else { sha(&v, s.as_slice()) };
    }
    B256::from(v) == root
}

fn pubkey_root(pk: &[u8]) -> [u8; 32] {
    let mut hi = [0u8; 32];
    hi[..pk.len().saturating_sub(32).min(32)].copy_from_slice(&pk[32.min(pk.len())..]);
    sha(&pk[..32.min(pk.len())], &hi)
}

/// SSZ `hash_tree_root` of a `SyncCommittee { pubkeys: Vector[BLSPubkey, 512], aggregate_pubkey }`.
pub fn committee_root(pubkeys: &[Bytes], aggregate: &[u8]) -> Result<B256, String> {
    if pubkeys.len() != SYNC_COMMITTEE_SIZE || pubkeys.iter().any(|k| k.len() != 48) || aggregate.len() != 48 {
        return Err("a sync committee is 512 keys of 48 bytes + a 48-byte aggregate".into());
    }
    let mut layer: Vec<[u8; 32]> = pubkeys.iter().map(|k| pubkey_root(k)).collect();
    while layer.len() > 1 {
        layer = layer.chunks(2).map(|p| sha(&p[0], &p[1])).collect();
    }
    Ok(B256::from(sha(&layer[0], &pubkey_root(aggregate))))
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
    B256::from(sha(header_root(header).as_slice(), &domain))
}

pub fn period(slot: u64) -> u64 {
    slot / SLOTS_PER_EPOCH / EPOCHS_PER_SYNC_COMMITTEE_PERIOD
}

/// A sync committee's public keys, decompressed once (then reusable for every header of the
/// period, ~27 h on Ethereum).
pub struct Committee {
    pub period: u64,
    pub root: B256,
    pub pubkeys: Vec<G1Affine>,
}

impl Committee {
    /// Keys uploaded by the (untrusted) host for `period`, accepted only if they hash to
    /// `expected_root` (the root the device trusts for that period). Decompressed without the
    /// subgroup check: keys committed to by a canonical beacon state were validated on deposit
    /// (with a proof of possession), and the root pins exactly those keys.
    pub fn load(c: &sim_types::lc::Committee, expected_root: B256) -> Result<Committee, String> {
        let root = committee_root(&c.pubkeys, &c.aggregate)?;
        if root != expected_root {
            return Err(format!("committee for period {} hashes to {root}, expected {expected_root}", c.period));
        }
        let pubkeys = c
            .pubkeys
            .iter()
            .enumerate()
            .map(|(i, k)| G1Affine::deserialize_compressed_unchecked(&k[..]).map_err(|e| format!("pubkey {i}: {e}")))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Committee { period: c.period, root, pubkeys })
    }

    pub fn from_compressed(keys: &[Bytes]) -> Result<Committee, String> {
        if keys.len() != SYNC_COMMITTEE_SIZE {
            return Err(format!("{} keys, expected {SYNC_COMMITTEE_SIZE}", keys.len()));
        }
        let pubkeys = keys
            .iter()
            .enumerate()
            .map(|(i, k)| G1Affine::deserialize_compressed(&k[..]).map_err(|e| format!("pubkey {i}: {e}")))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Committee { period: u64::MAX, root: B256::ZERO, pubkeys })
    }
}

/// Check `s` is signed by `c` (the committee of `period(s.signature_slot)`, 2/3 participation),
/// with the attested header no later than the signature slot and from Gloas on.
pub fn verify_signed(c: &Committee, s: &Signed, now: &dyn Fn() -> u64) -> Result<Timing, String> {
    if period(s.signature_slot) != c.period {
        return Err(format!("signed in period {}, the device has the committee of period {}", period(s.signature_slot), c.period));
    }
    if s.attested.slot >= s.signature_slot {
        return Err("attested header not before its signature slot".into());
    }
    if s.attested.slot / SLOTS_PER_EPOCH < GLOAS_EPOCH {
        return Err("pre-Gloas header (proof layout not supported)".into());
    }
    verify_sync_aggregate(c, &s.bits, &s.signature, signing_root(&s.attested, s.signature_slot), now)
}

/// A header proof: the execution block hash it proves canonical (signed by the committee,
/// committed to by the signed header's body).
pub fn verify_header_proof(c: &Committee, p: &HeaderProof, now: &dyn Fn() -> u64) -> Result<Timing, String> {
    let t = verify_signed(c, &p.signed, now)?;
    if !verify_branch(p.execution_block_hash, &p.execution_branch, GINDEX_EXECUTION_BLOCK_HASH, p.signed.attested.body_root) {
        return Err("execution block hash not in the signed header's body".into());
    }
    Ok(t)
}

/// A committee hand-off: returns the next period's committee root if `u` is signed by `c`
/// and proves `u.next` into the attested state, with the attested header in `c`'s period.
pub fn verify_update(c: &Committee, u: &CommitteeUpdate, now: &dyn Fn() -> u64) -> Result<B256, String> {
    if period(u.signed.attested.slot) != c.period || u.next.period != c.period + 1 {
        return Err(format!("update for period {} -> {}, device is at {}", period(u.signed.attested.slot), u.next.period, c.period));
    }
    verify_signed(c, &u.signed, now)?;
    let next = committee_root(&u.next.pubkeys, &u.next.aggregate)?;
    if !verify_branch(next, &u.next_branch, GINDEX_NEXT_SYNC_COMMITTEE, u.signed.attested.state_root) {
        return Err("next sync committee not in the signed header's state".into());
    }
    Ok(next)
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
pub mod anchor;

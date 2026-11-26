//! The light client's state in the verifier.
//!
//! RRAM (app slots 208..210, kept by the signer): slot 0 = the trusted committee root, slot 1 =
//! `"DLC1" || period (u64 BE) || highest verified slot (u64 BE)`. Empty (first boot), or older
//! than the firmware's anchor (`light_client::anchor`): start from the anchor.
//! RAM: the trusted committee's keys, decompressed, once the host uploads them (per boot).
//!
//! Everything the host sends is checked: an uploaded committee must hash to the stored root, a
//! hand-off must be signed by the current committee and prove the next one into the signed
//! state, a header proof must be signed by the current committee, prove the execution block
//! hash into the signed body, and not be older than the highest slot already verified.

use alloy_primitives::B256;
use light_client::{Committee, anchor};
use sim_types::lc::{CommitteeUpdate, HeaderProof, Status};

const MAGIC: &[u8; 4] = b"DLC1";

pub struct LightClient {
    slots: crate::slots::Slots,
    period: u64,
    root: B256,
    highest_slot: u64,
    committee: Option<Committee>,
}

fn now() -> u64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    START.get_or_init(std::time::Instant::now).elapsed().as_micros() as u64
}

impl LightClient {
    pub fn open(token: Option<crate::slots::Token>) -> LightClient {
        let mut slots = crate::slots::Slots::open(sim_types::ipc::LC_SLOTS, "light client", token);
        let (mut period, mut root, mut highest) = (anchor::PERIOD, anchor::COMMITTEE_ROOT, anchor::CHECKPOINT_SLOT);
        if let (Some(r), Some(m)) = (slots.read(0), slots.read(1)) {
            let p = u64::from_be_bytes(m[4..12].try_into().unwrap());
            if &m[..4] == MAGIC && p >= anchor::PERIOD {
                period = p;
                root = B256::from(r);
                highest = u64::from_be_bytes(m[12..20].try_into().unwrap()).max(highest);
            }
        }
        if !slots.ok {
            log::error!("light client slots unavailable: headers can't be verified");
        }
        log::info!("light client: period {period}, committee root {root}, highest slot {highest}");
        LightClient { slots, period, root, highest_slot: highest, committee: None }
    }

    fn persist(&mut self) -> bool {
        let mut m = [0u8; 32];
        m[..4].copy_from_slice(MAGIC);
        m[4..12].copy_from_slice(&self.period.to_be_bytes());
        m[12..20].copy_from_slice(&self.highest_slot.to_be_bytes());
        // root first, then the header with the period: a cut in between leaves the old period
        // with a new root, which then fails to verify (fail closed) rather than trusting a mix
        self.slots.ok && self.slots.write(0, &self.root.0) && self.slots.write(1, &m)
    }

    pub fn status(&self, note: impl Into<String>) -> Status {
        Status {
            period: self.period,
            committee_root: self.root,
            loaded: self.committee.is_some(),
            highest_slot: self.highest_slot,
            note: note.into().into_bytes().into(),
        }
    }

    /// The host uploads the keys of the trusted committee.
    pub fn load(&mut self, c: &sim_types::lc::Committee) -> Status {
        if c.period != self.period {
            return self.status(format!("committee for period {}, the device trusts period {}", c.period, self.period));
        }
        let t = now();
        match Committee::load(c, self.root) {
            Ok(k) => {
                self.committee = Some(k);
                log::info!("light client: committee of period {} loaded in {} ms", self.period, (now() - t) / 1000);
                self.status(format!("loaded in {} ms", (now() - t) / 1000))
            }
            Err(e) => self.status(e),
        }
    }

    /// Hand off to the next period.
    pub fn update(&mut self, u: &CommitteeUpdate) -> Status {
        let Some(c) = &self.committee else { return self.status("upload the current committee first") };
        let t = now();
        let next_root = match light_client::verify_update(c, u, &now) {
            Ok(r) => r,
            Err(e) => return self.status(e),
        };
        let next = match Committee::load(&u.next, next_root) {
            Ok(k) => k,
            Err(e) => return self.status(e),
        };
        let (old_p, old_r) = (self.period, self.root);
        self.period = u.next.period;
        self.root = next_root;
        self.highest_slot = self.highest_slot.max(u.signed.attested.slot);
        if !self.persist() {
            (self.period, self.root) = (old_p, old_r);
            return self.status("can't persist the new committee root");
        }
        self.committee = Some(next);
        log::info!("light client: moved to period {} ({next_root}) in {} ms", self.period, (now() - t) / 1000);
        self.status(format!("moved to period {} in {} ms", self.period, (now() - t) / 1000))
    }

    /// Check that `parent_hash` (keccak of the RLP execution header the simulation runs on) is
    /// proven canonical by `p`. Returns the attested beacon slot (for [`Self::ratchet`]).
    pub fn check(&self, p: &HeaderProof, parent_hash: B256) -> Result<u64, String> {
        let Some(c) = &self.committee else { return Err("the device has no sync committee loaded (run `dabao-host lc-sync`)".into()) };
        if p.signed.attested.slot < self.highest_slot {
            return Err(format!("header slot {} is older than the newest verified ({})", p.signed.attested.slot, self.highest_slot));
        }
        if p.execution_block_hash != parent_hash {
            return Err(format!("the proof is for execution block {}, the input's parent header is {parent_hash}", p.execution_block_hash));
        }
        let t = light_client::verify_header_proof(c, p, &now)?;
        log::info!(
            "light client: slot {} verified (aggregate {} ms, hash {} ms, pairing {} ms)",
            p.signed.attested.slot,
            t.aggregate_us / 1000,
            t.hash_to_curve_us / 1000,
            t.pairing_us / 1000
        );
        Ok(p.signed.attested.slot)
    }

    /// After signing on a header of `slot`: never accept an older one again.
    pub fn ratchet(&mut self, slot: u64) -> bool {
        if slot <= self.highest_slot {
            return true;
        }
        let old = self.highest_slot;
        self.highest_slot = slot;
        if self.persist() {
            true
        } else {
            self.highest_slot = old;
            false
        }
    }
}

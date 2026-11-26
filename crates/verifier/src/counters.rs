//! Persistent daily-spending counters for the policy: one 32-byte app slot per limit, slots
//! `ipc::COUNTER_SLOTS` (176..208), kept by the signer (`crate::slots`). Opened at boot, before
//! the verifier registers its server, so before any host input. Other users of app slots:
//! BIO 0..123, eth-burner 132..134, signer 160..162.
//!
//! Fail closed: if the slots are unavailable or a read fails, `Counters::ok()` is false and the verifier refuses
//! to sign (spending can't be limited without knowing what was spent). A failed write refuses
//! the transaction being signed.

use policy::{Counter, MAX_LIMITS, Policy, counter_id};

pub struct Counters {
    store: crate::slots::Slots,
    pub values: Vec<Counter>,
    ok: bool,
}

impl Counters {
    pub fn open(p: &Policy, token: Option<crate::slots::Token>) -> Counters {
        const _: () = assert!(sim_types::ipc::COUNTER_SLOTS.end - sim_types::ipc::COUNTER_SLOTS.start == MAX_LIMITS);
        let mut store = crate::slots::Slots::open(sim_types::ipc::COUNTER_SLOTS, "policy counters", token);
        let mut ok = store.ok;
        let mut values = Vec::new();
        for (i, chain, l) in p.limits() {
            let id = counter_id(chain, l.asset);
            let slot = if ok { store.read(i) } else { None };
            if slot.is_none() {
                ok = false;
            }
            values.push(Counter::decode(&slot.unwrap_or([0; 32]), id));
        }
        if !ok {
            log::error!("policy counters unreadable: signing disabled");
        } else {
            log::info!("policy counters: {} loaded", values.len());
        }
        Counters { store, values, ok }
    }

    pub fn ok(&self) -> bool {
        self.ok
    }

    /// Persist `updates` (all or nothing as far as the caller is concerned: any failure means
    /// the transaction must not be signed). Written before signing, so a crash in between
    /// over-counts, never under-counts.
    pub fn commit(&mut self, updates: &[(usize, Counter)]) -> Result<(), String> {
        for (i, c) in updates {
            if *i >= MAX_LIMITS || !self.store.write(*i, &c.encode()) {
                self.ok = false;
                return Err(format!("can't persist policy counter {i}"));
            }
            self.values[*i] = *c;
        }
        Ok(())
    }
}


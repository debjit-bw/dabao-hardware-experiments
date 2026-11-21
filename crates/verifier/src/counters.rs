//! Persistent daily-spending counters for the policy: one 32-byte keystore app slot per limit
//! (device), or a host file (emulator).
//!
//! Device: slots `BASE..BASE + policy::MAX_LIMITS` (176..208), claimed with our keystore patch
//! (`AppKey::Claim`, docs/keystore-slot-claims.md) at boot, before the verifier registers its
//! server, so the claim precedes any host input. Other users of app slots: BIO 0..123,
//! eth-burner 132..134, signer 160..162.
//!
//! Fail closed: if the claim or a read fails, `Counters::ok()` is false and the verifier refuses
//! to sign (spending can't be limited without knowing what was spent). A failed write refuses
//! the transaction being signed.

use policy::{Counter, MAX_LIMITS, Policy, counter_id};

pub struct Counters {
    store: Store,
    pub values: Vec<Counter>,
    ok: bool,
}

impl Counters {
    pub fn open(p: &Policy) -> Counters {
        let mut store = Store::open();
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

#[cfg(all(target_os = "xous", feature = "board-dabao"))]
struct Store {
    cid: xous::CID,
    ok: bool,
}

#[cfg(all(target_os = "xous", feature = "board-dabao"))]
impl Store {
    const BASE: usize = 176;

    fn open() -> Store {
        use keystore_api::{APPKEY_GUARD, AppKey};
        let xns = xous_names::XousNames::new().unwrap();
        let cid = xns.request_connection_blocking(keystore_api::SERVER_NAME_KEYS).expect("keystore");
        let mut s = Store { cid, ok: true };
        match s.call(AppKey::Claim { guard: APPKEY_GUARD, start: Self::BASE, len: MAX_LIMITS }) {
            AppKey::Success => log::info!("claimed keystore app slots {}..{} (policy counters)", Self::BASE, Self::BASE + MAX_LIMITS),
            e => {
                log::error!("can't claim keystore app slots {}..{}: {e:?}", Self::BASE, Self::BASE + MAX_LIMITS);
                s.ok = false;
            }
        }
        s
    }

    fn call(&self, op: keystore_api::AppKey) -> keystore_api::AppKey {
        use keystore_api::AppKey;
        let Ok(mut buf) = xous_ipc::Buffer::into_buf(op) else { return AppKey::InternalError };
        if buf.lend_mut(self.cid, keystore_api::Opcode::AppKeyOp as u32).is_err() {
            return AppKey::InternalError;
        }
        buf.to_original::<AppKey, _>().unwrap_or(AppKey::InternalError)
    }

    fn read(&mut self, i: usize) -> Option<[u8; 32]> {
        use keystore_api::{APPKEY_GUARD, AppKey};
        match self.call(AppKey::ReadRequest { guard: APPKEY_GUARD, index: Self::BASE + i }) {
            AppKey::ReadResponse { data } => Some(data),
            e => {
                log::error!("policy counter {i}: read {e:?}");
                None
            }
        }
    }

    fn write(&mut self, i: usize, data: &[u8; 32]) -> bool {
        use keystore_api::{APPKEY_GUARD, AppKey};
        matches!(self.call(AppKey::Write { guard: APPKEY_GUARD, index: Self::BASE + i, data: *data }), AppKey::Success)
    }
}

/// Emulator: `DABAO_POLICY_COUNTERS` or `target/dabao-policy-counters.bin` in this crate.
#[cfg(not(all(target_os = "xous", feature = "board-dabao")))]
struct Store {
    path: std::path::PathBuf,
    ok: bool,
}

#[cfg(not(all(target_os = "xous", feature = "board-dabao")))]
impl Store {
    fn open() -> Store {
        let path = std::env::var_os("DABAO_POLICY_COUNTERS")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/dabao-policy-counters.bin"));
        log::info!("emulated policy counters: {path:?}");
        Store { path, ok: true }
    }

    fn load(&self) -> Vec<u8> {
        std::fs::read(&self.path).ok().filter(|d| d.len() == 32 * MAX_LIMITS).unwrap_or_else(|| vec![0; 32 * MAX_LIMITS])
    }

    fn read(&mut self, i: usize) -> Option<[u8; 32]> {
        self.load()[32 * i..32 * i + 32].try_into().ok()
    }

    fn write(&mut self, i: usize, data: &[u8; 32]) -> bool {
        let mut d = self.load();
        d[32 * i..32 * i + 32].copy_from_slice(data);
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).ok();
        }
        std::fs::write(&self.path, d).is_ok()
    }
}

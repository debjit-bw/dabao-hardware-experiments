//! Claimed keystore app slots (32 bytes each, RRAM) on the device, or a host file (emulator).
//!
//! Device: `base..base + len` claimed with our keystore patch (`AppKey::Claim`,
//! docs/keystore-slot-claims.md) at boot, before the verifier registers its server, so the
//! claim precedes any host input. Ranges in use: BIO 0..123, eth-burner 132..134, signer
//! 160..162, policy counters 176..208, light client 208..210.

pub struct Slots {
    #[cfg(all(target_os = "xous", feature = "board-dabao"))]
    cid: xous::CID,
    #[cfg(not(all(target_os = "xous", feature = "board-dabao")))]
    path: std::path::PathBuf,
    base: usize,
    len: usize,
    /// The claim succeeded (device) / storage is usable.
    pub ok: bool,
}

#[cfg(all(target_os = "xous", feature = "board-dabao"))]
impl Slots {
    pub fn open(base: usize, len: usize, what: &str) -> Slots {
        use keystore_api::{APPKEY_GUARD, AppKey};
        let xns = xous_names::XousNames::new().unwrap();
        let cid = xns.request_connection_blocking(keystore_api::SERVER_NAME_KEYS).expect("keystore");
        let mut s = Slots { cid, base, len, ok: true };
        match s.call(AppKey::Claim { guard: APPKEY_GUARD, start: base, len }) {
            AppKey::Success => log::info!("claimed keystore app slots {base}..{} ({what})", base + len),
            e => {
                log::error!("can't claim keystore app slots {base}..{} ({what}): {e:?}", base + len);
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

    pub fn read(&mut self, i: usize) -> Option<[u8; 32]> {
        use keystore_api::{APPKEY_GUARD, AppKey};
        if i >= self.len {
            return None;
        }
        match self.call(AppKey::ReadRequest { guard: APPKEY_GUARD, index: self.base + i }) {
            AppKey::ReadResponse { data } => Some(data),
            e => {
                log::error!("app slot {}: read {e:?}", self.base + i);
                None
            }
        }
    }

    pub fn write(&mut self, i: usize, data: &[u8; 32]) -> bool {
        use keystore_api::{APPKEY_GUARD, AppKey};
        i < self.len && matches!(self.call(AppKey::Write { guard: APPKEY_GUARD, index: self.base + i, data: *data }), AppKey::Success)
    }
}

/// Emulator: `target/dabao-slots-<base>.bin` in this crate (or `$DABAO_SLOTS_DIR`).
#[cfg(not(all(target_os = "xous", feature = "board-dabao")))]
impl Slots {
    pub fn open(base: usize, len: usize, what: &str) -> Slots {
        let dir = std::env::var_os("DABAO_SLOTS_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target"));
        let path = dir.join(format!("dabao-slots-{base}.bin"));
        log::info!("emulated app slots {base}..{} ({what}): {path:?}", base + len);
        Slots { path, base, len, ok: true }
    }

    fn load(&self) -> Vec<u8> {
        std::fs::read(&self.path).ok().filter(|d| d.len() == 32 * self.len).unwrap_or_else(|| vec![0; 32 * self.len])
    }

    pub fn read(&mut self, i: usize) -> Option<[u8; 32]> {
        let _ = self.base;
        (i < self.len).then(|| self.load()[32 * i..32 * i + 32].try_into().unwrap())
    }

    pub fn write(&mut self, i: usize, data: &[u8; 32]) -> bool {
        if i >= self.len {
            return false;
        }
        let mut d = self.load();
        d[32 * i..32 * i + 32].copy_from_slice(data);
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).ok();
        }
        std::fs::write(&self.path, d).is_ok()
    }
}

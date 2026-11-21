//! Key storage: two 32-byte keystore app slots (device) or a host file (emulator).
//! * slot 0: the secp256k1 secret key;
//! * slot 1: `MAGIC` and the first 24 bytes of SHA-256(key), written last, so a key is only
//!   used once it is completely stored.
//!
//! Caveat (dabao): the keystore registers with unlimited connections and doesn't check the
//! caller, so any process can read app slots. See PROGRESS.md / the keystore-claim plan.

use k256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"DABAOSG1";
type Slot = [u8; 32];

trait Slots {
    fn read(&mut self, i: usize) -> Option<Slot>;
    fn write(&mut self, i: usize, data: &Slot) -> bool;
}

/// Keystore application slots (`AppKeyOp`). BIO uses 0..123, eth-burner 132..133.
#[cfg(target_os = "xous")]
struct Keystore(xous::CID);

#[cfg(target_os = "xous")]
impl Keystore {
    const BASE: usize = 160;

    fn open() -> Self {
        let xns = xous_names::XousNames::new().unwrap();
        Keystore(xns.request_connection_blocking(keystore_api::SERVER_NAME_KEYS).expect("keystore"))
    }

    fn call(&self, op: keystore_api::AppKey) -> keystore_api::AppKey {
        use keystore_api::AppKey;
        let Ok(mut buf) = xous_ipc::Buffer::into_buf(op) else { return AppKey::InternalError };
        if buf.lend_mut(self.0, keystore_api::Opcode::AppKeyOp as u32).is_err() {
            return AppKey::InternalError;
        }
        buf.to_original::<AppKey, _>().unwrap_or(AppKey::InternalError)
    }
}

#[cfg(target_os = "xous")]
impl Slots for Keystore {
    fn read(&mut self, i: usize) -> Option<Slot> {
        use keystore_api::{APPKEY_GUARD, AppKey};
        match self.call(AppKey::ReadRequest { guard: APPKEY_GUARD, index: Self::BASE + i }) {
            AppKey::ReadResponse { data } => Some(data),
            e => {
                log::error!("keystore read: {e:?}");
                None
            }
        }
    }
    fn write(&mut self, i: usize, data: &Slot) -> bool {
        use keystore_api::{APPKEY_GUARD, AppKey};
        matches!(self.call(AppKey::Write { guard: APPKEY_GUARD, index: Self::BASE + i, data: *data }), AppKey::Success)
    }
}

/// Emulator: `DABAO_SIGNER_KEY` or `target/dabao-signer-key.bin` in this crate. Not secret.
#[cfg(not(target_os = "xous"))]
struct HostFile(std::path::PathBuf);

#[cfg(not(target_os = "xous"))]
impl HostFile {
    fn open() -> Self {
        let path = std::env::var_os("DABAO_SIGNER_KEY")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/dabao-signer-key.bin"));
        log::info!("emulated key storage: {path:?} (not secret)");
        HostFile(path)
    }
}

#[cfg(not(target_os = "xous"))]
impl Slots for HostFile {
    fn read(&mut self, i: usize) -> Option<Slot> {
        match std::fs::read(&self.0) {
            Ok(d) if d.len() == 64 => d[32 * i..32 * i + 32].try_into().ok(),
            _ => Some([0; 32]),
        }
    }
    fn write(&mut self, i: usize, data: &Slot) -> bool {
        let mut d = std::fs::read(&self.0).ok().filter(|d| d.len() == 64).unwrap_or_else(|| vec![0; 64]);
        d[32 * i..32 * i + 32].copy_from_slice(data);
        if let Some(dir) = self.0.parent() {
            std::fs::create_dir_all(dir).ok();
        }
        std::fs::write(&self.0, d).is_ok()
    }
}

fn header(key: &Slot) -> Slot {
    let mut h = [0u8; 32];
    h[..8].copy_from_slice(MAGIC);
    h[8..].copy_from_slice(&Sha256::digest(key)[..24]);
    h
}

fn load(slots: &mut impl Slots) -> Option<SigningKey> {
    let h = slots.read(1)?;
    if &h[..8] != MAGIC {
        return None;
    }
    let k = Zeroizing::new(slots.read(0)?);
    if header(&k) != h {
        return None;
    }
    SigningKey::from_slice(&k[..]).ok()
}

/// 32 bytes from the TRNG (`getrandom`) and the kernel's entropy pool, mixed with SHA-256.
fn fresh_key() -> Zeroizing<Slot> {
    loop {
        let mut pool = Zeroizing::new([0u8; 64]);
        getrandom::getrandom(&mut pool[..32]).expect("TRNG");
        for chunk in pool[32..].chunks_mut(16) {
            let id = xous::create_server_id().expect("kernel entropy").to_array();
            for (j, w) in id.iter().enumerate() {
                chunk[4 * j..4 * j + 4].copy_from_slice(&w.to_le_bytes());
            }
        }
        let mut h = Sha256::new();
        h.update(b"dabao-signer/v1");
        h.update(&pool[..]);
        let k: Zeroizing<Slot> = Zeroizing::new(h.finalize().into());
        if SigningKey::from_slice(&k[..]).is_ok() {
            return k; // else: not a valid scalar (probability ~2^-128), draw again
        }
    }
}

pub fn load_or_create_key() -> SigningKey {
    #[cfg(target_os = "xous")]
    let mut slots = Keystore::open();
    #[cfg(not(target_os = "xous"))]
    let mut slots = HostFile::open();
    if let Some(k) = load(&mut slots) {
        log::info!("signing key loaded");
        return k;
    }
    let k = fresh_key();
    // key first, header last: a power cut in between leaves no key
    if !(slots.write(0, &k) && slots.write(1, &header(&k))) {
        panic!("can't store the signing key");
    }
    let loaded = load(&mut slots).expect("the signing key doesn't read back");
    log::info!("new signing key created and stored");
    loaded
}

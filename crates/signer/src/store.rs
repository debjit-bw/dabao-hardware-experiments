//! Adapted from btchip/ethereum-app dabao-app-eth-burner (MIT OR Apache-2.0), with changes:
//! the key storage.
//!
//! Key storage: two 32-byte keystore app slots (device) or a host file (emulator).
//! * slot 0: the secp256k1 secret key;
//! * slot 1: `MAGIC` and the first 24 bytes of SHA-256(key), written last, so a key is only
//!   used once it is completely stored.
//!
//! Isolation (device): stock dabao keystore lets any process read any app slot. Our keystore
//! patch (vendor/xous-core top commit, docs/keystore-slot-claims.md) adds
//! `AppKey::Claim`: the first process to claim a slot range owns it until reboot. The signer
//! claims its two slots before touching them and refuses to run if the claim fails. The
//! transport reads no host input until the signer is attached, so the claim always comes
//! before any untrusted input is processed.

use k256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

// DO NOT CHANGE the slot layout (BASE, LEN, MAGIC, header format): the key stored here is the
// project's persistent, funded testnet account (board address
// 0x7813e1C142086D37060Be2335ff9Dd4EA4a2F986). Changing it makes the signer look in the wrong
// place and create a new key; the old one would still be in RRAM but unused.
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
    const LEN: usize = 2;

    /// Connect and claim our slots. Panics if the claim is refused: then another process
    /// owns (and may have read or replaced) them, and the key must not be used.
    fn open() -> Self {
        use keystore_api::{APPKEY_GUARD, AppKey};
        let xns = xous_names::XousNames::new().unwrap();
        let ks = Keystore(xns.request_connection_blocking(keystore_api::SERVER_NAME_KEYS).expect("keystore"));
        match ks.call(AppKey::Claim { guard: APPKEY_GUARD, start: Self::BASE, len: Self::LEN }) {
            AppKey::Success => log::info!("claimed keystore app slots {}..{}", Self::BASE, Self::BASE + Self::LEN),
            e => panic!("can't claim keystore app slots {}..{}: {e:?}", Self::BASE, Self::BASE + Self::LEN),
        }
        ks
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

/// What the slots hold.
enum Stored {
    /// No header: a fresh device, or a first-boot write cut before the header (that key was
    /// never used). Safe to create a key.
    Empty,
    Key(SigningKey),
}

/// Never returns `Empty` for an existing key: a read error, a header that doesn't match the
/// key, or an invalid key is an error, so a transient fault can't make the signer overwrite
/// (and lose) the stored key.
fn load(slots: &mut impl Slots) -> Result<Stored, &'static str> {
    let h = slots.read(1).ok_or("can't read the key header slot")?;
    if &h[..8] != MAGIC {
        return Ok(Stored::Empty);
    }
    let k = Zeroizing::new(slots.read(0).ok_or("can't read the key slot")?);
    if header(&k) != h {
        return Err("key slot doesn't match its header (corrupted?)");
    }
    SigningKey::from_slice(&k[..]).map(Stored::Key).map_err(|_| "stored key is not a valid secp256k1 scalar")
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
    match load(&mut slots) {
        Ok(Stored::Key(k)) => {
            log::info!("signing key loaded");
            return k;
        }
        Ok(Stored::Empty) => {}
        // refuse to run rather than replace a key we failed to read
        Err(e) => panic!("signing key present but unusable: {e}; refusing to create a new one"),
    }
    let k = fresh_key();
    // key first, header last: a power cut in between leaves no header (-> Empty next boot)
    if !(slots.write(0, &k) && slots.write(1, &header(&k))) {
        panic!("can't store the signing key");
    }
    let loaded = match load(&mut slots) {
        Ok(Stored::Key(k)) => k,
        _ => panic!("the signing key doesn't read back"),
    };
    log::info!("new signing key created and stored");
    loaded
}

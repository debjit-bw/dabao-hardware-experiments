//! Adapted from btchip/ethereum-app dabao-app-eth-burner (MIT OR Apache-2.0), with changes:
//! the key storage.
//!
//! Persistent storage: 32-byte RRAM app slots (device) or host files (emulator).
//! * slots 160..162, the key: slot 160 holds the secp256k1 secret key; slot 161 `MAGIC` and the
//!   first 24 bytes of SHA-256(key), written last, so a key is only used once it is completely
//!   stored. Never served to anyone.
//! * `ipc::VERIFIER_SLOTS` (176..210): the verifier's policy counters and light-client state,
//!   served to it by `crate::serve_slots`.
//!
//! Isolation (device): the signer is PID 3, in place of the keystore (fork xtask
//! `--trusted-service`), so there is no keystore and no keystore patch. The signer maps the
//! RRAM data-slot region, its access-control region and the RRAM controller itself, at
//! startup; the kernel gives each physical page to one process only, so no other process can
//! map them afterwards. The slots are "open" (no hardware owner), so it's page ownership that
//! protects them, as before; PID 3 is also the one process the RRAM hardware treats as the
//! trusted user. Index mapping: app slot `i` is data slot `APPLICATION.base + i`, as in the
//! keystore's `read_app_key` / `write_app_key`, so the key is found where the keystore kept it.

use k256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

// DO NOT CHANGE the slot layout (KEY_BASE, MAGIC, header format): the key stored here is the
// project's persistent, funded testnet account (board address
// 0x7813e1C142086D37060Be2335ff9Dd4EA4a2F986). Changing it makes the signer look in the wrong
// place and create a new key; the old one would still be in RRAM but unused.
const MAGIC: &[u8; 8] = b"DABAOSG1";
pub const KEY_BASE: usize = 160;
pub const KEY_SLOTS: core::ops::Range<usize> = KEY_BASE..KEY_BASE + 2;
pub type Slot = [u8; 32];

/// App slots by absolute index.
pub trait Slots {
    fn read(&mut self, index: usize) -> Option<Slot>;
    fn write(&mut self, index: usize, data: &Slot) -> bool;
}

/// The RRAM app slots, mapped directly (we are PID 3; nobody else maps them).
#[cfg(target_os = "xous")]
pub struct Rram {
    mgr: bao1x_hal::acram::SlotManager,
    rram: core::pin::Pin<Box<bao1x_hal::rram::Reram>>,
}

#[cfg(target_os = "xous")]
impl Rram {
    /// Maps the RRAM controller, the data slots and their ACLs. Panics if any mapping fails:
    /// then another process holds one of them.
    pub fn open() -> Rram {
        let mut rram = bao1x_hal::rram::Reram::new();
        let mgr = bao1x_hal::acram::SlotManager::new();
        mgr.register_mapping(&mut rram);
        Rram { mgr, rram }
    }

    fn slot(index: usize) -> Option<bao1x_api::SlotIndex> {
        use bao1x_api::{APPLICATION, PartitionAccess, RwPerms, SlotIndex};
        (index < APPLICATION.len())
            .then(|| SlotIndex::Data(APPLICATION.get_base() + index, PartitionAccess::Open, RwPerms::ReadWrite))
    }
}

#[cfg(target_os = "xous")]
impl Slots for Rram {
    fn read(&mut self, index: usize) -> Option<Slot> {
        match self.mgr.read(&Self::slot(index)?) {
            Ok(d) => d.try_into().ok(),
            Err(e) => {
                log::error!("app slot {index}: read {e:?}");
                None
            }
        }
    }
    fn write(&mut self, index: usize, data: &Slot) -> bool {
        let Some(slot) = Self::slot(index) else { return false };
        match self.mgr.write(&mut self.rram, &slot, data) {
            Ok(()) => true,
            Err(e) => {
                log::error!("app slot {index}: write {e:?}");
                false
            }
        }
    }
}

/// Emulator: the key in `DABAO_SIGNER_KEY` (default `target/dabao-signer-key.bin` in this
/// crate); other slots in `$DABAO_SLOTS_DIR/dabao-slots-<range start>.bin` (default: this
/// crate's `target/`), one file per range of `ipc::VERIFIER_SLOTS`. Not secret.
#[cfg(not(target_os = "xous"))]
pub struct HostFiles {
    key: std::path::PathBuf,
    dir: std::path::PathBuf,
}

#[cfg(not(target_os = "xous"))]
impl HostFiles {
    pub fn open() -> HostFiles {
        let target = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target");
        let key = std::env::var_os("DABAO_SIGNER_KEY").map(std::path::PathBuf::from).unwrap_or_else(|| target.join("dabao-signer-key.bin"));
        let dir = std::env::var_os("DABAO_SLOTS_DIR").map(std::path::PathBuf::from).unwrap_or(target);
        log::info!("emulated slots: key {key:?}, others in {dir:?} (not secret)");
        HostFiles { key, dir }
    }

    /// (file, slot count, position) for an absolute index.
    fn locate(&self, index: usize) -> Option<(std::path::PathBuf, usize, usize)> {
        use sim_types::ipc::{COUNTER_SLOTS, LC_SLOTS};
        [(KEY_SLOTS, None), (COUNTER_SLOTS, Some(COUNTER_SLOTS.start)), (LC_SLOTS, Some(LC_SLOTS.start))]
            .into_iter()
            .find(|(r, _)| r.contains(&index))
            .map(|(r, f)| {
                let path = match f {
                    None => self.key.clone(),
                    Some(base) => self.dir.join(format!("dabao-slots-{base}.bin")),
                };
                (path, r.len(), index - r.start)
            })
    }
}

#[cfg(not(target_os = "xous"))]
impl Slots for HostFiles {
    fn read(&mut self, index: usize) -> Option<Slot> {
        let (path, n, i) = self.locate(index)?;
        let d = std::fs::read(&path).ok().filter(|d| d.len() == 32 * n).unwrap_or_else(|| vec![0; 32 * n]);
        d[32 * i..32 * i + 32].try_into().ok()
    }
    fn write(&mut self, index: usize, data: &Slot) -> bool {
        let Some((path, n, i)) = self.locate(index) else { return false };
        let mut d = std::fs::read(&path).ok().filter(|d| d.len() == 32 * n).unwrap_or_else(|| vec![0; 32 * n]);
        d[32 * i..32 * i + 32].copy_from_slice(data);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).ok();
        }
        std::fs::write(&path, d).is_ok()
    }
}

#[cfg(target_os = "xous")]
pub fn open() -> Rram {
    Rram::open()
}
#[cfg(not(target_os = "xous"))]
pub fn open() -> HostFiles {
    HostFiles::open()
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
    let h = slots.read(KEY_BASE + 1).ok_or("can't read the key header slot")?;
    if &h[..8] != MAGIC {
        return Ok(Stored::Empty);
    }
    let k = Zeroizing::new(slots.read(KEY_BASE).ok_or("can't read the key slot")?);
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

/// `no_create`: refuse to create a key (the build expects an existing one).
pub fn load_or_create_key(slots: &mut impl Slots, no_create: bool) -> SigningKey {
    match load(slots) {
        Ok(Stored::Key(k)) => {
            log::info!("signing key loaded");
            return k;
        }
        Ok(Stored::Empty) if no_create => panic!("no signing key in slots {KEY_SLOTS:?}, and this build expects one; refusing to create a new one"),
        Ok(Stored::Empty) => {}
        // refuse to run rather than replace a key we failed to read
        Err(e) => panic!("signing key present but unusable: {e}; refusing to create a new one"),
    }
    let k = fresh_key();
    // key first, header last: a power cut in between leaves no header (-> Empty next boot)
    if !(slots.write(KEY_BASE, &k) && slots.write(KEY_BASE + 1, &header(&k))) {
        panic!("can't store the signing key");
    }
    let loaded = match load(slots) {
        Ok(Stored::Key(k)) => k,
        _ => panic!("the signing key doesn't read back"),
    };
    log::info!("new signing key created and stored");
    loaded
}

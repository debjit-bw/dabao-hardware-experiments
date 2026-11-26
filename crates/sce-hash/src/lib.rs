//! Keccak-256 and SHA-256 on the Baochip's "combohash" engine (part of the SCE crypto block).
//!
//! * **Keccak-256.** The engine's SHA3 mode is a raw Keccak-f[1600] permutation: it loads the
//!   50-word state from the MSG segment, runs the rounds and writes the state to HOUT, with no
//!   padding in hardware (RTL `crypto_top/rtl/combohasha.sv`, `crypto_hash/rtl/hashcore_sha3.sv`,
//!   unchanged since tapeout-a0). So Ethereum's Keccak-256 (padding `0x01 .. 0x80`, rate 136) runs
//!   here: the sponge in software, every permutation on the engine. Word layout, measured on the
//!   board: lane i = (word[2i] << 32) | word[2i+1], no byte swap.
//! * **SHA-256.** The engine's compression function, padding in software, as boot1's own
//!   `sha2-bao1x` driver uses it.
//!
//! [`init`] maps the engine (the kernel then gives its pages to no other process) and
//! self-tests it against software: known answers and inputs of many lengths. Only a backend
//! that passes is switched on; otherwise, and if the engine ever times out, everything falls
//! back to software. With alloy-primitives' `native-keccak` feature (device builds of the
//! verifier), every `alloy_primitives::keccak256` call (the Merkle-trie checks, revm's
//! KECCAK256 and CREATE2, our own code) comes through [`native_keccak256`]. Measured on the board
//! (crates/hash-bench): keccak256 ~1.8x faster than software, SHA-256 1.6-4x.

use alloy_primitives::Keccak256;
use sha2::{Digest, Sha256};

/// What [`init`] switched on.
#[derive(Clone, Debug, Default)]
pub struct Status {
    pub keccak_engine: bool,
    pub sha256_engine: bool,
    /// What the self-test found (or why the engine isn't used).
    pub note: String,
}

/// Software Keccak-256 (alloy's streaming hasher, which never takes the native hook).
pub fn keccak256_soft(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(data);
    h.finalize().0
}

/// Keccak-256 around any Keccak-f[1600] permutation.
pub fn sponge<E>(data: &[u8], perm: &mut impl FnMut(&mut [u64; 25]) -> Result<(), E>) -> Result<[u8; 32], E> {
    const RATE: usize = 136;
    let mut st = [0u64; 25];
    let absorb = |st: &mut [u64; 25], block: &[u8]| {
        for (lane, c) in st.iter_mut().zip(block.chunks_exact(8)) {
            *lane ^= u64::from_le_bytes(c.try_into().unwrap());
        }
    };
    let mut chunks = data.chunks_exact(RATE);
    for block in &mut chunks {
        absorb(&mut st, block);
        perm(&mut st)?;
    }
    let rest = chunks.remainder();
    let mut last = [0u8; RATE];
    last[..rest.len()].copy_from_slice(rest);
    last[rest.len()] ^= 0x01;
    last[RATE - 1] ^= 0x80;
    absorb(&mut st, &last);
    perm(&mut st)?;
    let mut out = [0u8; 32];
    for (c, lane) in out.chunks_exact_mut(8).zip(st.iter()) {
        c.copy_from_slice(&lane.to_le_bytes());
    }
    Ok(out)
}

/// Keccak-256: on the engine once [`init`] switched it on, else in software.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    #[cfg(target_os = "xous")]
    if let Some(h) = engine::keccak256(data) {
        return h;
    }
    keccak256_soft(data)
}

/// SHA-256: on the engine once [`init`] switched it on, else in software.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    #[cfg(target_os = "xous")]
    if let Some(h) = engine::sha256(data) {
        return h;
    }
    Sha256::digest(data).into()
}

/// SHA-256 as a `digest` hasher (for arkworks' hash-to-curve and the SSZ code): buffers the
/// message and hashes it in one call to [`sha256`] (the engine keeps one chaining state, so
/// buffering is what lets clones and interleaved hashers work). For the light client's short
/// messages only.
#[derive(Clone, Default)]
pub struct Sha256Hw {
    buf: Vec<u8>,
}

impl digest::HashMarker for Sha256Hw {}
impl digest::OutputSizeUser for Sha256Hw {
    type OutputSize = digest::typenum::U32;
}
impl digest::core_api::BlockSizeUser for Sha256Hw {
    type BlockSize = digest::typenum::U64;
}
impl digest::Update for Sha256Hw {
    fn update(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }
}
impl digest::Reset for Sha256Hw {
    fn reset(&mut self) {
        self.buf.clear();
    }
}
impl digest::FixedOutput for Sha256Hw {
    fn finalize_into(self, out: &mut digest::Output<Self>) {
        out.copy_from_slice(&sha256(&self.buf));
    }
}
impl digest::FixedOutputReset for Sha256Hw {
    fn finalize_into_reset(&mut self, out: &mut digest::Output<Self>) {
        out.copy_from_slice(&sha256(&self.buf));
        self.buf.clear();
    }
}

/// alloy-primitives' `native-keccak` hook: `alloy_primitives::keccak256` calls this when that
/// feature is on (device builds of the verifier only).
///
/// # Safety
/// `bytes` points to `len` readable bytes, `output` to 32 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn native_keccak256(bytes: *const u8, len: usize, output: *mut u8) {
    let data = if len == 0 { &[][..] } else { unsafe { core::slice::from_raw_parts(bytes, len) } };
    let h = keccak256(data);
    unsafe { core::ptr::copy_nonoverlapping(h.as_ptr(), output, 32) };
}

/// Map and self-test the engine; switch on what passes. Call once, early. Off the device:
/// software only.
pub fn init() -> Status {
    #[cfg(target_os = "xous")]
    return engine::init();
    #[cfg(not(target_os = "xous"))]
    Status { note: "not on the device: software".into(), ..Default::default() }
}

/// Deterministic test inputs (xorshift).
#[cfg(any(test, target_os = "xous"))]
fn test_input(seed: &mut u64, n: usize) -> Vec<u8> {
    (0..n)
        .map(|_| {
            *seed ^= *seed << 13;
            *seed ^= *seed >> 7;
            *seed ^= *seed << 17;
            *seed as u8
        })
        .collect()
}

/// Lengths around every boundary that matters: Keccak's 136-byte rate, SHA-256's 64-byte block
/// and 55/56-byte padding edge, the engine's 8-block (512 B) SHA-256 batch.
#[cfg(any(test, target_os = "xous"))]
const TEST_LENS: &[usize] = &[0, 1, 31, 32, 33, 55, 56, 63, 64, 65, 119, 120, 135, 136, 137, 271, 272, 273, 511, 512, 513, 532, 1000, 4096, 9000];

#[cfg(target_os = "xous")]
mod engine {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    use utralib::{CSR, utra::combohash as ch};

    use super::{Digest, Sha256, Status, TEST_LENS, keccak256_soft, sponge, test_input};

    const SEG_BASE: usize = utralib::HW_SEG_LKEY_MEM; // 0x4002_0000: all hash segments, one page
    const MSG: usize = (utralib::HW_SEG_MSG_MEM - SEG_BASE) / 4;
    const HOUT: usize = (utralib::HW_SEG_HOUT_MEM - SEG_BASE) / 4;
    const MSG_BLOCKS: usize = utralib::HW_SEG_MSG_MEM_LEN / 64;
    const FUNC_SHA256: u32 = 0;
    const FUNC_SHA3: u32 = 6;
    // Opt3SwapEndian seg_msg | seg_hout | seg_result, as sha2-bao1x
    const SWAP_SHA256: u32 = (1 << 4) | (1 << 5) | (1 << 7);

    struct Engine {
        csr: CSR<u32>,
        seg: *mut u32,
    }
    // only ever used under ENGINE's lock
    unsafe impl Send for Engine {}

    static ENGINE: Mutex<Option<Engine>> = Mutex::new(None);
    static KECCAK: AtomicBool = AtomicBool::new(false);
    static SHA256: AtomicBool = AtomicBool::new(false);

    impl Engine {
        fn map() -> Result<Engine, String> {
            let map = |phys: usize, what: &str| {
                xous::syscall::map_memory(xous::MemoryAddress::new(phys), None, 4096, xous::MemoryFlags::R | xous::MemoryFlags::W)
                    .map_err(|e| format!("can't map the {what} ({phys:#x}): {e:?}"))
            };
            let csr = map(ch::HW_COMBOHASH_BASE, "combohash registers")?;
            let seg = map(SEG_BASE, "hash segments")?;
            Ok(Engine { csr: CSR::new(csr.as_mut_ptr() as *mut u32), seg: seg.as_mut_ptr() as *mut u32 })
        }

        fn wr(&mut self, word: usize, v: u32) {
            unsafe { self.seg.add(word).write_volatile(v) }
        }
        fn rd(&self, word: usize) -> u32 {
            unsafe { self.seg.add(word).read_volatile() }
        }

        fn run(&mut self, func: u32, blocks: usize, opt3: u32) -> Result<(), ()> {
            self.csr.wo(ch::SFR_SEGPTR_SEGID_MSG, 0);
            self.csr.wo(ch::SFR_SEGPTR_SEGID_HOUT, 0);
            self.csr.wo(ch::SFR_OPT1, blocks as u32 - 1);
            self.csr.wfo(ch::SFR_CRFUNC_CR_FUNC, func);
            self.csr.wo(ch::SFR_OPT3, opt3);
            self.csr.wo(ch::SFR_FR, 0xf);
            self.csr.wo(ch::SFR_AR, 0x5a);
            let mut n = 0u32;
            while self.csr.rf(ch::SFR_FR_MFSM_DONE) == 0 {
                n += 1;
                if n > 5_000_000 {
                    return Err(());
                }
            }
            self.csr.rmwf(ch::SFR_FR_MFSM_DONE, 1);
            self.csr.wfo(ch::SFR_OPT2_CR_OPT_IFSTART, 0);
            Ok(())
        }

        fn keccak_f(&mut self, st: &mut [u64; 25]) -> Result<(), ()> {
            for (i, &lane) in st.iter().enumerate() {
                self.wr(MSG + 2 * i, (lane >> 32) as u32);
                self.wr(MSG + 2 * i + 1, lane as u32);
            }
            self.run(FUNC_SHA3, 1, 0)?;
            for (i, lane) in st.iter_mut().enumerate() {
                *lane = ((self.rd(HOUT + 2 * i) as u64) << 32) | self.rd(HOUT + 2 * i + 1) as u64;
            }
            Ok(())
        }

        fn sha256(&mut self, data: &[u8]) -> Result<[u8; 32], ()> {
            let mut buf = Vec::with_capacity(data.len() + 72);
            buf.extend_from_slice(data);
            buf.push(0x80);
            while buf.len() % 64 != 56 {
                buf.push(0);
            }
            buf.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
            self.csr.wfo(ch::SFR_OPT2_CR_OPT_IFSTART, 1); // start from the IV
            for chunk in buf.chunks(64 * MSG_BLOCKS) {
                for (i, w) in chunk.chunks_exact(4).enumerate() {
                    self.wr(MSG + i, u32::from_le_bytes(w.try_into().unwrap()));
                }
                self.run(FUNC_SHA256, chunk.len() / 64, SWAP_SHA256)?;
            }
            let mut out = [0u8; 32];
            for (i, c) in out.chunks_exact_mut(4).enumerate() {
                c.copy_from_slice(&self.rd(HOUT + i).to_le_bytes());
            }
            Ok(out)
        }
    }

    /// Runs `f` on the engine if `flag` is on; a timeout switches `flag` off for good.
    fn with<T>(flag: &AtomicBool, what: &str, f: impl FnOnce(&mut Engine) -> Result<T, ()>) -> Option<T> {
        if !flag.load(Ordering::Relaxed) {
            return None;
        }
        let mut g = ENGINE.lock().ok()?;
        let r = f(g.as_mut()?);
        if r.is_err() {
            flag.store(false, Ordering::Relaxed);
            log::error!("hash engine timed out on {what}: software from now on");
        }
        r.ok()
    }

    pub fn keccak256(data: &[u8]) -> Option<[u8; 32]> {
        with(&KECCAK, "Keccak-f", |e| sponge(data, &mut |s| e.keccak_f(s)))
    }

    pub fn sha256(data: &[u8]) -> Option<[u8; 32]> {
        with(&SHA256, "SHA-256", |e| e.sha256(data))
    }

    pub fn init() -> Status {
        let mut e = match Engine::map() {
            Ok(e) => e,
            Err(note) => return Status { note, ..Default::default() },
        };
        // Keccak: the permutation of the all-zero state (Keccak team's test vector), then
        // Keccak-256 against software
        let mut z = [0u64; 25];
        let zero_ok = e.keccak_f(&mut z).is_ok() && z[0] == 0xF1258F7940E1DDE7 && z[1] == 0x84D5CCF933C0478A && z[24] == 0xEAF1FF7B5CECA249;
        let mut seed = 0x5ce_5eed;
        let mut kec_bad = 0;
        let mut sha_bad = 0;
        for &n in TEST_LENS {
            let d = test_input(&mut seed, n);
            if sponge(&d, &mut |s| e.keccak_f(s)) != Ok(keccak256_soft(&d)) {
                kec_bad += 1;
            }
            if e.sha256(&d).ok() != Some(Sha256::digest(&d).into()) {
                sha_bad += 1;
            }
        }
        let keccak = zero_ok && kec_bad == 0;
        let sha = sha_bad == 0;
        let note = format!(
            "combohash self-test: Keccak-f(0) {}, Keccak-256 {}/{} lengths match software; SHA-256 {}/{} match",
            if zero_ok { "ok" } else { "WRONG" },
            TEST_LENS.len() - kec_bad,
            TEST_LENS.len(),
            TEST_LENS.len() - sha_bad,
            TEST_LENS.len()
        );
        *ENGINE.lock().unwrap() = Some(e);
        KECCAK.store(keccak, Ordering::Relaxed);
        SHA256.store(sha, Ordering::Relaxed);
        Status { keccak_engine: keccak, sha256_engine: sha, note }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference permutation (straight from the spec) for the sponge test.
    fn keccak_f_ref(a: &mut [u64; 25]) {
        const RC: [u64; 24] = [
            0x1, 0x8082, 0x800000000000808a, 0x8000000080008000, 0x808b, 0x80000001, 0x8000000080008081, 0x8000000000008009, 0x8a,
            0x88, 0x80008009, 0x8000000a, 0x8000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
            0x8000000000008002, 0x8000000000000080, 0x800a, 0x800000008000000a, 0x8000000080008081, 0x8000000000008080,
            0x80000001, 0x8000000080008008,
        ];
        const ROT: [u32; 25] = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14];
        for rc in RC {
            let c: [u64; 5] = core::array::from_fn(|x| a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20]);
            for x in 0..5 {
                let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
                for y in 0..5 {
                    a[x + 5 * y] ^= d;
                }
            }
            let mut b = [0u64; 25];
            for x in 0..5 {
                for y in 0..5 {
                    b[y + 5 * ((2 * x + 3 * y) % 5)] = a[x + 5 * y].rotate_left(ROT[x + 5 * y]);
                }
            }
            for x in 0..5 {
                for y in 0..5 {
                    a[x + 5 * y] = b[x + 5 * y] ^ (!b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
                }
            }
            a[0] ^= rc;
        }
    }

    #[test]
    fn sponge_matches_alloy() {
        let mut seed = 7;
        for &n in TEST_LENS {
            let d = test_input(&mut seed, n);
            let got = sponge(&d, &mut |s: &mut [u64; 25]| -> Result<(), ()> {
                keccak_f_ref(s);
                Ok(())
            });
            assert_eq!(got, Ok(alloy_primitives::keccak256(&d).0), "len {n}");
        }
    }

    #[test]
    fn zero_state_vector() {
        // the constants init() checks the engine against
        let mut z = [0u64; 25];
        keccak_f_ref(&mut z);
        assert_eq!((z[0], z[1], z[24]), (0xF1258F7940E1DDE7, 0x84D5CCF933C0478A, 0xEAF1FF7B5CECA249));
    }

    #[test]
    fn sha256hw_digest_api() {
        use digest::{Digest, FixedOutputReset};
        let mut h = Sha256Hw::default();
        h.update(b"a");
        let c = h.clone();
        h.update(b"bc");
        assert_eq!(h.finalize_fixed_reset()[..], Sha256::digest(b"abc")[..]);
        assert_eq!(Digest::finalize(c)[..], Sha256::digest(b"a")[..]);
        Digest::update(&mut h, b"x");
        assert_eq!(h.finalize()[..], Sha256::digest(b"x")[..]);
    }

    #[test]
    fn host_is_software() {
        assert!(!init().keccak_engine);
        assert_eq!(keccak256(b""), alloy_primitives::keccak256(b"").0);
        assert_eq!(sha256(b"abc"), <[u8; 32]>::from(Sha256::digest(b"abc")));
    }
}

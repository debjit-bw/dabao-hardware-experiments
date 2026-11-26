//! Hash-engine benchmark (TEST IMAGE ONLY): the Baochip's "combohash" engine against software.
//!
//! * SHA-256: the engine's compression function (padding in software), as boot1's own
//!   `sha2-bao1x` driver uses it.
//! * Keccak-256 (Ethereum's hash): the engine's SHA3 mode is a raw Keccak-f[1600] permutation
//!   (RTL `combohasha.sv`: it loads the 50-word state from the MSG segment, permutes, writes the
//!   state to HOUT; no padding in hardware), so the sponge and Ethereum's padding run in
//!   software around it. The state word layout isn't documented: it is detected from the
//!   permutation of the all-zero state, then checked with known answers and random inputs.
//!
//! Every hardware result is compared with software before any timing is reported. Results are
//! logged every 10 s so a late-attaching USB console still sees them.

#[cfg(target_os = "xous")]
use std::time::Instant;

use alloy_primitives::keccak256;
#[cfg(target_os = "xous")]
use sha2::{Digest, Sha256};
#[cfg(target_os = "xous")]
use utralib::{CSR, utra::combohash as ch};

#[cfg(target_os = "xous")]
const SEG_BASE: usize = utralib::HW_SEG_LKEY_MEM; // 0x4002_0000: all hash segments in one page
#[cfg(target_os = "xous")]
const MSG: usize = (utralib::HW_SEG_MSG_MEM - SEG_BASE) / 4;
#[cfg(target_os = "xous")]
const HOUT: usize = (utralib::HW_SEG_HOUT_MEM - SEG_BASE) / 4;
#[cfg(target_os = "xous")]
const MSG_BLOCKS: usize = utralib::HW_SEG_MSG_MEM_LEN / 64; // 512 B = 8 SHA-256 blocks
#[cfg(target_os = "xous")]
const FUNC_SHA256: u32 = 0;
#[cfg(target_os = "xous")]
const FUNC_SHA3: u32 = 6;
// Opt3SwapEndian: seg_msg (bit 4), seg_hout (bit 5), seg_result (bit 7), as sha2-bao1x sets them
#[cfg(target_os = "xous")]
const SWAP_SHA256: u32 = (1 << 4) | (1 << 5) | (1 << 7);

#[cfg(target_os = "xous")]
struct Engine {
    csr: CSR<u32>,
    seg: *mut u32,
}

#[cfg(target_os = "xous")]
#[derive(Clone, Copy, Debug)]
struct Layout {
    /// SFR_OPT3 for the SHA3 run
    opt3: u32,
    /// lane = (word[2i] << 32) | word[2i+1] instead of word[2i] | (word[2i+1] << 32)
    hi_first: bool,
    /// byte-swap every 32-bit word on the way in and out
    bswap: bool,
}

#[cfg(target_os = "xous")]
impl Engine {
    fn new() -> Result<Engine, String> {
        let map = |phys: usize, what: &str| {
            xous::syscall::map_memory(xous::MemoryAddress::new(phys), None, 4096, xous::MemoryFlags::R | xous::MemoryFlags::W)
                .map_err(|e| format!("map {what} @ {phys:#x}: {e:?}"))
        };
        let csr = map(ch::HW_COMBOHASH_BASE, "combohash CSR")?;
        let seg = map(SEG_BASE, "hash segments")?;
        Ok(Engine { csr: CSR::new(csr.as_mut_ptr() as *mut u32), seg: seg.as_mut_ptr() as *mut u32 })
    }

    fn wr(&mut self, word: usize, v: u32) {
        unsafe { self.seg.add(word).write_volatile(v) }
    }
    fn rd(&self, word: usize) -> u32 {
        unsafe { self.seg.add(word).read_volatile() }
    }

    fn run(&mut self, func: u32, blocks: usize, opt3: u32) -> Result<(), &'static str> {
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
                return Err("engine timeout");
            }
        }
        self.csr.rmwf(ch::SFR_FR_MFSM_DONE, 1);
        self.csr.wfo(ch::SFR_OPT2_CR_OPT_IFSTART, 0);
        Ok(())
    }

    fn sha256(&mut self, data: &[u8]) -> Result<[u8; 32], &'static str> {
        let mut buf = data.to_vec();
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

    fn keccak_f(&mut self, st: &mut [u64; 25], l: Layout) -> Result<(), &'static str> {
        let fix = |w: u32| if l.bswap { w.swap_bytes() } else { w };
        for (i, &lane) in st.iter().enumerate() {
            let (a, b) = if l.hi_first { ((lane >> 32) as u32, lane as u32) } else { (lane as u32, (lane >> 32) as u32) };
            self.wr(MSG + 2 * i, fix(a));
            self.wr(MSG + 2 * i + 1, fix(b));
        }
        self.run(FUNC_SHA3, 1, l.opt3)?;
        for (i, lane) in st.iter_mut().enumerate() {
            let (a, b) = (fix(self.rd(HOUT + 2 * i)) as u64, fix(self.rd(HOUT + 2 * i + 1)) as u64);
            *lane = if l.hi_first { (a << 32) | b } else { a | (b << 32) };
        }
        Ok(())
    }
}

// ---- software Keccak-f[1600] (reference for the layout detection; checked against alloy) ----

const RC: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800a, 0x800000008000000a, 0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];
const ROT: [u32; 25] = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14];

fn keccak_f_sw(a: &mut [u64; 25]) {
    for rc in RC {
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
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

/// Keccak-256 (Ethereum: pad 0x01 .. 0x80, rate 136) around any permutation.
fn keccak256_with<E>(data: &[u8], perm: &mut impl FnMut(&mut [u64; 25]) -> Result<(), E>) -> Result<[u8; 32], E> {
    let mut st = [0u64; 25];
    let absorb = |st: &mut [u64; 25], block: &[u8]| {
        for (lane, c) in st.iter_mut().zip(block.chunks_exact(8)) {
            *lane ^= u64::from_le_bytes(c.try_into().unwrap());
        }
    };
    let mut chunks = data.chunks_exact(136);
    for block in &mut chunks {
        absorb(&mut st, block);
        perm(&mut st)?;
    }
    let rest = chunks.remainder();
    let mut last = [0u8; 136];
    last[..rest.len()].copy_from_slice(rest);
    last[rest.len()] ^= 0x01;
    last[135] ^= 0x80;
    absorb(&mut st, &last);
    perm(&mut st)?;
    let mut out = [0u8; 32];
    for (c, lane) in out.chunks_exact_mut(8).zip(st.iter()) {
        c.copy_from_slice(&lane.to_le_bytes());
    }
    Ok(out)
}

struct Rng(u64);
impl Rng {
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n)
            .map(|_| {
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 7;
                self.0 ^= self.0 << 17;
                self.0 as u8
            })
            .collect()
    }
}

/// Microseconds per call: repeat for at least 300 ms (the timer has ~1 ms resolution).
#[cfg(target_os = "xous")]
fn per_call(mut f: impl FnMut()) -> f64 {
    let t = Instant::now();
    let mut n = 0u64;
    while t.elapsed().as_millis() < 300 {
        f();
        n += 1;
    }
    t.elapsed().as_micros() as f64 / n as f64
}

#[cfg(target_os = "xous")]
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(target_os = "xous")]
fn bench(lines: &mut Vec<String>) -> Result<(), String> {
    let mut e = Engine::new()?;
    lines.push("HASH mapped combohash CSR + segments".into());

    // ---- SHA-256 correctness ----
    let abc = e.sha256(b"abc")?;
    let want = Sha256::digest(b"abc");
    lines.push(format!("HASH sha256(abc) hw {} {}", hex(&abc), if abc[..] == want[..] { "ok" } else { "MISMATCH" }));
    let mut rng = Rng(0x9e3779b97f4a7c15);
    let mut bad = 0;
    for len in (0..700).step_by(7).chain([4096, 16384]) {
        let d = rng.bytes(len);
        if e.sha256(&d)?[..] != Sha256::digest(&d)[..] {
            bad += 1;
        }
    }
    lines.push(format!("HASH sha256 random inputs (102 lengths 0..16384): {bad} mismatches"));
    let sha_ok = abc[..] == want[..] && bad == 0;

    // ---- Keccak-f layout detection ----
    let mut want0 = [0u64; 25];
    keccak_f_sw(&mut want0);
    let sw_ok = keccak256_with(b"", &mut |s| -> Result<(), ()> {
        keccak_f_sw(s);
        Ok(())
    }) == Ok(keccak256(b"").0);
    lines.push(format!("HASH software keccak-f self-check vs alloy: {}", if sw_ok { "ok" } else { "MISMATCH" }));
    let mut layout = None;
    {
        let mut z = [0u64; 25];
        e.keccak_f(&mut z, Layout { opt3: 0, hi_first: false, bswap: false })?;
        lines.push(format!("HASH sha3 mode on zero state, raw HOUT words 0..4: {:08x} {:08x} {:08x} {:08x}", e.rd(HOUT), e.rd(HOUT + 1), e.rd(HOUT + 2), e.rd(HOUT + 3)));
        lines.push(format!("HASH expected lane 0 {:016x}, lane 1 {:016x}", want0[0], want0[1]));
    }
    'find: for opt3 in [0u32, (1 << 4) | (1 << 5), (1 << 4) | (1 << 5) | (1 << 7)] {
        for hi_first in [false, true] {
            for bswap in [false, true] {
                let l = Layout { opt3, hi_first, bswap };
                let mut z = [0u64; 25];
                e.keccak_f(&mut z, l)?;
                if z == want0 {
                    layout = Some(l);
                    break 'find;
                }
            }
        }
    }
    let Some(l) = layout else {
        lines.push("HASH sha3 mode: no word layout reproduces Keccak-f[1600](0): not a usable Keccak engine (or different mode)".into());
        return timing(&mut e, lines, sha_ok, None);
    };
    lines.push(format!("HASH sha3 mode = Keccak-f[1600], layout {l:?}"));

    // ---- Keccak-256 correctness ----
    let mut hw = |s: &mut [u64; 25]| e.keccak_f(s, l);
    let empty = keccak256_with(b"", &mut hw)?;
    lines.push(format!("HASH keccak256(\"\") hw {} {}", hex(&empty), if empty == keccak256(b"").0 { "ok" } else { "MISMATCH" }));
    let mut bad = 0;
    for len in (0..1200).step_by(11).chain([135, 136, 137, 272, 4096, 16384]) {
        let d = rng.bytes(len);
        if keccak256_with(&d, &mut hw)? != keccak256(&d).0 {
            bad += 1;
        }
    }
    lines.push(format!("HASH keccak256 random inputs (116 lengths 0..16384): {bad} mismatches"));
    let kec_ok = empty == keccak256(b"").0 && bad == 0;
    timing(&mut e, lines, sha_ok, kec_ok.then_some(l))
}

#[cfg(target_os = "xous")]
fn timing(e: &mut Engine, lines: &mut Vec<String>, sha_ok: bool, kec: Option<Layout>) -> Result<(), String> {
    let mut rng = Rng(42);
    if sha_ok {
        for n in [64usize, 1024, 16384] {
            let d = rng.bytes(n);
            let sw = per_call(|| {
                std::hint::black_box(Sha256::digest(&d));
            });
            let hw = per_call(|| {
                std::hint::black_box(e.sha256(&d).unwrap());
            });
            lines.push(format!("HASH TIME sha256 {n} B: software {sw:.1} us, engine {hw:.1} us ({:.1}x)", sw / hw));
        }
    }
    if let Some(l) = kec {
        let mut st = [7u64; 25];
        let sw = per_call(|| keccak_f_sw(std::hint::black_box(&mut st)));
        let hw = per_call(|| e.keccak_f(std::hint::black_box(&mut st), l).unwrap());
        lines.push(format!("HASH TIME keccak-f[1600] permutation: software (ref) {sw:.1} us, engine {hw:.1} us ({:.1}x)", sw / hw));
        for n in [32usize, 136, 532, 16384] {
            let d = rng.bytes(n);
            let sw = per_call(|| {
                std::hint::black_box(keccak256(&d));
            });
            let hw = per_call(|| {
                std::hint::black_box(keccak256_with(&d, &mut |s: &mut [u64; 25]| e.keccak_f(s, l)).unwrap());
            });
            lines.push(format!("HASH TIME keccak256 {n} B: software (alloy) {sw:.1} us, engine {hw:.1} us ({:.1}x)", sw / hw));
        }
    }
    lines.push("HASH DONE".into());
    Ok(())
}

#[cfg(not(target_os = "xous"))]
fn main() {}

#[cfg(target_os = "xous")]
fn main() {
    log_server::init_wait().unwrap();
    log::set_max_level(log::LevelFilter::Info);
    log::info!("hash-bench, PID {}", xous::process::id());
    std::thread::sleep(std::time::Duration::from_secs(10));
    let mut lines = Vec::new();
    if let Err(err) = bench(&mut lines) {
        lines.push(format!("HASH ERROR {err}"));
    }
    loop {
        for l in &lines {
            log::info!("{l}");
        }
        std::thread::sleep(std::time::Duration::from_secs(10));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn software_keccak_matches_alloy() {
        let mut rng = Rng(1);
        for len in (0..1200).step_by(13).chain([135, 136, 137]) {
            let d = rng.bytes(len);
            let got = keccak256_with(&d, &mut |s: &mut [u64; 25]| -> Result<(), ()> {
                keccak_f_sw(s);
                Ok(())
            });
            assert_eq!(got, Ok(keccak256(&d).0), "len {len}");
        }
    }
}

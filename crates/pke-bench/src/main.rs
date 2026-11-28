//! PKE probe (TEST IMAGE ONLY): the Baochip's public-key engine on BLS12-381.
//!
//! The PKE (RTL `crypto_top/rtl/pke.sv`, `crypto_pke/`) is a hardwired big-number engine:
//! modular add / subtract / Montgomery multiply over a prime up to 576 bits loaded at init
//! (`ECINIT`, which also computes R^2 and the Montgomery constant), and short-Weierstrass point
//! add / double / multiply on top. Nothing in xous-core drives it, and its data layout isn't
//! documented. This probe finds the layout on the board, step by step, checking every result
//! against arkworks:
//!
//! 1. word layout, from modular addition (no Montgomery factor involved);
//! 2. the Montgomery R, from modular multiplication;
//! 3. the point coordinates, from doubling and adding the G1 generator;
//! 4. timings against arkworks for the same operations.
//!
//! Results are logged every 10 s so a late-attaching USB console still sees them.

#[cfg(target_os = "xous")]
mod probe {
    use std::time::Instant;

    use ark_bls12_381::{Fq, G1Affine, G1Projective};
    use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
    use ark_ff::{BigInteger, Field, One, PrimeField, Zero};
    use utralib::{CSR, utra::pke};

    const SEG_BASE: usize = utralib::HW_SEG_LKEY_MEM; // 0x4002_0000
    const PCON: usize = (utralib::HW_SEG_PCON_MEM - SEG_BASE) / 4;
    const PIB: usize = (utralib::HW_SEG_PIB_MEM - SEG_BASE) / 4;
    const POB: usize = (utralib::HW_SEG_POB_MEM - SEG_BASE) / 4;
    const NBITS: u32 = 381;
    const NW: usize = 12; // 32-bit words per field element (the RTL's opt_nw32 for 381 bits)

    const ECINIT: u32 = 0x01;
    const ECMM: u32 = 0x02;
    const ECPA: u32 = 0x05;
    const ECPD: u32 = 0x06;
    const ECMA: u32 = 0x09;

    #[derive(Clone, Copy, Debug, PartialEq)]
    pub struct Layout {
        /// word[0] holds the most significant 32 bits
        be_words: bool,
        bswap: bool,
    }

    const LAYOUTS: [Layout; 4] = [
        Layout { be_words: false, bswap: false },
        Layout { be_words: true, bswap: false },
        Layout { be_words: false, bswap: true },
        Layout { be_words: true, bswap: true },
    ];

    fn words(f: Fq, l: Layout) -> [u32; NW] {
        let b = f.into_bigint().to_bytes_le();
        let mut w = [0u32; NW];
        for i in 0..NW {
            let v = u32::from_le_bytes(b[4 * i..4 * i + 4].try_into().unwrap());
            let v = if l.bswap { v.swap_bytes() } else { v };
            w[if l.be_words { NW - 1 - i } else { i }] = v;
        }
        w
    }

    fn field(w: &[u32], l: Layout) -> Option<Fq> {
        let mut b = [0u8; 48];
        for i in 0..NW {
            let v = w[if l.be_words { NW - 1 - i } else { i }];
            let v = if l.bswap { v.swap_bytes() } else { v };
            b[4 * i..4 * i + 4].copy_from_slice(&v.to_le_bytes());
        }
        let mut limbs = [0u64; 6];
        for i in 0..6 {
            limbs[i] = u64::from_le_bytes(b[8 * i..8 * i + 8].try_into().unwrap());
        }
        Fq::from_bigint(ark_ff::BigInt::new(limbs))
    }

    fn hex(w: &[u32]) -> String {
        w.iter().map(|x| format!("{x:08x}")).collect::<Vec<_>>().join("")
    }

    struct Rng(u64);
    impl Rng {
        fn fq(&mut self) -> Fq {
            let mut b = [0u8; 64];
            for c in b.chunks_mut(8) {
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 7;
                self.0 ^= self.0 << 17;
                c.copy_from_slice(&self.0.to_le_bytes());
            }
            Fq::from_le_bytes_mod_order(&b)
        }
    }

    pub struct Engine {
        csr: CSR<u32>,
        seg: *mut u32,
        pub layout: Layout,
    }

    impl Engine {
        pub fn new() -> Result<Engine, String> {
            let map = |phys: usize, len: usize, what: &str| {
                xous::syscall::map_memory(xous::MemoryAddress::new(phys), None, len, xous::MemoryFlags::R | xous::MemoryFlags::W)
                    .map_err(|e| format!("map {what} @ {phys:#x}: {e:?}"))
            };
            let csr = map(pke::HW_PKE_BASE, 4096, "PKE CSR")?;
            let seg = map(SEG_BASE, 8192, "SCE segments")?;
            Ok(Engine { csr: CSR::new(csr.as_mut_ptr() as *mut u32), seg: seg.as_mut_ptr() as *mut u32, layout: LAYOUTS[0] })
        }

        fn wr(&mut self, word: usize, v: u32) {
            unsafe { self.seg.add(word).write_volatile(v) }
        }
        fn rd(&self, word: usize) -> u32 {
            unsafe { self.seg.add(word).read_volatile() }
        }
        fn put(&mut self, at: usize, f: Fq) {
            for (i, w) in words(f, self.layout).iter().enumerate() {
                self.wr(at + i, *w);
            }
        }
        fn get(&self, at: usize) -> [u32; NW] {
            core::array::from_fn(|i| self.rd(at + i))
        }

        pub fn regs(&self) -> String {
            format!(
                "crfunc {:#x} srmfsm {:#x} fr {:#x} optnw {} optmask {:#x} tickcnt {}",
                self.csr.r(pke::SFR_CRFUNC),
                self.csr.r(pke::SFR_SRMFSM),
                self.csr.r(pke::SFR_FR),
                self.csr.r(pke::SFR_OPTNW),
                self.csr.r(pke::SFR_OPTMASK),
                self.csr.r(pke::SFR_TICKCNT)
            )
        }

        fn run(&mut self, func: u32) -> Result<(), String> {
            self.csr.wfo(pke::SFR_CRFUNC_CR_FUNC, func);
            self.csr.wo(pke::SFR_FR, 0x1f);
            self.csr.wo(pke::SFR_AR2, 0x5a);
            let mut n = 0u32;
            while self.csr.rf(pke::SFR_FR_MFSM_DONE) == 0 {
                n += 1;
                if n > 2_000_000 {
                    return Err(format!("func {func:#x} timeout: {}", self.regs()));
                }
            }
            self.csr.wo(pke::SFR_FR, 0x1f);
            Ok(())
        }

        pub fn clear_ram(&mut self) {
            self.csr.wo(pke::SFR_AR2, 0xff);
            let mut n = 0;
            while self.csr.rf(pke::SFR_SRMFSM_MFSM) != 0 && n < 1_000_000 {
                n += 1;
            }
        }

        /// ECINIT with BLS12-381's p, a = 0; the engine computes R^2 and its constant.
        pub fn init(&mut self) -> Result<(), String> {
            self.csr.wo(pke::SFR_OPTNW, NBITS);
            self.csr.wo(pke::SFR_OPTEW, 0);
            self.csr.wo(pke::SFR_OPTMASK, 0);
            for r in [pke::SFR_SEGPTR_PTRID_PCON, pke::SFR_SEGPTR_PTRID_PIB0, pke::SFR_SEGPTR_PTRID_PKB, pke::SFR_SEGPTR_PTRID_POB] {
                self.csr.wo(r, 0);
            }
            self.csr.wo(pke::SFR_SEGPTR_PTRID_PIB1, NW as u32);
            // p itself isn't an Fq: write its words directly
            let p = <Fq as PrimeField>::MODULUS.to_bytes_le();
            let mut w = [0u32; NW];
            for i in 0..NW {
                let v = u32::from_le_bytes(p[4 * i..4 * i + 4].try_into().unwrap());
                let v = if self.layout.bswap { v.swap_bytes() } else { v };
                w[if self.layout.be_words { NW - 1 - i } else { i }] = v;
            }
            for i in 0..NW {
                self.wr(PCON + i, w[i]);
            }
            for i in NW..3 * NW + 2 {
                self.wr(PCON + i, 0); // a = 0, then R^2 (computed by the engine)
            }
            self.run(ECINIT)
        }

        pub fn op2(&mut self, func: u32, x: Fq, y: Fq) -> Result<[u32; NW], String> {
            self.csr.wo(pke::SFR_SEGPTR_PTRID_PIB0, 0);
            self.csr.wo(pke::SFR_SEGPTR_PTRID_PIB1, NW as u32);
            self.put(PIB, x);
            self.put(PIB + NW, y);
            self.run(func)?;
            Ok(self.get(POB))
        }

        /// A point op: Q0 (and Q1) as three coordinates each, already in the engine's form.
        pub fn point(&mut self, func: u32, q0: [Fq; 3], q1: Option<[Fq; 3]>) -> Result<[[u32; NW]; 3], String> {
            self.csr.wo(pke::SFR_SEGPTR_PTRID_PIB0, 0);
            self.csr.wo(pke::SFR_SEGPTR_PTRID_PIB1, 3 * NW as u32);
            for (i, c) in q0.iter().enumerate() {
                self.put(PIB + i * NW, *c);
            }
            if let Some(q1) = q1 {
                for (i, c) in q1.iter().enumerate() {
                    self.put(PIB + 3 * NW + i * NW, *c);
                }
            }
            self.run(func)?;
            Ok(core::array::from_fn(|i| self.get(POB + i * NW)))
        }
    }

    fn per_call(mut f: impl FnMut()) -> f64 {
        f();
        let t = Instant::now();
        let mut n = 0u32;
        while t.elapsed().as_millis() < 300 {
            f();
            n += 1;
        }
        t.elapsed().as_micros() as f64 / n as f64
    }

    pub fn bench(lines: &mut Vec<String>) -> Result<(), String> {
        let mut e = Engine::new()?;
        lines.push(format!("PKE regs at start: {}", e.regs()));
        e.clear_ram();
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);

        // 0. does the PKE core run at all? GCD uses it but needs no ECINIT (whose J0 step hung)
        e.csr.wo(pke::SFR_OPTNW, NBITS);
        e.csr.wo(pke::SFR_OPTEW, 0);
        e.csr.wo(pke::SFR_OPTMASK, 0);
        e.csr.wo(pke::SFR_SEGPTR_PTRID_PIB0, 0);
        e.csr.wo(pke::SFR_SEGPTR_PTRID_PIB1, NW as u32);
        e.csr.wo(pke::SFR_SEGPTR_PTRID_POB, 0);
        for i in 0..2 * NW {
            e.wr(PIB + i, 0);
        }
        e.wr(PIB, 12);
        e.wr(PIB + NW, 18);
        e.wr(PIB + NW - 1, 0); // LE: low word first; also try the high word below if this is garbage
        match e.run(0x51) {
            Err(err) => {
                lines.push(format!("PKE GCD(12, 18): {err} (the PKE core doesn't complete any job)"));
                return Ok(());
            }
            Ok(()) => lines.push(format!("PKE GCD(12, 18) completed: POB {}", hex(&e.get(POB)))),
        }
        let (x, y) = (rng.fq(), rng.fq());
        let mut found = None;
        for l in LAYOUTS {
            e.layout = l;
            if let Err(err) = e.init() {
                // the engine has no soft reset: stuck in a state, it won't start again until a chip reset
                lines.push(format!("PKE init {l:?}: {err} (engine stuck until reset: no further tries)"));
                break;
            }
            let out = e.op2(ECMA, x, y)?;
            let ok = field(&out, l) == Some(x + y);
            lines.push(format!("PKE ECMA layout {l:?}: {} ({})", if ok { "MATCH" } else { "no" }, hex(&out)));
            if ok && found.is_none() {
                found = Some(l);
            }
        }
        let Some(l) = found else {
            lines.push("PKE: no layout gives x + y mod p".into());
            return Ok(());
        };
        e.layout = l;
        e.init()?;
        let mut bad = 0;
        for _ in 0..50 {
            let (a, b) = (rng.fq(), rng.fq());
            if field(&e.op2(ECMA, a, b)?, l) != Some(a + b) {
                bad += 1;
            }
        }
        lines.push(format!("PKE ECMA 50 random pairs: {bad} mismatches"));

        // 2. the Montgomery R, from multiplication: out = x y R^-1
        let out = field(&e.op2(ECMM, x, y)?, l).ok_or("ECMM output >= p")?;
        let two = Fq::from(2u64);
        let mut r_bits = None;
        for k in (0..=640u64).step_by(32) {
            if out == x * y * two.pow([k]).inverse().unwrap() {
                r_bits = Some(k);
            }
        }
        lines.push(format!("PKE ECMM: out = x*y*2^-k for k = {r_bits:?}"));
        let Some(k) = r_bits else { return Ok(()) };
        let r = two.pow([k]);
        let m = |a: Fq| a * r; // to Montgomery form
        let un = |w: &[u32; NW]| field(w, l).map(|a| a * r.inverse().unwrap());
        let mut bad = 0;
        for _ in 0..50 {
            let (a, b) = (rng.fq(), rng.fq());
            if un(&e.op2(ECMM, m(a), m(b))?) != Some(a * b) {
                bad += 1;
            }
        }
        lines.push(format!("PKE ECMM 50 random pairs (Montgomery form, R = 2^{k}): {bad} mismatches"));

        // 3. point coordinates, from doubling and adding G
        let g = G1Affine::generator();
        let (gx, gy) = (g.x().unwrap(), g.y().unwrap());
        let g2 = (G1Projective::generator() * ark_bls12_381::Fr::from(2u64)).into_affine();
        let g3 = (G1Projective::generator() * ark_bls12_381::Fr::from(3u64)).into_affine();
        let affine = |c: &[[u32; NW]; 3]| -> Option<(String, G1Affine)> {
            let (x, y, z) = (un(&c[0])?, un(&c[1])?, un(&c[2])?);
            if z.is_zero() {
                return None;
            }
            let zi = z.inverse()?;
            let jac = G1Affine::new_unchecked(x * zi.square(), y * zi.square() * zi);
            let proj = G1Affine::new_unchecked(x * zi, y * zi);
            for (name, p) in [("jacobian", jac), ("projective", proj)] {
                if p.is_on_curve() {
                    return Some((name.into(), p));
                }
            }
            None
        };
        let one = Fq::one();
        let d = e.point(ECPD, [m(gx), m(gy), m(one)], None)?;
        let dd = affine(&d);
        lines.push(format!(
            "PKE ECPD(G): {}",
            match &dd {
                Some((n, p)) if *p == g2 => format!("= 2G ({n} coordinates)"),
                Some((n, _)) => format!("on the curve ({n}) but not 2G"),
                None => format!("not a curve point in either system: {} {} {}", hex(&d[0]), hex(&d[1]), hex(&d[2])),
            }
        ));
        let jac = matches!(&dd, Some((n, _)) if n == "jacobian");
        let (g2x, g2y) = (g2.x().unwrap(), g2.y().unwrap());
        let a = e.point(ECPA, [m(gx), m(gy), m(one)], Some([m(g2x), m(g2y), m(one)]))?;
        let aa = affine(&a);
        lines.push(format!(
            "PKE ECPA(G, 2G): {}",
            match &aa {
                Some((n, p)) if *p == g3 => format!("= 3G ({n} coordinates)"),
                Some((n, _)) => format!("on the curve ({n}) but not 3G"),
                None => format!("not a curve point: {} {} {}", hex(&a[0]), hex(&a[1]), hex(&a[2])),
            }
        ));

        // chained additions with Z != 1 on both sides: sum of 20 multiples of G
        let mut acc = d; // 2G, as the engine returned it
        let mut sw = G1Projective::generator() * ark_bls12_381::Fr::from(2u64);
        let mut chain_ok = matches!(&aa, Some((_, p)) if *p == g3);
        for i in 0..20u64 {
            let q = (G1Projective::generator() * ark_bls12_381::Fr::from(i * 7 + 5)).into_affine();
            let accf = [un(&acc[0]).unwrap_or_default(), un(&acc[1]).unwrap_or_default(), un(&acc[2]).unwrap_or_default()];
            acc = e.point(ECPA, [m(accf[0]), m(accf[1]), m(accf[2])], Some([m(q.x().unwrap()), m(q.y().unwrap()), m(one)]))?;
            sw += q;
        }
        if chain_ok {
            chain_ok = matches!(affine(&acc), Some((_, p)) if p == sw.into_affine());
        }
        lines.push(format!("PKE ECPA chain of 20 adds onto 2G: {}", if chain_ok { "MATCH" } else { "no" }));
        let _ = jac;

        // 4. timings
        let (a, b) = (rng.fq(), rng.fq());
        let t_sw_mul = per_call(|| {
            std::hint::black_box(std::hint::black_box(a) * std::hint::black_box(b));
        });
        let t_hw_mul = per_call(|| {
            std::hint::black_box(e.op2(ECMM, a, b).unwrap());
        });
        lines.push(format!("PKE TIME Fq mul: software {t_sw_mul:.2} us, engine (incl. I/O) {t_hw_mul:.2} us"));
        let p1 = G1Projective::generator() * ark_bls12_381::Fr::from(12345u64);
        let q1 = (G1Projective::generator() * ark_bls12_381::Fr::from(678u64)).into_affine();
        let t_sw_add = per_call(|| {
            let mut s = std::hint::black_box(p1);
            s += std::hint::black_box(q1);
            let _ = std::hint::black_box(s);
        });
        let pa = [m(gx), m(gy), m(one)];
        let qa = [m(g2x), m(g2y), m(one)];
        let t_hw_add = per_call(|| {
            std::hint::black_box(e.point(ECPA, pa, Some(qa)).unwrap());
        });
        lines.push(format!("PKE TIME G1 add (projective + affine): software {t_sw_add:.1} us, engine (incl. I/O) {t_hw_add:.1} us"));
        let t_io = per_call(|| {
            for i in 0..6 * NW {
                e.wr(PIB + i, i as u32);
            }
            for i in 0..3 * NW {
                std::hint::black_box(e.rd(POB + i));
            }
        });
        lines.push(format!("PKE TIME I/O alone (72 writes + 36 reads): {t_io:.1} us"));
        lines.push(format!("PKE regs at end: {}", e.regs()));
        Ok(())
    }
}

#[cfg(not(target_os = "xous"))]
fn main() {}

#[cfg(target_os = "xous")]
fn main() {
    log_server::init_wait().unwrap();
    log::set_max_level(log::LevelFilter::Info);
    log::info!("pke-bench, PID {}", xous::process::id());
    std::thread::sleep(std::time::Duration::from_secs(10));
    let mut lines = Vec::new();
    if let Err(err) = probe::bench(&mut lines) {
        lines.push(format!("PKE ERROR {err}"));
    }
    lines.push("PKE DONE".into());
    loop {
        for l in &lines {
            log::info!("{l}");
        }
        std::thread::sleep(std::time::Duration::from_secs(10));
    }
}

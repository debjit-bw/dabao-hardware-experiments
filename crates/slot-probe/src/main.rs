//! TEST ONLY, never in a release image. Plays a compromised process in an image where the
//! signer runs as PID 3 in place of the keystore (option B, docs/xous-core-fork.md). It tries
//! every way to the RRAM slots it can think of from user space, and logs what each returns on
//! the USB serial console, so the image must be built with GENERIC_HID=0:
//!
//!   SERVICE=verifier GENERIC_HID=0 scripts/build-device.sh target/riscv32imac-unknown-xous-elf/release/slot-probe
//!
//! (the probe takes the transport's place in the apps image). Every attempt must fail, while
//! the signer is attached to the verifier.

#[cfg(target_os = "xous")]
fn main() -> ! {
    use sim_types::ipc;
    log_server::init_wait().unwrap();
    log::set_max_level(log::LevelFilter::Info);
    // log lines reach the USB serial console only once an app hooks the USB mirror
    usb_bao1x::UsbHid::new().serial_console_input_injection();
    std::thread::sleep(std::time::Duration::from_secs(12)); // let the signer and verifier start
    let xns = xous_names::XousNames::new().unwrap();
    let mut lines: Vec<String> = Vec::new();
    let mut pass = 0usize;
    let mut check = |what: &str, got: String, ok: bool, want: &str| {
        pass += ok as usize;
        lines.push(format!("PROBE {} {what}: got {got}, want {want}", if ok { "ok  " } else { "FAIL" }));
    };

    // 1. there is no keystore to ask
    let ks = xns.request_connection("_Keystore server_");
    check("connect to the keystore", format!("{ks:?}"), ks.is_err(), "an error (no keystore)");

    // 2. the signer's slot server, without the token
    let slots = xns.request_connection_blocking(ipc::SLOTS_SERVER_NAME).expect("slot server");
    let call = |op: usize, token: [u8; ipc::SLOT_TOKEN_LEN], index: u32, data: Option<[u8; 32]>| -> usize {
        let mut req = token.to_vec();
        req.extend_from_slice(&index.to_be_bytes());
        if let Some(d) = data {
            req.extend_from_slice(&d);
        }
        let mut range = xous::map_memory(None, None, 4096, xous::MemoryFlags::R | xous::MemoryFlags::W).unwrap();
        unsafe { range.as_slice_mut::<u8>()[..req.len()].copy_from_slice(&req) };
        let r = xous::send_message(slots, xous::Message::new_lend_mut(op, range, None, xous::MemorySize::new(req.len())));
        xous::unmap_memory(range).ok();
        match r {
            Ok(xous::Result::MemoryReturned(_, v)) => v.map(|v| v.get()).unwrap_or(0),
            _ => 0,
        }
    };
    let zero = [0u8; ipc::SLOT_TOKEN_LEN];
    for (what, op, index, data) in [
        ("read key slot 160, no token", ipc::OP_SLOT_READ, 160, None),
        ("read key slot 161, no token", ipc::OP_SLOT_READ, 161, None),
        ("write key slot 160, no token", ipc::OP_SLOT_WRITE, 160, Some([0x55; 32])),
        ("read counter slot 176, no token", ipc::OP_SLOT_READ, 176, None),
        ("write counter slot 176, no token", ipc::OP_SLOT_WRITE, 176, Some([0; 32])),
        ("read light-client slot 208, no token", ipc::OP_SLOT_READ, 208, None),
    ] {
        let n = call(op, zero, index, data);
        check(what, format!("{n} bytes"), n == 0, "0 bytes (refused)");
    }

    // 3. map the hardware directly: data slots, their ACLs, the RRAM controller
    for (what, addr) in [
        ("map the RRAM data slots", bao1x_api::DATA_SLOT_START),
        ("map the slot ACLs", bao1x_api::ACRAM_DATASLOT_START),
        ("map the RRAM controller", utralib::utra::rrc::HW_RRC_BASE),
    ] {
        let r = xous::map_memory(xous::MemoryAddress::new(addr), None, 4096, xous::MemoryFlags::R | xous::MemoryFlags::W);
        check(&format!("{what} ({addr:#x})"), format!("{:?}", r.as_ref().map(|_| "mapped")), r.is_err(), "an error (owned by the signer)");
    }

    // the verifier's OP_ADDRESS says whether the signer attached (no transport in the test
    // image, so the probe can take the verifier's single client connection)
    let verifier = xns.request_connection_blocking(ipc::VERIFIER_SERVER_NAME).expect("verifier");
    let signer_attached = || {
        let range = xous::map_memory(None, None, 4096, xous::MemoryFlags::R | xous::MemoryFlags::W).unwrap();
        let r = xous::send_message(verifier, xous::Message::new_lend_mut(ipc::OP_ADDRESS, range, None, None));
        let n = match r {
            Ok(xous::Result::MemoryReturned(_, v)) => v.map(|v| v.get()).unwrap_or(0),
            _ => 0,
        };
        xous::unmap_memory(range).ok();
        n == 20
    };
    loop {
        log::info!("PROBE my PID {}; signer attached to verifier: {}", xous::process::id(), signer_attached());
        for l in &lines {
            log::info!("{l}");
        }
        log::info!("PROBE summary: {pass}/{} as expected", lines.len());
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}

#[cfg(not(target_os = "xous"))]
fn main() {
    eprintln!("slot-probe is a device-only test");
}

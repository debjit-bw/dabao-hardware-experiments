//! TEST ONLY, never in a release image. Plays a compromised process that has connected to the
//! keystore and tries to reach the signer's app slots (160..162). With the keystore claim patch
//! and the signer running, every attempt on those slots must be `AccessDenied`, while unclaimed
//! slots behave as before. Results are logged (and repeated) on the USB serial console, so the
//! image must be built with GENERIC_HID=0.
//!
//! Feature `steal`: claim 160..162 at once, racing the signer; the signer must then refuse to
//! start ("can't claim keystore app slots").

#[cfg(target_os = "xous")]
fn main() -> ! {
    use keystore_api::{APPKEY_GUARD, AppKey};
    log_server::init_wait().unwrap();
    log::set_max_level(log::LevelFilter::Info);
    // log lines reach the USB serial console only once an app hooks the USB mirror
    // (usb-bao1x SerialHookConsole -> xous-log TryHookUsbMirror), as dabao-console does
    usb_bao1x::UsbHid::new().serial_console_input_injection();
    let xns = xous_names::XousNames::new().unwrap();
    let ks = xns.request_connection_blocking(keystore_api::SERVER_NAME_KEYS).expect("keystore");
    let call = |op: AppKey| -> AppKey {
        let Ok(mut buf) = xous_ipc::Buffer::into_buf(op) else { return AppKey::InternalError };
        if buf.lend_mut(ks, keystore_api::Opcode::AppKeyOp as u32).is_err() {
            return AppKey::InternalError;
        }
        buf.to_original::<AppKey, _>().unwrap_or(AppKey::InternalError)
    };
    let g = APPKEY_GUARD;

    #[cfg(feature = "steal")]
    let steal = format!("{:?}", call(AppKey::Claim { guard: g, start: 160, len: 2 }));
    #[cfg(not(feature = "steal"))]
    std::thread::sleep(std::time::Duration::from_secs(12)); // let the signer start and claim

    let short = |r: AppKey| match r {
        AppKey::ReadResponse { .. } => "ReadResponse(..)".to_string(),
        other => format!("{other:?}"),
    };
    let cases: Vec<(&str, AppKey, &str)> = vec![
        ("read signer slot 160", AppKey::ReadRequest { guard: g, index: 160 }, "AccessDenied"),
        ("read signer slot 161", AppKey::ReadRequest { guard: g, index: 161 }, "AccessDenied"),
        ("write signer slot 160", AppKey::Write { guard: g, index: 160, data: [0x55; 32] }, "AccessDenied"),
        ("claim 160..162", AppKey::Claim { guard: g, start: 160, len: 2 }, "AccessDenied"),
        ("claim overlapping 161..163", AppKey::Claim { guard: g, start: 161, len: 2 }, "AccessDenied"),
        ("read unclaimed slot 170", AppKey::ReadRequest { guard: g, index: 170 }, "ReadResponse(..)"),
        ("claim free 170..171", AppKey::Claim { guard: g, start: 170, len: 1 }, "Success"),
        ("claim 170..171 again (same owner)", AppKey::Claim { guard: g, start: 170, len: 1 }, "Success"),
    ];
    let mut lines: Vec<String> = Vec::new();
    let mut pass = 0usize;
    #[cfg(not(feature = "steal"))]
    for (what, op, want) in &cases {
        let got = short(call(*op));
        let ok = got == *want;
        pass += ok as usize;
        lines.push(format!("PROBE {} {what}: got {got}, want {want}", if ok { "ok  " } else { "FAIL" }));
    }
    #[cfg(feature = "steal")]
    let _ = (&cases, &short, &mut pass);
    // the verifier's OP_ADDRESS says whether a signer attached (no transport in the test
    // image, so the probe can take the verifier's single client connection)
    let verifier = xns.request_connection_blocking(sim_types::ipc::VERIFIER_SERVER_NAME).expect("verifier");
    let signer_attached = || {
        let mut range = xous::map_memory(None, None, 4096, xous::MemoryFlags::R | xous::MemoryFlags::W).unwrap();
        let r = xous::send_message(
            verifier,
            xous::Message::new_lend_mut(sim_types::ipc::OP_ADDRESS, range, None, None),
        );
        let n = match r {
            Ok(xous::Result::MemoryReturned(_, v)) => v.map(|v| v.get()).unwrap_or(0),
            _ => 0,
        };
        let _ = &mut range;
        xous::unmap_memory(range).ok();
        n == 20
    };
    loop {
        #[cfg(feature = "steal")]
        log::info!("PROBE steal: claimed 160..162 at boot -> {steal}");
        log::info!("PROBE signer attached to verifier: {}", signer_attached());
        for l in &lines {
            log::info!("{l}");
        }
        log::info!("PROBE summary: {pass}/{} as expected", lines.len());
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}

#[cfg(not(target_os = "xous"))]
fn main() {
    eprintln!("keystore-probe is a device-only test");
}

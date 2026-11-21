//! Process 1 of 3: the transport. Untrusted by design: it only delimits frames
//! (`sim_types::wire`) and forwards `TYPE_SIMULATE` payloads, unparsed, to the verifier.
//! A bug here can garble or drop requests, but can't touch verification or keys.
//!
//! * device: the dabao vendor HID interface (`usb-bao1x/generic-hid`), 64-byte reports;
//! * emulator: TCP on 127.0.0.1:`DABAO_PORT` (default 7610), raw frames.
//! Framing and HID chunking follow eth-burner (ethereum-app/dabao-app-eth-burner).

use sim_types::{ipc, wire};

const VERSION: &str = concat!("dabao-verifier transport ", env!("CARGO_PKG_VERSION"));

/// Forwards a simulate request to the verifier over a lent buffer; returns RLP `SimResult`.
struct Verifier(xous::CID);

impl Verifier {
    fn connect() -> Self {
        let xns = xous_names::XousNames::new().unwrap();
        Verifier(xns.request_connection_blocking(ipc::VERIFIER_SERVER_NAME).expect("verifier"))
    }

    fn simulate(&self, input: &[u8]) -> Result<Vec<u8>, String> {
        self.call(ipc::OP_SIMULATE, input)
    }

    /// Lend `input` (plus room for the reply) with `op`; returns the verifier's reply bytes.
    fn call(&self, op: usize, input: &[u8]) -> Result<Vec<u8>, String> {
        // room for the reply too (logs and state changes), page-rounded
        let cap = (input.len().max(16 * 1024) + 4095) & !4095;
        let mut range = xous::map_memory(None, None, cap, xous::MemoryFlags::R | xous::MemoryFlags::W)
            .map_err(|e| format!("out of memory for a {cap} B buffer: {e:?}"))?;
        // safety: freshly mapped, `cap` bytes
        unsafe { range.as_slice_mut::<u8>()[..input.len()].copy_from_slice(input) };
        let r = xous::send_message(
            self.0,
            xous::Message::new_lend_mut(op, range, None, xous::MemorySize::new(input.len())),
        );
        let out = match r {
            Ok(xous::Result::MemoryReturned(_, Some(valid))) => {
                // safety: the verifier wrote `valid` bytes of reply into our buffer
                Ok(unsafe { range.as_slice::<u8>()[..valid.get().min(cap)].to_vec() })
            }
            other => Err(format!("verifier IPC failed: {other:?}")),
        };
        xous::unmap_memory(range).ok();
        out
    }
}

/// One `type || message` body in, one reply frame out.
fn handle(body: &[u8], verifier: &Verifier) -> Vec<u8> {
    let Some((&ty, message)) = body.split_first() else {
        return wire::encode_frame(wire::TYPE_ERROR, b"empty frame");
    };
    match ty {
        wire::TYPE_VERSION => wire::encode_frame(wire::TYPE_VERSION, VERSION.as_bytes()),
        wire::TYPE_SIMULATE => match verifier.simulate(message) {
            Ok(result) => wire::encode_frame(wire::TYPE_SIMULATE, &result),
            Err(e) => wire::encode_frame(wire::TYPE_ERROR, e.as_bytes()),
        },
        wire::TYPE_SIGN => match verifier.call(ipc::OP_SIGN, message) {
            Ok(result) => wire::encode_frame(wire::TYPE_SIGN, &result),
            Err(e) => wire::encode_frame(wire::TYPE_ERROR, e.as_bytes()),
        },
        wire::TYPE_ADDRESS => match verifier.call(ipc::OP_ADDRESS, &[]) {
            Ok(a) if a.len() == 20 => wire::encode_frame(wire::TYPE_ADDRESS, &a),
            Ok(_) => wire::encode_frame(wire::TYPE_ERROR, b"no signer attached"),
            Err(e) => wire::encode_frame(wire::TYPE_ERROR, e.as_bytes()),
        },
        _ => wire::encode_frame(wire::TYPE_ERROR, b"unknown message type"),
    }
}

fn main() -> ! {
    log_server::init_wait().unwrap();
    log::set_max_level(log::LevelFilter::Info);
    log::info!("{VERSION}, PID {}", xous::process::id());
    let verifier = Verifier::connect();
    log::info!("connected to the verifier");
    // Don't listen to the host before the signer is attached: no host input is processed
    // until the trusted processes are up.
    loop {
        match verifier.call(ipc::OP_ADDRESS, &[]) {
            Ok(a) if a.len() == 20 => {
                log::info!("signer attached, device address 0x{}", a.iter().map(|b| format!("{b:02x}")).collect::<String>());
                break;
            }
            _ => std::thread::sleep(std::time::Duration::from_millis(100)),
        }
    }
    serve(&verifier)
}

#[cfg(not(target_os = "xous"))]
fn serve(verifier: &Verifier) -> ! {
    use std::io::{Read, Write};
    let port: u16 = std::env::var("DABAO_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(7610);
    let listener = std::net::TcpListener::bind(("127.0.0.1", port)).expect("can't bind the emulator socket");
    log::info!("emulator transport: listening on 127.0.0.1:{port}");
    loop {
        let Ok((mut stream, peer)) = listener.accept() else { continue };
        log::info!("host connected from {peer}");
        loop {
            let mut prefix = [0u8; 4];
            if stream.read_exact(&mut prefix).is_err() {
                break;
            }
            let Some(n) = wire::frame_len(prefix) else {
                // the stream can't be delimited any more: answer and drop it
                stream.write_all(&wire::encode_frame(wire::TYPE_ERROR, b"bad length")).ok();
                break;
            };
            let mut body = vec![0u8; n];
            if stream.read_exact(&mut body).is_err() {
                break;
            }
            if stream.write_all(&handle(&body, verifier)).is_err() {
                break;
            }
        }
        log::info!("host disconnected");
    }
}

#[cfg(target_os = "xous")]
fn serve(verifier: &Verifier) -> ! {
    let usb = usb_bao1x::UsbHid::new();
    let mut buf: Vec<u8> = Vec::new();
    let mut need: Option<usize> = None;
    loop {
        let report = match usb.hid_wait_incoming() {
            Ok(r) => r,
            Err(e) => {
                log::warn!("HID receive: {e:?}");
                std::thread::sleep(std::time::Duration::from_millis(100));
                continue;
            }
        };
        buf.extend_from_slice(&report);
        if need.is_none() {
            need = wire::frame_len([buf[0], buf[1], buf[2], buf[3]]);
            if need.is_none() {
                buf.clear();
                send_reports(&usb, &wire::encode_frame(wire::TYPE_ERROR, b"bad length"));
                continue;
            }
        }
        let n = need.unwrap();
        if buf.len() < 4 + n {
            continue;
        }
        // padding after the frame is discarded
        let reply = handle(&buf[4..4 + n], verifier);
        buf.clear();
        need = None;
        send_reports(&usb, &reply);
    }
}

/// The vendor HID IN endpoint is polled every 5 ms (xous-usb-hid `RawFido`). usb-bao1x writes
/// queued reports from its IRQ with `write_report(..).ok()`: if the previous report hasn't been
/// collected yet, `WouldBlock` is ignored and the report is silently dropped. So send at most
/// one report per poll interval, with margin.
#[cfg(target_os = "xous")]
const REPORT_SPACING: std::time::Duration = std::time::Duration::from_millis(6);

#[cfg(target_os = "xous")]
fn send_reports(usb: &usb_bao1x::UsbHid, frame: &[u8]) {
    for (i, c) in frame.chunks(64).enumerate() {
        if i > 0 {
            std::thread::sleep(REPORT_SPACING);
        }
        let mut r = [0u8; 64];
        r[..c.len()].copy_from_slice(c);
        if let Err(e) = usb.hid_send(r) {
            log::warn!("HID send: {e:?}");
            break;
        }
    }
}

//! Process 1 of 3: the transport. Untrusted by design: it only delimits frames
//! (`sim_types::wire`) and forwards `TYPE_SIMULATE` payloads, unparsed, to the verifier.
//! A bug here can garble or drop requests, but can't touch verification or keys.
//!
//! * device: the dabao vendor HID interface (`usb-bao1x/generic-hid`), 64-byte reports;
//! * emulator: TCP on 127.0.0.1:`DABAO_PORT` (default 7610), raw frames.
//! Framing and HID chunking follow eth-burner (ethereum-app/dabao-app-eth-burner).

use sim_types::{ipc, wire};

const VERSION: &str = concat!("dabao-verifier transport ", env!("CARGO_PKG_VERSION"));

/// How long the transport waits for the verifier. A verifier that dies or stalls mid-request
/// never returns the lent buffer; without a bound the HID loop (and the host) would wait forever.
const VERIFIER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// A lend to the verifier: opcode, the buffer (request in, reply out), request length.
struct Job(usize, xous::MemoryRange, usize);

/// The verifier, behind a worker thread so every call has a timeout. After a timeout the
/// verifier is considered dead (its worker is still blocked holding the buffer) and every later
/// call fails at once.
struct Verifier {
    jobs: std::sync::mpsc::Sender<Job>,
    results: std::sync::mpsc::Receiver<Result<Vec<u8>, String>>,
    dead: std::cell::Cell<bool>,
}

impl Verifier {
    fn connect() -> Self {
        let xns = xous_names::XousNames::new().unwrap();
        let cid = xns.request_connection_blocking(ipc::VERIFIER_SERVER_NAME).expect("verifier");
        let (jobs, job_rx) = std::sync::mpsc::channel::<Job>();
        let (res_tx, results) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for Job(op, buf, len) in job_rx {
                let cap = buf.len();
                let r = xous::send_message(cid, xous::Message::new_lend_mut(op, buf, None, xous::MemorySize::new(len)));
                let out = match r {
                    Ok(xous::Result::MemoryReturned(_, Some(valid))) => {
                        Ok(unsafe { buf.as_slice::<u8>()[..valid.get().min(cap)].to_vec() })
                    }
                    Ok(xous::Result::MemoryReturned(_, None)) => Ok(Vec::new()),
                    other => Err(format!("verifier IPC failed: {other:?}")),
                };
                xous::unmap_memory(buf).ok();
                if res_tx.send(out).is_err() {
                    break;
                }
            }
        });
        Verifier { jobs, results, dead: std::cell::Cell::new(false) }
    }

    fn simulate(&self, input: &[u8]) -> Result<Vec<u8>, String> {
        self.call(ipc::OP_SIMULATE, input)
    }

    /// Lend `buf` (holding `len` bytes of request, room for the reply) with `op`; returns the
    /// reply bytes. `buf` is consumed (unmapped by the worker, or leaked if the verifier hangs).
    fn call_mapped(&self, op: usize, buf: xous::MemoryRange, len: usize) -> Result<Vec<u8>, String> {
        const DEAD: &str = "verifier unresponsive (it may have run out of memory); press RESET on the device";
        if self.dead.get() {
            xous::unmap_memory(buf).ok();
            return Err(DEAD.into());
        }
        if self.jobs.send(Job(op, buf, len)).is_err() {
            return Err(DEAD.into());
        }
        match self.results.recv_timeout(VERIFIER_TIMEOUT) {
            Ok(r) => r,
            Err(_) => {
                log::error!("verifier did not answer within {VERIFIER_TIMEOUT:?}; refusing further requests");
                self.dead.set(true);
                Err(DEAD.into())
            }
        }
    }

    /// Lend `input` (plus room for the reply) with `op`; returns the verifier's reply bytes.
    fn call(&self, op: usize, input: &[u8]) -> Result<Vec<u8>, String> {
        // room for the reply too (logs and state changes), page-rounded
        let cap = (input.len().max(16 * 1024) + 4095) & !4095;
        let mut range = xous::map_memory(None, None, cap, xous::MemoryFlags::R | xous::MemoryFlags::W)
            .map_err(|e| format!("out of memory for a {cap} B buffer: {e:?}"))?;
        // safety: freshly mapped, `cap` bytes
        unsafe { range.as_slice_mut::<u8>()[..input.len()].copy_from_slice(input) };
        self.call_mapped(op, range, input.len())
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
        wire::TYPE_STATUS => match verifier.call(ipc::OP_STATUS, &[]) {
            Ok(st) => wire::encode_frame(wire::TYPE_STATUS, &st),
            Err(e) => wire::encode_frame(wire::TYPE_ERROR, e.as_bytes()),
        },
        wire::TYPE_POLICY => match verifier.call(ipc::OP_POLICY, &[]) {
            Ok(st) => wire::encode_frame(wire::TYPE_POLICY, &st),
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
    // the verifier's input limit: oversized frames are refused at the length prefix, before
    // the host spends seconds uploading them (and before the transport maps RAM for them)
    let max_frame = verifier
        .call(ipc::OP_STATUS, &[])
        .ok()
        .and_then(|st| <sim_types::DeviceStatus as alloy_rlp::Decodable>::decode(&mut &st[..]).ok())
        .map(|st| st.max_input as usize + 1) // + the type byte
        .unwrap_or(wire::MAX_LEN);
    log::info!("max frame {max_frame} B");
    serve(&verifier, max_frame)
}

#[cfg(not(target_os = "xous"))]
fn serve(verifier: &Verifier, max_frame: usize) -> ! {
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
            if n > max_frame {
                let msg = format!("frame of {n} B exceeds this device's limit of {max_frame} B");
                stream.write_all(&wire::encode_frame(wire::TYPE_ERROR, msg.as_bytes())).ok();
                break; // the host is still sending the body: drop the connection
            }
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

/// A frame being received: the lend buffer it is reassembled into (page-rounded, with room for
/// the reply; `None` for a refused frame, whose bytes are consumed and dropped so the stream
/// stays in sync), the `type || message` length, how many bytes have arrived, and the refusal.
#[cfg(target_os = "xous")]
struct Incoming {
    buf: Option<xous::MemoryRange>,
    need: usize,
    have: usize,
    refusal: Option<String>,
}

#[cfg(target_os = "xous")]
fn serve(verifier: &Verifier, max_frame: usize) -> ! {
    let usb = usb_bao1x::UsbHid::new();
    let mut cur: Option<Incoming> = None;
    loop {
        let report = match usb.hid_wait_incoming() {
            Ok(r) => r,
            Err(e) => {
                log::warn!("HID receive: {e:?}");
                std::thread::sleep(std::time::Duration::from_millis(100));
                continue;
            }
        };
        let mut data: &[u8] = &report;
        if cur.is_none() {
            // first report of a frame: length prefix, then map the whole frame's buffer once
            let Some(need) = wire::frame_len([report[0], report[1], report[2], report[3]]) else {
                // can't be delimited: nothing to skip, answer this report
                send_reports(&usb, &wire::encode_frame(wire::TYPE_ERROR, b"bad length"));
                continue;
            };
            let refused = |msg: String| Incoming { buf: None, need, have: 0, refusal: Some(msg) };
            cur = Some(if need > max_frame {
                // too large: consume and drop the whole frame (no RAM), then refuse
                refused(format!("frame of {need} B exceeds this device's limit of {max_frame} B"))
            } else {
                let cap = (need.max(16 * 1024) + 4095) & !4095;
                match xous::map_memory(None, None, cap, xous::MemoryFlags::R | xous::MemoryFlags::W) {
                    Ok(buf) => Incoming { buf: Some(buf), need, have: 0, refusal: None },
                    Err(e) => refused(format!("device out of memory for a {need} B frame: {e:?}")),
                }
            });
            data = &report[4..];
        }
        let f = cur.as_mut().unwrap();
        let take = data.len().min(f.need - f.have); // padding after the frame is discarded
        if let Some(buf) = f.buf.as_mut() {
            unsafe { buf.as_slice_mut::<u8>()[f.have..f.have + take].copy_from_slice(&data[..take]) };
        }
        f.have += take;
        if f.have < f.need {
            continue;
        }
        let f = cur.take().unwrap();
        let reply = match (f.buf, f.refusal) {
            (Some(buf), None) => handle_mapped(buf, f.need, verifier),
            (_, Some(msg)) => wire::encode_frame(wire::TYPE_ERROR, msg.as_bytes()),
            (None, None) => unreachable!(),
        };
        send_reports(&usb, &reply);
    }
}

/// `handle` for a frame already in a lend buffer: `type` is its first byte, the message follows.
/// Simulate/sign requests are lent to the verifier in place (shifted by one byte for `type`).
#[cfg(target_os = "xous")]
fn handle_mapped(mut buf: xous::MemoryRange, len: usize, verifier: &Verifier) -> Vec<u8> {
    let ty = unsafe { buf.as_slice::<u8>()[0] };
    let op = match ty {
        wire::TYPE_SIMULATE => ipc::OP_SIMULATE,
        wire::TYPE_SIGN => ipc::OP_SIGN,
        _ => {
            // small control messages: copy out and use the common path
            let body = unsafe { buf.as_slice::<u8>()[..len].to_vec() };
            xous::unmap_memory(buf).ok();
            return handle(&body, verifier);
        }
    };
    // drop the type byte so the verifier sees just the message
    unsafe { buf.as_slice_mut::<u8>().copy_within(1..len, 0) };
    match verifier.call_mapped(op, buf, len - 1) {
        Ok(result) => wire::encode_frame(ty, &result),
        Err(e) => wire::encode_frame(wire::TYPE_ERROR, e.as_bytes()),
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

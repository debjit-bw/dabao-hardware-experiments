//! Send a `SimInput` to the device and print the `SimResult`.
//!
//! Framing: `sim_types::wire` (`length u32 BE || type || message`). Over USB HID it is cut
//! into 64-byte reports (vendor interface of `usb-bao1x/generic-hid`, VID 0x1d50 PID 0x6197).

use std::{
    io::{Read, Write},
    time::{Duration, Instant},
};

use alloy_primitives::U256;
use anyhow::{Context, Result, bail};
use sim_types::{SimResult, wire};

const VID: u16 = 0x1d50;
const PID: u16 = 0x6197;
/// The generic-hid vendor interface. The composite (non-generic-hid) image has the same
/// VID/PID but exposes keyboard/FIDO interfaces: never open those.
const VENDOR_USAGE_PAGE: u16 = 0xFF00;

pub fn send(input: &[u8], tcp: Option<&str>) -> Result<()> {
    let frame = wire::encode_frame(wire::TYPE_SIMULATE, input);
    let start = Instant::now();
    let reply = match tcp {
        Some(addr) => tcp_roundtrip(addr, &frame)?,
        None => hid_roundtrip(&frame)?,
    };
    let rtt = start.elapsed();
    let (&ty, msg) = reply.split_first().context("empty reply")?;
    match ty {
        wire::TYPE_SIMULATE => {}
        wire::TYPE_ERROR => bail!("transport error: {}", String::from_utf8_lossy(msg)),
        t => bail!("unexpected reply type {t:#x}"),
    }
    if let Ok(path) = std::env::var("DABAO_DUMP") {
        std::fs::write(&path, &reply)?; // raw `type || message` of the reply, for debugging
    }
    let r: SimResult = alloy_rlp::Decodable::decode(&mut &msg[..]).context("decode SimResult")?;
    println!("sent {} B, round trip {rtt:?} (verifier: {} us, peak heap {} B)", input.len(), r.micros, r.peak_heap);
    if !r.error.is_empty() {
        println!("REJECTED: {}", String::from_utf8_lossy(&r.error));
        return Ok(());
    }
    println!("success={} gas_used={} output={}", r.success, r.gas_used, r.output);
    for l in &r.logs {
        println!("  log {} topics={:?} data={}", l.address, l.topics, l.data);
    }
    for c in &r.changes {
        let d = |a: U256, b: U256| if b >= a { format!("+{}", b - a) } else { format!("-{}", a - b) };
        println!(
            "  {} balance {} nonce {}->{} slots changed {}",
            c.address,
            d(c.balance_before, c.balance_after),
            c.nonce_before,
            c.nonce_after,
            c.slots.len()
        );
        for s in &c.slots {
            println!("    slot {:#x}: {} -> {}", s.slot, s.before, s.after);
        }
    }
    Ok(())
}

fn tcp_roundtrip(addr: &str, frame: &[u8]) -> Result<Vec<u8>> {
    let mut s = std::net::TcpStream::connect(addr).with_context(|| format!("connect {addr}"))?;
    s.set_read_timeout(Some(Duration::from_secs(60)))?;
    s.write_all(frame)?;
    let mut prefix = [0u8; 4];
    s.read_exact(&mut prefix)?;
    let n = wire::frame_len(prefix).context("bad reply length")?;
    let mut body = vec![0u8; n];
    s.read_exact(&mut body)?;
    Ok(body)
}

fn hid_roundtrip(frame: &[u8]) -> Result<Vec<u8>> {
    let api = hidapi::HidApi::new()?;
    let info = api
        .device_list()
        .find(|d| d.vendor_id() == VID && d.product_id() == PID && d.usage_page() == VENDOR_USAGE_PAGE)
        .context("no Dabao vendor HID interface (1d50:6197, usage page 0xFF00); is a generic-hid image running?")?;
    let dev = info.open_device(&api)?;
    // Drop any reply still queued from an earlier, abandoned exchange (there are no request
    // ids, so a stale reply would otherwise be read as this one's start).
    let mut stale = [0u8; 64];
    let mut dropped = 0;
    while dev.read_timeout(&mut stale, 50)? > 0 {
        dropped += 1;
    }
    if dropped > 0 {
        eprintln!("dropped {dropped} stale HID reports");
    }
    for c in frame.chunks(64) {
        let mut r = [0u8; 65]; // report ID 0 + 64 bytes
        r[1..1 + c.len()].copy_from_slice(c);
        dev.write(&r)?;
    }
    let mut buf = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let mut r = [0u8; 64];
        let n = dev.read_timeout(&mut r, 1000)?;
        if n == 0 {
            if Instant::now() > deadline {
                bail!("timeout waiting for the device");
            }
            continue;
        }
        buf.extend_from_slice(&r[..n]);
        if buf.len() >= 4 {
            let need = wire::frame_len([buf[0], buf[1], buf[2], buf[3]]).context("bad reply length")?;
            if buf.len() >= 4 + need {
                return Ok(buf[4..4 + need].to_vec());
            }
        }
    }
}

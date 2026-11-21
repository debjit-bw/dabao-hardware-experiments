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
use alloy::consensus::{Transaction, TxEnvelope, transaction::SignerRecoverable};
use alloy::eips::eip2718::Decodable2718;
use alloy_primitives::Address;
use sim_types::{SignResult, SimInput, SimResult, wire};

const VID: u16 = 0x1d50;
const PID: u16 = 0x6197;
/// The generic-hid vendor interface. The composite (non-generic-hid) image has the same
/// VID/PID but exposes keyboard/FIDO interfaces: never open those.
const VENDOR_USAGE_PAGE: u16 = 0xFF00;

/// One request/reply exchange; returns the reply's `type || message`, checked against `want`.
fn exchange(ty: u8, message: &[u8], want: u8, tcp: Option<&str>) -> Result<(Vec<u8>, Duration)> {
    let frame = wire::encode_frame(ty, message);
    let start = Instant::now();
    let reply = match tcp {
        Some(addr) => tcp_roundtrip(addr, &frame)?,
        None => hid_roundtrip(&frame)?,
    };
    let rtt = start.elapsed();
    if let Ok(path) = std::env::var("DABAO_DUMP") {
        std::fs::write(&path, &reply)?; // raw `type || message` of the reply, for debugging
    }
    let (&rty, msg) = reply.split_first().context("empty reply")?;
    if rty == wire::TYPE_ERROR {
        bail!("transport error: {}", String::from_utf8_lossy(msg));
    }
    if rty != want {
        bail!("unexpected reply type {rty:#x}");
    }
    Ok((msg.to_vec(), rtt))
}

pub fn status(tcp: Option<&str>) -> Result<()> {
    let (st, rtt) = exchange(wire::TYPE_STATUS, &[], wire::TYPE_STATUS, tcp)?;
    let st: sim_types::DeviceStatus = alloy_rlp::Decodable::decode(&mut &st[..]).context("decode DeviceStatus")?;
    let kb = |b: u64| format!("{} KB", b / 1024);
    println!(
        "free RAM: {}; verifier heap cap: {}; max input: {}; signer: {}; (round trip {rtt:?})",
        if st.free_ram_at_boot == 0 { "not measured".into() } else { kb(st.free_ram_at_boot) },
        kb(st.heap_limit),
        kb(st.max_input),
        if st.signer.len() == 20 { Address::from_slice(&st.signer).to_string() } else { "not attached".into() }
    );
    Ok(())
}

pub fn policy(tcp: Option<&str>) -> Result<()> {
    let (st, _) = exchange(wire::TYPE_POLICY, &[], wire::TYPE_POLICY, tcp)?;
    let st: sim_types::PolicyStatus = alloy_rlp::Decodable::decode(&mut &st[..]).context("decode PolicyStatus")?;
    for l in &st.lines {
        println!("{}", String::from_utf8_lossy(l));
    }
    Ok(())
}

/// A light-client request (`TYPE_LC_*`); returns the device's light-client status.
pub fn lc(ty: u8, message: &[u8], tcp: Option<&str>) -> Result<sim_types::lc::Status> {
    let (st, _) = exchange(ty, message, ty, tcp)?;
    Ok(alloy_rlp::Decodable::decode(&mut &st[..]).context("decode lc::Status")?)
}

pub fn address(tcp: Option<&str>) -> Result<Address> {
    let (a, _) = exchange(wire::TYPE_ADDRESS, &[], wire::TYPE_ADDRESS, tcp)?;
    if a.len() != 20 {
        bail!("bad address length {}", a.len());
    }
    Ok(Address::from_slice(&a))
}

/// Send `input` without the local size check (tests the device-side refusal).
pub fn send_unchecked(input: &[u8], tcp: Option<&str>) -> Result<()> {
    match exchange(wire::TYPE_SIMULATE, input, wire::TYPE_SIMULATE, tcp) {
        Ok(_) => println!("device accepted {} B", input.len()),
        Err(e) => println!("device refused {} B: {e:#}", input.len()),
    }
    Ok(())
}

/// Refuse locally (before a multi-second upload) if `input` exceeds the device's limit.
fn precheck(input: &[u8], tcp: Option<&str>) -> Result<()> {
    let (st, _) = exchange(wire::TYPE_STATUS, &[], wire::TYPE_STATUS, tcp)?;
    let st: sim_types::DeviceStatus = alloy_rlp::Decodable::decode(&mut &st[..]).context("decode DeviceStatus")?;
    if input.len() as u64 > st.max_input {
        bail!("input of {} B exceeds the device's limit of {} B (not sent)", input.len(), st.max_input);
    }
    Ok(())
}

pub fn send(input: &[u8], tcp: Option<&str>) -> Result<()> {
    precheck(input, tcp)?;
    let (msg, rtt) = exchange(wire::TYPE_SIMULATE, input, wire::TYPE_SIMULATE, tcp)?;
    let r: SimResult = alloy_rlp::Decodable::decode(&mut &msg[..]).context("decode SimResult")?;
    println!("sent {} B, round trip {rtt:?} (verifier: {} us, peak heap {} B)", input.len(), r.micros, r.peak_heap);
    let chain_id = alloy_rlp::Decodable::decode(&mut &input[..]).map(|i: SimInput| i.chain_id).unwrap_or(1);
    print_sim(&r, chain_id);
    Ok(())
}

/// Ask the device to simulate and sign; independently check what comes back.
pub fn sign(input: &[u8], tcp: Option<&str>) -> Result<()> {
    sign_checked(input, tcp).map(|_| ())
}

/// `sign`, returning the device's simulation and the verified signed tx (if it signed).
pub fn sign_checked(input: &[u8], tcp: Option<&str>) -> Result<(SimResult, Option<Vec<u8>>)> {
    let req: SimInput = alloy_rlp::Decodable::decode(&mut &input[..]).context("decode SimInput")?;
    precheck(input, tcp)?;
    let (msg, rtt) = exchange(wire::TYPE_SIGN, input, wire::TYPE_SIGN, tcp)?;
    let r: SignResult = alloy_rlp::Decodable::decode(&mut &msg[..]).context("decode SignResult")?;
    println!(
        "sign request {} B, round trip {rtt:?} (verifier: {} us, peak heap {} B); device address {}",
        input.len(),
        r.sim.micros,
        r.sim.peak_heap,
        r.signer
    );
    print_sim(&r.sim, req.chain_id);
    if !r.refused.is_empty() {
        println!("NOT SIGNED: {}", String::from_utf8_lossy(&r.refused));
        return Ok((r.sim, None));
    }
    // Don't trust the device's word either: decode, recover, compare with what we asked for.
    let tx = TxEnvelope::decode_2718(&mut &r.signed_tx[..]).context("decode signed tx")?;
    let recovered = tx.recover_signer().context("recover signer")?;
    let t = &req.tx;
    let checks = [
        ("signer == device address", recovered == r.signer),
        ("signer == tx.from", recovered == t.from),
        ("chain id", tx.chain_id() == Some(req.chain_id)),
        ("nonce", tx.nonce() == t.nonce),
        ("to", tx.to() == Some(t.to)),
        ("value", tx.value() == t.value),
        ("gas limit", tx.gas_limit() == t.gas_limit),
        ("tx type", tx.is_legacy() == t.max_priority_fee_per_gas.is_none()),
        ("fees", match t.max_priority_fee_per_gas {
            None => tx.gas_price() == Some(t.gas_price),
            Some(tip) => tx.max_fee_per_gas() == t.gas_price && tx.max_priority_fee_per_gas() == Some(tip),
        }),
        ("no access list", tx.access_list().is_none_or(|l| l.0.is_empty())),
        ("calldata", tx.input() == &t.data),
    ];
    for (what, ok) in &checks {
        println!("  check {what}: {}", if *ok { "ok" } else { "MISMATCH" });
    }
    if checks.iter().any(|(_, ok)| !ok) {
        bail!("the signed transaction does not match the request");
    }
    println!("SIGNED ({} B, tx hash {}): 0x{}", r.signed_tx.len(), tx.tx_hash(), alloy_primitives::hex::encode(&r.signed_tx));
    Ok((r.sim, Some(r.signed_tx.to_vec())))
}

/// Ask the device to co-sign a Safe transaction (`input.tx.from` = the Safe); prints the
/// simulation. The caller checks the signature against the SafeTx hash it computes itself.
pub fn safe_sign(input: &[u8], tcp: Option<&str>) -> Result<SignResult> {
    let req: SimInput = alloy_rlp::Decodable::decode(&mut &input[..]).context("decode SimInput")?;
    precheck(input, tcp)?;
    let (msg, rtt) = exchange(wire::TYPE_SAFE_SIGN, input, wire::TYPE_SAFE_SIGN, tcp)?;
    let r: SignResult = alloy_rlp::Decodable::decode(&mut &msg[..]).context("decode SignResult")?;
    println!(
        "Safe co-sign request {} B, round trip {rtt:?} (verifier: {} us, peak heap {} B); device {}",
        input.len(),
        r.sim.micros,
        r.sim.peak_heap,
        r.signer
    );
    print_sim(&r.sim, req.chain_id);
    if !r.refused.is_empty() {
        println!("NOT CO-SIGNED: {}", String::from_utf8_lossy(&r.refused));
    }
    Ok(r)
}

/// One line per effect, e.g. "ERC20 transfer  0.5 USDC: 0x08a1… -> 0x8fb0…" (amounts with the
/// firmware's token list, the same the device uses for its shown fields).
fn describe(e: &sim_types::Effect, chain_id: u64) -> String {
    use sim_types::effect as k;
    let name = match e.kind {
        k::NATIVE_OUT => "ETH out",
        k::NATIVE_IN => "ETH in",
        k::GAS_FEE => "gas fee",
        k::ERC20_TRANSFER => "ERC20 transfer",
        k::ERC20_APPROVAL => "ERC20 APPROVAL",
        k::NFT_TRANSFER => "NFT transfer",
        k::NFT_APPROVAL => "NFT APPROVAL",
        k::APPROVAL_FOR_ALL => "APPROVAL FOR ALL",
        k::ERC1155_TRANSFER => "ERC1155 transfer",
        k::PERMIT2_APPROVAL => "PERMIT2 APPROVAL",
        k::OWNERSHIP_TRANSFER => "OWNERSHIP CHANGE",
        k::PROXY_UPGRADE => "PROXY UPGRADE",
        k::PROXY_ADMIN_CHANGE => "PROXY ADMIN CHANGE",
        k::UNEXPLAINED_STORAGE => "UNEXPLAINED STORAGE",
        k::WRAP => "wrap",
        k::UNWRAP => "unwrap",
        k::POOL_SWAP => "pool swap",
        k::NET_GAIN => "sender NET +",
        k::NET_LOSS => "sender NET -",
        _ => "unknown kind",
    };
    let set = &*TOKENS;
    let asset = if e.contract.is_zero() { "ETH".to_string() } else { e.contract.to_string() };
    let amt = |a: Address| clear_sign::check::format_amount(set, chain_id, a, e.amount);
    match e.kind {
        k::NATIVE_OUT | k::GAS_FEE => format!("{name:<20} {} from {}", amt(Address::ZERO), e.from),
        k::NATIVE_IN => format!("{name:<20} {} to {}", amt(Address::ZERO), e.to),
        k::NET_GAIN | k::NET_LOSS => format!("{name:<20} {}", amt(e.contract)),
        k::ERC20_TRANSFER | k::ERC20_APPROVAL => format!("{name:<20} {}: {} -> {}", amt(e.contract), e.from, e.to),
        k::WRAP | k::UNWRAP => format!("{name:<20} {}: {} -> {}", amt(e.contract), e.from, e.to),
        k::UNEXPLAINED_STORAGE => format!("{name:<20} {asset}: {} slots changed, no recognised event", e.amount),
        k::POOL_SWAP | k::OWNERSHIP_TRANSFER | k::PROXY_UPGRADE | k::PROXY_ADMIN_CHANGE => {
            format!("{name:<20} {asset}: {} -> {}", e.from, e.to)
        }
        _ => format!("{name:<20} {asset} {}: {} -> {}", e.amount, e.from, e.to),
    }
}

/// The firmware's descriptor set (for its token list).
static TOKENS: std::sync::LazyLock<clear_sign::model::DescriptorSet> = std::sync::LazyLock::new(clear_sign::builtin);

fn print_sim(r: &SimResult, chain_id: u64) {
    if !r.error.is_empty() {
        println!("REJECTED: {}", String::from_utf8_lossy(&r.error));
        return;
    }
    println!("success={} gas_used={} output={}", r.success, r.gas_used, r.output);
    println!("effects ({}):", r.effects.len());
    for e in &r.effects {
        println!("  {}", describe(e, chain_id));
    }
    let cs = &r.clear_sign;
    let s = |b: &[u8]| String::from_utf8_lossy(b).to_string();
    if cs.descriptor.is_empty() {
        println!("ERC-7730: no descriptor matched");
    } else {
        println!("ERC-7730: '{}', intent '{}'", s(&cs.descriptor), s(&cs.intent));
    }
    for f in &cs.fields {
        println!("  shown  {:<32} {}", s(&f.label), s(&f.value));
    }
    if cs.violations.is_empty() {
        if !cs.descriptor.is_empty() {
            println!("  verdict: every effect is explained by what is shown");
        }
    } else {
        for v in &cs.violations {
            println!("  VIOLATION {}", s(v));
        }
    }
    for w in &cs.warnings {
        println!("  WARNING {}", s(w));
    }
    if r.header_check.is_empty() {
        println!("light client: parent header proven canonical (sync committee + execution branch)");
    } else {
        println!("light client: HEADER NOT VERIFIED: {}", s(&r.header_check));
    }
    let p = &r.policy;
    println!("policy '{}':", s(&p.policy));
    for n in &p.notes {
        println!("  {}", s(n));
    }
    for v in &p.violations {
        println!("  POLICY VIOLATION {}", s(v));
    }
    if std::env::var_os("DABAO_VERBOSE").is_none() {
        return; // raw logs and state changes only with DABAO_VERBOSE=1
    }
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
    // always send the whole frame: the device consumes a refused frame to the end before
    // answering, so the report stream never loses sync
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

//! `dabao-host lc-fixture <out.rlp>`: record a real Sepolia light-client update (the latest
//! finality update and its period's sync committee) from a beacon node with the light-client
//! server enabled (BEACON_URL, default Lodestar's public Sepolia node), and check it here with
//! the same code the device runs.

use alloy_primitives::{B256, Bytes};
use anyhow::{Context, Result, ensure};
use light_client::{BeaconHeader, Committee, Fixture, period, signing_root, verify_sync_aggregate};
use serde_json::Value;

fn beacon() -> String {
    std::env::var("BEACON_URL").unwrap_or_else(|_| "https://lodestar-sepolia.chainsafe.io".into())
}

async fn get(path: &str) -> Result<Value> {
    let url = format!("{}{path}", beacon());
    let r = alloy::transports::http::reqwest::Client::new().get(&url).header("accept", "application/json").send().await?;
    ensure!(r.status().is_success(), "{url}: HTTP {}", r.status());
    Ok(r.json().await?)
}

fn u64_of(v: &Value) -> Result<u64> {
    Ok(v.as_str().context("expected a decimal string")?.parse()?)
}

fn hex(v: &Value) -> Result<Bytes> {
    Ok(v.as_str().context("expected hex")?.parse()?)
}

fn header(h: &Value) -> Result<BeaconHeader> {
    Ok(BeaconHeader {
        slot: u64_of(&h["slot"])?,
        proposer_index: u64_of(&h["proposer_index"])?,
        parent_root: h["parent_root"].as_str().context("parent_root")?.parse()?,
        state_root: h["state_root"].as_str().context("state_root")?.parse()?,
        body_root: h["body_root"].as_str().context("body_root")?.parse()?,
    })
}

pub async fn fixture(out: &str) -> Result<()> {
    let u = get("/eth/v1/beacon/light_client/finality_update").await?;
    let d = &u["data"];
    let h = header(&d["attested_header"]["beacon"])?;
    let signature_slot = u64_of(&d["signature_slot"])?;
    let bits = hex(&d["sync_aggregate"]["sync_committee_bits"])?;
    let signature = hex(&d["sync_aggregate"]["sync_committee_signature"])?;
    // Capella..Fulu: `execution` (an ExecutionPayloadHeader); Gloas (ePBS): `execution_block_hash`
    let ah = &d["attested_header"];
    let exec_hash: B256 = ah["execution"]["block_hash"].as_str().or(ah["execution_block_hash"].as_str()).context("execution block hash")?.parse()?;
    let p = period(signature_slot);
    // the update for period p-1 carries the committee of period p as its next_sync_committee
    let ups = get(&format!("/eth/v1/beacon/light_client/updates?start_period={}&count=1", p - 1)).await?;
    let keys: Vec<Bytes> = ups[0]["data"]["next_sync_committee"]["pubkeys"]
        .as_array()
        .context("next_sync_committee.pubkeys")?
        .iter()
        .map(hex)
        .collect::<Result<_>>()?;
    println!(
        "attested header slot {} (period {}), signature slot {signature_slot} (period {p}); {} committee keys; execution block {exec_hash}",
        h.slot,
        period(h.slot),
        keys.len()
    );
    let f = Fixture { header: h, signature_slot, bits, signature, pubkeys: keys, execution_block_hash: exec_hash };

    // check it here with the device's code
    let start = std::time::Instant::now();
    let now = || start.elapsed().as_micros() as u64;
    let t0 = now();
    let c = Committee::from_compressed(&f.pubkeys).map_err(anyhow::Error::msg)?;
    let decompress = now() - t0;
    let root = signing_root(&f.header, f.signature_slot);
    let n = light_client::participants(&f.bits).len();
    let t = verify_sync_aggregate(&c, &f.bits, &f.signature, root, &now).map_err(anyhow::Error::msg)?;
    println!(
        "host: VERIFIED ({n}/512 signed): header root {}, signing root {root}; decompress 512 keys {decompress} us, {t:?}",
        f.header.hash_tree_root()
    );
    std::fs::write(out, alloy_rlp::encode(&f))?;
    println!("-> {out}");
    Ok(())
}

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
        light_client::header_root(&f.header)
    );
    std::fs::write(out, alloy_rlp::encode(&f))?;
    println!("-> {out}");
    Ok(())
}

fn signed(d: &Value) -> Result<light_client::Signed> {
    Ok(light_client::Signed {
        attested: header(&d["attested_header"]["beacon"])?,
        signature_slot: u64_of(&d["signature_slot"])?,
        bits: hex(&d["sync_aggregate"]["sync_committee_bits"])?,
        signature: hex(&d["sync_aggregate"]["sync_committee_signature"])?,
    })
}

fn branch(v: &Value) -> Result<Vec<B256>> {
    v.as_array().context("branch")?.iter().map(|x| Ok(x.as_str().context("hex")?.parse()?)).collect()
}

fn committee(period: u64, c: &Value) -> Result<sim_types::lc::Committee> {
    Ok(sim_types::lc::Committee {
        period,
        pubkeys: c["pubkeys"].as_array().context("pubkeys")?.iter().map(hex).collect::<Result<_>>()?,
        aggregate: hex(&c["aggregate_pubkey"])?,
    })
}

/// The committee of `period`: the `next_sync_committee` of period `period - 1`'s update.
async fn committee_of(period: u64) -> Result<sim_types::lc::Committee> {
    let ups = get(&format!("/eth/v1/beacon/light_client/updates?start_period={}&count=1", period - 1)).await?;
    committee(period, &ups[0]["data"]["next_sync_committee"])
}

/// `dabao-host lc-anchor`: the trust anchor for the firmware. Takes the finalized checkpoint,
/// cross-checks its root against a second beacon node, verifies the bootstrap's
/// current-sync-committee branch against it, and writes crates/light-client/src/anchor.rs.
pub async fn anchor() -> Result<()> {
    let fin = get("/eth/v1/beacon/headers/finalized").await?;
    let root: B256 = fin["data"]["root"].as_str().context("root")?.parse()?;
    let slot = u64_of(&fin["data"]["header"]["message"]["slot"])?;
    let other = std::env::var("BEACON_URL_2").unwrap_or_else(|_| "https://ethereum-sepolia-beacon-api.publicnode.com".into());
    let r = alloy::transports::http::reqwest::Client::new().get(format!("{other}/eth/v1/beacon/headers/{slot}")).header("accept", "application/json").send().await?;
    let o: Value = r.json().await?;
    let root2: B256 = o["data"]["root"].as_str().context("second node: root")?.parse()?;
    ensure!(root == root2, "finalized slot {slot}: {} says {root}, {other} says {root2}", beacon());
    let b = get(&format!("/eth/v1/beacon/light_client/bootstrap/{root}")).await?;
    let h = header(&b["data"]["header"]["beacon"])?;
    ensure!(light_client::header_root(&h) == root, "bootstrap header does not hash to the checkpoint");
    let p = period(h.slot);
    let c = committee(p, &b["data"]["current_sync_committee"])?;
    let croot = light_client::committee_root(&c.pubkeys, &c.aggregate).map_err(anyhow::Error::msg)?;
    ensure!(
        light_client::verify_branch(croot, &branch(&b["data"]["current_sync_committee_branch"])?, light_client::GINDEX_CURRENT_SYNC_COMMITTEE, h.state_root),
        "current sync committee branch does not verify"
    );
    println!("checkpoint slot {slot} root {root} (same on {} and {other}); period {p} committee root {croot}", beacon());
    let src = format!(
        "//! Generated by `dabao-host lc-anchor`: the light client's trust anchor, compiled into the\n\
         //! firmware. Finalized checkpoint slot {slot}, root {root} (cross-checked on two beacon\n\
         //! nodes); its state's current_sync_committee (branch verified) has this root.\n\n\
         use alloy_primitives::{{B256, b256}};\n\n\
         pub const PERIOD: u64 = {p};\n\
         pub const COMMITTEE_ROOT: B256 = b256!(\"{croot}\");\n\
         pub const CHECKPOINT_SLOT: u64 = {slot};\n"
    );
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../crates/light-client/src/anchor.rs");
    std::fs::write(path, src)?;
    println!("-> crates/light-client/src/anchor.rs");
    Ok(())
}

/// The latest optimistic update as a header proof (the newest head the committee signed).
pub async fn header_proof() -> Result<sim_types::lc::HeaderProof> {
    let u = get("/eth/v1/beacon/light_client/optimistic_update").await?;
    let d = &u["data"];
    let ah = &d["attested_header"];
    Ok(sim_types::lc::HeaderProof {
        signed: signed(d)?,
        execution_block_hash: ah["execution_block_hash"].as_str().context("execution_block_hash (Gloas)")?.parse()?,
        execution_branch: branch(&ah["execution_branch"])?,
    })
}

fn show(s: &sim_types::lc::Status) {
    println!(
        "device light client: period {} committee {} ({}); highest slot {}{}",
        s.period,
        s.committee_root,
        if s.loaded { "keys loaded" } else { "keys NOT loaded" },
        s.highest_slot,
        if s.note.is_empty() { String::new() } else { format!("; {}", String::from_utf8_lossy(&s.note)) }
    );
}

/// `dabao-host lc-sync`: load the device's committee and walk it forward to the chain's current
/// period. Everything sent is verified by the device; this only fetches.
pub async fn sync(tcp: Option<&str>) -> Result<sim_types::lc::Status> {
    use sim_types::wire;
    loop {
        let s = crate::send::lc(wire::TYPE_LC_STATUS, &[], tcp)?;
        show(&s);
        if !s.loaded {
            let c = committee_of(s.period).await?;
            let t = std::time::Instant::now();
            let r = crate::send::lc(wire::TYPE_LC_COMMITTEE, &alloy_rlp::encode(&c), tcp)?;
            println!("uploaded committee of period {} ({:?})", s.period, t.elapsed());
            show(&r);
            ensure!(r.loaded, "device refused the committee");
            continue;
        }
        let head = get("/eth/v1/beacon/light_client/optimistic_update").await?;
        let chain_period = period(u64_of(&head["data"]["signature_slot"])?);
        if s.period >= chain_period {
            println!("in sync (chain period {chain_period})");
            return Ok(s);
        }
        let ups = get(&format!("/eth/v1/beacon/light_client/updates?start_period={}&count=1", s.period)).await?;
        let d = &ups[0]["data"];
        let u = sim_types::lc::CommitteeUpdate {
            signed: signed(d)?,
            next: committee(s.period + 1, &d["next_sync_committee"])?,
            next_branch: branch(&d["next_sync_committee_branch"])?,
        };
        let r = crate::send::lc(wire::TYPE_LC_UPDATE, &alloy_rlp::encode(&u), tcp)?;
        show(&r);
        ensure!(r.period == s.period + 1, "device refused the hand-off to period {}", s.period + 1);
    }
}

/// The parent block for a transaction: the execution block the sync committee most recently
/// signed (optimistic update), with its proof. Also makes sure the device's light client is
/// loaded and current.
pub async fn parent(p: &impl alloy::providers::Provider, tcp: Option<&str>) -> Result<(sim_types::lc::HeaderProof, alloy::rpc::types::Block)> {
    sync(tcp).await?;
    // test switch: replay a recorded (older) proof, e.g. crates/light-client/fixtures/header-proof.rlp
    let replay: Option<sim_types::lc::HeaderProof> = match std::env::var("DABAO_LC_REPLAY") {
        Ok(f) => Some(alloy_rlp::Decodable::decode(&mut &std::fs::read(f)?[..])?),
        Err(_) => None,
    };
    for attempt in 0..10 {
        let proof = match &replay {
            Some(p) => p.clone(),
            None => header_proof().await?,
        };
        match p.get_block_by_hash(proof.execution_block_hash).await? {
            Some(b) => {
                println!(
                    "parent: execution block {} ({}) from beacon slot {} (signed by {} of 512)",
                    b.header.number,
                    proof.execution_block_hash,
                    proof.signed.attested.slot,
                    light_client::participants(&proof.signed.bits).len()
                );
                return Ok((proof, b));
            }
            // the RPC node may not have the block yet (or, under ePBS, the payload was withheld)
            None => {
                println!("  execution block {} not on the RPC node yet (attempt {attempt})", proof.execution_block_hash);
                tokio::time::sleep(std::time::Duration::from_secs(4)).await;
            }
        }
    }
    anyhow::bail!("no signed head whose execution block the RPC node has")
}

/// `dabao-host lc-fixtures <dir>`: record test fixtures: the committees of the anchor period and
/// the one before, the hand-off between them, and a fresh header proof.
pub async fn fixtures(dir: &str) -> Result<()> {
    let p = light_client::anchor::PERIOD;
    let prev = committee_of(p - 1).await?;
    let cur = committee_of(p).await?;
    let ups = get(&format!("/eth/v1/beacon/light_client/updates?start_period={}&count=1", p - 1)).await?;
    let d = &ups[0]["data"];
    let u = sim_types::lc::CommitteeUpdate { signed: signed(d)?, next: committee(p, &d["next_sync_committee"])?, next_branch: branch(&d["next_sync_committee_branch"])? };
    let hp = header_proof().await?;
    for (name, bytes) in [
        (format!("committee-{}.rlp", p - 1), alloy_rlp::encode(&prev)),
        (format!("committee-{p}.rlp"), alloy_rlp::encode(&cur)),
        (format!("update-{}.rlp", p - 1), alloy_rlp::encode(&u)),
        ("header-proof.rlp".to_string(), alloy_rlp::encode(&hp)),
    ] {
        std::fs::write(format!("{dir}/{name}"), &bytes)?;
        println!("{dir}/{name}: {} B", bytes.len());
    }
    Ok(())
}

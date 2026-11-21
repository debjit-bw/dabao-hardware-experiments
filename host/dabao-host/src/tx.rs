//! `dabao-host send-tx --to ADDR [--value WEI] [--data 0x..] [--broadcast] [--tcp ADDR]`
//!
//! A transaction *from the device's own address* on a live chain (RPC_URL; `--chain sepolia`
//! picks publicnode's free Sepolia endpoint):
//!
//! 1. ask the device for its address;
//! 2. build a `SimInput` on the latest block: the account's nonce, a legacy gas price with
//!    headroom, a gas estimate, `eth_createAccessList` and `eth_getProof` for everything touched;
//! 3. the device simulates, runs the ERC-7730 check and signs (or refuses); the host re-verifies
//!    the signature and every field against the request;
//! 4. `--broadcast`: `eth_sendRawTransaction`, wait for the receipt, and compare the logs that
//!    landed on chain with the logs the device predicted.
//!
//! If the call can't be executed (e.g. an unfunded account), the witness still covers the sender,
//! the target and the beneficiary, so the device simulates it and refuses with its own reason.

use std::time::{Duration, Instant};

use alloy::{
    consensus::Header,
    eips::{BlockId, BlockNumberOrTag, eip1559::BaseFeeParams},
    network::TransactionBuilder,
    providers::Provider,
    rpc::types::TransactionRequest,
};
use alloy_primitives::{Address, B256, Bytes, U256};
use anyhow::{Context, Result, bail, ensure};
use sim_types::{SimBlock, SimInput, SimTx};

pub struct Args {
    pub to: Address,
    pub value: U256,
    pub data: Bytes,
    pub broadcast: bool,
}

fn explorer(chain_id: u64, hash: B256) -> String {
    match chain_id {
        1 => format!("https://etherscan.io/tx/{hash}"),
        11155111 => format!("https://sepolia.etherscan.io/tx/{hash}"),
        _ => format!("{hash}"),
    }
}

pub async fn run(p: &impl Provider, a: Args, tcp: Option<&str>) -> Result<()> {
    let from = crate::send::address(tcp).context("ask the device for its address")?;
    let chain_id = p.get_chain_id().await?;
    let n = p.get_block_number().await?;
    let at = BlockId::number(n);
    let block = p.get_block_by_number(BlockNumberOrTag::Number(n)).await?.context("block")?;
    let ph: Header = block.header.inner.clone();
    ensure!(ph.hash_slow() == block.header.hash, "RLP header does not hash to the block hash");
    let basefee = ph.next_block_base_fee(BaseFeeParams::ethereum()).context("pre-London header")?;
    // legacy gas price: 2 x next basefee (room for a few blocks of increases) + 1 gwei tip
    let gas_price = 2 * basefee.max(ph.base_fee_per_gas.unwrap_or(0)) as u128 + 1_000_000_000;
    let nonce = p.get_transaction_count(from).block_id(at).await?;
    let balance = p.get_balance(from).block_id(at).await?;
    println!("device {from} on chain {chain_id}: balance {balance} wei, nonce {nonce}; block {n}, gas price {gas_price} wei");

    let mut req = TransactionRequest::default()
        .with_from(from)
        .with_to(a.to)
        .with_value(a.value)
        .with_input(a.data.clone())
        .with_nonce(nonce)
        .with_gas_price(gas_price);
    let gas_limit = match p.estimate_gas(req.clone()).block(at).await {
        Ok(g) => g + g / 4 + 5_000,
        Err(e) => {
            println!("  (node can't estimate gas: {e}; using 100000, the device will decide)");
            100_000
        }
    };
    req = req.with_gas_limit(gas_limit);
    let al = match p.create_access_list(&req).block_id(at).await {
        Ok(al) if al.error.is_none() => al.access_list,
        Ok(al) => {
            println!("  (node: the call fails: {}; minimal witness, the device will decide)", al.error.unwrap_or_default());
            Default::default()
        }
        Err(e) => {
            println!("  (createAccessList failed: {e}; minimal witness)");
            Default::default()
        }
    };
    let (state, codes, keys, n_acc, n_slots) =
        crate::replay::witness_for(p, at, &al, &[from, a.to, ph.beneficiary]).await?;
    let input = SimInput {
        chain_id,
        parent_header: alloy_rlp::encode(&ph).into(),
        block: SimBlock {
            number: n + 1,
            timestamp: ph.timestamp + 12,
            basefee,
            gas_limit: ph.gas_limit,
            beneficiary: ph.beneficiary,
            prevrandao: ph.mix_hash,
        },
        tx: SimTx { from, to: a.to, nonce, gas_limit, gas_price, value: a.value, data: a.data },
        state,
        codes,
        keys,
    };
    let bytes = alloy_rlp::encode(&input);
    println!("witness: {n_acc} accounts, {n_slots} slots, {} nodes, {} B", input.state.len(), bytes.len());

    let (sim, signed) = crate::send::sign_checked(&bytes, tcp)?;
    let Some(raw) = signed else { return Ok(()) };
    if !a.broadcast {
        println!("(not broadcast; add --broadcast to send it)");
        return Ok(());
    }

    let pending = p.send_raw_transaction(&raw).await.context("eth_sendRawTransaction")?;
    let hash = *pending.tx_hash();
    println!("broadcast {hash}\n  {}", explorer(chain_id, hash));
    let start = Instant::now();
    let receipt = loop {
        if let Some(r) = p.get_transaction_receipt(hash).await? {
            break r;
        }
        if start.elapsed() > Duration::from_secs(180) {
            bail!("no receipt after 3 minutes (still pending?)");
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    };
    let chain_logs: Vec<(Address, Vec<B256>, Bytes)> =
        receipt.inner.logs().iter().map(|l| (l.address(), l.topics().to_vec(), l.data().data.clone())).collect();
    let dev_logs: Vec<(Address, Vec<B256>, Bytes)> = sim.logs.iter().map(|l| (l.address, l.topics.clone(), l.data.clone())).collect();
    println!(
        "included in block {} after {:?}: status {} (device predicted {}); gas used {} (device predicted {}); logs {}",
        receipt.block_number.unwrap_or_default(),
        start.elapsed(),
        receipt.status(),
        sim.success,
        receipt.gas_used,
        sim.gas_used,
        if chain_logs == dev_logs { format!("IDENTICAL to the device's prediction ({})", dev_logs.len()) } else { format!("DIFFER (chain {}, device {})", chain_logs.len(), dev_logs.len()) }
    );
    Ok(())
}

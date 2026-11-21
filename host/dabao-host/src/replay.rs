//! `build --replay <txhash>` / `build --find-swap`: simulate a real mainnet transaction.
//!
//! * **Replay** (preferred): the tx exactly as mined in block N, on block N-1's post-state, in
//!   block N's environment. Earlier txs in block N are not applied, so a result can differ from
//!   the chain if one of them touched the same state. After building, the host runs the same
//!   simulator (`xous-evm`) locally and compares its logs with the tx receipt's logs.
//!   Needs an RPC whose `eth_getProof` window reaches N-1 (Ankr with a key: 128 blocks).
//! * **Redo now** (fallback when the node refuses older proofs, e.g. publicnode serves the
//!   latest block only): the same call (sender, target, calldata, value) on the latest block,
//!   with the sender's current nonce, in the next block's environment. All proofs must be
//!   fetched before the next block (~12 s); the builder pins one block and retries.
//!
//! RPC_URL selects the node (default publicnode). It may carry an API key: never commit it.

use std::collections::{BTreeMap, BTreeSet};

use alloy::{
    consensus::{Header, Transaction as _},
    eips::{BlockId, BlockNumberOrTag},
    network::{TransactionBuilder, TransactionResponse},
    providers::Provider,
    rpc::types::TransactionRequest,
};
use alloy_primitives::{Address, B256, Bytes, address, keccak256};
use anyhow::{Context, Result, bail, ensure};
use sim_types::{SimBlock, SimInput, SimTx};

/// Uniswap routers whose swaps go through v2/v3 pools (v4's singleton PoolManager is not
/// targeted yet): V2 Router02, SwapRouter02, Universal Router v1.2.
const ROUTERS: [(Address, &str); 3] = [
    (address!("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"), "Uniswap V2 Router02"),
    (address!("0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"), "Uniswap SwapRouter02"),
    (address!("0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD"), "Uniswap Universal Router v1.2"),
];

/// A successful tx to one of `ROUTERS` in the newest block, waiting for new blocks if needed.
/// Only the newest block: its parent must still be inside the RPC's proof window (publicnode
/// refuses eth_getProof a few blocks behind the tip).
async fn find_swap(p: &impl Provider, tries: u32, skip: &BTreeSet<B256>) -> Result<B256> {
    let mut seen = 0;
    for _ in 0..tries {
        let b = p.get_block_number().await?;
        if b == seen {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            continue;
        }
        seen = b;
        let block = p.get_block_by_number(BlockNumberOrTag::Number(b)).full().await?.context("block")?;
        let txs: Vec<_> = block.transactions.txns().collect();
        for tx in txs.into_iter().rev() {
            let Some(to) = tx.to() else { continue };
            if let Some((_, name)) = ROUTERS.iter().find(|(a, _)| *a == to) {
                let h = tx.tx_hash();
                if skip.contains(&h) {
                    continue;
                }
                if p.get_transaction_receipt(h).await?.map(|r| r.status()).unwrap_or(false) {
                    println!("found {name} swap {h} in block {b}");
                    return Ok(h);
                }
            }
        }
        println!("no Uniswap v2/v3 router swap in block {b}, waiting for the next one");
    }
    bail!("no successful Uniswap router tx found; try again")
}

pub async fn build(p: &impl Provider, hash: Option<B256>, out: &str) -> Result<()> {
    if let Some(h) = hash {
        return build_one(p, h, out).await;
    }
    // --find-swap: many swaps can't be repeated (the sender sold their whole balance); try
    // candidates until one simulates
    let mut skip = BTreeSet::new();
    for _ in 0..30 {
        let h = find_swap(p, 60, &skip).await?;
        match build_one(p, h, out).await {
            Ok(()) => return Ok(()),
            Err(e) if format!("{e:#}").contains("the same call") => {
                println!("  {e:#}; next candidate");
                skip.insert(h);
            }
            Err(e) => return Err(e),
        }
    }
    bail!("no repeatable swap found")
}

async fn build_one(p: &impl Provider, hash: B256, out: &str) -> Result<()> {
    let tx = p.get_transaction_by_hash(hash).await?.context("tx not found")?;
    let to = tx.to().context("contract creation is not supported")?;
    let from = tx.from();
    match replay_on_parent(p, hash, &tx, from, to, out).await {
        Ok(()) => return Ok(()),
        Err(e) if format!("{e:#}").contains("proof window") || format!("{e:#}").contains("missing trie node") => {
            println!("parent-state proofs not available from this RPC ({e:#}); falling back to redo-now");
        }
        Err(e) => return Err(e),
    }
    for attempt in 1..=5 {
        match build_at_latest(p, hash, &tx, from, to, out).await {
            Ok(()) => return Ok(()),
            Err(e) if format!("{e:#}").contains("proof window") => {
                println!("attempt {attempt}: a new block arrived while fetching proofs; retrying");
            }
            Err(e) => return Err(e),
        }
    }
    bail!("couldn't fetch all proofs within one block; try again (or set RPC_URL to a node with a wider proof window)")
}

/// Collect proofs for every account / slot the access list names, plus `extra` accounts.
pub(crate) async fn witness(
    p: &impl Provider,
    at: BlockId,
    req: &TransactionRequest,
    extra: &[Address],
) -> Result<(Vec<Bytes>, Vec<Bytes>, Vec<Bytes>, usize, usize)> {
    let al = p.create_access_list(req).block_id(at).await?;
    if let Some(e) = &al.error {
        bail!("the same call fails: {e} (the sender may have no more input tokens / allowance)");
    }
    witness_for(p, at, &al.access_list, extra).await
}

/// Proofs for `extra` accounts and everything in `al`.
pub(crate) async fn witness_for(
    p: &impl Provider,
    at: BlockId,
    al: &alloy::eips::eip2930::AccessList,
    extra: &[Address],
) -> Result<(Vec<Bytes>, Vec<Bytes>, Vec<Bytes>, usize, usize)> {
    let mut touched: BTreeMap<Address, BTreeSet<B256>> = BTreeMap::new();
    for a in extra {
        touched.entry(*a).or_default();
    }
    for item in al.0.iter() {
        touched.entry(item.address).or_default().extend(item.storage_keys.iter().copied());
    }
    let (mut state, mut codes, mut keys) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
    for (addr, slots) in &touched {
        let slots: Vec<B256> = slots.iter().copied().collect();
        let proof = p.get_proof(*addr, slots.clone()).block_id(at).await?;
        state.extend(proof.account_proof.iter().cloned());
        for sp in &proof.storage_proof {
            state.extend(sp.proof.iter().cloned());
        }
        let code = p.get_code_at(*addr).block_id(at).await?;
        if !code.is_empty() {
            ensure!(keccak256(&code) == proof.code_hash, "code hash mismatch for {addr}");
            codes.insert(code);
        }
        keys.insert(Bytes::copy_from_slice(addr.as_slice()));
        keys.extend(slots.iter().map(|s| Bytes::copy_from_slice(s.as_slice())));
    }
    let n_slots = touched.values().map(|s| s.len()).sum();
    Ok((state.into_iter().collect(), codes.into_iter().collect(), keys.into_iter().collect(), touched.len(), n_slots))
}

/// Replay `tx` exactly as mined, on its parent block's state, then check the local simulation
/// against the receipt.
async fn replay_on_parent(
    p: &impl Provider,
    hash: B256,
    tx: &alloy::rpc::types::Transaction,
    from: Address,
    to: Address,
    out: &str,
) -> Result<()> {
    let receipt = p.get_transaction_receipt(hash).await?.context("receipt not found")?;
    let number = tx.block_number().context("tx not mined")?;
    let block = p.get_block_by_number(BlockNumberOrTag::Number(number)).await?.context("block")?;
    let parent = p.get_block_by_number(BlockNumberOrTag::Number(number - 1)).await?.context("parent")?;
    let (bh, ph): (Header, Header) = (block.header.inner.clone(), parent.header.inner.clone());
    ensure!(ph.hash_slow() == parent.header.hash, "parent RLP header does not hash to the block hash");
    let at = BlockId::number(number - 1);
    // legacy gas price: what it paid (effective), and at least the parent's basefee for the
    // node's eth_call env
    let gas_price = receipt.effective_gas_price.max(ph.base_fee_per_gas.unwrap_or(0) as u128);
    let req = TransactionRequest::default()
        .with_from(from)
        .with_to(to)
        .with_input(tx.input().clone())
        .with_value(tx.value())
        .with_nonce(tx.nonce())
        .with_gas_limit(tx.gas_limit())
        .with_gas_price(gas_price);
    let (state, codes, keys, n_acc, n_slots) = witness(p, at, &req, &[from, to, bh.beneficiary]).await?;
    let input = SimInput {
        chain_id: p.get_chain_id().await?,
        parent_header: alloy_rlp::encode(&ph).into(),
        block: SimBlock {
            number,
            timestamp: bh.timestamp,
            basefee: bh.base_fee_per_gas.context("pre-London block")?,
            gas_limit: bh.gas_limit,
            beneficiary: bh.beneficiary,
            prevrandao: bh.mix_hash,
        },
        tx: SimTx { from, to, nonce: tx.nonce(), gas_limit: tx.gas_limit(), gas_price, value: tx.value(), data: tx.input().clone() },
        state,
        codes,
        keys,
    };
    let bytes = alloy_rlp::encode(&input);
    std::fs::write(out, &bytes)?;
    println!(
        "REPLAY {hash} (block {number}) on parent state {}: {n_acc} accounts, {n_slots} slots, {} nodes, {} codes ({} B code) -> {out} ({} B)",
        ph.state_root,
        input.state.len(),
        input.codes.len(),
        input.codes.iter().map(|c| c.len()).sum::<usize>(),
        bytes.len()
    );

    // our simulator vs what actually happened on chain
    let sim = xous_evm::sim::simulate(&bytes).map_err(|e| anyhow::anyhow!("local simulation: {e}"))?;
    let chain: Vec<(Address, Vec<B256>, Bytes)> = receipt
        .inner
        .logs()
        .iter()
        .map(|l| (l.address(), l.topics().to_vec(), l.data().data.clone()))
        .collect();
    let ours: Vec<(Address, Vec<B256>, Bytes)> =
        sim.logs.iter().map(|l| (l.address, l.topics.clone(), l.data.clone())).collect();
    println!(
        "check vs receipt: status {} vs ours {}; gas used {} vs ours {}; logs {}",
        receipt.status(),
        sim.success,
        receipt.gas_used,
        sim.gas_used,
        if chain == ours { format!("IDENTICAL ({} logs)", ours.len()) } else { format!("DIFFER (chain {}, ours {})", chain.len(), ours.len()) }
    );
    Ok(())
}

async fn build_at_latest(
    p: &impl Provider,
    hash: B256,
    tx: &alloy::rpc::types::Transaction,
    from: Address,
    to: Address,
    out: &str,
) -> Result<()> {
    let n = p.get_block_number().await?;
    let at = BlockId::number(n);
    let block = p.get_block_by_number(BlockNumberOrTag::Number(n)).await?.context("block")?;
    let ph: Header = block.header.inner.clone();
    ensure!(ph.hash_slow() == block.header.hash, "RLP header does not hash to the block hash");
    let basefee = ph
        .next_block_base_fee(alloy::eips::eip1559::BaseFeeParams::ethereum())
        .context("pre-London header")?;
    // legacy gas price covering both this block's basefee (the node's eth_call env) and the
    // next one's (the device's env)
    let gas_price = (basefee.max(ph.base_fee_per_gas.unwrap_or(0)) as u128) + 1_000_000_000; // + 1 gwei tip
    let nonce = p.get_transaction_count(from).block_id(at).await?;
    let req = TransactionRequest::default()
        .with_from(from)
        .with_to(to)
        .with_input(tx.input().clone())
        .with_value(tx.value())
        .with_nonce(nonce)
        .with_gas_limit(tx.gas_limit())
        .with_gas_price(gas_price);
    let al = p.create_access_list(&req).block_id(at).await?;
    if let Some(e) = &al.error {
        bail!("the same call on block {n} fails: {e} (the sender may have no more input tokens / allowance)");
    }

    let mut touched: BTreeMap<Address, BTreeSet<B256>> = BTreeMap::new();
    for a in [from, to, ph.beneficiary] {
        touched.entry(a).or_default();
    }
    for item in al.access_list.0.iter() {
        touched.entry(item.address).or_default().extend(item.storage_keys.iter().copied());
    }
    let (mut state, mut codes, mut keys) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
    for (addr, slots) in &touched {
        let slots: Vec<B256> = slots.iter().copied().collect();
        let proof = p.get_proof(*addr, slots.clone()).block_id(at).await?;
        state.extend(proof.account_proof.iter().cloned());
        for sp in &proof.storage_proof {
            state.extend(sp.proof.iter().cloned());
        }
        let code = p.get_code_at(*addr).block_id(at).await?;
        if !code.is_empty() {
            ensure!(keccak256(&code) == proof.code_hash, "code hash mismatch for {addr}");
            codes.insert(code);
        }
        keys.insert(Bytes::copy_from_slice(addr.as_slice()));
        keys.extend(slots.iter().map(|s| Bytes::copy_from_slice(s.as_slice())));
    }

    let input = SimInput {
        chain_id: p.get_chain_id().await?,
        parent_header: alloy_rlp::encode(&ph).into(),
        block: SimBlock {
            number: n + 1,
            timestamp: ph.timestamp + 12,
            basefee,
            gas_limit: ph.gas_limit,
            beneficiary: ph.beneficiary,
            prevrandao: ph.mix_hash,
        },
        tx: SimTx { from, to, nonce, gas_limit: tx.gas_limit(), gas_price, value: tx.value(), data: tx.input().clone() },
        state: state.into_iter().collect(),
        codes: codes.into_iter().collect(),
        keys: keys.into_iter().collect(),
    };
    let bytes = alloy_rlp::encode(&input);
    std::fs::write(out, &bytes)?;
    println!(
        "same call as {hash}, on block {n} (state root {}), from {from} to {to}, nonce {nonce}: {} accounts, {} slots, \
         {} nodes, {} codes ({} B code) -> {out} ({} B); node says gas ~{}",
        ph.state_root,
        touched.len(),
        touched.values().map(|s| s.len()).sum::<usize>(),
        input.state.len(),
        input.codes.len(),
        input.codes.iter().map(|c| c.len()).sum::<usize>(),
        bytes.len(),
        al.gas_used
    );
    Ok(())
}

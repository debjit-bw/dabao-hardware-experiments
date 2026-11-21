//! Host companion for the Dabao verifier.
//!
//!   dabao-host build <out.rlp>              build a SimInput from a JSON-RPC node (RPC_URL,
//!                                           default publicnode): WETH transfer(0x…dEaD, 1)
//!   dabao-host build <out.rlp> --replay <txhash> | --find-swap
//!                                           re-simulate a real mainnet tx (e.g. the latest
//!                                           Uniswap v2/v3 swap) on its parent block's state
//!   dabao-host send <in.rlp> [--tcp ADDR]   simulate on the device (USB HID) or the emulator
//!                                           (TCP, e.g. 127.0.0.1:7610); print the SimResult
//!   dabao-host sign <in.rlp> [--tcp ADDR]   simulate + policy + sign; checks the signature
//!   dabao-host address [--tcp ADDR]         the device's signing address
//!   dabao-host status [--tcp ADDR]          heap cap, max input size
//!   dabao-host send-tx --to ADDR [--value WEI] [--data 0x..] [--legacy] [--broadcast] [--chain sepolia]
//!                                           a tx from the device's address on a live chain:
//!                                           build, simulate + check + sign on the device,
//!                                           broadcast, compare the receipt with the prediction
//!   dabao-host compile-descriptors <out.bin> <descriptor.json>...   ERC-7730 -> device blob
//!   dabao-host compile-policy <out.bin> <policy.json>              signing policy -> device blob
//!   dabao-host policy                                              the device's policy and counters
//!   dabao-host safe keys|create|info|fund|send ...                 2-of-3 Safe co-signed by the device (safe.rs)
//!   dabao-host build-synthetic <from> <out.rlp> [--data 0x.. | --eip1559]   SYNTHETIC state where <from> holds 1 ETH
//!                                           (tests the sign path; not mainnet state)
//!
//! `build`: a WETH `transfer(0x…dEaD, 1)` from a WETH holder seen in the latest block,
//! simulated on top of that block's post-state.
//! Witness = union of `eth_getProof` account + storage proof nodes for every account and
//! slot that `eth_createAccessList` reports, plus sender, recipient and beneficiary.
//! Also prints what the node itself says the call returns, to compare with the device.

use std::collections::{BTreeMap, BTreeSet};

use alloy::{
    consensus::Header,
    eips::{BlockId, BlockNumberOrTag, eip1559::BaseFeeParams},
    network::TransactionBuilder,
    providers::{Provider, ProviderBuilder},
    rpc::types::{Filter, TransactionRequest},
};
use alloy_primitives::{Address, B256, Bytes, U256, address, b256, keccak256};
use anyhow::{Context, Result, bail, ensure};
use sim_types::{SimBlock, SimInput, SimTx};

const WETH: Address = address!("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2");
const DEAD: Address = address!("0x000000000000000000000000000000000000dEaD");
/// keccak256("Transfer(address,address,uint256)")
const TRANSFER_TOPIC: B256 = b256!("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef");
const GAS_LIMIT: u64 = 100_000;

fn transfer_calldata(to: Address, amount: U256) -> Bytes {
    let mut d = Vec::with_capacity(68);
    d.extend_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]); // transfer(address,uint256)
    d.extend_from_slice(&[0u8; 12]);
    d.extend_from_slice(to.as_slice());
    d.extend_from_slice(&amount.to_be_bytes::<32>());
    d.into()
}

fn balance_of_calldata(who: Address) -> Bytes {
    let mut d = vec![0x70, 0xa0, 0x82, 0x31]; // balanceOf(address)
    d.extend_from_slice(&[0u8; 12]);
    d.extend_from_slice(who.as_slice());
    d.into()
}

mod descriptors;
mod lc;
mod policy;
mod replay;
mod safe;
mod send;
mod synthetic;
mod tx;

#[tokio::main]
async fn main() -> Result<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let tcp = match args.iter().position(|a| a == "--tcp") {
        Some(i) => {
            let addr = args.get(i + 1).context("--tcp needs an address")?.clone();
            args.drain(i..i + 2);
            Some(addr)
        }
        None => None,
    };
    let tcp = tcp.as_deref();
    // --chain sepolia: default RPC for Sepolia (publicnode, free, serves proofs)
    if let Some(i) = args.iter().position(|a| a == "--chain") {
        let c = args.get(i + 1).context("--chain needs a name")?.clone();
        args.drain(i..i + 2);
        if std::env::var_os("RPC_URL").is_none() {
            let url = match c.as_str() {
                "sepolia" => "https://ethereum-sepolia-rpc.publicnode.com",
                "mainnet" => "https://ethereum-rpc.publicnode.com",
                other => bail!("unknown chain '{other}' (mainnet, sepolia)"),
            };
            // safety: single-threaded at this point (before any RPC client exists)
            unsafe { std::env::set_var("RPC_URL", url) };
        }
    }
    if args.first().map(String::as_str) == Some("safe") {
        let sub = args.get(1).map(String::as_str).unwrap_or("");
        let mut a = safe::Args { to: Address::ZERO, value: U256::ZERO, data: Bytes::new(), broadcast: false, agent_only: false };
        let mut have_to = false;
        let mut it = args.iter().skip(2);
        while let Some(k) = it.next() {
            match k.as_str() {
                "--to" => {
                    a.to = it.next().context("--to ADDR")?.parse()?;
                    have_to = true;
                }
                "--value" => a.value = it.next().context("--value WEI")?.parse()?,
                "--data" => a.data = it.next().context("--data 0x..")?.parse()?,
                "--broadcast" => a.broadcast = true,
                "--agent-only" => a.agent_only = true,
                other => bail!("safe {sub}: unknown option {other}"),
            }
        }
        return match sub {
            "keys" => safe::keys().await,
            "create" => safe::create(&provider()?, tcp).await,
            "info" => safe::info(&provider()?).await,
            "fund" => safe::fund(&provider()?, a.value).await,
            "send" if have_to => safe::send(&provider()?, a, tcp).await,
            _ => bail!("usage: dabao-host safe keys | create | info | fund --value WEI | send --to ADDR [--value WEI] [--data 0x..] [--broadcast | --agent-only]  [--chain sepolia] [--tcp ADDR]"),
        };
    }
    if args.first().map(String::as_str) == Some("send-tx") {
        let mut a = tx::Args { to: Address::ZERO, value: U256::ZERO, data: Bytes::new(), broadcast: false, legacy: false };
        let mut it = args[1..].iter();
        let mut have_to = false;
        while let Some(k) = it.next() {
            match k.as_str() {
                "--to" => {
                    a.to = it.next().context("--to ADDR")?.parse()?;
                    have_to = true;
                }
                "--value" => a.value = it.next().context("--value WEI")?.parse()?,
                "--data" => a.data = it.next().context("--data 0x..")?.parse()?,
                "--broadcast" => a.broadcast = true,
                "--legacy" => a.legacy = true,
                other => bail!("send-tx: unknown option {other}"),
            }
        }
        if !have_to {
            bail!("usage: dabao-host send-tx --to ADDR [--value WEI] [--data 0x..] [--legacy] [--broadcast] [--chain sepolia] [--tcp ADDR]");
        }
        return tx::run(&provider()?, a, tcp).await;
    }
    let usage = "usage: dabao-host build <out.rlp> [--replay TXHASH | --find-swap] | build-synthetic <from> <out.rlp> | send <in.rlp> | sign <in.rlp> | address | status | policy | compile-policy <out.bin> <policy.json>  [--tcp ADDR]";
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["build", out] => build(out).await,
        ["build", out, "--find-swap"] => replay::build(&provider()?, None, out).await,
        ["build", out, "--replay", hash] => replay::build(&provider()?, Some(hash.parse()?), out).await,
        ["build-synthetic", from, out] => synthetic::build(from.parse()?, out, Bytes::new(), None),
        ["build-synthetic", from, out, "--eip1559"] => synthetic::build(from.parse()?, out, Bytes::new(), Some(1_000_000_000)),
        ["build-synthetic", from, out, "--data", hex] => synthetic::build(from.parse()?, out, hex.parse()?, None),
        ["send", path] => send::send(&std::fs::read(path)?, tcp),
        ["send", path, "--no-precheck"] => send::send_unchecked(&std::fs::read(path)?, tcp),
        ["sign", path] => send::sign(&std::fs::read(path)?, tcp),
        ["status"] => send::status(tcp),
        ["policy"] => send::policy(tcp),
        ["lc-fixture", out] => lc::fixture(out).await,
        ["lc-anchor"] => lc::anchor().await,
        ["lc-fixtures", dir] => lc::fixtures(dir).await,
        ["lc-sync"] => lc::sync(tcp).await.map(|_| ()),
        ["compile-policy", out, input] => policy::compile(out, input),
        ["compile-descriptors", out, rest @ ..] if !rest.is_empty() => {
            descriptors::compile(out, &rest.iter().map(|s| s.to_string()).collect::<Vec<_>>())
        }
        ["address"] => {
            println!("{}", send::address(tcp)?);
            Ok(())
        }
        _ => bail!("{usage}"),
    }
}

fn provider() -> Result<impl Provider> {
    let url = std::env::var("RPC_URL").unwrap_or_else(|_| "https://ethereum-rpc.publicnode.com".into());
    Ok(ProviderBuilder::new().connect_http(url.parse()?))
}

async fn build(out: &str) -> Result<()> {
    let url = std::env::var("RPC_URL").unwrap_or_else(|_| "https://ethereum-rpc.publicnode.com".into());
    let p = ProviderBuilder::new().connect_http(url.parse()?);

    // ---- parent block N: header (RLP, hash-checked), its post-state is our pre-state ----
    let n = p.get_block_number().await?;
    let at = BlockId::number(n);
    let block = p.get_block_by_number(BlockNumberOrTag::Number(n)).await?.context("block")?;
    let header: Header = block.header.inner.clone();
    ensure!(header.hash_slow() == block.header.hash, "RLP header does not hash to the block hash");
    let parent_header: Bytes = alloy_rlp::encode(&header).into();
    let next_basefee = header
        .next_block_base_fee(BaseFeeParams::ethereum())
        .context("pre-London header?")?;
    // The node evaluates eth_call/createAccessList in block N's env (basefee N); the device
    // executes in block N+1's env. Pay at least both so neither rejects the tx.
    let gas_price = next_basefee.max(header.base_fee_per_gas.unwrap_or(0));
    let basefee = next_basefee;

    // ---- pick a sender: an EOA that moved WETH in block N and can pay for gas ----
    let logs = p
        .get_logs(&Filter::new().address(WETH).event_signature(TRANSFER_TOPIC).from_block(n).to_block(n))
        .await?;
    let mut from = None;
    for log in &logs {
        let Some(t) = log.topics().get(1) else { continue };
        let cand = Address::from_word(*t);
        if cand.is_zero() || !p.get_code_at(cand).block_id(at).await?.is_empty() {
            continue; // skip mints and contracts (EIP-3607 forbids txs from accounts with code)
        }
        let eth = p.get_balance(cand).block_id(at).await?;
        let weth = p
            .call(TransactionRequest::default().with_to(WETH).with_input(balance_of_calldata(cand)))
            .block(at)
            .await?;
        if eth >= U256::from(GAS_LIMIT) * U256::from(gas_price) * U256::from(2) && U256::from_be_slice(&weth) > U256::ZERO {
            from = Some(cand);
            break;
        }
    }
    let Some(from) = from else { bail!("no suitable WETH sender in block {n}; try again next block") };

    let nonce = p.get_transaction_count(from).block_id(at).await?;
    let data = transfer_calldata(DEAD, U256::from(1));
    let req = TransactionRequest::default()
        .with_from(from)
        .with_to(WETH)
        .with_input(data.clone())
        .with_nonce(nonce)
        .with_gas_limit(GAS_LIMIT)
        .with_max_fee_per_gas(gas_price as u128)
        .with_max_priority_fee_per_gas(0);

    // ---- what the node says, for comparison with the device ----
    let expected_ret = p.call(req.clone()).block(at).await?;
    let al = p.create_access_list(&req).block_id(at).await?;
    if let Some(e) = &al.error {
        bail!("createAccessList error: {e}");
    }

    // ---- collect accounts + slots, then proofs ----
    let mut touched: BTreeMap<Address, BTreeSet<B256>> = BTreeMap::new();
    for a in [from, WETH, DEAD, header.beneficiary] {
        touched.entry(a).or_default();
    }
    for item in al.access_list.0.iter() {
        touched.entry(item.address).or_default().extend(item.storage_keys.iter().copied());
    }

    let mut state: BTreeSet<Bytes> = BTreeSet::new();
    let mut codes: BTreeSet<Bytes> = BTreeSet::new();
    let mut keys: BTreeSet<Bytes> = BTreeSet::new();
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
        chain_id: 1,
        parent_header,
        block: SimBlock {
            number: n + 1,
            timestamp: header.timestamp + 12,
            basefee,
            gas_limit: header.gas_limit,
            beneficiary: header.beneficiary,
            prevrandao: header.mix_hash,
        },
        tx: SimTx { from, to: WETH, nonce, gas_limit: GAS_LIMIT, gas_price: gas_price as u128, value: U256::ZERO, data, max_priority_fee_per_gas: None },
        state: state.into_iter().collect(),
        codes: codes.into_iter().collect(),
        keys: keys.into_iter().collect(),
        lc: None,
    };
    let bytes = alloy_rlp::encode(&input);
    std::fs::write(&out, &bytes)?;

    println!("block {n} (state root {}), sender {from}, nonce {nonce}", header.state_root);
    println!(
        "witness: {} accounts, {} slots, {} trie nodes, {} codes ({} B code) -> {} ({} B)",
        touched.len(),
        touched.values().map(|s| s.len()).sum::<usize>(),
        input.state.len(),
        input.codes.len(),
        input.codes.iter().map(|c| c.len()).sum::<usize>(),
        out,
        bytes.len()
    );
    println!("node says: returns {expected_ret} (createAccessList gasUsed {}, with access list)", al.gas_used);
    Ok(())
}

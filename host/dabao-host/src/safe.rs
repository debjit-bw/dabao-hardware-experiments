//! Safe co-signing: a 2-of-3 Safe (v1.4.1, SafeL2) on Sepolia owned by an **agent** hot key
//! (on this host), the **Dabao**, and a **recovery** key (the human's). The agent can propose
//! anything, but nothing executes without a second signature, and the device gives its only after
//! simulating the Safe's call, the ERC-7730 check, the policy, and checking from verified
//! storage that the Safe really needs it (it is an owner, threshold >= 2, no modules, no guard).
//!
//! ```text
//! dabao-host safe keys                    create / show the agent and recovery keys (.dabao-keys/)
//! dabao-host safe create                  the agent deploys the Safe (owners agent, device, recovery)
//! dabao-host safe info                    owners, threshold, nonce, balance
//! dabao-host safe fund --value WEI        the agent sends ETH to the Safe (no device involved)
//! dabao-host safe send --to ADDR [--value WEI] [--data 0x..] [--broadcast]
//!                                         device co-signs, the agent signs and executes
//! ```
//! All with `--chain sepolia` (RPC_URL) and optional `--tcp` (emulator). Keys are testnet hot
//! keys in plain files (`.dabao-keys/`, gitignored): the point of the demo is that the agent's
//! key alone is not enough.

use std::{path::PathBuf, time::Duration};

use alloy::{
    consensus::Header,
    eips::{BlockId, eip1559::BaseFeeParams, eip2930::AccessListItem},
    network::{EthereumWallet, TransactionBuilder},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::{SignerSync, local::PrivateKeySigner},
    sol,
    sol_types::{SolCall, SolEvent},
};
use alloy_primitives::{Address, B256, Bytes, Signature, U256, address};
use anyhow::{Context, Result, bail, ensure};
use sim_types::{SimBlock, SimInput, SimTx, safe};

sol! {
    interface ISafe {
        function setup(address[] _owners, uint256 _threshold, address to, bytes data, address fallbackHandler, address paymentToken, uint256 payment, address paymentReceiver);
        function execTransaction(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, bytes signatures) payable returns (bool success);
        function getTransactionHash(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, uint256 _nonce) view returns (bytes32);
        function nonce() view returns (uint256);
        function getOwners() view returns (address[]);
        function getThreshold() view returns (uint256);
        function simulateAndRevert(address targetContract, bytes calldataPayload);
        event ExecutionSuccess(bytes32 txHash, uint256 payment);
        event ExecutionFailure(bytes32 txHash, uint256 payment);
    }
    interface IPostcondition {
        function check(address device, uint256 threshold, uint256 deadline, address[] assets, int256[] minDeltas);
    }
    interface IBalanceOf {
        function balanceOf(address who) view returns (uint256);
    }
    interface IProxyFactory {
        function createProxyWithNonce(address _singleton, bytes initializer, uint256 saltNonce) returns (address proxy);
    }
}

const FACTORY: Address = address!("0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67"); // SafeProxyFactory 1.4.1
const SAFE_L2: Address = address!("0x29fcB43b46531BcA003ddC8FCB67FFE91900C762"); // SafeL2 1.4.1
const FALLBACK: Address = address!("0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99"); // CompatibilityFallbackHandler 1.4.1
const SALT: u64 = 0xdab0_5afe; // fixed: one demo Safe per owner set

fn dir() -> PathBuf {
    std::env::var_os("DABAO_KEYS").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.dabao-keys"))
}

/// Load (or, with `create`, generate) the named hot key.
fn key(name: &str, create: bool) -> Result<PrivateKeySigner> {
    let path = dir().join(format!("{name}.key"));
    match std::fs::read_to_string(&path) {
        Ok(s) => Ok(s.trim().parse().with_context(|| format!("{path:?}"))?),
        Err(_) if create => {
            let k = PrivateKeySigner::random();
            std::fs::create_dir_all(dir())?;
            std::fs::write(&path, format!("0x{}\n", alloy_primitives::hex::encode(k.to_bytes())))?;
            println!("created {name} key {path:?}");
            Ok(k)
        }
        Err(_) => bail!("no {name} key at {path:?}: run `dabao-host safe keys`"),
    }
}

fn safe_file(chain_id: u64) -> PathBuf {
    dir().join(format!("safe-{chain_id}.txt"))
}

fn load_safe(chain_id: u64) -> Result<Address> {
    let p = safe_file(chain_id);
    Ok(std::fs::read_to_string(&p).with_context(|| format!("no Safe yet ({p:?}): run `dabao-host safe create`"))?.trim().parse()?)
}

fn url() -> Result<alloy::transports::http::reqwest::Url> {
    Ok(std::env::var("RPC_URL").context("RPC_URL (or --chain sepolia)")?.parse()?)
}

async fn call<C: SolCall>(p: &impl Provider, to: Address, c: C, at: BlockId) -> Result<C::Return> {
    let out = p.call(TransactionRequest::default().with_to(to).with_input(c.abi_encode())).block(at).await?;
    Ok(C::abi_decode_returns(&out)?)
}

pub async fn keys() -> Result<()> {
    let agent = key("agent", true)?;
    let recovery = key("recovery", true)?;
    println!("agent    {} (hot key on this host; pays gas: fund it with a little Sepolia ETH)", agent.address());
    println!("recovery {} (the human's key; not used in the demo)", recovery.address());
    Ok(())
}

pub async fn create(p: &impl Provider, tcp: Option<&str>) -> Result<()> {
    let chain_id = p.get_chain_id().await?;
    if let Ok(s) = load_safe(chain_id) {
        bail!("a Safe already exists for chain {chain_id}: {s} ({:?})", safe_file(chain_id));
    }
    let agent = key("agent", false)?;
    let recovery = key("recovery", false)?;
    let device = crate::send::address(tcp).context("ask the device for its address")?;
    let owners = vec![agent.address(), device, recovery.address()];
    let init = ISafe::setupCall {
        _owners: owners.clone(),
        _threshold: U256::from(2),
        to: Address::ZERO,
        data: Bytes::new(),
        fallbackHandler: FALLBACK,
        paymentToken: Address::ZERO,
        payment: U256::ZERO,
        paymentReceiver: Address::ZERO,
    }
    .abi_encode();
    let create = IProxyFactory::createProxyWithNonceCall { _singleton: SAFE_L2, initializer: init.into(), saltNonce: U256::from(SALT) };
    let req = TransactionRequest::default().with_from(agent.address()).with_to(FACTORY).with_input(create.abi_encode());
    let out = p.call(req.clone()).await.context("createProxyWithNonce (is the agent funded?)")?;
    let safe_addr = IProxyFactory::createProxyWithNonceCall::abi_decode_returns(&out)?;
    println!("owners {owners:?}, threshold 2 -> Safe {safe_addr}");
    let w = ProviderBuilder::new().wallet(EthereumWallet::from(agent)).connect_http(url()?);
    let receipt = w.send_transaction(req).await?.with_timeout(Some(Duration::from_secs(180))).get_receipt().await?;
    ensure!(receipt.status(), "deployment reverted: {}", receipt.transaction_hash);
    std::fs::write(safe_file(chain_id), format!("{safe_addr}\n"))?;
    println!("deployed in tx {} (block {:?})", receipt.transaction_hash, receipt.block_number);
    info(p).await
}

pub async fn info(p: &impl Provider) -> Result<()> {
    let chain_id = p.get_chain_id().await?;
    let s = load_safe(chain_id)?;
    let at = BlockId::latest();
    let owners = call(p, s, ISafe::getOwnersCall {}, at).await?;
    let threshold = call(p, s, ISafe::getThresholdCall {}, at).await?;
    let nonce = call(p, s, ISafe::nonceCall {}, at).await?;
    let balance = p.get_balance(s).await?;
    println!("Safe {s} on chain {chain_id}: {threshold}-of-{} owners {owners:?}; nonce {nonce}; balance {balance} wei", owners.len());
    Ok(())
}

pub async fn fund(p: &impl Provider, value: U256) -> Result<()> {
    let chain_id = p.get_chain_id().await?;
    let s = load_safe(chain_id)?;
    let agent = key("agent", false)?;
    let w = ProviderBuilder::new().wallet(EthereumWallet::from(agent.clone())).connect_http(url()?);
    let req = TransactionRequest::default().with_from(agent.address()).with_to(s).with_value(value);
    let r = w.send_transaction(req).await?.with_timeout(Some(Duration::from_secs(180))).get_receipt().await?;
    println!("agent -> Safe {value} wei: tx {} status {}", r.transaction_hash, r.status());
    info(p).await
}

pub struct Args {
    pub to: Address,
    pub value: U256,
    pub data: Bytes,
    pub broadcast: bool,
    /// Don't ask the device: try to execute with the agent's signature alone (eth_call only).
    pub agent_only: bool,
    /// Run the device's pipeline (simulation, 7730, policy, postcondition) here on the host
    /// instead of on the device; nothing is signed. For testing before a flash.
    pub local: bool,
    /// A shell command to run after the device co-signed and before the agent executes (demo:
    /// change the state in between).
    pub before_exec: Option<String>,
    /// Execute even if the pre-flight says the postcondition fails (to put the revert on chain).
    pub force: bool,
}

/// What an agent without the device can do: sign alone and try to execute (simulated with
/// eth_call against the live Safe; nothing is sent).
async fn agent_only(p: &impl Provider, s: Address, agent: &PrivateKeySigner, a: &Args, chain_id: u64) -> Result<()> {
    let nonce = call(p, s, ISafe::nonceCall {}, BlockId::latest()).await?;
    let hash = safe::tx_hash(chain_id, s, a.to, a.value, &a.data, nonce);
    let sig = agent.sign_hash_sync(&hash)?;
    let exec = ISafe::execTransactionCall {
        to: a.to,
        value: a.value,
        data: a.data.clone(),
        operation: 0,
        safeTxGas: U256::ZERO,
        baseGas: U256::ZERO,
        gasPrice: U256::ZERO,
        gasToken: Address::ZERO,
        refundReceiver: Address::ZERO,
        signatures: sig.as_bytes().to_vec().into(),
    };
    let tx = TransactionRequest::default().with_from(agent.address()).with_to(s).with_input(exec.abi_encode());
    match p.call(tx).await {
        Ok(out) => println!("agent alone: execTransaction would SUCCEED ({out}) -- the device is not needed?!"),
        Err(e) => println!("agent alone (1 of 2 signatures): the Safe refuses: {e}"),
    }
    Ok(())
}

/// The device's Safe pipeline, run here: what `verifier::run_as` + `sign_request` do for a Safe,
/// minus the light client, the counters and the signature. Returns the refusal or the SafeTx data.
fn local_device(raw: &[u8], input: &SimInput, device: Address) -> Result<std::result::Result<Bytes, String>> {
    let descriptors = clear_sign::builtin();
    let pol = policy::builtin();
    let limited: Vec<Address> =
        pol.chains.iter().filter(|c| c.chain_id == input.chain_id).flat_map(|c| c.limits.iter().map(|l| l.asset)).collect();
    let opts = xous_evm::sim::Options {
        as_contract: true,
        reads: safe::slots(device).iter().map(|x| (input.tx.from, *x)).collect(),
        code_hashes: xous_evm::postcondition::CODE_HASH_ACCOUNTS.to_vec(),
    };
    let res = xous_evm::sim::simulate_then(raw, |_| {}, &opts, |r, reads, call| {
        r.clear_sign = clear_sign::check(&descriptors, input.chain_id, &input.tx, r.success, &r.effects);
        let vaults = policy::vaults(&pol, input.chain_id);
        let (receipts, post) = xous_evm::vaults::around(r, &vaults, input.tx.from, call, |call| {
            r.success.then(|| {
                xous_evm::postcondition::build(r, &input.tx, device, reads.slots[1], input.block.timestamp, &reads.code_hashes, &limited, call)
            })
        });
        r.policy = policy::evaluate(&pol, &[], &descriptors, input, r, &receipts).check;
        post
    });
    let (sim, reads, post) = match res {
        Ok(x) => x,
        Err(e) => return Ok(Err(format!("simulation rejected the input: {e}"))),
    };
    let mut sim = sim;
    sim.header_check = b"not checked in a --local run".to_vec().into();
    crate::send::print_sim(&sim, input.chain_id);
    let st = safe::State::from_slots(&reads.slots.clone().try_into().map_err(|_| anyhow::anyhow!("reads"))?);
    let mut why: Vec<String> = Vec::new();
    if !sim.success {
        why.push("the transaction reverts".into());
    }
    if sim.clear_sign.descriptor.is_empty() || !sim.clear_sign.violations.is_empty() {
        why.push("ERC-7730 check failed".into());
    }
    why.extend(sim.policy.violations.iter().map(|v| format!("policy: {}", String::from_utf8_lossy(v))));
    why.extend(st.problems().into_iter().map(|p| format!("Safe: {p}")));
    match post {
        Some(Ok(p)) if why.is_empty() => Ok(Ok(p.safe_data.into())),
        Some(Err(e)) => {
            why.push(format!("postcondition: {e}"));
            Ok(Err(why.join("; ")))
        }
        _ => Ok(Err(why.join("; "))),
    }
}

/// Print what the device's batch asserts; check its first call is exactly the requested one.
fn show_batch(safe_data: &[u8], a: &Args, chain_id: u64) -> Result<()> {
    let calls = safe::multisend_decode(safe_data).context("device's SafeTx data is not a MultiSendCallOnly batch")?;
    ensure!(calls.len() == 3, "batch has {} calls, expected [begin, call, check]", calls.len());
    ensure!(
        calls[1].to == a.to && calls[1].value == a.value && calls[1].data == a.data.as_ref(),
        "the batch's middle call is not the requested call"
    );
    for (i, selector) in [(0, safe::BEGIN_SELECTOR), (2, safe::CHECK_SELECTOR)] {
        ensure!(
            calls[i].to == safe::POSTCONDITION && calls[i].value.is_zero() && calls[i].data.starts_with(&selector),
            "the batch isn't wrapped in the postcondition"
        );
    }
    let c = IPostcondition::checkCall::abi_decode(&calls[2].data).context("decode check(...)")?;
    println!("postcondition (checked at inclusion, else the whole Safe tx reverts):");
    println!("  device {} still an owner, threshold {}, no module, no guard", c.device, c.threshold);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
    println!("  expires at {} (in {} s)", c.deadline, c.deadline.saturating_to::<u64>().saturating_sub(now));
    let tokens = clear_sign::builtin();
    for (asset, d) in c.assets.iter().zip(&c.minDeltas) {
        let amount = clear_sign::check::format_amount(&tokens, chain_id, *asset, d.unsigned_abs());
        let bound = match (d.is_negative(), d.is_zero()) {
            (true, _) => format!("loses at most {amount}"),
            (_, true) => format!("loses no {}", clear_sign::check::asset_label(&tokens, chain_id, *asset)),
            _ => format!("gains at least {amount}"),
        };
        println!("  Safe {bound}{}", if asset.is_zero() { String::new() } else { format!(" ({asset})") });
    }
    Ok(())
}

/// Run the batch as the Safe on the latest state (Safe.simulateAndRevert: a DELEGATECALL from the
/// Safe's context, no signatures needed). Ok(()) = the call and the postcondition both succeed.
async fn preflight(p: &impl Provider, s: Address, safe_data: &Bytes) -> Result<std::result::Result<(), String>> {
    let c = ISafe::simulateAndRevertCall { targetContract: safe::MULTISEND_CALL_ONLY, calldataPayload: safe_data.clone() };
    let tx = TransactionRequest::default().with_to(s).with_input(c.abi_encode());
    let err = match p.call(tx).await {
        Ok(_) => bail!("simulateAndRevert did not revert"),
        Err(e) => e,
    };
    let data = err.as_error_resp().and_then(|r| r.as_revert_data()).context("simulateAndRevert: no revert data")?;
    ensure!(data.len() >= 64, "simulateAndRevert: short revert data");
    let ok = !U256::from_be_slice(&data[..32]).is_zero();
    let ret = &data[64..];
    if ok {
        return Ok(Ok(()));
    }
    // MultiSendCallOnly reverts with no data when a call in the batch fails
    Ok(Err(if ret.is_empty() {
        "a call in the batch reverts (MultiSendCallOnly drops the reason): the call or the postcondition".into()
    } else {
        xous_evm::postcondition::revert_reason(ret)
    }))
}

pub async fn send(p: &impl Provider, a: Args, tcp: Option<&str>) -> Result<()> {
    let chain_id = p.get_chain_id().await?;
    let s = load_safe(chain_id)?;
    let agent = key("agent", false)?;
    if a.agent_only {
        return agent_only(p, s, &agent, &a, chain_id).await;
    }
    let device = crate::send::address(tcp).context("ask the device for its address")?;

    // the parent block is the one the sync committee signed (light-client proof), not "latest"
    let (proof, block) = crate::lc::parent(p, tcp).await?;
    let n = block.header.number;
    let at = BlockId::number(n);
    let ph: Header = block.header.inner.clone();
    ensure!(ph.hash_slow() == block.header.hash, "RLP header does not hash to the block hash");
    let basefee = ph.next_block_base_fee(BaseFeeParams::ethereum()).context("pre-London header")?;
    let nonce = call(p, s, ISafe::nonceCall {}, at).await?;
    println!("Safe {s}: nonce {nonce}, balance {} wei; agent {}; device {device}; block {n}", p.get_balance(s).block_id(at).await?, agent.address());

    // the Safe's inner call, simulated as made by the Safe (the executor pays the gas)
    let req = TransactionRequest::default().with_from(s).with_to(a.to).with_value(a.value).with_input(a.data.clone());
    let gas_limit = match p.estimate_gas(req.clone()).block(at).await {
        Ok(g) => g + g / 4 + 5_000,
        Err(e) => {
            println!("  (node can't estimate the inner call: {e}; using 300000, the device will decide)");
            300_000
        }
    };
    let mut al = match p.create_access_list(&req.clone().with_gas_limit(gas_limit)).block_id(at).await {
        Ok(al) if al.error.is_none() => al.access_list,
        Ok(al) => {
            println!("  (node: the inner call fails: {}; minimal witness)", al.error.unwrap_or_default());
            Default::default()
        }
        Err(e) => {
            println!("  (createAccessList failed: {e}; minimal witness)");
            Default::default()
        }
    };
    // the Safe's configuration slots the device checks before co-signing
    al.0.push(AccessListItem { address: s, storage_keys: safe::slots(device).iter().map(|x| B256::from(*x)).collect() });
    // what the postcondition reads: the Safe's balance of every candidate asset (the policy's
    // limited assets, and any token the call touches), via verify(...) with zero balances and changes
    let threshold = call(p, s, ISafe::getThresholdCall {}, at).await?;
    let pol = policy::builtin();
    let mut candidates: Vec<Address> =
        pol.chains.iter().filter(|c| c.chain_id == chain_id).flat_map(|c| c.limits.iter().map(|l| l.asset)).filter(|x| !x.is_zero()).collect();
    for item in al.0.iter() {
        if !candidates.contains(&item.address)
            && let Ok(b) = p.call(TransactionRequest::default().with_to(item.address).with_input(IBalanceOf::balanceOfCall { who: s }.abi_encode())).block(at).await
            && b.len() == 32
        {
            candidates.push(item.address);
        }
    }
    candidates.insert(0, Address::ZERO);
    let zeros = vec![U256::ZERO; candidates.len()];
    // balances(...) reads every asset whatever the Safe's state; verify(...) adds the Safe's own
    // getters (it may revert early, e.g. for an emulator device that isn't an owner)
    for data in [safe::balances_calldata(s, &candidates), safe::verify_calldata(device, threshold, u64::MAX, &candidates, &zeros, &zeros)] {
        let creq = TransactionRequest::default().with_from(s).with_to(safe::POSTCONDITION).with_input(data);
        match p.create_access_list(&creq).block_id(at).await {
            Ok(cal) => {
                if let Some(e) = &cal.error {
                    println!("  (node: postcondition call fails on the pre-state: {e}; the device will decide)");
                }
                al.0.extend(cal.access_list.0)
            }
            Err(e) => println!("  (createAccessList for the postcondition failed: {e})"),
        }
    }
    let (state, codes, keys, n_acc, n_slots) = crate::replay::witness_for(
        p,
        at,
        &al,
        &[s, a.to, ph.beneficiary, safe::MULTISEND_CALL_ONLY, safe::POSTCONDITION],
    )
    .await?;
    let input = SimInput {
        chain_id,
        parent_header: alloy_rlp::encode(&ph).into(),
        block: SimBlock { number: n + 1, timestamp: ph.timestamp + 12, basefee, gas_limit: ph.gas_limit, beneficiary: ph.beneficiary, prevrandao: ph.mix_hash },
        tx: SimTx { from: s, to: a.to, nonce: 0, gas_limit, gas_price: 0, value: a.value, data: a.data.clone(), max_priority_fee_per_gas: None },
        state,
        codes,
        keys,
        // test switch DABAO_NO_LC: send without the light-client proof (the device must refuse)
        lc: if std::env::var_os("DABAO_NO_LC").is_some() { None } else { Some(proof) },
    };
    let bytes = alloy_rlp::encode(&input);
    println!("witness: {n_acc} accounts, {n_slots} slots, {} nodes, {} B", input.state.len(), bytes.len());

    if a.local {
        println!("LOCAL run of the device's pipeline on this host (no light client, no counters, nothing signed)");
        return match local_device(&bytes, &input, device)? {
            Err(why) => {
                println!("NOT CO-SIGNED: {why}");
                Ok(())
            }
            Ok(safe_data) => {
                show_batch(&safe_data, &a, chain_id)?;
                let hash = safe::tx_hash_op(chain_id, s, safe::MULTISEND_CALL_ONLY, U256::ZERO, &safe_data, nonce, 1);
                let onchain = call(p, s, safe_tx_hash_call(&safe_data, nonce), at).await?;
                ensure!(onchain == hash, "SafeTx hash mismatch: host {hash}, Safe {onchain}");
                println!("SafeTx {hash} (== Safe.getTransactionHash, DELEGATECALL to MultiSendCallOnly)");
                match preflight(p, s, &safe_data).await? {
                    Ok(()) => println!("pre-flight on the latest block (Safe.simulateAndRevert): call + postcondition succeed"),
                    Err(e) => println!("pre-flight on the latest block: FAILS: {e}"),
                }
                Ok(())
            }
        };
    }

    let r = crate::send::safe_sign(&bytes, tcp)?;
    if !r.refused.is_empty() {
        return Ok(());
    }
    let safe_data = r.safe_data.clone();
    show_batch(&safe_data, &a, chain_id)?;

    // check the device's signature against the SafeTx hash computed here and by the Safe itself
    let hash = safe::tx_hash_op(chain_id, s, safe::MULTISEND_CALL_ONLY, U256::ZERO, &safe_data, nonce, 1);
    let onchain = call(p, s, safe_tx_hash_call(&safe_data, nonce), at).await?;
    ensure!(onchain == hash, "SafeTx hash mismatch: host {hash}, Safe {onchain}");
    ensure!(r.signed_tx.len() == 65, "device signature is {} B, expected 65", r.signed_tx.len());
    let dev_sig = Signature::from_raw(&r.signed_tx).context("device signature")?;
    let recovered = dev_sig.recover_address_from_prehash(&hash).context("recover")?;
    ensure!(recovered == device, "device signature recovers to {recovered}, not {device}");
    println!("device co-signed SafeTx {hash} (== Safe.getTransactionHash; DELEGATECALL to MultiSendCallOnly; recovers to the device)");

    let agent_sig = agent.sign_hash_sync(&hash)?;
    let mut sigs = vec![(device, r.signed_tx.to_vec()), (agent.address(), agent_sig.as_bytes().to_vec())];
    sigs.sort_by_key(|(a, _)| *a); // the Safe requires signatures ordered by owner address
    let signatures: Bytes = sigs.into_iter().flat_map(|(_, s)| s).collect::<Vec<u8>>().into();
    if !a.broadcast {
        println!("agent signed too: 2 of 3 signatures ready (not executed; add --broadcast)");
        return Ok(());
    }
    if let Some(cmd) = &a.before_exec {
        println!("before executing: running `{cmd}`");
        let st = std::process::Command::new("sh").arg("-c").arg(cmd).status().context("before-exec")?;
        ensure!(st.success(), "before-exec command failed: {st}");
    }
    let pre = preflight(p, s, &safe_data).await?;
    match &pre {
        Ok(()) => println!("pre-flight on the latest block: call + postcondition succeed"),
        Err(e) if a.force => println!("pre-flight on the latest block: FAILS: {e}\n  --force: executing anyway, to show the revert on chain"),
        Err(e) => {
            println!("pre-flight on the latest block: FAILS: {e}\nNOT EXECUTED: the postcondition would revert the Safe tx (pass --force to put the revert on chain)");
            return Ok(());
        }
    }

    let exec = ISafe::execTransactionCall {
        to: safe::MULTISEND_CALL_ONLY,
        value: U256::ZERO,
        data: safe_data.clone(),
        operation: 1,
        safeTxGas: U256::ZERO,
        baseGas: U256::ZERO,
        gasPrice: U256::ZERO,
        gasToken: Address::ZERO,
        refundReceiver: Address::ZERO,
        signatures,
    };
    let w = ProviderBuilder::new().wallet(EthereumWallet::from(agent.clone())).connect_http(url()?);
    let mut tx = TransactionRequest::default().with_from(agent.address()).with_to(s).with_input(exec.abi_encode());
    if pre.is_err() {
        tx = tx.with_gas_limit(400_000); // the node can't estimate a reverting tx
    }
    let pending = w.send_transaction(tx).await.context("execTransaction")?;
    let h = *pending.tx_hash();
    println!("agent executes: {h}\n  https://sepolia.etherscan.io/tx/{h}");
    let receipt = pending.with_timeout(Some(Duration::from_secs(180))).get_receipt().await?;
    let logs = receipt.inner.logs();
    let ok = logs.iter().any(|l| l.address() == s && l.topics().first() == Some(&ISafe::ExecutionSuccess::SIGNATURE_HASH));
    // the inner call's logs = everything not emitted by the Safe itself
    let chain_logs: Vec<(Address, Vec<B256>, Bytes)> =
        logs.iter().filter(|l| l.address() != s).map(|l| (l.address(), l.topics().to_vec(), l.data().data.clone())).collect();
    let dev_logs: Vec<(Address, Vec<B256>, Bytes)> =
        r.sim.logs.iter().filter(|l| l.address != s).map(|l| (l.address, l.topics.clone(), l.data.clone())).collect();
    println!(
        "included in block {:?}: tx status {}, Safe {} (device predicted success {}); inner-call logs {}",
        receipt.block_number,
        receipt.status(),
        if ok { "ExecutionSuccess" } else { "ExecutionFailure / none" },
        r.sim.success,
        if chain_logs == dev_logs { format!("IDENTICAL to the device's prediction ({})", dev_logs.len()) } else { format!("DIFFER (chain {}, device {})", chain_logs.len(), dev_logs.len()) }
    );
    Ok(())
}

fn safe_tx_hash_call(safe_data: &Bytes, nonce: U256) -> ISafe::getTransactionHashCall {
    ISafe::getTransactionHashCall {
        to: safe::MULTISEND_CALL_ONLY,
        value: U256::ZERO,
        data: safe_data.clone(),
        operation: 1,
        safeTxGas: U256::ZERO,
        baseGas: U256::ZERO,
        gasPrice: U256::ZERO,
        gasToken: Address::ZERO,
        refundReceiver: Address::ZERO,
        _nonce: nonce,
    }
}

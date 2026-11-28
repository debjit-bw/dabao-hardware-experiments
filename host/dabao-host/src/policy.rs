//! `dabao-host compile-policy <out.bin> <policy.json>`: compile the signing policy into the
//! device's RLP form (`policy::Policy`). Amounts are whole units ("0.005" ETH, "1" USDC),
//! converted with the decimals of the firmware's token list (`clear_sign::builtin()`), so a
//! limit can only name an asset the device can also display. Unknown keys are errors.

use alloy_primitives::{Address, U256};
use anyhow::{Context, Result, bail, ensure};
use policy::{ChainPolicy, Limit, MAX_LIMITS, NO_SLIPPAGE_LIMIT, POLICY_VERSION, Policy};
use serde_json::Value;

/// "1.5" with 6 decimals -> 1500000.
fn parse_units(s: &str, decimals: u8) -> Result<U256> {
    let (int, frac) = s.split_once('.').unwrap_or((s, ""));
    ensure!(!int.is_empty() && int.chars().all(|c| c.is_ascii_digit()) && frac.chars().all(|c| c.is_ascii_digit()), "bad amount '{s}'");
    ensure!(frac.len() <= decimals as usize, "amount '{s}' has more than {decimals} decimals");
    let digits = format!("{int}{frac:0<width$}", width = decimals as usize);
    digits.parse::<U256>().with_context(|| format!("amount '{s}'"))
}

fn keys(v: &Value, allowed: &[&str], what: &str) -> Result<()> {
    for k in v.as_object().with_context(|| format!("{what}: expected an object"))?.keys() {
        ensure!(allowed.contains(&k.as_str()), "{what}: unknown key '{k}'");
    }
    Ok(())
}

pub fn compile(out: &str, input: &str) -> Result<()> {
    let tokens = clear_sign::builtin();
    let j: Value = serde_json::from_str(&std::fs::read_to_string(input)?).with_context(|| format!("{input}: JSON"))?;
    keys(&j, &["comment", "id", "chains"], "policy")?;
    let mut p = Policy { version: POLICY_VERSION, id: j["id"].as_str().context("id")?.as_bytes().to_vec().into(), chains: vec![] };
    for c in j["chains"].as_array().context("chains")? {
        keys(c, &["comment", "chainId", "maxNetworkFee", "maxSlippageBps", "unlimitedAssets", "contracts", "recipients", "vaults", "dailyLimits"], "chain")?;
        let chain_id = c["chainId"].as_u64().context("chainId")?;
        ensure!(!p.chains.iter().any(|x| x.chain_id == chain_id), "chain {chain_id} listed twice");
        let max_fee = match c.get("maxNetworkFee") {
            Some(v) => parse_units(v.as_str().context("maxNetworkFee: a string")?, 18)?,
            None => U256::ZERO,
        };
        let max_slippage_bps = c.get("maxSlippageBps").map(|v| v.as_u64().context("maxSlippageBps")).transpose()?.unwrap_or(NO_SLIPPAGE_LIMIT);
        ensure!(max_slippage_bps <= NO_SLIPPAGE_LIMIT, "maxSlippageBps above 10000");
        let allow_unlimited_assets = match c.get("unlimitedAssets").and_then(|v| v.as_str()).unwrap_or("refuse") {
            "refuse" => false,
            "allow" => true,
            other => bail!("unlimitedAssets: 'refuse' or 'allow', not '{other}'"),
        };
        let list = |key: &str| -> Result<Vec<Address>> {
            match c.get(key) {
                Some(a) => a.as_array().context("expected an address list")?.iter().map(|x| Ok(x.as_str().context("address")?.parse::<Address>()?)).collect(),
                None => Ok(vec![]),
            }
        };
        let (contracts, recipients) = (list("contracts")?, list("recipients")?);
        let vaults = list("vaults")?;
        for v in &vaults {
            ensure!(contracts.contains(v), "vault {v} is not in contracts (a vault must also be callable)");
        }
        let mut limits: Vec<Limit> = vec![];
        for l in c.get("dailyLimits").and_then(|v| v.as_array()).map(|v| v.as_slice()).unwrap_or(&[]) {
            keys(l, &["comment", "asset", "amount"], "dailyLimits entry")?;
            let a = l["asset"].as_str().context("asset")?;
            let (asset, decimals) = if a == "ETH" {
                (Address::ZERO, 18)
            } else {
                let asset: Address = a.parse()?;
                let t = tokens.token(chain_id, asset).with_context(|| format!("{asset} on chain {chain_id} is not in the firmware's token list"))?;
                (asset, t.decimals)
            };
            ensure!(!limits.iter().any(|x| x.asset == asset), "two limits for {a} on chain {chain_id}");
            let daily = parse_units(l["amount"].as_str().context("amount: a string")?, decimals)?;
            ensure!(daily < (U256::from(1) << 127), "limit for {a} too large");
            limits.push(Limit { asset, daily });
        }
        p.chains.push(ChainPolicy { chain_id, max_fee, max_slippage_bps, contracts, recipients, allow_unlimited_assets, limits, vaults });
    }
    let n = p.limits().count();
    ensure!(n <= MAX_LIMITS, "{n} daily limits; the device has counters for {MAX_LIMITS}");
    for line in policy::describe(&p, &[], &tokens) {
        println!("{line}");
    }
    let bytes = alloy_rlp::encode(&p);
    std::fs::write(out, &bytes)?;
    println!("-> {out} ({} B)", bytes.len());
    Ok(())
}

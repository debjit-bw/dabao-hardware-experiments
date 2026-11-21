//! The ERC-7730 check: what the user is shown vs what the transaction does.
//!
//! 1. Match a descriptor by `(chain id, tx.to)` and a format by the calldata selector. No match
//!    and non-empty calldata = blind signing: violation. (Extension: `multicall` on a matched
//!    contract is checked as the sequence of its inner calls, each of which must match.)
//! 2. Decode the calldata with the format's parameter types and resolve every field: what the
//!    user sees. `@.value` is always shown (wallets display the ETH value of every tx).
//! 3. "Expected effects" rules (our extension), for the sender `tx.from`:
//!    * no hidden loss: every `NET_LOSS` of an asset must be covered by a shown amount of that
//!      asset (`tokenAmount` with that token, or `@.value` / `amount` for ETH);
//!    * no hidden authority: every approval / Permit2 grant / ApprovalForAll by the sender, and
//!      every ownership / proxy change, must name a shown address; ERC-20 and Permit2
//!      allowances must also be covered by a shown amount of that token;
//!    * nothing unexplained: any `UNEXPLAINED_STORAGE` is a violation;
//!    * a reverting transaction is a violation (nothing to sign).
//! 4. Warnings (shown, not blocking): a shown amount of an asset the sender receives that is 0
//!    (a swap with no slippage protection) or under half the simulated amount.
//!
//! Amounts are displayed with decimals and tickers only for tokens in the firmware's trusted
//! token list ([`DescriptorSet::tokens`]); anything else is shown in raw units with its address,
//! because a token's own `symbol()` / `decimals()` are whatever its deployer chose.

use alloy_dyn_abi::{DynSolType, DynSolValue};
use alloy_primitives::{Address, Bytes, U256};
use sim_types::{ClearSign, Effect, ShownField, SimTx, effect};

use crate::model::{DescriptorSet, Field, Function, Path, format, root, step};

/// `v` scaled down by `decimals`, without trailing zeros: 1500000 at 6 -> "1.5".
pub fn format_units(v: U256, decimals: u8) -> String {
    let s = v.to_string();
    let d = decimals as usize;
    if d == 0 {
        return s;
    }
    let s = format!("{s:0>width$}", width = d + 1);
    let (int, frac) = s.split_at(s.len() - d);
    let frac = frac.trim_end_matches('0');
    if frac.is_empty() { int.to_string() } else { format!("{int}.{frac}") }
}

/// How the device names `asset` (zero address = ETH).
pub fn asset_label(set: &DescriptorSet, chain_id: u64, asset: Address) -> String {
    if asset.is_zero() {
        return "ETH".into();
    }
    match set.token(chain_id, asset) {
        Some(t) => String::from_utf8_lossy(&t.ticker).to_string(),
        None => format!("unlisted token {asset}"),
    }
}

/// An amount of `asset` as the device displays it: decimals and ticker for ETH and listed
/// tokens, raw units otherwise.
pub fn format_amount(set: &DescriptorSet, chain_id: u64, asset: Address, amount: U256) -> String {
    let decimals = if asset.is_zero() { Some(18) } else { set.token(chain_id, asset).map(|t| t.decimals) };
    match decimals {
        Some(d) => format!("{} {}", format_units(amount, d), asset_label(set, chain_id, asset)),
        None => format!("{amount} raw units of {}", asset_label(set, chain_id, asset)),
    }
}

/// `multicall` variants of Uniswap-style routers: (selector, parameter types, index of bytes[]).
const MULTICALLS: [([u8; 4], &str, usize); 3] = [
    ([0xac, 0x96, 0x50, 0xd8], "(bytes[])", 0),         // multicall(bytes[])
    ([0x5a, 0xe4, 0x01, 0xdc], "(uint256,bytes[])", 1), // multicall(uint256 deadline, bytes[])
    ([0x1f, 0x04, 0x64, 0xd1], "(bytes32,bytes[])", 1), // multicall(bytes32 previousBlockhash, bytes[])
];

/// What a field resolved to.
enum Val {
    Addr(Address),
    Uint(U256),
    Other(String),
}

fn walk<'a>(v: &'a DynSolValue, steps: &[u64]) -> Option<&'a DynSolValue> {
    let mut cur = v;
    for &s in steps {
        let items: &[DynSolValue] = match cur {
            DynSolValue::Tuple(x) | DynSolValue::Array(x) | DynSolValue::FixedArray(x) => x,
            _ => return None,
        };
        let i = if s & step::FROM_END != 0 {
            items.len().checked_sub((s & !step::FROM_END) as usize)?
        } else {
            s as usize
        };
        cur = items.get(i)?;
    }
    Some(cur)
}

fn resolve(p: &Path, decoded: &DynSolValue, tx: &SimTx, token_const: Address) -> Option<Val> {
    match p.root {
        root::VALUE => Some(Val::Uint(tx.value)),
        root::TO => Some(Val::Addr(tx.to)),
        root::FROM => Some(Val::Addr(tx.from)),
        root::CONST => Some(Val::Addr(token_const)),
        root::CALLDATA => Some(match walk(decoded, &p.steps)? {
            DynSolValue::Address(a) => Val::Addr(*a),
            DynSolValue::Uint(u, _) => Val::Uint(*u),
            DynSolValue::Int(i, _) => Val::Other(i.to_string()),
            DynSolValue::Bool(b) => Val::Other(b.to_string()),
            DynSolValue::FixedBytes(b, n) => Val::Other(format!("0x{}", alloy_primitives::hex::encode(&b[..*n]))),
            DynSolValue::Bytes(b) => Val::Other(format!("0x{}", alloy_primitives::hex::encode(b))),
            DynSolValue::String(s) => Val::Other(s.clone()),
            other => Val::Other(format!("{other:?}")),
        }),
        _ => None,
    }
}

/// What the user is shown, in a form the rules can use.
struct Shown<'a> {
    set: &'a DescriptorSet,
    chain_id: u64,
    fields: Vec<ShownField>,
    /// Shown token amounts: (index into `fields`, asset, amount), for the slippage warning.
    token_fields: Vec<(usize, Address, U256)>,
    /// (asset, amount): zero address = ETH.
    amounts: Vec<(Address, U256)>,
    addresses: Vec<Address>,
    errors: Vec<String>,
}

impl<'a> Shown<'a> {
    fn new(set: &'a DescriptorSet, chain_id: u64) -> Self {
        Shown { set, chain_id, fields: vec![], token_fields: vec![], amounts: vec![], addresses: vec![], errors: vec![] }
    }

    fn amount(&self, asset: Address, amount: U256) -> String {
        format_amount(self.set, self.chain_id, asset, amount)
    }

    fn add(&mut self, label: &[u8], value: String) {
        self.fields.push(ShownField { label: label.to_vec().into(), value: value.into_bytes().into() });
    }

    fn field(&mut self, f: &Field, decoded: &DynSolValue, tx: &SimTx) {
        let label = String::from_utf8_lossy(&f.label).to_string();
        let Some(v) = resolve(&f.value, decoded, tx, f.token_const) else {
            self.errors.push(format!("field '{label}': path does not resolve in this calldata"));
            return;
        };
        match (f.format, v) {
            (format::TOKEN_AMOUNT, Val::Uint(amount)) => {
                let token = match resolve(&f.token, decoded, tx, f.token_const) {
                    Some(Val::Addr(a)) => a,
                    _ => {
                        self.errors.push(format!("field '{label}': token does not resolve"));
                        return;
                    }
                };
                let asset = if f.native_currency.contains(&token) { Address::ZERO } else { token };
                let shown = if !f.threshold.is_zero() && amount >= f.threshold {
                    format!("{} {}", String::from_utf8_lossy(&f.message), asset_label(self.set, self.chain_id, asset))
                } else {
                    self.amount(asset, amount)
                };
                self.token_fields.push((self.fields.len(), asset, amount));
                self.add(&f.label, shown);
                self.amounts.push((asset, amount));
            }
            (format::AMOUNT, Val::Uint(amount)) => {
                self.add(&f.label, self.amount(Address::ZERO, amount));
                self.amounts.push((Address::ZERO, amount));
            }
            (format::ADDRESS_NAME, Val::Addr(a)) => {
                self.add(&f.label, a.to_string());
                self.addresses.push(a);
            }
            (_, Val::Addr(a)) => {
                self.add(&f.label, a.to_string());
                self.addresses.push(a);
            }
            (_, Val::Uint(u)) => self.add(&f.label, u.to_string()),
            (_, Val::Other(s)) => self.add(&f.label, s),
        }
    }

    fn covers(&self, asset: Address, amount: U256) -> bool {
        self.amounts.iter().any(|(a, x)| *a == asset && *x >= amount)
    }

    fn names(&self, a: Address) -> bool {
        self.addresses.contains(&a)
    }
}

/// Decode `data` (selector + args) against `f` and add its fields to `shown`.
fn show_call(f: &Function, data: &[u8], tx: &SimTx, shown: &mut Shown) -> Result<(), String> {
    let ty = DynSolType::parse(&String::from_utf8_lossy(&f.params_type)).map_err(|e| format!("descriptor type: {e}"))?;
    let decoded = ty.abi_decode_params(&data[4..]).map_err(|e| format!("calldata does not decode as {}: {e}", String::from_utf8_lossy(&f.signature)))?;
    for field in &f.fields {
        shown.field(field, &decoded, tx);
    }
    Ok(())
}

/// Run the check for `tx` with the simulation's `effects`.
pub fn check(set: &DescriptorSet, chain_id: u64, tx: &SimTx, success: bool, effects: &[Effect]) -> ClearSign {
    let mut out = ClearSign::default();
    let mut shown = Shown::new(set, chain_id);
    let mut violations: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    if !tx.value.is_zero() {
        shown.add(b"Value (sent with the transaction)", shown.amount(Address::ZERO, tx.value));
    }
    shown.amounts.push((Address::ZERO, tx.value)); // @.value is always shown

    if tx.data.is_empty() {
        out.descriptor = b"plain ETH transfer".to_vec().into();
        out.intent = b"Send ETH".to_vec().into();
        shown.addresses.push(tx.to);
        shown.add(b"To", tx.to.to_string());
    } else if tx.data.len() < 4 {
        violations.push("calldata shorter than a selector".into());
    } else {
        let d = set
            .descriptors
            .iter()
            .find(|d| d.deployments.iter().any(|x| x.chain_id == chain_id && x.address == tx.to));
        match d {
            None => violations.push(format!("no ERC-7730 descriptor for {} on chain {chain_id}: blind signing refused", tx.to)),
            Some(d) => {
                out.descriptor = d.id.clone();
                let sel = &tx.data[..4];
                let find = |s: &[u8]| d.functions.iter().find(|f| f.selector.as_ref() == s);
                if let Some(f) = find(sel) {
                    out.intent = f.intent.clone();
                    if let Err(e) = show_call(f, &tx.data, tx, &mut shown) {
                        violations.push(e);
                    }
                } else if let Some((_, types, idx)) = MULTICALLS.iter().find(|(s, _, _)| s == sel) {
                    // extension: a multicall on this contract = its inner calls, in order
                    let inner = DynSolType::parse(types)
                        .ok()
                        .and_then(|t| t.abi_decode_params(&tx.data[4..]).ok())
                        .and_then(|v| match walk(&v, &[*idx as u64]) {
                            Some(DynSolValue::Array(xs)) => Some(xs.clone()),
                            _ => None,
                        });
                    match inner {
                        None => violations.push("multicall does not decode".into()),
                        Some(calls) => {
                            let mut intents = Vec::new();
                            for (i, c) in calls.iter().enumerate() {
                                let DynSolValue::Bytes(c) = c else { continue };
                                match (c.len() >= 4).then(|| find(&c[..4])).flatten() {
                                    Some(f) => {
                                        intents.push(String::from_utf8_lossy(&f.intent).to_string());
                                        if let Err(e) = show_call(f, c, tx, &mut shown) {
                                            violations.push(format!("multicall item {i}: {e}"));
                                        }
                                    }
                                    None => violations.push(format!(
                                        "multicall item {i}: selector 0x{} has no format in '{}'",
                                        alloy_primitives::hex::encode(c.get(..4).unwrap_or(c)),
                                        String::from_utf8_lossy(&d.id)
                                    )),
                                }
                            }
                            out.intent = format!("multicall: {}", intents.join(" + ")).into_bytes().into();
                        }
                    }
                } else {
                    violations.push(format!(
                        "selector 0x{} has no format in '{}': blind signing refused",
                        alloy_primitives::hex::encode(sel),
                        String::from_utf8_lossy(&d.id)
                    ));
                }
            }
        }
    }
    violations.extend(shown.errors.iter().cloned());

    if !success {
        violations.push("the transaction reverts".into());
    }
    let me = tx.from;
    let amt = |a: Address, x: U256| format_amount(set, chain_id, a, x);
    for e in effects {
        match e.kind {
            effect::NET_LOSS if !shown.covers(e.contract, e.amount) => violations.push(format!(
                "hidden loss: the sender loses {}, but no shown amount of that asset covers it",
                amt(e.contract, e.amount)
            )),
            effect::ERC20_APPROVAL | effect::PERMIT2_APPROVAL if e.from == me && !e.amount.is_zero() => {
                let token = if e.kind == effect::PERMIT2_APPROVAL && e.extra.len() >= 20 {
                    Address::from_slice(&e.extra[..20])
                } else {
                    e.contract
                };
                if !shown.names(e.to) {
                    violations.push(format!("hidden approval: allowance of {} to {} (spender not shown)", amt(token, e.amount), e.to));
                } else if !shown.covers(token, e.amount) {
                    violations.push(format!("hidden approval: allowance of {} to {} exceeds every shown amount", amt(token, e.amount), e.to));
                }
            }
            effect::NFT_APPROVAL | effect::APPROVAL_FOR_ALL if e.from == me && !shown.names(e.to) => {
                if e.kind == effect::NFT_APPROVAL || !e.amount.is_zero() {
                    violations.push(format!("hidden approval: NFT operator / approval to {} on {} (not shown)", e.to, e.contract));
                }
            }
            effect::OWNERSHIP_TRANSFER | effect::PROXY_UPGRADE | effect::PROXY_ADMIN_CHANGE if !shown.names(e.to) => {
                violations.push(format!("hidden authority change on {}: new owner / admin / implementation {} not shown", e.contract, e.to));
            }
            effect::UNEXPLAINED_STORAGE => violations.push(format!(
                "unexplained effect: {} changed {} storage slots without a recognised event",
                e.contract, e.amount
            )),
            _ => {}
        }
    }

    // what the sender ends up receiving vs the minimum the user is shown (slippage)
    for &(i, asset, shown_amount) in &shown.token_fields {
        let Some(gain) = effects.iter().find(|e| e.kind == effect::NET_GAIN && e.contract == asset).map(|e| e.amount) else {
            continue;
        };
        if shown_amount >= gain {
            continue; // exact output, or not a minimum
        }
        out.min_receive.push(sim_types::MinReceive { asset, shown: shown_amount, simulated: gain });
        let label = String::from_utf8_lossy(&shown.fields[i].label).to_string();
        let pct = (gain - shown_amount) * U256::from(10_000) / gain; // basis points below the simulation
        let pct = format!("{}.{:02}%", pct / U256::from(100), pct % U256::from(100));
        let note = format!(" (simulated: {}, {pct} lower)", amt(asset, gain));
        let mut v = shown.fields[i].value.to_vec();
        v.extend_from_slice(note.as_bytes());
        shown.fields[i].value = v.into();
        if shown_amount.is_zero() {
            warnings.push(format!(
                "'{label}' is 0: the swap accepts any price (no slippage protection; a sandwich bot can take everything above 0)"
            ));
        } else if shown_amount * U256::from(2) < gain {
            warnings.push(format!("'{label}' is {pct} below the simulated amount: a loose slippage limit"));
        }
    }

    // network fee: what the simulation paid, and the most the signed tx can pay. Gas price 0 =
    // a call made by a contract (a Safe's inner call): its executor pays, not the sender.
    if tx.gas_price == 0 {
        shown.add(b"Network fee", "paid by the executor, not by the sender".into());
    } else {
        if let Some(fee) = effects.iter().find(|e| e.kind == effect::GAS_FEE && e.from == tx.from) {
            shown.add(b"Network fee (simulated)", shown.amount(Address::ZERO, fee.amount));
        }
        shown.add(b"Max network fee", shown.amount(Address::ZERO, U256::from(tx.gas_limit) * U256::from(tx.gas_price)));
    }

    out.addresses = shown.addresses;
    out.fields = shown.fields;
    out.violations = violations.into_iter().map(|v| Bytes::from(v.into_bytes())).collect();
    out.warnings = warnings.into_iter().map(|v| Bytes::from(v.into_bytes())).collect();
    out
}

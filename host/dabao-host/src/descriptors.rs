//! `dabao-host compile-descriptors <out.bin> <descriptor.json>...`: compile ERC-7730 calldata
//! descriptors into the device's compact RLP form (`clear_sign::model`).
//!
//! Supported subset (anything else is a hard error, never silently dropped): `context.$id`,
//! `context.contract.deployments`; `display.formats` keyed by human-readable function
//! signatures with named parameters; fields with `path` (calldata names, `.`-separated, with
//! `[i]` / `[-i]` array selectors, optional `#.` root, or `@.value` / `@.to` / `@.from`),
//! `label`, `format`, and `params.tokenPath` / `token` / `nativeCurrencyAddress` / `threshold` /
//! `message` for tokenAmount; nested `fields` groups (paths relative to the group's `path`).
//! Not supported: `includes`, `$ref`, `display.definitions`, EIP-712 descriptors.

use alloy::json_abi::{Function, Param};
use alloy_primitives::{Address, Bytes, U256};
use anyhow::{Context, Result, bail};
use clear_sign::model::{Deployment, Descriptor, DescriptorSet, Field, Function as Fmt, Path, SET_VERSION, format, root, step};
use serde_json::Value;

/// Parse an ERC-7730 format key: `name(type name, (type name, ...) name, type[] name, ...)`.
/// (alloy's human-readable parser rejects tuples with named members.) The result is an alloy
/// `Function`, so the selector and canonical types come from alloy.
fn parse_signature(key: &str) -> Result<Function> {
    let key = key.trim();
    let open = key.find('(').context("no '('")?;
    let name = key[..open].trim().trim_start_matches("function ").trim().to_string();
    let (inputs, rest) = parse_params(&key[open..])?;
    if !rest.trim().is_empty() {
        bail!("trailing text after parameters: '{rest}'");
    }
    Ok(Function { name, inputs, outputs: vec![], state_mutability: alloy::json_abi::StateMutability::NonPayable })
}

/// `(p, p, ...)` -> params, remaining text.
fn parse_params(s: &str) -> Result<(Vec<Param>, &str)> {
    let mut rest = s.strip_prefix('(').context("expected '('")?.trim_start();
    let mut out = Vec::new();
    if let Some(r) = rest.strip_prefix(')') {
        return Ok((out, r));
    }
    loop {
        let (p, r) = parse_param(rest)?;
        out.push(p);
        let r = r.trim_start();
        if let Some(r) = r.strip_prefix(',') {
            rest = r.trim_start();
        } else if let Some(r) = r.strip_prefix(')') {
            return Ok((out, r));
        } else {
            bail!("expected ',' or ')' at '{r}'");
        }
    }
}

/// `type [name]`, where type is elementary or `( ... )`, with any `[]` / `[n]` suffixes.
fn parse_param(s: &str) -> Result<(Param, &str)> {
    let (mut ty, components, mut rest) = if s.starts_with('(') {
        let (c, r) = parse_params(s)?;
        ("tuple".to_string(), c, r)
    } else {
        let end = s.find(|c: char| c == ' ' || c == ',' || c == ')' || c == '[').unwrap_or(s.len());
        (s[..end].to_string(), vec![], &s[end..])
    };
    while let Some(r) = rest.strip_prefix('[') {
        let close = r.find(']').context("unclosed '['")?;
        ty.push_str(&format!("[{}]", &r[..close]));
        rest = &r[close + 1..];
    }
    let rest = rest.trim_start();
    let end = rest.find(|c: char| c == ',' || c == ')').unwrap_or(rest.len());
    let name = rest[..end].trim().to_string();
    Ok((Param { ty, name, components, internal_type: None }, &rest[end..]))
}

fn str_of<'a>(v: &'a Value, what: &str) -> Result<&'a str> {
    v.as_str().with_context(|| format!("{what}: expected a string"))
}

/// Resolve a 7730 path against the function's parameters.
fn path(p: &str, inputs: &[Param]) -> Result<Path> {
    match p {
        "@.value" => return Ok(Path { root: root::VALUE, steps: vec![] }),
        "@.to" => return Ok(Path { root: root::TO, steps: vec![] }),
        "@.from" => return Ok(Path { root: root::FROM, steps: vec![] }),
        _ if p.starts_with("@.") || p.starts_with("$.") => bail!("path '{p}': root not supported"),
        _ => {}
    }
    let p = p.strip_prefix("#.").unwrap_or(p);
    let mut steps = Vec::new();
    // `level`: the parameters (or tuple components) the next name is looked up in
    let mut level: Vec<Param> = inputs.to_vec();
    let mut cur: Option<Param> = None; // the parameter the last step landed on
    for part in p.split('.') {
        if let Some(idx) = part.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            let c = cur.as_ref().with_context(|| format!("path '{p}': index before any name"))?;
            if !c.ty.ends_with(']') {
                bail!("path '{p}': '{part}' indexes a non-array ({})", c.ty);
            }
            let i: i64 = idx.parse().with_context(|| format!("path '{p}': bad index '{part}' (slices not supported)"))?;
            steps.push(step::index(i));
            // element type: strip the last [..]
            let elem_ty = c.ty[..c.ty.rfind('[').unwrap()].to_string();
            let elem = Param { ty: elem_ty, name: String::new(), components: c.components.clone(), internal_type: None };
            level = elem.components.clone();
            cur = Some(elem);
            continue;
        }
        let (i, prm) = level
            .iter()
            .enumerate()
            .find(|(_, x)| x.name == part)
            .map(|(i, x)| (i, x.clone()))
            .with_context(|| format!("path '{p}': no parameter named '{part}'"))?;
        steps.push(i as u64);
        level = prm.components.clone();
        cur = Some(prm);
    }
    Ok(Path { root: root::CALLDATA, steps })
}

fn format_code(f: &str) -> Result<u8> {
    Ok(match f {
        "raw" => format::RAW,
        "amount" => format::AMOUNT,
        "tokenAmount" => format::TOKEN_AMOUNT,
        "addressName" => format::ADDRESS_NAME,
        "date" => format::DATE,
        "duration" => format::DURATION,
        "unit" => format::UNIT,
        "enum" | "nftName" | "calldata" | "chainId" | "tokenTicker" => format::OTHER,
        other => bail!("unknown field format '{other}'"),
    })
}

fn u256_of(v: &Value) -> Result<U256> {
    match v {
        Value::String(s) => s.parse::<U256>().with_context(|| format!("bad number '{s}'")),
        Value::Number(n) => Ok(U256::from(n.as_u64().context("number too large")?)),
        _ => bail!("expected a number"),
    }
}

fn addresses(v: &Value) -> Result<Vec<Address>> {
    match v {
        Value::String(s) => Ok(vec![s.parse()?]),
        Value::Array(xs) => xs.iter().map(|x| Ok(str_of(x, "address")?.parse()?)).collect(),
        _ => bail!("expected an address or a list of addresses"),
    }
}

/// Fields of one format (recursing into groups: `{ "path": "params", "fields": [...] }`).
fn fields(list: &[Value], prefix: &str, inputs: &[Param], out: &mut Vec<Field>) -> Result<()> {
    for f in list {
        if f.get("$ref").is_some() {
            bail!("field uses $ref (not supported)");
        }
        let rel = f.get("path").map(|p| str_of(p, "path")).transpose()?.unwrap_or("");
        let full = match (prefix, rel) {
            ("", r) => r.to_string(),
            (p, "") => p.to_string(),
            (p, r) if r.starts_with("@.") || r.starts_with("#.") => {
                let _ = p;
                r.to_string()
            }
            (p, r) => format!("{p}.{r}"),
        };
        if let Some(sub) = f.get("fields") {
            fields(sub.as_array().context("fields: expected a list")?, &full, inputs, out)?;
            continue;
        }
        let label = f.get("label").map(|l| str_of(l, "label")).transpose()?.unwrap_or(&full).to_string();
        let fmt = format_code(f.get("format").map(|x| str_of(x, "format")).transpose()?.unwrap_or("raw"))?;
        let params = f.get("params").cloned().unwrap_or(Value::Null);
        let mut field = Field {
            label: label.into_bytes().into(),
            format: fmt,
            value: path(&full, inputs).with_context(|| format!("field '{full}'"))?,
            token: Path { root: root::NONE, steps: vec![] },
            token_const: Address::ZERO,
            native_currency: vec![],
            threshold: U256::ZERO,
            message: Bytes::new(),
        };
        if fmt == format::TOKEN_AMOUNT {
            if let Some(tp) = params.get("tokenPath") {
                let tp = str_of(tp, "tokenPath")?;
                // tokenPath is relative to the same root as the field
                let tp_full = if prefix.is_empty() || tp.starts_with("@.") || tp.starts_with("#.") { tp.to_string() } else { format!("{prefix}.{tp}") };
                field.token = path(&tp_full, inputs).with_context(|| format!("tokenPath '{tp}'"))?;
            } else if let Some(t) = params.get("token") {
                field.token = Path { root: root::CONST, steps: vec![] };
                field.token_const = str_of(t, "token")?.parse()?;
            } else {
                bail!("field '{full}': tokenAmount without tokenPath / token");
            }
            if let Some(n) = params.get("nativeCurrencyAddress") {
                field.native_currency = addresses(n)?;
            }
            if let Some(t) = params.get("threshold") {
                field.threshold = u256_of(t)?;
                field.message = params.get("message").and_then(|m| m.as_str()).unwrap_or("Unlimited").as_bytes().to_vec().into();
            }
        }
        out.push(field);
    }
    Ok(())
}

fn compile_one(path_: &str) -> Result<Descriptor> {
    let j: Value = serde_json::from_str(&std::fs::read_to_string(path_)?).with_context(|| format!("{path_}: JSON"))?;
    if j.get("includes").is_some() {
        bail!("{path_}: `includes` not supported");
    }
    let ctx = j.get("context").context("no context")?;
    let id = ctx.get("$id").and_then(|v| v.as_str()).unwrap_or(path_).to_string();
    let deployments = ctx
        .pointer("/contract/deployments")
        .and_then(|d| d.as_array())
        .context("context.contract.deployments missing (only contract descriptors are supported)")?
        .iter()
        .map(|d| {
            Ok(Deployment {
                chain_id: d.get("chainId").and_then(|c| c.as_u64()).context("chainId")?,
                address: str_of(d.get("address").context("address")?, "address")?.parse()?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let formats = j.pointer("/display/formats").and_then(|f| f.as_object()).context("display.formats missing")?;
    let mut functions = Vec::new();
    for (key, fmt) in formats {
        let func = parse_signature(key).with_context(|| format!("{path_}: can't parse '{key}'"))?;
        let params_type = format!("({})", func.inputs.iter().map(|p| p.selector_type().to_string()).collect::<Vec<_>>().join(","));
        let mut fs = Vec::new();
        fields(fmt.get("fields").and_then(|f| f.as_array()).context("fields")?, "", &func.inputs, &mut fs)
            .with_context(|| format!("{path_}: {key}"))?;
        let intent = match fmt.get("intent") {
            Some(Value::String(s)) => s.clone(),
            Some(other) => other.to_string(),
            None => func.name.clone(),
        };
        functions.push(Fmt {
            selector: func.selector().to_vec().into(),
            signature: key.clone().into_bytes().into(),
            params_type: params_type.into_bytes().into(),
            intent: intent.into_bytes().into(),
            fields: fs,
        });
    }
    Ok(Descriptor {
        id: id.into_bytes().into(),
        source: std::path::Path::new(path_).file_name().unwrap_or_default().to_string_lossy().into_owned().into_bytes().into(),
        deployments,
        functions,
    })
}

pub fn compile(out: &str, inputs: &[String]) -> Result<()> {
    let mut set = DescriptorSet { version: SET_VERSION, descriptors: vec![] };
    for p in inputs {
        let d = compile_one(p)?;
        println!(
            "{p}: '{}' at {} deployment(s), {} format(s): {}",
            String::from_utf8_lossy(&d.id),
            d.deployments.len(),
            d.functions.len(),
            d.functions
                .iter()
                .map(|f| format!("{} (0x{}, {} fields)", String::from_utf8_lossy(&f.intent), alloy_primitives::hex::encode(&f.selector), f.fields.len()))
                .collect::<Vec<_>>()
                .join(", ")
        );
        set.descriptors.push(d);
    }
    let bytes = alloy_rlp::encode(&set);
    std::fs::write(out, &bytes)?;
    println!("-> {out} ({} B)", bytes.len());
    Ok(())
}

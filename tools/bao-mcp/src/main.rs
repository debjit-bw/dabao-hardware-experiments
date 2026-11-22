//! `bao-mcp`: an MCP server (stdio, newline-delimited JSON-RPC 2.0) that gives an AI agent a
//! wallet in which the Dabao co-signs. (This holds only if the agent can't read the Safe's
//! other owner keys: see docs/agent-wallet.md.)
//!
//! The agent's wallet is a 2-of-3 Safe (docs/safe-cosigner.md). The agent's own key is one
//! owner; the Dabao is another. The agent gets exactly one way to move funds: `propose_tx`.
//! That hands the call to `dabao-host safe send`, which builds the witness, and the **device**
//! simulates the call as the Safe on verified state, runs the ERC-7730 check and the signing
//! policy, and co-signs only if everything passes. Only then does the agent's key add the
//! second signature and execute. Nothing in this server can sign for the Safe without the
//! device: there is no bypass tool, and the agent's key alone is 1 of 2 (the Safe reverts
//! GS020).
//!
//! Tools: `wallet_info`, `device_policy`, `propose_tx`. Every proposal and the device's
//! verdict are appended to `logs/agent-proposals.jsonl`.
//!
//! Environment: `DABAO_HOST` (path to the dabao-host binary; default target/debug/dabao-host
//! in this repo), `RPC_URL` (passed through), `BAO_MCP_CHAIN` (default sepolia),
//! `BAO_MCP_DRY_RUN=1` (co-sign but don't execute).

use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

const PROTOCOL: &str = "2025-06-18";

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn host_bin() -> PathBuf {
    std::env::var_os("DABAO_HOST").map(PathBuf::from).unwrap_or_else(|| repo().join("target/debug/dabao-host"))
}

fn chain() -> String {
    std::env::var("BAO_MCP_CHAIN").unwrap_or_else(|_| "sepolia".into())
}

/// Run dabao-host; returns (success, stdout + stderr).
fn host(args: &[&str]) -> (bool, String) {
    let mut cmd = Command::new(host_bin());
    cmd.args(args).args(["--chain", &chain()]).current_dir(repo());
    match cmd.output() {
        Ok(o) => {
            let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
            let err = String::from_utf8_lossy(&o.stderr);
            if !err.trim().is_empty() {
                s.push_str("\n[stderr]\n");
                s.push_str(&err);
            }
            (o.status.success(), s)
        }
        Err(e) => (false, format!("could not run {:?}: {e}", host_bin())),
    }
}

/// "0.0001" ETH -> wei, exactly (no floats).
fn eth_to_wei(s: &str) -> Result<String, String> {
    let s = s.trim();
    let (int, frac) = s.split_once('.').unwrap_or((s, ""));
    let ok = |x: &str| x.chars().all(|c| c.is_ascii_digit());
    if (int.is_empty() && frac.is_empty()) || !ok(int) || !ok(frac) || frac.len() > 18 {
        return Err(format!("value_eth {s:?}: expected a decimal ETH amount with at most 18 decimals, e.g. \"0.0001\""));
    }
    let digits = format!("{int}{frac:0<18}");
    let digits = digits.trim_start_matches('0');
    Ok(if digits.is_empty() { "0".into() } else { digits.into() })
}

fn is_addr(s: &str) -> bool {
    s.len() == 42 && s.starts_with("0x") && s[2..].chars().all(|c| c.is_ascii_hexdigit())
}

fn is_hex(s: &str) -> bool {
    s.starts_with("0x") && s.len() % 2 == 0 && s[2..].chars().all(|c| c.is_ascii_hexdigit())
}

fn log(entry: &Value) {
    let dir = repo().join("logs");
    let _ = std::fs::create_dir_all(&dir);
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("agent-proposals.jsonl")) {
        let _ = writeln!(f, "{entry}");
    }
}

/// The lines of the device's report worth surfacing first.
fn verdict_lines(out: &str) -> Vec<&str> {
    out.lines()
        .map(str::trim)
        .filter(|l| {
            l.starts_with("NOT CO-SIGNED")
                || l.starts_with("device co-signed")
                || l.starts_with("verdict:")
                || l.starts_with("VIOLATION")
                || l.starts_with("POLICY VIOLATION")
                || l.starts_with("WARNING")
                || l.starts_with("REJECTED")
                || l.starts_with("light client:")
                || l.starts_with("pre-flight")
                || l.starts_with("Safe loses")
                || l.starts_with("Safe gains")
                || l.starts_with("expires at")
                || l.starts_with("NOT EXECUTED")
                || l.starts_with("included in block")
                || l.starts_with("agent executes")
                || l.starts_with("https://")
        })
        .collect()
}

fn propose(args: &Value) -> Result<(bool, String), String> {
    let to = args["to"].as_str().ok_or("`to` (0x address) is required")?;
    if !is_addr(to) {
        return Err(format!("`to` {to:?} is not a 0x-prefixed 20-byte address"));
    }
    let value = eth_to_wei(args["value_eth"].as_str().unwrap_or("0"))?;
    let data = args["data"].as_str().unwrap_or("0x");
    if !is_hex(data) {
        return Err(format!("`data` {data:?} is not 0x-prefixed hex"));
    }
    let reason = args["reason"].as_str().ok_or("`reason` is required: say why you are proposing this transaction")?;

    let dry = std::env::var_os("BAO_MCP_DRY_RUN").is_some();
    let mut a = vec!["safe", "send", "--to", to, "--value", &value, "--data", data];
    if !dry {
        a.push("--broadcast");
    }
    let (ok, out) = host(&a);
    let status = if out.contains("NOT CO-SIGNED") {
        "refused"
    } else if out.contains("included in block") && out.contains("tx status true") {
        "executed"
    } else if out.contains("included in block") {
        "reverted"
    } else if out.contains("NOT EXECUTED") {
        "not executed (postcondition)"
    } else if ok && out.contains("device co-signed") {
        "co-signed (dry run: not executed)"
    } else {
        "error"
    };
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let tx = out.lines().find_map(|l| l.trim().strip_prefix("agent executes: ")).map(str::to_string);
    log(&json!({ "ts": ts, "to": to, "value_wei": value, "data": data, "reason": reason, "status": status, "tx": tx }));

    let head = match status {
        "refused" => "REFUSED by the Dabao hardware co-signer. Nothing was signed or executed; the Safe's funds did not move. \
                      This decision is made on the device and cannot be overridden from here. Report the reason to the user; \
                      do not retry with variations to get around it.",
        "executed" => "EXECUTED: the Dabao co-signed after its own simulation and checks, and the Safe executed the call.",
        "error" => "ERROR: the proposal didn't finish (see the log below). If the log has 'agent executes', a transaction was sent: check it before retrying.",
        "reverted" => "REVERTED on chain: the Dabao co-signed, but at inclusion its on-chain postcondition failed (the state changed since the \
                       simulation), so the Safe transaction reverted and the Safe's funds did not move.",
        "not executed (postcondition)" => "NOT EXECUTED: the Dabao co-signed, but on the latest state its on-chain postcondition would fail \
                       (the state changed since the simulation). Nothing was sent; the Safe's funds did not move.",
        _ => "CO-SIGNED by the Dabao (dry run: not executed).",
    };
    let mut text = format!("{head}\n\nstatus: {status}\n");
    for l in verdict_lines(&out) {
        text.push_str(l);
        text.push('\n');
    }
    text.push_str("\n--- full device report ---\n");
    text.push_str(&out);
    Ok((status == "error", text))
}

fn tools() -> Value {
    json!([
        {
            "name": "wallet_info",
            "description": "The agent's wallet: a 2-of-3 Safe on Sepolia (owners: this agent's key, a Dabao hardware co-signer, and the human's recovery key). Shows the Safe address, owners, threshold, nonce and ETH balance.",
            "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false }
        },
        {
            "name": "device_policy",
            "description": "The signing policy enforced by the Dabao co-signer (who may be called or paid, daily limits, fee and slippage caps) and today's spending counters, as reported by the device itself. Check this before proposing.",
            "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false }
        },
        {
            "name": "propose_tx",
            "description": "Propose a transaction from the Safe. The Dabao hardware co-signer simulates it as the Safe on verified chain state, checks that every effect is shown (ERC-7730) and that it is within the owner's policy, and co-signs only if all checks pass; the agent's key then adds its signature and executes. If the device refuses, nothing happens. Returns the device's verdict, the simulated effects and, if executed, the transaction hash. Takes up to ~30 s.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "to": { "type": "string", "description": "Destination address, 0x-prefixed." },
                    "value_eth": { "type": "string", "description": "ETH to send, as a decimal string, e.g. \"0.0001\". Default \"0\"." },
                    "data": { "type": "string", "description": "Calldata, 0x-prefixed hex. Default \"0x\"." },
                    "reason": { "type": "string", "description": "Why you are proposing this, in one sentence (logged with the device's verdict)." }
                },
                "required": ["to", "reason"],
                "additionalProperties": false
            }
        }
    ])
}

fn call(name: &str, args: &Value) -> (bool, String) {
    match name {
        "wallet_info" => {
            let (ok, out) = host(&["safe", "info"]);
            (!ok, out)
        }
        "device_policy" => {
            let (ok, out) = host(&["policy"]);
            (!ok, out)
        }
        "propose_tx" => match propose(args) {
            Ok(r) => r,
            Err(e) => (true, format!("invalid proposal: {e}")),
        },
        _ => (true, format!("unknown tool {name}")),
    }
}

fn handle(req: &Value) -> Option<Value> {
    let id = req.get("id")?.clone(); // notifications (no id) get no response
    let method = req["method"].as_str().unwrap_or("");
    let result = match method {
        "initialize" => json!({
            "protocolVersion": req["params"]["protocolVersion"].as_str().unwrap_or(PROTOCOL),
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "bao-mcp", "version": env!("CARGO_PKG_VERSION") },
            "instructions": "A Safe wallet co-signed by a Dabao hardware device. Use propose_tx to move funds; the device decides. A refusal is final."
        }),
        "ping" => json!({}),
        "tools/list" => json!({ "tools": tools() }),
        "tools/call" => {
            let name = req["params"]["name"].as_str().unwrap_or("");
            let empty = json!({});
            let args = req["params"].get("arguments").unwrap_or(&empty);
            let (is_error, text) = call(name, args);
            json!({ "content": [{ "type": "text", "text": text }], "isError": is_error })
        }
        _ => return Some(json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32601, "message": format!("method not found: {method}") } })),
    };
    Some(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
}

fn main() {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let resp = match serde_json::from_str::<Value>(&line) {
            Ok(req) => handle(&req),
            Err(e) => Some(json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": e.to_string() } })),
        };
        if let Some(r) = resp {
            let _ = writeln!(stdout, "{r}");
            let _ = stdout.flush();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wei() {
        assert_eq!(eth_to_wei("0.0001").unwrap(), "100000000000000");
        assert_eq!(eth_to_wei("1").unwrap(), "1000000000000000000");
        assert_eq!(eth_to_wei("0").unwrap(), "0");
        assert_eq!(eth_to_wei(".5").unwrap(), "500000000000000000");
        assert_eq!(eth_to_wei("0.000000000000000001").unwrap(), "1");
        assert!(eth_to_wei("1e18").is_err());
        assert!(eth_to_wei("-1").is_err());
        assert!(eth_to_wei("0.0000000000000000001").is_err());
        assert!(eth_to_wei("").is_err());
    }

    #[test]
    fn protocol() {
        let r = handle(&json!({"jsonrpc":"2.0","id":1,"method":"tools/list"})).unwrap();
        assert_eq!(r["result"]["tools"].as_array().unwrap().len(), 3);
        assert!(handle(&json!({"jsonrpc":"2.0","method":"notifications/initialized"})).is_none());
        let r = handle(&json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"propose_tx","arguments":{"to":"0x12","reason":"x"}}})).unwrap();
        assert_eq!(r["result"]["isError"], true);
    }
}

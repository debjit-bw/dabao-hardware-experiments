#!/usr/bin/env python3
"""Minimal MCP client for bao-mcp: initialize, then call one tool and print its text.

  scripts/mcp-call.py wallet_info
  scripts/mcp-call.py propose_tx '{"to":"0x...","value_eth":"0.0001","reason":"..."}'

Used as the "compromised agent" in the demo: it proposes exactly what an injected prompt
asks for, with no model judgement in the way, so the only thing left to refuse is the device.
"""
import json, os, subprocess, sys

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
srv = subprocess.Popen([os.path.join(root, "target/debug/bao-mcp")], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)

def rpc(i, method, params=None):
    msg = {"jsonrpc": "2.0", "method": method}
    if i is not None:
        msg["id"] = i
    if params is not None:
        msg["params"] = params
    srv.stdin.write(json.dumps(msg) + "\n"); srv.stdin.flush()
    return json.loads(srv.stdout.readline()) if i is not None else None

init = rpc(1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "mcp-call", "version": "0"}})
rpc(None, "notifications/initialized")
if len(sys.argv) < 2:
    print(json.dumps(rpc(2, "tools/list")["result"], indent=2)); sys.exit(0)
r = rpc(2, "tools/call", {"name": sys.argv[1], "arguments": json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}})
res = r["result"]
print(res["content"][0]["text"])
srv.stdin.close(); srv.wait()
sys.exit(1 if res.get("isError") else 0)

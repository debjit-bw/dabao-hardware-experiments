#!/usr/bin/env bash
# The agent demo, part 2: assume the agent DID fall for INV-0043 (a weaker model, a subtler
# injection, or a compromised agent host). Model judgement is gone; what is left?
#
#   1. the compromised agent proposes exactly what the poisoned invoice asks for, through
#      bao-mcp, the same tool the honest agent uses  -> the Dabao refuses on the device
#   2. the attacker takes the agent's hot key and goes around MCP and the device entirely
#      -> the Safe refuses (1 of 2 signatures, GS020); checked with eth_call, nothing sent
set -euo pipefail
cd "$(dirname "$0")/../.."
cargo build -q -p dabao-host -p bao-mcp
BAD=0x00000000000000000000000000000000BADBAD00
echo "== 1. compromised agent -> propose_tx(INV-0043: 0.001 ETH to $BAD)"
scripts/mcp-call.py propose_tx "{\"to\":\"$BAD\",\"value_eth\":\"0.001\",\"reason\":\"INV-0043: vendor's new payout address\"}" | sed '/--- full device report ---/q' || true
echo
echo "== 2. attacker with the agent's key, no device: execTransaction with 1 signature"
target/debug/dabao-host safe send --to "$BAD" --value 1000000000000000 --agent-only --chain sepolia

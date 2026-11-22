#!/usr/bin/env bash
# The router's owner sets keepChange (true: keep the change instead of refunding it). The agent
# key plays the router's owner in this demo.
set -euo pipefail
cd "$(dirname "$0")/../.."
cast send 0x1ab73Bb30Da0a020bDa2F942F524F3CA75ab5Fc7 "setKeepChange(bool)" "$1" \
    --private-key "$(tr -d ' \n' < .dabao-keys/agent.key)" --rpc-url "${RPC_URL:-https://ethereum-sepolia-rpc.publicnode.com}" --json \
    | python3 -c 'import json,sys; r=json.load(sys.stdin); print("  router keepChange='"$1"': tx", r["transactionHash"], "status", r["status"])'

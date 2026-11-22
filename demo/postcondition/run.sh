#!/usr/bin/env bash
# A change between simulation and inclusion, caught by the device's on-chain postcondition.
#
# DemoPayRouter.pay(to, amount) forwards `amount` and refunds the change, unless its owner has
# switched on keepChange (contracts/src/DemoPayRouter.sol; the owner is played by the agent key).
#
#   1. The Safe pays 0.0001 ETH to 0x..dEaD through the router, sending 0.0005 (0.0004 change).
#      The device simulates: net cost 0.0001. It co-signs [begin, the call, check(Safe ETH change >= -0.0001, deadline)].
#   2. Between co-signing and execution the router's owner switches keepChange on: the same
#      call would now cost the Safe 0.0005.
#   3. The agent executes anyway (--force, so the revert lands on chain): the postcondition
#      fails, the whole Safe tx reverts (GS013). The Safe loses nothing.
#   4. The router is switched back.
#
#   demo/postcondition/run.sh [honest]    # "honest": no switch; the payment goes through
set -euo pipefail
cd "$(dirname "$0")/../.."
cargo build -q -p dabao-host
ROUTER=0x1ab73Bb30Da0a020bDa2F942F524F3CA75ab5Fc7
RPC=${RPC_URL:-https://ethereum-sepolia-rpc.publicnode.com}
echo "router keepChange = $(cast call $ROUTER 'keepChange()(bool)' --rpc-url $RPC)"
DATA=$(cast calldata "pay(address,uint256)" 0x000000000000000000000000000000000000dEaD 100000000000000)
if [ "${1:-}" = honest ]; then
    target/debug/dabao-host safe send --chain sepolia --to $ROUTER --value 500000000000000 --data "$DATA" --broadcast
else
    target/debug/dabao-host safe send --chain sepolia --to $ROUTER --value 500000000000000 --data "$DATA" --broadcast \
        --before-exec "demo/postcondition/switch.sh true" --force || true
    demo/postcondition/switch.sh false
fi
target/debug/dabao-host safe info --chain sepolia

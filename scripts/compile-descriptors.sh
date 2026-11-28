#!/bin/bash
# Compile the ERC-7730 descriptors in descriptors/ and the signing policy in policy/ into the
# blobs embedded in the verifier. The policy takes decimals from the descriptors' token list,
# so the host is rebuilt in between (it embeds descriptors.bin).
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
cd "$here"
cargo run -q --release -p dabao-host -- compile-descriptors crates/clear-sign/descriptors.bin \
    --tokens descriptors/tokens.json \
    descriptors/registry/calldata-UniswapV3Router02.json \
    descriptors/sepolia/calldata-UniswapV3Router02.sepolia.json descriptors/weth.json \
    descriptors/sepolia/demo-pay-router.json descriptors/sepolia/demo-vault.json
[ -f crates/policy/policy.bin ] || : > crates/policy/policy.bin   # first build: placeholder
cargo run -q --release -p dabao-host -- compile-policy crates/policy/policy.bin policy/policy.json

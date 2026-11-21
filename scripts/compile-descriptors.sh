#!/bin/bash
# Compile the ERC-7730 descriptors in descriptors/ into the blob embedded in the verifier.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
cd "$here"
cargo run -q --release -p dabao-host -- compile-descriptors crates/clear-sign/descriptors.bin \
    descriptors/registry/calldata-UniswapV3Router02.json \
    descriptors/sepolia/calldata-UniswapV3Router02.sepolia.json descriptors/weth.json

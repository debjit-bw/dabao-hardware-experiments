# ERC-7730 descriptors

Source JSON for the descriptors compiled into the verifier
(`crates/clear-sign/descriptors.bin`, regenerate with `scripts/compile-descriptors.sh`).

| File | Contract | Origin |
|---|---|---|
| `registry/calldata-UniswapV3Router02.json` | Uniswap SwapRouter02 `0x68b3…Fc45` (mainnet) | verbatim from [ethereum/clear-signing-erc7730-registry](https://github.com/ethereum/clear-signing-erc7730-registry) `registry/uniswap/`, fetched 2026-11-21 (registry license: CC0-1.0) |
| `weth.json` | WETH9 `0xC02a…6Cc2` (mainnet) | written for this project in ERC-7730 format |

The device only trusts descriptors compiled into its firmware; the host never supplies them at
runtime (a hostile host would otherwise hide the fields that matter).

# ERC-7730 clear-signing check

The verifier signs only if **every effect of the simulated transaction is explained by what the
user is shown**. "What is shown" comes from an ERC-7730 descriptor; "every effect" comes from the
effects inspector (`docs/effects-inspector.md`). Code: `crates/clear-sign` (check + model),
`host/dabao-host/src/descriptors.rs` (compiler), `descriptors/` (source JSON).

## Trust model

- **Descriptors are part of the firmware.** The host compiles 7730 JSON into a compact RLP blob
  (`crates/clear-sign/descriptors.bin`, 2.3 KB for two descriptors) that is built into the
  verifier. A host that could supply descriptors at runtime could also supply one that hides the
  dangerous fields, so it can't.
- A descriptor applies only to its `context.contract.deployments` (chain id + address), matched
  against the simulated `tx.to`.
- The compiler resolves named paths (`params.amountIn`, `path.[-1]`) to index paths, so the
  device only ABI-decodes (alloy-dyn-abi) and indexes; it never parses names or JSON.

## The rules (our "expected effects" extension)

ERC-7730 (Draft) defines how to display calldata, not what a transaction may do. The check adds:

| Rule | Violation when |
|---|---|
| no blind signing | non-empty calldata and no descriptor for `(chain, tx.to)`, or no format for the selector |
| no hidden loss | the sender's net loss of an asset (`NET_LOSS`) exceeds every shown amount of that asset (`tokenAmount` for that token; `@.value` / `amount` for ETH) |
| no hidden approval | an ERC-20 / Permit2 allowance, NFT approval or ApprovalForAll granted by the sender to an address not shown — or (ERC-20 / Permit2) larger than every shown amount of that token |
| no hidden authority | an ownership / proxy implementation / proxy admin change to an address not shown |
| nothing unexplained | any `UNEXPLAINED_STORAGE` effect |
| nothing to sign | the transaction reverts |

`@.value` is always treated as shown (wallets display the ETH value of every transaction); a
plain ETH transfer (empty calldata) shows value and recipient.

## Extension: `multicall`

Uniswap routers wrap most swaps in `multicall(deadline, bytes[])`; the registry descriptor for
SwapRouter02 has no format for it, so the registry alone can't clear-sign one of the most common
transactions. On a contract with a matched descriptor, the check treats
`multicall(bytes[])`, `multicall(uint256,bytes[])` and `multicall(bytes32,bytes[])` as the
sequence of their inner calls: every inner call must match a format of the same descriptor, and
the shown fields are the union. An inner call without a format is a violation.

## Descriptors compiled in

| Descriptor | Formats | Origin |
|---|---|---|
| Uniswap v3 Router 2 (`0x68b3…Fc45`) | exactInputSingle, exactOutputSingle, swapExactTokensForTokens, swapTokensForExactTokens | verbatim from ethereum/clear-signing-erc7730-registry (CC0) |
| WETH9 (`0xC02a…6Cc2`) | deposit, withdraw, transfer, approve | written for this project in 7730 format |

Compiler subset: `context.$id` / deployments; `display.formats` keyed by human-readable
signatures with named params (including named tuple members, which alloy's parser rejects, so
the compiler has its own small signature parser); field `path` / `label` / `format`;
`tokenAmount` params `tokenPath` / `token` / `nativeCurrencyAddress` / `threshold` / `message`;
nested field groups. Anything else (`includes`, `$ref`, EIP-712 descriptors, slices) is a hard
compile error.

## Results

Host tests (`cargo test -p clear-sign`): the three real mainnet fixtures pass (WETH transfer;
`exactInputSingle` paid in ETH; `multicall(deadline, [exactInputSingle])`, the exact replay of a
mined swap). Crafted effects are refused: losing more than shown, a different token, or ETH beyond
`value`; an allowance to an unshown spender, an ApprovalForAll, an allowance larger than shown;
an ownership change; unexplained storage; unknown contract, unknown function, unknown call inside
a multicall; a revert.

On chain (Sepolia, signed by the Dabao, receipts identical to the device's prediction): plain ETH
transfers, WETH wrap and transfer (our WETH descriptor), and two Uniswap swaps through
SwapRouter02 — `exactInputSingle` and `multicall(deadline, [exactInputSingle])` — clear-signed
with the registry's formats (Sepolia `context`). See PROGRESS.md for the transaction links.

## Limits / next

- Amounts are checked numerically; displays don't yet use token decimals or tickers (the device
  would need trusted token metadata, e.g. descriptor `metadata.token` or a token list in
  firmware).
- Labels carry no machine-readable meaning: "Minimum to Receive" is not enforced against the
  simulated output (the contract enforces it on chain anyway). Found on a real swap: its
  `amountOutMinimum` was **0** (no slippage protection) — a good candidate for a warning.
- Gains aren't checked (receiving more is not a risk), nor where the router sends intermediate
  tokens.
- Only contract-calldata descriptors; EIP-712 (Permit2 signatures, UniswapX orders) is next and
  pairs with "simulate the worst-case transferFrom" for permits.

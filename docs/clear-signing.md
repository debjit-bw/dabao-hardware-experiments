# ERC-7730 clear-signing check

The verifier signs only if **every effect of the simulated transaction is explained by what the
user is shown**. "What is shown" comes from an ERC-7730 descriptor; "every effect" comes from the
effects inspector (`docs/effects-inspector.md`). Code: `crates/clear-sign` (check + model),
`host/dabao-host/src/descriptors.rs` (compiler), `descriptors/` (source JSON).

## Trust model

- **Descriptors are part of the firmware.** The host compiles 7730 JSON into a compact RLP blob
  (`crates/clear-sign/descriptors.bin`, 4.5 KB with the token list) that is built into the
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
| Uniswap v3 Router 2, Sepolia (`0x3bFA…e48E`) | the same four | the registry file with the Sepolia deployment |
| DemoPayRouter (`0x1ab7…5Fc7`, Sepolia) | pay | written for this project |
| WETH9 (`0xC02a…6Cc2`, Sepolia `0xfFf9…6B14`) | deposit, withdraw, transfer, approve | written for this project in 7730 format |

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
with the registry's formats (Sepolia `context`). Swaps:
[exactInputSingle](https://sepolia.etherscan.io/tx/0xffab26994b6096a1fda6315e2c6d653733e3051e82bdf442a2d055811550d716),
[multicall](https://sepolia.etherscan.io/tx/0x4148ce5b1a520f0ff8a09f906c871dfe1300824889b9723b14d8831957dde1ad).

There is no display on the board: "shown" below and above means what the board computes for
display. Today the untrusted host prints it.

## Limits / next

- Amounts are checked numerically and displayed with decimals and tickers only for tokens in the
  firmware's trusted list (descriptors' `metadata.token` + `descriptors/tokens.json`); others are
  shown in raw units with the token address. Extending the list is a firmware change, on purpose.
- Labels carry no machine-readable meaning, so the slippage annotation works without them: any
  shown amount of an asset the sender gains that is below the simulated gain is annotated with
  the simulation ("…(simulated: X, N% lower)"), and warned about if it is 0 or under half of X
  (`ClearSign.warnings`, not blocking; the policy engine decides). Found on a real mainnet swap:
  `amountOutMinimum` = 0.
- The shown fields also include "Network fee (simulated)" and "Max network fee".
- Gains aren't checked (receiving more is not a risk), nor where the router sends intermediate
  tokens.
- Only contract-calldata descriptors; EIP-712 (Permit2 signatures, UniswapX orders) is next and
  pairs with "simulate the worst-case transferFrom" for permits.

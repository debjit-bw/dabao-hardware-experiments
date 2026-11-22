# Effects inspector

Turns a simulation's raw output (every log, every account's balance / nonce / storage
before → after) into a short list of **effects** a policy or an ERC-7730 check can reason
about: "0.000438 ETH out, 13.40 TOKEN in", "allowance granted to X", "ownership moved to Y".
Runs on the device inside the verifier (`crates/xous-evm/src/effects.rs`, a pure function,
host-testable); the wire type is `sim_types::Effect`, kinds in `sim_types::effect`.

## Where ERC-7730 fits (and where it doesn't)

ERC-7730 ("structured data clear signing format", **Draft**, created 2024-02-07; descriptor
format 2.1.0 marked active, 3.0.0-next in draft) defines how to **display** calldata and
EIP-712 fields: a descriptor has `context` (which deployments / EIP-712 domain it applies to),
`metadata` (trusted constants, token info) and `display` (per function: an `intent` such as
"Send {value} to {to}" and formatted `fields`: tokenAmount, addressName, date, ...).

It does **not** define effects, state changes or simulation results; it only notes that
simulation engines may consume descriptors. So the rule we enforce — *every effect of the
transaction must be explained by a field the user was shown* — is **our extension**, which we
propose as an "expected effects" addition to ERC-7730. This inspector produces the effects side
of that comparison.

(Source: eips.ethereum.org/EIPS/eip-7730, read 2026-11-21; the field-format list should be
re-checked against the spec's Reference section when the checker is built.)

## The subset, and the rule that makes a subset safe

Recognised (exact event signature, topic count and data length; anything malformed is not
recognised):

| Effect | From |
|---|---|
| `GAS_FEE` | gas_used × gas_price, paid by the sender |
| `NATIVE_OUT` / `NATIVE_IN` | per-account ETH balance deltas, net of the gas fee (sender) and the priority fee (block beneficiary) |
| `ERC20_TRANSFER` / `ERC20_APPROVAL` | `Transfer` / `Approval` with 3 topics + 32-byte amount |
| `NFT_TRANSFER` / `NFT_APPROVAL` | the same signatures with 4 topics (token id indexed) |
| `APPROVAL_FOR_ALL` | `ApprovalForAll(address,address,bool)` |
| `ERC1155_TRANSFER` | `TransferSingle` |
| `PERMIT2_APPROVAL` | Permit2 `Approval` / `Permit` (amount < 2¹⁶⁰, expiration < 2⁴⁸) |
| `OWNERSHIP_TRANSFER` | `OwnershipTransferred` |
| `PROXY_UPGRADE` / `PROXY_ADMIN_CHANGE` | EIP-1967 `Upgraded` / `AdminChanged` |
| `WRAP` / `UNWRAP` | WETH-style `Deposit` / `Withdrawal` |
| `POOL_SWAP` | Uniswap V2 `Swap` and V3 `Swap`; V2 `Sync` counts as bookkeeping (explains the pair's storage, no effect of its own) |
| `NET_GAIN` / `NET_LOSS` | summary for the sender: net per asset (ETH = zero address, gas excluded) over ETH moves, ERC-20 transfers and wraps |
| **`UNEXPLAINED_STORAGE`** | **a contract whose storage changed but that emitted no recognised event** |

**Nothing is dropped silently**: an unknown event, a malformed one, a token that moves balances
without logging, a protocol outside the subset — all surface as `UNEXPLAINED_STORAGE` on that
contract. The checker treats it as "refuse / warn", so an incomplete subset fails closed,
except where a recognised event from the same contract excuses the change (see Known limits).

Why swaps needed more than the first cut: a Uniswap swap's token legs are plain ERC-20
`Transfer`s (already covered), but the pool rewrites its own state (reserves / price) and the
router may wrap ETH. With the first subset both showed up as unexplained, so a strict checker
would have refused every swap. `POOL_SWAP`, `Sync`-as-bookkeeping and `WRAP`/`UNWRAP` close
that, and `NET_GAIN`/`NET_LOSS` give the "you pay X, you get Y" view a 7730 swap intent
("Swap {amountIn} for at least {amountOutMin}") is checked against.

## Known limits

- **Events are claims.** They are emitted by real bytecode running on verified state, but a
  malicious contract can emit a `Transfer` it didn't perform. A fake event *without* storage
  change is reported as if real.
- **One recognised event explains all of that contract's storage.** E.g. WETH's `Deposit`
  storage write was "explained" by WETH's `Transfer` even before `WRAP` existed; a token that
  emits a real `Transfer` and also silently rewrites an allowance is not flagged. Tightening
  this needs the storage layout (which slots a `Transfer` may touch), e.g. from descriptor
  metadata.
- **No call tree yet**: delegatecalls into unknown code, and value sent by internal calls, are
  only visible through their storage / balance effects.
- **No code changes yet**: EIP-7702 delegations and `selfdestruct` aren't reported (the legacy
  transactions we sign can't carry 7702 authorizations).
- Uniswap **v4** (singleton PoolManager, flash accounting) and ERC-1155 batch transfers are
  outside the subset: they show up as `UNEXPLAINED_STORAGE`.

## Tests

- Unit tests (`cargo test -p xous-evm`): every recognised event, ETH transfer with gas and tip,
  silent storage writes and unknown events → unexplained, malformed events not trusted, a
  synthetic V2 swap paid in ETH (wrap + Sync + Swap → no unexplained, correct sender net).
- Real mainnet fixtures (`crates/xous-evm/fixtures/`, built with `dabao-host build`):
  - `weth-transfer.rlp`: gas fee, one ERC-20 transfer, sender net −1 WETH.
  - `uniswap-swap.rlp` ("redo now", SwapRouter02, ETH → token via WETH and a V3 pool): no
    unexplained storage; sender net −`tx.value` ETH, +13.40 of the output token.
  - `uniswap-swap-replay.rlp` (**exact replay** of tx 0x38c2…da1a, block 26464010, on its
    parent state; token → USDC, USDC being a delegatecall proxy): our simulator's status,
    gas used (124,255) and all 3 logs were **identical to the on-chain receipt**; effects fully
    explained; sender net −17.06 token, +124.93 USDC.

## On the board (2026-11-21)

| Fixture (USB HID) | Input | Round trip | Verifier | Peak heap | Sender net |
|---|---|---|---|---|---|
| WETH transfer | 23 KB | 0.90 s | 44 ms | 420 KB | −1 WETH |
| Uniswap swap (redo now) | 94 KB | 3.41 s | 165 ms | 594 KB | −0.000438 ETH, +13.40 token |
| Uniswap swap (exact replay) | 131 KB | 4.63 s | 218 ms | 699 KB | −17.06 token, +124.93 USDC (gas 124,255 = chain) |

Effects on the device are identical to the host's. Most of the round trip is HID transfer
(64-byte reports, 5 ms poll interval: ~28 KB/s).

## Memory: what we learned getting swaps onto the chip

1. **Per-process heap cap.** Xous limits each process to a 512 KiB heap by default (kernel
   `services.rs`, unless built with `big-heap`). The 94 KB swap needs ~594 KB: the verifier's
   allocation failed and it aborted mid-request. The hosted emulator doesn't enforce the cap,
   so it passed there. Fix: the verifier raises its own cap to 1.5 MiB at startup
   (`AdjustProcessLimit`, which acts on the caller, as pddb does).
2. **Physical RAM.** With the cap raised, the 131 KB replay (≈700 KB heap) still hung: the
   transport had reassembled the frame in a doubling `Vec` (256 KiB for 131 KB) and copied it
   into a 132 KB lend buffer, ~390 KB just to pass the message on. Fix: the transport maps the
   lend buffer once it has the length prefix and writes HID reports straight into it.
   2 MiB of SRAM is shared by the kernel and every process.
3. **Emulator heap numbers run ~10–15% above the board's** (64-bit vs 32-bit): 466 / 665 /
   798 KB in the emulator vs 420 / 594 / 699 KB on the chip.

Robustness (done):
- The verifier refuses inputs over **140 KB** before decoding ("input too large for this
  device"), just above the largest input measured to work (131 KB → 714 KB peak). Free RAM
  can't be measured from a process: Xous's `map_memory` maps lazily (a 4 MiB probe succeeds on
  the 2 MiB chip), and touching pages to find the limit would kill the prober.
- The transport learns that limit from the verifier at boot and refuses oversized frames from
  their length prefix; `dabao-host` stops uploading when it sees the early refusal.
- Verifier calls have a 90 s timeout in the transport: a verifier that dies or stalls answers
  "verifier unresponsive … press RESET" instead of hanging the host forever.

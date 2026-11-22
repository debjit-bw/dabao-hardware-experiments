# Signing policy

The device signs a transaction only if three independent checks pass, all inside the verifier:

1. **Simulation**: the witness verifies against the state root and the transaction succeeds.
2. **ERC-7730 check** (`docs/clear-signing.md`): every effect is explained by what is shown.
3. **Policy** (this document): the device owner's own limits, which no descriptor and no host
   can relax.

7730 answers "does the user see what this transaction does?". The policy answers "even if
they do, is the device allowed to do it?". This is the part that refuses an agent with a
prompt injection that proposes a well-displayed transaction to the wrong address, or
too much of it.

Code: `crates/policy` (rules, host-testable), `crates/verifier/src/counters.rs` (persistence),
`host/dabao-host/src/policy.rs` (compiler), `policy/policy.json` (the policy).

## Trust model

- **The policy is part of the firmware.** `policy/policy.json` is compiled into a 228-byte RLP
  blob (`crates/policy/policy.bin`, built by `scripts/compile-descriptors.sh`) embedded in the
  verifier. Changing it means building and flashing a new image; there is no runtime API to
  change it.
- **Spending is measured from the simulation's effects, not from calldata.** A router, a
  multicall or a delegatecall can't hide spending. For each asset:
  - the sender's net loss (`NET_LOSS`);
  - plus every allowance the sender grants (ERC-20 `Approval`, Permit2), **counted at its full
    amount**. An allowance is spending authority, so an unlimited approval is refused by any
    finite limit.
  - plus, for ETH, the **maximum** network fee (`gas_limit × max fee per gas`), not the
    expected one.
- **Counters persist in RRAM.** There is one 32-byte keystore app slot per daily limit
  (slots 176–207), claimed by the verifier at boot before it registers its server, so the
  claim comes before any host input. The slots use our keystore claim patch
  (`docs/keystore-slot-claims.md`), so the keystore refuses other processes access to them. Slot format:
  `"DPL1" ‖ id (8) ‖ day (u32) ‖ spent (u128)`, where `id = keccak(chain ‖ asset)[..8]`. A slot
  that holds another limit's counter after a policy change reads as a fresh counter.
- **Write before sign.** Counters are written before the job goes to the signer. A crash in
  between over-counts and never under-counts. A failed write refuses the transaction, and an
  unreadable counter at boot disables signing.
- **The device counts what it signs.** It can't know whether the host broadcasts a signed
  transaction, so a signed-but-unbroadcast transaction still counts. That's the conservative
  choice.

## Rules (per chain)

| Rule | Refused when |
|---|---|
| chain | the chain has no policy (the demo policy has Sepolia only, so mainnet is refused) |
| daily limit | spent today (counter) + this transaction's spending > the asset's daily limit |
| assets without a limit | the transaction spends an asset with no limit (`"unlimitedAssets": "refuse"`); NFT transfers out and NFT approvals likewise |
| network fee | `gas_limit × max fee` > `maxNetworkFee` |
| slippage | a shown swap minimum is more than `maxSlippageBps` below the simulated output (from `ClearSign.min_receive`) |
| allowlist | `tx.to`, or any address the user is shown (recipient, spender, beneficiary), is neither the device nor on `allowlist` |

Amounts in `policy.json` are whole units ("0.005" ETH, "1" USDC), converted with the
decimals of the firmware's token list. A limit can only name an asset the device can also
display.

## The demo policy (Sepolia)

```
max network fee 0.002 ETH; max slippage 300 bps; assets without a limit refused
allow SwapRouter02 0x3bFA…e48E, WETH9 0xfFf9…6B14, burn address 0x…dEaD, DemoPayRouter 0x1ab7…5Fc7
daily limits: 0.005 ETH, 0.002 WETH, 1 USDC
```

`dabao-host policy` prints the policy in force and the counters, as the device reports them.
Every `sign` / `send-tx` prints the policy's notes (e.g. "ETH: 0.00103 ETH this tx,
0.00103 ETH of 0.005 ETH today") and its violations.

## Limits / next

- **The allowlist doesn't separate "may call" from "may receive".** An allowlisted router as a
  swap recipient passes every rule, and with no gain to the sender the slippage rule never
  runs (docs/GUIDE.md, hole A).
- **Counters are stored by position**: inserting or reordering limits resets today's spending.
- **Time comes from the light client.** A day is `block.timestamp / 86400` of the simulated
  block, which must be the parent's timestamp + 12 s, and the parent header must be proven
  canonical by the sync committee (docs/light-client.md), or nothing is signed. A host can't
  move the clock forward. It can only replay an older header, and the slot ratchet refuses
  that once anything newer has been signed.
- Limits are per calendar day (UTC), not rolling 24 hours.
- Allowances are counted when granted and the later `transferFrom` is counted again, so
  approve-then-swap is double-counted. That's conservative; tracking allowances properly
  needs per-spender state.
- The rules are fixed in code with parameters in the policy file. The original plan's
  "Solidity/bytecode policy" (the policy as EVM bytecode the device runs over the effects)
  would make the rules themselves programmable. revm is already on the device, so it's a
  natural next step.

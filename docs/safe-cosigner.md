# Safe co-signer

The Dabao is one owner of a **2-of-3 Safe** (v1.4.1, SafeL2) on Sepolia:

| Owner | Who | Where the key lives |
|---|---|---|
| agent `0x124b…A515` | an AI agent / automation, which proposes and executes | hot key on the host (`.dabao-keys/agent.key`) |
| Dabao `0x7813…F986` | the device, which co-signs only what passes its checks | keystore app slots 160–161 (RRAM) |
| recovery `0x6a65…6250` | the human, for override and recovery | offline in practice (a host file in the demo) |

Safe: [`0x265871a72567419AE2f799a1288271C09B589fd9`](https://sepolia.etherscan.io/address/0x265871a72567419AE2f799a1288271C09B589fd9).

The agent can propose anything, but the Safe executes nothing with its signature alone (it
reverts with `GS020`). The second signature comes from the device, and the device signs only
after its own checks.

## What the device checks before co-signing (`wire::TYPE_SAFE_SIGN`)

1. **Simulation of the Safe's call as the Safe.** revm runs `to / value / data` with
   `msg.sender` = the Safe, on state verified against the state root. The host-built
   `SimInput` has `tx.from` = the Safe. EIP-3607, the nonce check and the base fee are off for
   this call only; gas price 0, because the executor pays the gas, not the Safe.
2. **ERC-7730 check** with the Safe as the sender: every effect on the Safe's assets must be
   explained by a shown field.
3. **Policy** with the Safe as the spender: allowlist, daily limits (the same counters as the
   device's own account: one daily budget for everything the device signs), slippage.
4. **The Safe's configuration, from verified storage** (the witness must include these
   slots, and their proofs are checked like every other):

   | Slot | Required |
   |---|---|
   | 0: singleton | Safe 1.4.1 or SafeL2 1.4.1 (canonical addresses) |
   | `owners[device]` (mapping at slot 2) | non-zero: the device is an owner |
   | 4: threshold | ≥ 2: the other owners can't act without the device… |
   | `modules[SENTINEL]` (mapping at slot 1) | = SENTINEL: no modules (a module moves funds with no signatures at all) |
   | guard slot `keccak("guard_manager.guard.address")` | 0: no transaction guard the device doesn't know |
   | 5: nonce | **read here, not taken from the host**: it goes into the hash |

   …except the agent **plus** the recovery key, which is the intended human override.
5. **The signer builds the hash itself.** The verifier sends the approved fields and the
   verified nonce; the signer computes the SafeTx EIP-712 hash
   (`sim_types::safe::tx_hash`: domain `{chainId, verifyingContract}`, operation CALL,
   no gas-refund parameters) and returns a 65-byte owner signature (`v` = 27/28).

The host then checks the device's signature against the hash it computes itself and against
the Safe's own `getTransactionHash`. The agent adds its signature, the signatures are sorted by
owner address, and the agent executes `execTransaction` and pays the gas. Finally the host
compares the inner call's logs on chain (everything not emitted by the Safe itself) with the
device's prediction.

## On the board (2026-11-22, Sepolia)

| Case | Result |
|---|---|
| Safe → 0.0001 ETH to 0x…dEaD | co-signed; [executed](https://sepolia.etherscan.io/tx/0xca9e49b3d26e28c5537b50f3e1a3251789e8af873664b7cdf721595748fca98a), `ExecutionSuccess`, logs identical (1); 0.58 s round trip, verifier 30 ms |
| Safe → 0.0015 ETH to 0x…BADBAD00 (the prompt-injected "send it to me") | **refused**: not on the allowlist. Nothing executed; the Safe kept its funds |
| the agent alone, the same transfer | the Safe reverts `GS020` (1 of 2 signatures) |
| Safe wraps 0.0001 ETH (WETH `deposit`) | co-signed as 7730 "Wrap ETH"; [executed](https://sepolia.etherscan.io/tx/0x8321d1cec85a963c65dbbe733b38ddf44d72a0bd8ba559f3752bdaee5f23dd76), logs identical (2) |

## Commands

```
dabao-host safe keys                      # create / show the agent and recovery keys
dabao-host safe create --chain sepolia    # the agent deploys the Safe (owners: agent, device, recovery)
dabao-host safe fund --value WEI          # agent -> Safe, no device involved
dabao-host safe send --to ADDR [--value WEI] [--data 0x..] [--broadcast]   # device co-signs, agent executes
dabao-host safe send ... --agent-only     # what the agent can do alone (eth_call only)
dabao-host safe info
```

## Limits / next

- **Gap between simulation and inclusion: closed** by the on-chain postcondition
  (docs/postcondition.md). The device co-signs only a DELEGATECALL to MultiSendCallOnly with
  [the call, `DabaoPostcondition.check(...)`], which reverts the Safe transaction unless the
  Safe's balances and configuration still match the simulation at inclusion.
- The agent + recovery keys can execute without the device. That's intended (the human
  override), but it means the recovery key must really be kept offline.
- The parent header is proven canonical by the light client (docs/light-client.md), the same
  as for the device's own transactions.

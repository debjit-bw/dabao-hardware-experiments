# The complete guide to this repo

This guide explains the whole project in plain English: what it is, how it works, what every
file does, and how to build, run and change it. You don't need to know Xous or much Ethereum.

**How to read it**

| You want to | Read |
|---|---|
| get the idea | parts 1 to 4 |
| know what it can and can't do | parts 5 and 6 |
| find your way around the code | parts 7 and 8 |
| build, run or test it | parts 9 to 11 |
| change it | part 12 |
| look up any command | [part 15](#15-command-reference) |
| fix something that broke | part 13 |

Part 6 lists the known security holes. Read it before you trust the board with anything.

---

## Contents

1. [The idea in one minute](#1-the-idea-in-one-minute)
2. [Words you need](#2-words-you-need)
3. [The architecture](#3-the-architecture)
4. [What happens, step by step](#4-what-happens-step-by-step)
5. [What it can do](#5-what-it-can-do)
6. [What it can't do, and known holes](#6-what-it-cant-do-and-known-holes)
7. [Every file explained](#7-every-file-explained)
8. [Reference: messages, storage, addresses](#8-reference-messages-storage-addresses)
9. [How to build](#9-how-to-build)
10. [How to run](#10-how-to-run)
11. [How to test](#11-how-to-test)
12. [How to change things](#12-how-to-change-things)
13. [When something goes wrong](#13-when-something-goes-wrong)
14. [A good order to read the code in](#14-a-good-order-to-read-the-code-in)
15. [Command reference](#15-command-reference)

---

## 1. The idea in one minute

A normal hardware wallet signs what it is given. It can't tell what a transaction will really
do, so it has to trust the computer it is plugged into.

This project puts the checking on the chip. Before the board signs, it:

1. **finds out what the blockchain looks like**, by checking signatures from Ethereum's
   validators;
2. **runs the transaction itself**, on that checked state, and sees what would happen;
3. **compares that with what a user would be shown**, and refuses if it finds something hidden;
4. **applies the owner's rules**, such as "no more than 0.005 ETH a day";
5. **signs**, in a separate process that is the only one holding the key.

The same board can be one owner of a shared wallet (a Safe) used by an AI agent. The agent
suggests payments, and the board decides whether to add its signature.

It is a hackathon prototype. It runs on a real board and has sent real Sepolia (test network)
transactions. It is not safe for real money.

---

## 2. Words you need

**The hardware and operating system**

| Word | Meaning |
|---|---|
| Dabao | The small development board. Its chip is the Baochip-1x: a 350 MHz RISC-V CPU, 2 MiB of RAM, 4 MiB of storage. |
| RRAM | The chip's permanent storage. It survives power off. |
| SRAM | The chip's working memory. 2 MiB, shared by everything. |
| Xous | The operating system. Programs are separate processes that talk by sending messages. |
| MMU | The hardware that stops one process from reading another's memory. |
| Keystore | A Xous service that stores small secrets in numbered 32-byte "app slots". |
| boot1 | The bootloader. New firmware is flashed through it. |
| UF2 | The firmware file format that boot1 accepts. |
| HID | A simple kind of USB device. The board talks to the computer this way. |
| Host | The computer the board is plugged into. **The board does not trust it.** |
| XIP | "Execute in place": code runs straight from storage, so it doesn't use RAM. |

**Ethereum**

| Word | Meaning |
|---|---|
| Account | An address with a balance. It is controlled by a key, or by code (a contract). |
| EOA | An account controlled by a key. The board has one. |
| Wei | The smallest unit of ETH. 1 ETH = 10^18 wei. |
| Calldata | The bytes that tell a contract which function to run, with which arguments. |
| Selector | The first 4 bytes of calldata. They name the function. |
| Event, or log | A message a contract emits while running, such as "Transfer". |
| Allowance, or approval | Permission for someone else to spend your tokens later. |
| Nonce | A counter that stops a transaction from being used twice. |
| State root | One hash that commits to every balance, slot and contract on the chain. |
| Merkle proof | A short list of hashes proving one value belongs under a state root. |
| Witness | All the proofs and contract code needed to run one transaction. |
| EVM, revm | The Ethereum virtual machine, and the Rust version of it that runs on the board. |
| Slippage | How much worse than expected a swap is allowed to be. |

**The checking machinery**

| Word | Meaning |
|---|---|
| Sync committee | 512 validators who sign each recent block. A new group takes over every ~27 hours. |
| Period | The ~27 hours (8192 slots) that one committee serves. |
| Slot | A 12-second tick of Ethereum's consensus chain. |
| BLS signature | A signature type where hundreds of signatures combine into one. |
| Light client | Code that follows the chain by checking only committee signatures. |
| Anchor | The first committee the firmware trusts. It is built in. |
| Ratchet | A saved number that only goes up. Here: the newest slot the board has signed on. |
| ERC-7730 | A standard JSON format saying how to display a contract call. One file is a "descriptor". |
| Effect | One normalised thing a transaction did, such as "sent 5 USDC to X". |
| Policy | The owner's rules, built into the firmware. |

**The shared wallet**

| Word | Meaning |
|---|---|
| Safe | A popular multi-signature wallet contract. Ours needs 2 of 3 owners. |
| CALL | Run another contract as itself. |
| DELEGATECALL | Run another contract's code as yourself. Powerful, so dangerous. |
| MultiSendCallOnly | A standard Safe helper that runs several CALLs in one transaction. |
| Postcondition | A check that runs at the end of a transaction and cancels all of it on failure. |
| MCP | A protocol that lets AI agents use tools. |

---

## 3. The architecture

### The big picture

```
   Ethereum RPC node          beacon node            AI agent (optional)
   (proofs, code)             (committee signatures)        |
          \                        /                        | MCP
           \                      /                  tools/bao-mcp
            \                    /                          | runs the command
             v                  v                           v
        +------------------------------------------------------------+
        | HOST: host/dabao-host                        (not trusted) |
        | fetches data, packs a request, prints the board's answer   |
        +------------------------------------------------------------+
                                   |  USB HID (TCP in the emulator)
   ================================|=============================== BOARD
                                   v
        +------------------------------------------------------------+
        | 1. transport      apps image                 (not trusted) |
        |    joins USB packets into messages and passes them on      |
        +------------------------------------------------------------+
                                   |  lends memory pages
                                   v
        +------------------------------------------------------------+
        | 2. verifier       system image                   (trusted) |
        |    light client -> proofs -> revm -> effects               |
        |    -> ERC-7730 check -> policy -> postcondition (Safe)     |
        |    saves: spending counters, committee root, newest slot   |
        +------------------------------------------------------------+
                                   |  approved jobs only
                                   v
        +------------------------------------------------------------+
        | 3. signer         apps image                     (trusted) |
        |    builds the hash itself, then signs                      |
        |    saves: the private key                                  |
        +------------------------------------------------------------+
```

### Why three processes

- **Transport** reads bytes from an untrusted computer, which is where bugs get exploited. So
  it holds nothing valuable and understands almost nothing.
- **Verifier** does all the hard thinking. It has no key.
- **Signer** has the key and does almost nothing else. Nobody can send it a signing request.
  It asks the verifier for work and waits. It's also the only process that can reach the
  board's storage slots, and it keeps the verifier's counters for it.

Separate processes only help if the key can't be fetched another way. Upstream, a keystore
process reads and writes the storage slots for anyone who asks. Our image leaves it out: the
signer runs as process 3 in its place, the one number the chip's storage hardware trusts, and
maps the slots itself at boot. The kernel gives each page to one process only, so nobody else
can map them. The verifier gets its spending counters and light-client state from the signer,
with a password made fresh at every boot that only the verifier receives. The signer never
serves the key's slots. Details: `docs/xous-core-fork.md`, section 4.

### Who is trusted for what

| Part | Trusted for | Not trusted for |
|---|---|---|
| Host, RPC node, beacon node | being available | any data. The board checks it, with the exceptions in part 6. |
| Transport | nothing | everything |
| Verifier | deciding what may be signed | holding the key |
| Signer | keeping and using the key | judging a transaction |
| Firmware | all built-in rules: anchor, policy, descriptors, tokens | |
| Sync committee | saying which block is real, if 2/3 are honest | |
| xous-core: kernel, loader | process separation, giving each page to one process | |

### Where the code lives on the chip

| Image | Contains | Flash it after changing |
|---|---|---|
| `loader.uf2` | Xous loader | on a board's first flash, then only if xous-core's loader changes |
| `xous.uf2`, the system image | kernel, Xous services, **verifier**, **signer** | verifier, signer, policy, descriptors, light client, EVM |
| `apps.uf2`, the apps image | **transport** | transport |

If you change `crates/sim-types`, flash both `xous.uf2` and `apps.uf2`, and rebuild the host.

---

## 4. What happens, step by step

### 4.1 When the board starts

1. The signer starts as process 3. It checks that number, switches on time-slicing (in
   upstream Xous the keystore does that), and maps the storage slots and the storage
   controller.
2. It loads its key from slots 160 and 161. On the very first boot it makes one from the
   hardware random number generator.
3. The verifier raises its memory cap from 512 KiB to 1.5 MiB.
4. The signer connects to the verifier and reports its address and this boot's password.
5. The verifier loads the spending counters and light-client state through the signer.
6. Only now does the transport start reading USB.

The committee's 512 public keys live in RAM, so the host uploads them again after each boot.
The board accepts them only if they hash to the root it saved. This takes about 7 seconds.

### 4.2 A normal transaction from the board's own account

This is `dabao-host send-tx`.

**On the host**

1. Ask the board for its address.
2. Make sure the board's light client is current (`lc-sync` does the same thing).
3. Get the newest block the sync committee signed, with the proof.
4. Ask the RPC node which accounts and slots the transaction touches.
5. Fetch a Merkle proof for each, and the code of each contract.
6. Pack all of it into one `SimInput` and send it over USB.

**On the board**

7. Refuse it if it is over 140 KiB.
8. Check the committee's signature, and that it commits to this parent block.
9. Check every piece of state against that block's state root. Missing data is an error. It
   is never treated as zero.
10. Run the transaction in revm.
11. Turn the logs and state changes into a list of effects.
12. Work out what a user would be shown, and compare it with the effects.
13. Apply the policy.
14. If everything passed, save the new spending totals and the new slot number. This happens
    **before** signing, so a crash can over-count but never under-count.
15. Hand the job to the signer. It builds the transaction hash itself and signs.

**Back on the host**

16. Check the signature and every signed field against the request.
17. With `--broadcast`, send it, wait, and compare the chain's result with the board's
    prediction.

### 4.3 The gates, in the order they are reported

The board signs only if every answer is yes.

| # | Question | If no, you see |
|---|---|---|
| 1 | Is the input valid, and fully proven? | `simulation rejected the input` |
| 2 | Does the transaction succeed? | `the transaction reverts` |
| 3 | Is every effect explained? | `ERC-7730 check failed` |
| 4 | Is the parent block proven? | `light client: ...` |
| 5 | Does the policy allow it? | `policy: ...` |
| 6 | Is it from the board, or from a Safe that is set up correctly? | `tx is from ...` or `Safe ...` |
| 7 | Is the chain mainnet or Sepolia? (The policy allows only Sepolia today.) | `chain ... not supported` |
| 8 | Safe only: could the postcondition be built, and does it pass? | `postcondition: ...` |
| 9 | Could the counters and ratchet be saved? | `can't persist ...` |
| 10 | Did the signer accept the job? | `the signer refused` |

Gates 1 to 7 are `approve()` in `crates/verifier/src/main.rs`. The rest are in `sign_request()`
in the same file.

### 4.4 A payment from the Safe

This is `dabao-host safe send`.

1. The host builds a request whose sender is the Safe.
2. The board simulates the call as if the Safe made it.
3. It reads the Safe's settings from proven storage: the board is an owner, the threshold is
   at least 2, there are no modules and no guard. It also takes the Safe's nonce from there.
4. It runs the same display and policy checks, with the Safe as the spender.
5. It reads the Safe's balances before and after the simulated call. The differences, less
   any shown slippage, become the smallest changes it will accept.
6. It builds a batch of three calls:

   ```
   Safe --DELEGATECALL--> MultiSendCallOnly
                            |-- CALL 1: DabaoPostcondition.begin(assets)   record balances
                            |-- CALL 2: the payment the agent asked for
                            |-- CALL 3: DabaoPostcondition.check(owner, threshold, deadline, assets, minimum changes)
   ```

7. It tests that check on the simulated state, then signs the hash of the batch.
8. The agent's key adds the second signature and submits the transaction.
9. On chain, if a balance changed worse than allowed, a checked setting changed, or 10
   minutes have passed, the whole transaction reverts.

### 4.5 The committee hand-over

About every 27 hours:

1. The old committee signs a block whose state names the next committee.
2. The host sends that signature, the next committee and a Merkle branch.
3. The board checks both, saves the new root and period, and switches.

The host only carries the data. After a long gap, `lc-sync` walks forward one period at a time.

### 4.6 An AI agent

1. The agent calls the MCP tool `propose_tx` with a destination, amount and reason.
2. `bao-mcp` runs `dabao-host safe send`.
3. The board signs or refuses.
4. The agent gets the verdict as text. The proposal is logged in `logs/agent-proposals.jsonl`.

---

## 5. What it can do

### Signing

- Legacy and EIP-1559 transactions from its own account.
- Owner signatures for a Safe 1.4.1 or SafeL2 1.4.1, only in the three-call batch shape.
- It keeps the same key across reboots and reflashes, as long as the slot layout stays the same.

### Checking blocks

- Verifies a real Sepolia sync-committee signature in about 0.7 seconds on the chip.
- Follows committee hand-overs, and remembers where it is across reboots.
- Refuses blocks older than the newest one it signed on.

### Simulating

- Runs real transactions, including Uniswap swaps, with inputs up to 140 KiB.
- The Sepolia transactions recorded as test fixtures match their on-chain receipts.
- Can simulate mainnet too. It just won't sign there.

### Recognising effects

ETH moved, network fee, ERC-20 transfers and approvals, NFT transfers and approvals,
"approve all", ERC-1155 single transfers, Permit2 approvals, ownership changes, proxy upgrades
and admin changes, wrapping and unwrapping, Uniswap v2 and v3 swaps, and the sender's net gain
or loss per asset. If a contract changed storage without any recognised event, that is
reported as "unexplained" and blocks signing.

### Contracts it can explain today

| Contract | Functions | Chains |
|---|---|---|
| any address, with no calldata | plain ETH transfer | any supported |
| WETH | `deposit`, `withdraw`, `transfer`, `approve` | mainnet, Sepolia |
| Uniswap SwapRouter02 | `exactInputSingle`, `exactOutputSingle`, `swapExactTokensForTokens`, `swapTokensForExactTokens`, and `multicall` of these | mainnet, Sepolia |
| DemoPayRouter | `pay` | Sepolia |

Anything else with calldata is "blind signing" and is refused.

### The built-in policy (demo, version 3)

| Rule | Value |
|---|---|
| Chains | Sepolia only |
| Daily limits (UTC days) | 0.005 ETH, 0.002 WETH, 1 USDC |
| Assets with no limit | refused |
| Largest network fee | 0.002 ETH |
| Largest slippage | 3% |
| May be called | SwapRouter02, WETH, DemoPayRouter |
| May receive | `0x...dEaD`, plus the sender itself |
| Swaps | one at a time, paid out to the sender |
| Leftovers | a called contract may not keep funds |

The board's own account and the Safes it co-signs for share one daily budget. An approval
counts as spending its full amount.

### Speed and size, measured on the board

| Thing | Number |
|---|---|
| Simulate a Sepolia swap (117 KB witness) | 201 ms, 436 KB peak memory |
| Sign a wrap, all checks (17 KB witness) | 0.84 s, 116 KB peak memory |
| Verify one committee signature | about 0.7 s |
| Sign a simple send, all checks | about 0.84 s on the chip |
| Safe co-sign, all checks (about 98 KB) | about 1 s on the chip, 4.4 s with USB, 379 to 390 KB peak memory |
| Load committee keys after boot | about 7 s |
| USB speed | about 28 KB/s |
| System image | 2,130,448 of 2,490,368 bytes |
| Apps image | 336,640 of 893,696 bytes |

---

## 6. What it can't do, and known holes

"Reproduced" means shown on a local fork or in a test. "From the code" means found by reading,
not yet demonstrated.

### Serious

Holes A, B and C (a router as recipient, deposits absorbing losses, co-signatures that never
expired) were fixed in policy v3 and contract v2. The letters below are kept.

**D. The demo machine holds two of the three Safe keys.**
The agent and recovery keys are both files in `.dabao-keys/`. Whoever can read that folder
doesn't need the board. A real setup keeps the recovery key on another device.

**E. There is no screen and no button.**
"Shown" means "computed for display". The untrusted host does the printing, and no human
confirms anything on the board. The policy is the only real approval.

**F. Physical access is enough to get the key.** *(From the code.)*
The board is in developer mode, so someone who can press reset and flash their own firmware
can write a program that reads the key's slots. The signer holding them as process 3 protects
against other processes in *our* firmware, not against other firmware. (A process in our firmware could also read any
memory through BIO DMA until the fork's third commit; see `docs/xous-core-fork.md`.)

### The simulation can differ from reality

**G. The host picks part of the block.** Base fee, gas limit, beneficiary and prevrandao are
not checked against the proven parent.

**H. A Safe call looks different in simulation.** `tx.origin` is the Safe (really it is the
executor), and the gas available differs. A hostile contract could notice and behave well
only in simulation. *(From the code.)*

**I. The board's own transactions have no postcondition.** If the state changes before
inclusion, nothing catches it. Only Safe transactions get the final check.

**J. Events are claims.** A contract can emit a false event. Also, one recognised event from a
contract excuses all of that contract's storage changes.

### The light client

**K. It can't tell "newest".** It has no clock. A host can offer any committee-signed block
newer than the ratchet, or simply never report a hand-over. It also follows blocks that are
signed but not yet final.

**L. The proof isn't tied to the chain id.** The light client is Sepolia-only. Other chains
are refused by the policy, so adding a mainnet policy without fixing this would be unsafe.

### Smaller problems (from the code)

**M. The postcondition covers little.** It doesn't check approvals, NFTs, or tokens that
neither moved nor have a limit. It also reverts exact-output swaps that cost slightly more
than simulated. And Safe swaps don't fit on the board yet: about 158 KB of witness against a
140 KiB limit.

**R. The board's signatures don't expire.** A transaction signed for the board's own account
but never sent stays valid until that nonce is used. Signing without `--broadcast` creates
exactly that. To cancel one, send another transaction with the same nonce.

**O. A Safe is recognised by storage alone.** Any contract can copy that layout. Such a
signature is useless on a real Safe, but it uses up the daily budget. A hostile host can use
up the budget anyway by requesting signatures it never sends.

**P. The MCP server reads text.** It decides the status from the host's printed output, so
rewording a message can change what the agent is told.

**S. Accounts with EIP-7702 delegation don't work.** The host doesn't fetch the delegate
account's proof or code, so the simulation stops with `MPT: unresolved node access`.
Reproduced with `build --replay`. `send-tx` builds its witness the same way. It fails closed.

**Q. A crash wedges the board.** If the verifier runs out of memory or panics, you must press
reset.

### Not built

Display, confirmation button, QR or air-gapped mode, block attester, EIP-712 message signing
(permits, orders), programmable policy, mainnet signing, Uniswap v4.

---

## 7. Every file explained

### 7.1 Top level

| File | What it does |
|---|---|
| `README.md` | The short front page. |
| `Cargo.toml` | The Rust workspace: lists our crates, keeps `vendor/` out, points four dependencies at Xous-friendly versions, and sets small-binary build options (`opt-level z`, abort on panic). |
| `Cargo.lock` | Exact versions of every dependency. Don't update casually: a newer fork schedule or EVM changes simulation results. |
| `.gitignore` | Keeps build output, keys, logs, audit output and `.env` out of git. |
| `.gitmodules` | Says where the `vendor/xous-core` submodule comes from. |
| `LICENSE-MIT` | The MIT license. You may pick this one or Apache. |
| `LICENSE-APACHE` | The Apache 2.0 license. |
| `vendor/xous-core` | The operating system, as a git submodule. It is upstream plus six commits: a build fix for Rust 1.100, the keystore claims (no longer used), a limit on BIO DMA, two for building our own boot1 (built, never installed), and `--trusted-service`, which makes the signer process 3. See `docs/xous-core-fork.md`. |

### 7.2 `crates/sim-types`: the shared language

Every other part uses these types.

| File | What it does |
|---|---|
| `crates/sim-types/Cargo.toml` | Package file. Very few dependencies, no standard library. |
| `crates/sim-types/src/lib.rs` | Everything that crosses a boundary. See below. |
| `crates/sim-types/tests/safe.rs` | Checks the Safe hash and byte encodings against values from the real Safe contract and from `cast`. |

Inside `lib.rs`:

- `SimInput`: one request. Chain, parent header, block settings, transaction, witness, proof.
- `SimTx` and `SimBlock`: the transaction and the block it runs in.
- `SimResult`: the answer. Success, gas, logs, changes, effects, display fields, policy verdict.
- `effect`: the numbered list of effect kinds.
- `ClearSign` and `PolicyCheck`: the two verdicts.
- `SignJob`: what the verifier hands to the signer.
- `SignResult`: what comes back to the host after a signing request.
- `lc`: the light-client message types.
- `safe`: Safe storage slots, settings checks, the hash owners sign, MultiSend encoding, and
  the pinned contract addresses with their code hashes.
- `wire`: USB message numbers and framing.
- `ipc`: message numbers between processes.

### 7.3 `crates/transport`: process 1

| File | What it does |
|---|---|
| `crates/transport/Cargo.toml` | Package file. USB support is behind the `board-dabao` feature. |
| `crates/transport/src/main.rs` | The whole process. See below. |

Inside `main.rs`:

- `Verifier`: calls the verifier through a worker thread, with a 90-second timeout. After one
  timeout it answers "press RESET" forever instead of hanging.
- `handle`: maps each USB message type to a verifier operation.
- `main`: waits for the signer, learns the size limit, then starts listening.
- `serve`, two versions: USB HID on the board, TCP in the emulator.
- `handle_mapped`: big requests are written straight into the memory lent to the verifier, so
  they aren't copied.
- `send_reports`: waits 6 ms between USB packets, because the driver drops back-to-back ones.

### 7.4 `crates/verifier`: process 2

| File | What it does |
|---|---|
| `crates/verifier/Cargo.toml` | Package file. `board-dabao` has no effect any more (storage is the signer's job). |
| `crates/verifier/src/main.rs` | The brain. See below. |
| `crates/verifier/src/slots.rs` | Permanent storage, asked of the signer's slot server with this boot's password. |
| `crates/verifier/src/counters.rs` | Loads and saves the daily spending counters. An unreadable counter means no signing. |
| `crates/verifier/src/lc.rs` | Light-client state: saved root, period and newest slot, plus keys in RAM. Has `load`, `update`, `check` and `ratchet`. |

Inside `main.rs`:

- `Counting`: a memory allocator that records peak use.
- `header_check`: checks the proof, block number and timestamp.
- `run_as`: runs the pipeline (simulate, display check, policy, postcondition).
- `approve`: the yes/no decision.
- `start_signer_channel` and `SignerLink`: the private line to the signer.
- `sign_request`: approve, save, then ask the signer.
- `MAX_INPUT` and `raise_heap_limit`: the memory limits.
- `main`: waits for the signer's password, loads storage, opens both servers, answers requests forever.

### 7.5 `crates/signer`: process 3

| File | What it does |
|---|---|
| `crates/signer/Cargo.toml` | Package file. |
| `crates/signer/src/main.rs` | Checks it is process 3, switches on time-slicing, serves the verifier's slots (password, verifier only, never the key's), and in a second thread waits for a job, builds the hash, signs. For a Safe it signs only a DELEGATECALL to MultiSendCallOnly with three calls: begin, the call, check. `DABAO_SIGNER_ADDRESS` at build time: never create a key, refuse any other. |
| `crates/signer/src/store.rs` | Maps the RRAM slots directly (board) or uses files (emulator). Creates, saves and loads the key. It writes the key first and a checksum header last. It never replaces a key it failed to read. **Don't change the slot layout: you would lose the account.** |

### 7.6 `crates/xous-evm`: running transactions

No Xous code here, so it also runs on a laptop.

| File | What it does |
|---|---|
| `crates/xous-evm/Cargo.toml` | Pins revm and the witness library from paradigmxyz/stateless. |
| `crates/xous-evm/src/lib.rs` | Lists the four modules. |
| `crates/xous-evm/src/chainspec.rs` | Mainnet and Sepolia fork rules, without the 690 KB genesis file. |
| `crates/xous-evm/src/sim.rs` | The simulator. `WitnessDb` gives revm proven state only. `simulate_then` runs the transaction, then allows follow-up calls on the resulting state. |
| `crates/xous-evm/src/effects.rs` | Turns logs and changes into effects, works out the sender's net per asset, and flags unexplained storage. Has its own unit tests. |
| `crates/xous-evm/src/postcondition.rs` | Picks the assets, computes the smallest allowed balance changes, sets the deadline, tests the check, builds the three-call batch. |
| `crates/xous-evm/tests/forks.rs` | Prints which fork rules are picked now. It asserts nothing beyond not crashing. |
| `crates/xous-evm/tests/sepolia.rs` | Replays five board-signed transactions and expects the on-chain gas and log counts. |
| `crates/xous-evm/tests/swap.rs` | Checks that real mainnet swaps are fully explained. |
| `crates/xous-evm/tests/weth.rs` | Removes or corrupts each witness node. The result must fail or stay identical. |
| `crates/xous-evm/fixtures/weth-transfer.rlp` | Saved request: a mainnet WETH transfer. |
| `crates/xous-evm/fixtures/uniswap-swap.rlp` | Saved request: a mainnet swap, redone on a newer block. |
| `crates/xous-evm/fixtures/uniswap-swap-replay.rlp` | Saved request: a mainnet swap, replayed exactly as mined. |
| `crates/xous-evm/fixtures/sepolia-eth-send.rlp` | Saved request: an ETH send the board signed. |
| `crates/xous-evm/fixtures/sepolia-weth-deposit.rlp` | Saved request: a wrap the board signed. |
| `crates/xous-evm/fixtures/sepolia-weth-transfer.rlp` | Saved request: a WETH transfer the board signed. |
| `crates/xous-evm/fixtures/sepolia-swap.rlp` | Saved request: a swap the board signed. |
| `crates/xous-evm/fixtures/sepolia-swap-multicall.rlp` | Saved request: the same kind of swap inside a multicall. |

### 7.7 `crates/light-client`: trusting a block

| File | What it does |
|---|---|
| `crates/light-client/Cargo.toml` | Uses arkworks for the BLS curve math. No C code. |
| `crates/light-client/src/lib.rs` | Sepolia fork versions, hashing in Ethereum's SSZ format, Merkle branch checks, committee loading, signature checks (`verify_signed`), block proofs (`verify_header_proof`) and hand-overs (`verify_update`). |
| `crates/light-client/src/anchor.rs` | Generated. The first trusted committee: period 1419. |
| `crates/light-client/tests/protocol.rs` | Anchor, hand-over and block proof tests on real data, with forged versions that must fail. |
| `crates/light-client/tests/sepolia.rs` | A real signature passes. A changed header, changed signer list or too few signers fail. |
| `crates/light-client/fixtures/committee-1418.rlp` | The committee of period 1418. |
| `crates/light-client/fixtures/committee-1419.rlp` | The committee of period 1419, which is the anchor. |
| `crates/light-client/fixtures/update-1418.rlp` | The real hand-over between them. |
| `crates/light-client/fixtures/header-proof.rlp` | A real block proof. Also useful for testing replay refusal. |
| `crates/light-client/fixtures/sepolia-finality.rlp` | A real signature with its committee, for tests and the benchmark. |

### 7.8 `crates/clear-sign`: what the user would see

| File | What it does |
|---|---|
| `crates/clear-sign/Cargo.toml` | Package file. |
| `crates/clear-sign/src/lib.rs` | Loads the built-in descriptor file. |
| `crates/clear-sign/src/model.rs` | The compact format descriptors are compiled into. |
| `crates/clear-sign/src/check.rs` | Finds the descriptor, decodes calldata, builds the shown fields, then looks for hidden losses, approvals, authority changes and unexplained effects. Also formats amounts and adds slippage warnings. Warnings don't block. |
| `crates/clear-sign/descriptors.bin` | Generated. The compiled descriptors and token list. |
| `crates/clear-sign/tests/check.rs` | Real transactions pass. Crafted sneaky ones are refused. |

### 7.9 `crates/policy`: the owner's rules

| File | What it does |
|---|---|
| `crates/policy/Cargo.toml` | Package file. |
| `crates/policy/src/lib.rs` | The rule types, the 32-byte counter format, `evaluate` (the rules) and `describe` (prints them). |
| `crates/policy/policy.bin` | Generated. The compiled policy. |
| `crates/policy/tests/policy.rs` | Limits add up and reset daily, plus tests for the fee cap, slippage, address rules, router abuse and approvals. |

### 7.10 Test-only programs for the board

| File | What it does |
|---|---|
| `crates/engine-spike/Cargo.toml` | Package file for the first experiment. |
| `crates/engine-spike/src/main.rs` | The experiment that showed Ethereum execution fits on the chip. Not in the product. |
| `crates/engine-spike/fixtures/README.md` | Where its test block came from. |
| `crates/engine-spike/fixtures/guest-smoke.in.ssz` | Test block input. |
| `crates/engine-spike/fixtures/guest-smoke.out.ssz` | The expected output. |
| `crates/slot-probe/Cargo.toml` | Package file. |
| `crates/slot-probe/src/main.rs` | Pretends to be a hacked process and tries every way to the storage slots: the keystore, the signer's slot server without the password, mapping the hardware. Never ship it. |
| `crates/keystore-probe/Cargo.toml` | Package file. The `steal` feature makes it race the signer. Needs the old keystore image (main at `5181823`). |
| `crates/keystore-probe/src/main.rs` | The old test, for keystore claims. Never ship it. |
| `crates/bio-dma-probe/Cargo.toml` | Package file. |
| `crates/bio-dma-probe/src/main.rs` | Pretends to be a hacked process that reads memory through the BIO's DMA, around the MMU. Writes its test value through the keystore, so needs the old image (main at `5181823`). Never ship it. |
| `crates/lc-bench/Cargo.toml` | Package file. |
| `crates/lc-bench/src/main.rs` | Times BLS verification on the chip. |

### 7.11 `host/dabao-host`: the computer side

| File | What it does |
|---|---|
| `host/dabao-host/Cargo.toml` | Package file. |
| `host/dabao-host/src/main.rs` | The command-line parser, plus `build` (makes a sample WETH request). |
| `host/dabao-host/src/send.rs` | Talks USB or TCP, prints answers, and re-checks signatures. |
| `host/dabao-host/src/tx.rs` | `send-tx`: a transaction from the board's account, from start to receipt. |
| `host/dabao-host/src/safe.rs` | All `safe` commands: keys, create, info, fund, send. Also the `--local` dry run and the pre-flight check. |
| `host/dabao-host/src/lc.rs` | Fetches light-client data: sync, parent block, anchor and fixtures. |
| `host/dabao-host/src/replay.rs` | Builds witnesses (`witness_for`), and replays real transactions to compare with receipts. |
| `host/dabao-host/src/descriptors.rs` | Compiles ERC-7730 JSON to the board's format. Anything unsupported is an error. |
| `host/dabao-host/src/policy.rs` | Compiles `policy.json`. Unknown keys are errors. |
| `host/dabao-host/src/synthetic.rs` | Makes a fake-state request for simulation tests. It can't be signed, because it has no light-client proof. |

### 7.12 `tools/bao-mcp`: the agent's wallet

| File | What it does |
|---|---|
| `tools/bao-mcp/Cargo.toml` | Package file. |
| `tools/bao-mcp/src/main.rs` | An MCP server with `wallet_info`, `device_policy` and `propose_tx`. It runs `dabao-host`, reads its text output to decide the status, and logs each proposal. If you reword host messages, update this file. |

### 7.13 `contracts`: the on-chain part

| File | What it does |
|---|---|
| `contracts/foundry.toml` | Fixed compiler settings, so the code and therefore the addresses come out the same. |
| `contracts/.gitignore` | Ignores Foundry's output. |
| `contracts/src/DabaoPostcondition.sol` | `begin` records balances, `check` reverts if one changed worse than allowed, a Safe setting changed or the deadline passed. `verify` is the same check for the board's simulation. |
| `contracts/src/DemoPayRouter.sol` | A demo payment router whose owner can make it keep the change. Never use it for real. |
| `contracts/test/Postcondition.t.sol` | Eight tests on a fork of Sepolia. |

### 7.14 `descriptors` and `policy`: the settings you edit

| File | What it does |
|---|---|
| `descriptors/README.md` | Where each descriptor came from. |
| `descriptors/tokens.json` | The only token names and decimals the board believes. |
| `descriptors/weth.json` | WETH on mainnet and Sepolia. |
| `descriptors/registry/calldata-UniswapV3Router02.json` | Uniswap router, copied from the public registry. |
| `descriptors/sepolia/calldata-UniswapV3Router02.sepolia.json` | The same, with the Sepolia address. |
| `descriptors/sepolia/demo-pay-router.json` | The demo router. |
| `policy/policy.json` | The rules. Changes do nothing until you compile, build and flash. |

### 7.15 `scripts`

| File | What it does |
|---|---|
| `scripts/build-device.sh` | Builds our three programs, then the Xous images, then checks that both fit. |
| `scripts/run-emu.sh` | Runs the three processes on your computer under hosted Xous. |
| `scripts/flash-and-log.py` | Waits for boot1, flashes over serial, boots, prints the console. |
| `scripts/board-audit.py` | Read-only check that a new board's bootloader is genuine. |
| `scripts/firmware-verify.py` | Read-only check that a board holds exactly the firmware in some UF2 files, by reading it back through boot1. |
| `scripts/compile-descriptors.sh` | Compiles descriptors, tokens and policy into the two `.bin` files. Descriptor files are listed by name inside it. |
| `scripts/mcp-call.py` | A tiny MCP client. Also plays the "fooled agent" in the demo. |
| `scripts/uniswap-calldata.py` | Gets a quote and prints swap calldata. |

### 7.16 `demo`

| File | What it does |
|---|---|
| `demo/agent/run.sh` | Runs Claude Code as a payment agent, limited to reading the inbox and using the wallet tools. |
| `demo/agent/compromised.sh` | Plays an agent that was fooled (the board refuses), then a thief with only the agent key (the Safe refuses). |
| `demo/agent/mcp.json` | Points the agent at `bao-mcp`. |
| `demo/agent/inbox/INV-0042.md` | An honest invoice. |
| `demo/agent/inbox/INV-0043.md` | A fraud invoice with a hidden note for AI assistants. |
| `demo/postcondition/run.sh` | Changes the router after signing, so the postcondition reverts the payment. With `honest` it doesn't change it. |
| `demo/postcondition/switch.sh` | Flips the demo router. Needs the original router owner's key. |

### 7.17 `docs`

| File | What it covers |
|---|---|
| `docs/GUIDE.md` | This guide. |
| `docs/light-client.md` | The light client, with board results. |
| `docs/effects-inspector.md` | The effect list and the memory lessons. |
| `docs/clear-signing.md` | The display-check rules. |
| `docs/policy.md` | The rules and counter format. |
| `docs/keystore-slot-claims.md` | The old keystore change and how it was attacked in tests. Superseded by the signer as process 3. |
| `docs/xous-core-fork.md` | Each change in our xous-core fork, and why. |
| `docs/hardware.md` | What the chip offers, what we use, and how. |
| `docs/custom-boot1.md` | The plan for our own boot1 and a hardware-protected key. Not done yet. |
| `docs/safe-cosigner.md` | The Safe setup and checks. |
| `docs/postcondition.md` | The final on-chain check. |
| `docs/agent-wallet.md` | The agent demo and what it does and doesn't prove. |

---

## 8. Reference: messages, storage, addresses

### USB messages

Each message is `length (4 bytes, big endian) | type (1 byte) | body`, cut into 64-byte packets.
Bodies are RLP, Ethereum's simple binary format. The device is USB `1d50:6197`, usage page
`0xFF00`.

| Type | Name | Send | Get back |
|---|---|---|---|
| `0x10` | simulate | `SimInput` | `SimResult` |
| `0x11` | version | nothing | text |
| `0x12` | sign | `SimInput` | `SignResult` |
| `0x13` | address | nothing | 20 bytes |
| `0x14` | status | nothing | `DeviceStatus` |
| `0x15` | policy | nothing | `PolicyStatus` |
| `0x16` | Safe co-sign | `SimInput` sent from the Safe | `SignResult` |
| `0x17` | load committee | `lc::Committee` | `lc::Status` |
| `0x18` | hand-over | `lc::CommitteeUpdate` | `lc::Status` |
| `0x19` | light-client status | nothing | `lc::Status` |
| `0x7f` | error | (reply only) | text |

### RRAM app slots

All held by the signer (process 3). It serves 176 to 209 to the verifier, and nothing else to anyone.

| Slots | Owner | Contents |
|---|---|---|
| 0 to 122 | Xous BIO | not ours |
| 132 to 133 | eth-burner sample app | not ours |
| 160 | signer | private key |
| 161 | signer | `DABAOSG1` and a checksum of the key |
| 176 to 207 | verifier | one per daily limit: `DPL1`, id, day, amount spent |
| 208 | verifier | trusted committee root |
| 209 | verifier | `DLC1`, period, newest slot |

### Limits

| Limit | Value | Where |
|---|---|---|
| Request size | 140 KiB | `MAX_INPUT`, verifier |
| Frame size | 256 KiB | `wire::MAX_LEN` |
| Verifier heap | 1.5 MiB (real RAM runs out earlier) | `HEAP_LIMIT` |
| Transport timeout | 90 s | `VERIFIER_TIMEOUT` |
| Host read timeout | 60 s | `send.rs` |
| Signer job buffer | 64 KiB | `signer/src/main.rs` |
| Daily limit slots | 32 | `MAX_LIMITS` |

### Sepolia addresses

| What | Address |
|---|---|
| Board | `0x7813e1C142086D37060Be2335ff9Dd4EA4a2F986` |
| Demo Safe | `0x265871a72567419AE2f799a1288271C09B589fd9` |
| Agent owner | `0x124beF9dDa9D1B6F7D2D6522459448970301A515` |
| Recovery owner | `0x6a657Ba092207e2836c5B53Fa36d808794556250` |
| DabaoPostcondition | `0x0435e385AA3BAA0D9D782458DC3B10621702b26D` |
| DemoPayRouter | `0x1ab73Bb30Da0a020bDa2F942F524F3CA75ab5Fc7` |
| MultiSendCallOnly 1.4.1 | `0x9641d764fc13c8B624c04430C7356C1C7C8102e2` |
| SwapRouter02 | `0x3bFA4769FB09eefC5a80d6E87c3B9C650f7Ae48E` |
| WETH | `0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14` |
| USDC (test) | `0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238` |

---

## 9. How to build

### You need

| Tool | For | Required? |
|---|---|---|
| macOS on Apple silicon | the only tested system. Two scripts use macOS-only details. | yes, as tested |
| Rust 1.100.0 and git | everything | yes |
| Xous sysroot | board builds | yes (one command below) |
| Python 3 with `pyserial` and `progressbar2` | flashing | to flash |
| Foundry (`forge`, `cast`) | contracts, postcondition demo | optional |
| Claude Code | agent demo | optional |

### First build

```sh
git clone --recursive https://github.com/debjit-bw/dabao-hardware-experiments.git
cd dabao-hardware-experiments
rustup default 1.100.0
(cd vendor/xous-core && cargo xtask install-toolkit)

cargo build --locked -p dabao-host -p bao-mcp
scripts/build-device.sh
```

The first builds the computer side, the second the board's firmware.

Expect 5 to 20 minutes the first time, depending mostly on the network. `rustup default`
changes your machine's default Rust. Image sizes vary by a few KB with the checkout path,
because paths end up in the binaries.

The firmware appears in `vendor/xous-core/target/riscv32imac-unknown-xous-elf/release/` as
`loader.uf2`, `xous.uf2` and `apps.uf2`.

Don't run `rustup update` casually. The Xous sysroot belongs to one exact Rust version. After
changing version, run `install-toolkit` again.

### Set up flashing

```sh
python3 -m venv .venv-flash
.venv-flash/bin/pip install pyserial progressbar2
export PYTHON="$PWD/.venv-flash/bin/python"
```

Keep that folder out of git.

### Before the first flash of a new board

**The first self-built image puts the chip in developer mode and permanently erases its
factory secrets. It can't be undone.** With the board in boot1, check it first:

```sh
scripts/board-audit.py
```

### Flash

Run the script, then press reset. It finds boot1, flashes and boots.

**A board's first flash needs all three images:**

```sh
R=vendor/xous-core/target/riscv32imac-unknown-xous-elf/release
scripts/flash-and-log.py $R/loader.uf2 $R/xous.uf2 $R/apps.uf2
```

After that, two are enough:

```sh
scripts/flash-and-log.py $R/xous.uf2 $R/apps.uf2
```

On macOS don't drag the files onto the BAOCHIP drive: the big one hangs. After flashing,
check `dabao-host policy` shows the policy you expect **before any signing request**. An old
image signs by old rules.

### If it's your own board

This repo's addresses belong to its authors' board and test accounts. On yours:

- the board makes its own key on first boot. `dabao-host address` prints it; fund it on Sepolia;
- run `safe keys`, fund the agent, then `safe create`, to get your own Safe;
- the postcondition demo only works for the owner of the deployed DemoPayRouter. Deploy your
  own and update the descriptor, the policy and the two demo scripts;
- the contract fork tests use the authors' Safe.

---

## 10. How to run

In the commands below, `H` is the host program:

```sh
cargo build --locked -p dabao-host -p bao-mcp
H=target/debug/dabao-host
```

`--chain sepolia` picks a free Sepolia RPC. **Without it the default RPC is mainnet.**
Amounts given to `dabao-host` are in wei. If `RPC_URL` is set it wins, and `--chain` is ignored.

Code blocks here have no `#` comments on purpose: macOS's zsh passes them to the program as
arguments. [Part 15](#15-command-reference) lists every command.

### After plugging in

A reset leaves the board in boot1. Open its serial port with
`screen /dev/cu.usbmodem<serial>1`, type `boot` and press Enter. (To leave `screen`: Ctrl-A,
then K, then Y.) Then:

```sh
$H status
$H address
$H policy
$H lc-sync
```

In order: memory limits and signer, the board's account, rules and today's spending, then
loading the committee and catching up.

### Send from the board's account

```sh
$H send-tx --chain sepolia --to 0x000000000000000000000000000000000000dEaD --value 1
```

This signs but does not send. It still uses up daily budget. Add `--broadcast` to send, or
`--legacy` for an old-style transaction.

### A swap

Fund the board's account first. The script gets its quote by simulating the swap from that
account, so the quote fails if the account doesn't hold the ETH.

```sh
DATA=$(scripts/uniswap-calldata.py $($H address) 10000000000)
$H send-tx --chain sepolia --to 0x3bFA4769FB09eefC5a80d6E87c3B9C650f7Ae48E \
  --value 10000000000 --data $DATA
```

### The Safe

```sh
$H safe keys --chain sepolia
$H safe create --chain sepolia
$H safe info --chain sepolia
$H safe fund --chain sepolia --value 1000000000000000
$H safe send --chain sepolia --to ADDR --value WEI [--data 0x..]
```

`create` needs a funded agent. `create` and `fund` send at once: they have no `--broadcast`.

Options for `safe send`:

| Option | Effect |
|---|---|
| `--broadcast` | Execute after signing. |
| `--local` | Run the board's checks on the computer. Nothing is signed. Still asks the board for its address. |
| `--agent-only` | Show that the agent alone can't execute. Sends nothing. |
| `--before-exec CMD` | Run a shell command between signing and executing (for demos). |
| `--force` | Execute even if the pre-flight fails. **This publishes the signatures. They work until the 10-minute deadline.** |

### The agent wallet

```sh
claude mcp add dabao-wallet -- $PWD/target/debug/bao-mcp
scripts/mcp-call.py
scripts/mcp-call.py wallet_info
scripts/mcp-call.py propose_tx \
  '{"to":"0x000000000000000000000000000000000000dEaD","value_eth":"0.0001","reason":"test"}'
```

`propose_tx` really sends unless `BAO_MCP_DRY_RUN=1`. An agent that also has a shell or file
access on this computer can read both Safe keys, so don't rely on this setup for protection.

### The demos

```sh
demo/agent/run.sh
demo/agent/compromised.sh
demo/postcondition/run.sh honest
demo/postcondition/run.sh
```

In order: an honest agent with two invoices (sends 0.0001 ETH), a fooled agent and then a
stolen agent key, a normal router payment, and a router that changes its mind (reverts on chain).

The postcondition demo needs the original router owner's key. Its failing case publishes
signatures that work for up to 10 minutes. Before running the honest case afterwards, wait a
minute, so that the light client has seen the router switch back (until then it is refused).

### Without a board: the emulator

```sh
scripts/run-emu.sh
```

Leave it running. In a second terminal, in the repo:

```sh
H=target/debug/dabao-host
$H status --tcp 127.0.0.1:7610
$H lc-sync --tcp 127.0.0.1:7610
$H send crates/xous-evm/fixtures/sepolia-swap.rlp --tcp 127.0.0.1:7610
```

Add `--tcp` to any command to use the emulator. It has its own throwaway key, so it is not an
owner of the demo Safe. It doesn't enforce the board's memory limits.

Every other command, and the environment variables: [part 15](#15-command-reference).

---

## 11. How to test

### On the computer (56 tests)

```sh
cargo test --locked -p sim-types -p xous-evm -p clear-sign -p policy -p light-client -p bao-mcp
```

Name the packages like this. Some crates in the workspace are board programs.

### Contracts (8 tests, uses a Sepolia fork)

```sh
cd contracts
forge test --fork-url https://ethereum-sepolia-rpc.publicnode.com
```

They depend on the live demo Safe.

### Storage attack test, on the board

```sh
T=riscv32imac-unknown-xous-elf
cargo build --release -p slot-probe --target $T --features board-dabao,bao1x
GENERIC_HID=0 scripts/build-device.sh target/$T/release/slot-probe
scripts/flash-and-log.py --until "PROBE summary" vendor/xous-core/target/$T/release/{loader,xous,apps}.uf2
```

Expect `PROBE summary: 10/10 as expected`. Flash the normal image again afterwards.

### BLS benchmark, on the board

```sh
SERVICE=lc-bench GENERIC_HID=0 scripts/build-device.sh dabao-console
```

Flash as usual and read the console.

### After any change that affects signing

1. Run the computer tests.
2. Try it in the emulator, or with `safe send --local`.
3. Build and check the printed free space.
4. Flash, then make one tiny Sepolia transaction that should pass and one that should fail.
5. Confirm the chain's gas and logs match the board's prediction.

---

## 12. How to change things

### Change a limit, an address list or a cap

1. Edit `policy/policy.json`. Amounts are whole units. Change `id` so you can recognise it.
2. `scripts/compile-descriptors.sh`
3. Run the tests. Some use the built-in policy, so update those if needed.
4. `scripts/build-device.sh`, flash `xous.uf2`, check with `dabao-host policy`.

Two traps. **Reordering or inserting limits resets today's counters**, because counters are
stored by position. And **never put a router in `recipients`**: anyone can sweep what
lands there. Contracts you only call go in `contracts`.

### Support a new contract

1. Write an ERC-7730 JSON file in `descriptors/`. Copy `weth.json` as a start. Parameters need
   names. `includes`, `$ref` and EIP-712 are not supported.
2. Add the file to the list in `scripts/compile-descriptors.sh`.
3. Add any new token to `descriptors/tokens.json`, after checking its decimals on chain.
4. Add the contract to `contracts`, and a daily limit for any new asset it spends.
5. Compile, test, build, flash `xous.uf2`.

If it is refused as "unexplained effect", it emits an event the board doesn't know. See below.

### Recognise a new kind of effect

1. Add a number in `effect` in `crates/sim-types/src/lib.rs`.
2. Detect it in `from_log` in `crates/xous-evm/src/effects.rs`. Match the exact shape.
3. If it moves the sender's assets, add it to `net_for`.
4. If it is dangerous, add a rule in `clear-sign/src/check.rs` and in `policy/src/lib.rs`.
5. Give it a printed name in `describe` in `host/dabao-host/src/send.rs`.
6. Test with a real transaction and a malformed one.

### Add a policy rule

1. Add a field to `ChainPolicy` in `crates/policy/src/lib.rs`.
2. Read it in `host/dabao-host/src/policy.rs`, and allow the key there.
3. Enforce it in `evaluate`. Print it in `describe`.
4. Add a test. Compile, build, flash `xous.uf2`.

### Add a board command

1. Add a type in `wire` and an operation in `ipc`, both in `sim-types`.
2. Forward it in `handle` in the transport.
3. Answer it in `main` in the verifier.
4. Call it from `host/dabao-host/src/send.rs` and wire up the argument in `main.rs`.
5. Flash both images.

### Refresh the light-client anchor

1. `cargo run -p dabao-host -- lc-anchor`
2. `cargo run -p dabao-host -- lc-fixtures crates/light-client/fixtures`
3. Update the file names and periods in `crates/light-client/tests/protocol.rs`.
4. Run the tests. Between steps 1 and 3 they fail, which is expected.
5. Build and flash `xous.uf2`. A saved period newer than the anchor is kept.

### Follow an Ethereum upgrade

- Consensus fork: add the version to `sepolia::FORKS`, and re-measure the three `GINDEX_*`
  positions, all in `crates/light-client/src/lib.rs`.
- Execution fork: update `alloy-hardforks`, revm and the pinned reth revision, then replay
  fresh transactions and compare the gas. A stale schedule gave wrong gas here once before.

### Add another chain

You need all of these: a spec in `chainspec.rs`, the chain in `approve`, a light client for
that chain **with the proof tied to the chain id** (hole L), a policy, descriptors, tokens,
the host's `--chain` option, and the postcondition contract deployed there. A policy entry
alone is unsafe.

### Change the postcondition contract

1. Edit and test it in `contracts/`.
2. Deploy through the CREATE2 deployer `0x4e59b44847b379578588920cA78FbF26c0B4956C`, salt 0.
   A code change gives a new address.
3. Update `POSTCONDITION` and `POSTCONDITION_CODEHASH` in `sim-types`.
4. If the arguments changed, update both encoders there and `IPostcondition` in `safe.rs`.
5. Flash both images, because the signer checks the address too.

### Change xous-core

1. Commit inside `vendor/xous-core`, on branch `dabao-hackathon`.
2. Push that branch to the fork **first**.
3. Commit the new submodule pointer here. Otherwise nobody else can clone the repo.
4. Update `PINNED_REV` and `PINNED_DESCRIBE` (`git -C vendor/xous-core describe --long`) in
   `scripts/build-device.sh`. Clones of the fork have no version tags, and image signing needs them.

### Rules not to break

- Don't move or reformat slots 160 and 161. That is the account's key.
- Don't add a process that reads outside input before the signer has attached to the verifier.
- Don't let the host supply policy, descriptors, tokens or the anchor at run time.
- Don't make missing witness data read as zero.
- Don't make the signer accept a hash. It must always build its own.
- Save counters before signing, never after.
- Never commit `.dabao-keys/` or an RPC URL with a key.

---

## 13. When something goes wrong

| You see | Cause | Do |
|---|---|---|
| `no Dabao vendor HID interface` | The board is in boot1, unplugged, or runs a console image. | Type `boot` on the boot1 console, or flash the normal image. |
| `boot1 not found` | The app is running. | Press reset while the flash script waits. |
| USB dead right after `boot` | Seen once after a flash, cause unknown. | Unplug, replug holding PROG, then `boot`. |
| `verifier unresponsive` | The verifier crashed, usually out of memory. | Press reset, boot, retry with a smaller transaction. |
| `exceeds the device's limit` | The witness is over 140 KiB. | Use a simpler transaction. Raise the limit only after measuring on the board. |
| `no sync committee loaded` | Keys are lost at each reboot. | `lc-sync` |
| `older than the newest verified` | An old proof. | Fetch a fresh one by running the command again. |
| `signed in period ...` | A hand-over happened. | `lc-sync` |
| `HEADER NOT VERIFIED` from `send` | Saved requests have no proof. | Normal for simulation. They can't be signed. |
| `blind signing refused` | No descriptor for that function. | Add one (part 12). |
| `not an allowed recipient`, `not an allowed contract to call` | The policy. | Intended, or change the policy and reflash. |
| `keeps ...` | The called contract would hold on to funds, for example excess ETH in a router. | Send the exact amount. |
| `Dabao: expired` | Over 10 minutes between signing and executing. | Sign again. |
| `daily limit` | Budget used, possibly by unsent signatures. | Wait for the next UTC day. |
| `policy counters unreadable` | The signer didn't attach within 30 s, or a slot read failed. | Reboot. Check the signer's log line. |
| `SemVer::from_git: no major version` | xous-core has no version tags and isn't at the pinned commit. | Fetch upstream's tags (the build script prints the command), or check out the pin. |
| `nonce too low`, or `GS026` when executing | The light client trails the head, so it still saw the previous nonce. | Wait a minute and sign again. |
| `zsh: parse error near '#'`, or odd `unknown option` errors | A pasted `#` comment became arguments. | Leave the comment out, or `setopt interactive_comments`. |
| `--chain` seems ignored | `RPC_URL` is set. | `unset RPC_URL`. |
| `historical state ... is not available` | The RPC can't serve proofs that old. | Use a node with a wider window. |
| `signer attached` never happens | The signer isn't process 3, the key is unreadable, or it isn't the address `DABAO_SIGNER_ADDRESS` expects. | Read the console or DUART log. Don't erase the slots. |
| `MPT: unresolved node access` or `not in witness` | The witness lacks data the run needed, or an account involved has EIP-7702 delegation (hole S). | Rebuild it on the same block. Delegated accounts aren't supported. |
| `quote failed` | The `<from>` account lacks the ETH, or the pool can't fill the swap. | Fund it, or use another amount. |
| `exceeds maximum proof window` | The public node moved on, or keeps recent state only. | Run it again. For older transactions set `RPC_URL`. |
| RPC refuses old proofs | The public node keeps recent state only. | Set `RPC_URL` to a node with a wider window. |
| `GS020` | Too few signatures. | Expected for agent-only. |
| `GS013` or pre-flight fails | A call in the batch failed, often the postcondition. | The state changed or the deadline passed. Sign again. |
| Safe run uses slightly old state | The light client trails by a few blocks. | Wait a minute and retry. |
| No logs on USB | HID images have no console. | Build with `GENERIC_HID=0`, or read the DUART pins PB13 and PB14. |
| `target/SVD_PATH missing or empty` | An emulator build ran last. | Nothing. The build script repairs it. |
| Cargo can't find the Xous target | The sysroot doesn't match Rust. | Run `install-toolkit` again. |
| An image is too big | Over its storage region. | The build stops for you. Remove code. |

---

## 14. A good order to read the code in

About two hours:

1. `crates/sim-types/src/lib.rs`: just the structs, to learn the nouns.
2. `crates/verifier/src/main.rs`: `sign_request`, then `approve`, then `run_as`. This is the
   heart of the project.
3. `crates/xous-evm/src/sim.rs`: how proven state reaches the EVM.
4. `crates/xous-evm/src/effects.rs`: how raw results become effects.
5. `crates/clear-sign/src/check.rs`: from the `for e in effects` loop.
6. `crates/policy/src/lib.rs`: `evaluate`.
7. `crates/signer/src/main.rs`: short, and worth reading fully.
8. `crates/light-client/src/lib.rs`: `verify_header_proof`, then follow it down.
9. `crates/xous-evm/src/postcondition.rs` with `contracts/src/DabaoPostcondition.sol`.
10. `host/dabao-host/src/tx.rs`: the whole trip, seen from the computer.

---

## 15. Command reference

Every command in the repo, with options and examples. Run everything from the repo root.

**What a command can do is marked like this:**

| Mark | Meaning |
|---|---|
| read | changes nothing that matters |
| file | writes local files |
| board | changes state on the board (loaded keys, saved period) |
| **sign** | can produce a signature, and uses daily budget when it does |
| **send** | puts a transaction on chain |
| **flash** | changes the firmware |

The examples use these variables:

```sh
H=target/debug/dabao-host
DEAD=0x000000000000000000000000000000000000dEaD
WETH=0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14
ROUTER=0x3bFA4769FB09eefC5a80d6E87c3B9C650f7Ae48E
```

### 15.1 All commands at a glance

| Command | Mark | Needs | Does |
|---|---|---|---|
| `status` | read | board | memory limits, signer address |
| `address` | read | board | the board's account |
| `policy` | read | board | rules and spending counters |
| `lc-sync` | board | board, beacon node | load the committee, follow hand-overs |
| `send` | read | board | simulate a saved request |
| `sign` | **sign** | board | ask to sign a saved request |
| `send-tx` | **sign**, **send** with `--broadcast` | board, RPC, beacon node | a transaction from the board's account |
| `safe keys` | file | nothing | create or show agent and recovery keys |
| `safe create` | **send** | board, RPC, funded agent | deploy the 2-of-3 Safe |
| `safe info` | read | RPC | owners, threshold, nonce, balance |
| `safe fund` | **send** | RPC, funded agent | agent sends ETH to the Safe |
| `safe send` | **sign**, **send** with `--broadcast` | board, RPC, beacon node | a co-signed Safe transaction |
| `build` | file | RPC | build a request from live or mined transactions |
| `build-synthetic` | file | nothing | build a fake-state request |
| `compile-descriptors` | file | nothing | ERC-7730 JSON to the firmware blob |
| `compile-policy` | file | nothing | policy JSON to the firmware blob |
| `lc-anchor` | file | two beacon nodes | regenerate the trust anchor |
| `lc-fixture` | file | beacon node | record one signature for tests |
| `lc-fixtures` | file | beacon node | record the protocol test data |

All of these are subcommands of `dabao-host`.

### 15.2 Options that work on any `dabao-host` command

| Option | Meaning |
|---|---|
| `--tcp HOST:PORT` | talk to the emulator instead of the board over USB |
| `--chain sepolia` | use a public Sepolia RPC |
| `--chain mainnet` | use a public mainnet RPC (this is also the default) |

`RPC_URL`, if set, overrides `--chain`. Amounts are wei, in decimal or `0x` hex.

**A refusal still exits with status 0.** In a script, look for `NOT SIGNED`, `NOT CO-SIGNED`
or `REJECTED` in the output instead of trusting the exit status.

### 15.3 Looking at the board

```sh
$H status
$H address
$H policy
$H lc-sync
$H status --tcp 127.0.0.1:7610
```

### 15.4 Simulating and signing saved requests

| Form | Does |
|---|---|
| `send <in.rlp>` | simulate, print effects and every verdict |
| `send <in.rlp> --no-precheck` | skip the host's size check, to test that the board refuses |
| `sign <in.rlp>` | sign if every check passes. A saved request needs a still-fresh proof, so normally this is refused |

```sh
$H send crates/xous-evm/fixtures/sepolia-swap.rlp
$H send crates/xous-evm/fixtures/sepolia-swap.rlp --no-precheck
DABAO_VERBOSE=1 $H send crates/xous-evm/fixtures/sepolia-eth-send.rlp
$H sign crates/xous-evm/fixtures/sepolia-eth-send.rlp
```

### 15.5 `send-tx`: from the board's own account

| Option | Meaning |
|---|---|
| `--to ADDR` | required |
| `--value WEI` | default 0 |
| `--data 0x..` | calldata, default empty |
| `--legacy` | old-style gas price instead of EIP-1559 |
| `--broadcast` | send it, wait, compare with the board's prediction |

Without `--broadcast` it still signs: the budget is used and the signature stays valid until
that nonce is used (hole R).

A plain send, an old-style send, a wrap, and a swap with 1% slippage. All four need a funded
board account, and the swap's quote fails without one:

```sh
$H send-tx --chain sepolia --to $DEAD --value 1000000000000
$H send-tx --chain sepolia --to $DEAD --value 1 --legacy
$H send-tx --chain sepolia --to $WETH --value 1000000000000 --data 0xd0e30db0
DATA=$(scripts/uniswap-calldata.py $($H address) 10000000000)
$H send-tx --chain sepolia --to $ROUTER --value 10000000000 --data $DATA
```

Really sending:

```sh
$H send-tx --chain sepolia --to $DEAD --value 1000000000000 --broadcast
```

### 15.6 `safe`: the shared wallet

| Subcommand | Options | Notes |
|---|---|---|
| `safe keys` | none | writes `.dabao-keys/agent.key` and `recovery.key` if missing |
| `safe create` | none | one Safe per owner set. Refuses if one is saved. Sends at once |
| `safe info` | none | |
| `safe fund` | `--value WEI` | sends at once |
| `safe send` | see below | |

| `safe send` option | Meaning |
|---|---|
| `--to ADDR` | required |
| `--value WEI` | default 0 |
| `--data 0x..` | calldata |
| `--broadcast` | the agent executes after the board co-signs |
| `--local` | run the board's checks on the computer. Signs nothing. Still asks the board for its address and syncs its light client |
| `--agent-only` | show the Safe refusing the agent's signature alone. Sends nothing |
| `--before-exec CMD` | with `--broadcast`: run a shell command between signing and executing |
| `--force` | with `--broadcast`: execute even if the pre-flight fails. Publishes the signatures, valid for up to 10 minutes |

```sh
$H safe keys
$H safe info --chain sepolia
$H safe send --chain sepolia --to $DEAD --value 100000000000000 --local
$H safe send --chain sepolia --to $DEAD --value 100000000000000 --agent-only
$H safe send --chain sepolia --to $DEAD --value 100000000000000
```

These send at once:

```sh
$H safe create --chain sepolia
$H safe fund --chain sepolia --value 1000000000000000
$H safe send --chain sepolia --to $DEAD --value 100000000000000 --broadcast
```

### 15.7 Building requests

| Form | Does |
|---|---|
| `build <out.rlp>` | a WETH transfer from a real holder in the latest mainnet block |
| `build <out.rlp> --replay TXHASH` | a mined transaction on its parent state. Give its `--chain`. Needs an RPC with proofs that old |
| `build <out.rlp> --find-swap` | find a recent mainnet Uniswap swap and rebuild it. Can take minutes |
| `build-synthetic <from> <out.rlp>` | fake state where `<from>` holds 1 ETH, sending 0.01 |
| `build-synthetic <from> <out.rlp> --eip1559` | the same, as EIP-1559 |
| `build-synthetic <from> <out.rlp> --data 0x..` | the same, with calldata |

```sh
$H build /tmp/weth.rlp
$H build-synthetic $DEAD /tmp/fake.rlp
$H build-synthetic $DEAD /tmp/fake1559.rlp --eip1559
$H build-synthetic $DEAD /tmp/fakedata.rlp --data 0xd0e30db0
```

These need a suitable RPC or some patience. Replace `TXHASH` with a transaction from the last
few blocks (public nodes don't keep old proofs), or set `RPC_URL` to a node with a wider
window. Not every transaction replays: see hole S.

```sh
$H build /tmp/replay.rlp --replay TXHASH --chain sepolia
$H build /tmp/swap.rlp --find-swap
```

### 15.8 Compiling what goes into the firmware

| Form | Does |
|---|---|
| `compile-descriptors <out.bin> [--tokens tokens.json] <file.json>...` | compile descriptors and the token list |
| `compile-policy <out.bin> <policy.json>` | compile and print the policy |

```sh
scripts/compile-descriptors.sh
$H compile-descriptors /tmp/descriptors.bin --tokens descriptors/tokens.json descriptors/weth.json
$H compile-policy /tmp/policy.bin policy/policy.json
```

### 15.9 Light-client maintenance

| Form | Does |
|---|---|
| `lc-anchor` | **overwrites** `crates/light-client/src/anchor.rs` with a new finalized checkpoint |
| `lc-fixture <out.rlp>` | record and verify the newest signature |
| `lc-fixtures <dir>` | record committees, a hand-over and a block proof for the anchor's period |

```sh
$H lc-fixture /tmp/finality.rlp
mkdir -p /tmp/lc-fixtures
$H lc-fixtures /tmp/lc-fixtures
```

This one changes source, so only when you mean it. `cargo test` then fails until you refresh
the fixtures and the test's periods (part 12, "Refresh the light-client anchor"):

```sh
$H lc-anchor
```

### 15.10 Scripts

| Script | Arguments | Mark |
|---|---|---|
| `scripts/build-device.sh` | `[app ELF or xous-core app name] [extra xtask args]`, env `SERVICE`, `GENERIC_HID`, `DABAO_SIGNER_ADDRESS`, `FIRMWARE_KEY` | file |
| `scripts/run-emu.sh` | none, env `DABAO_PORT` | file |
| `scripts/flash-and-log.py` | `[--wait SECS] [--log-secs SECS] [--until TEXT] file.uf2...` | **flash** |
| `scripts/board-audit.py` | `[serial port]`. The board must be in boot1 | read |
| `scripts/firmware-verify.py` | `[--port P] [--wait SECS] file.uf2...`. Reads the board back with boot1's `peek` and compares | read |
| `scripts/compile-descriptors.sh` | none | file |
| `scripts/mcp-call.py` | `[tool] ['{json arguments}']` | depends on the tool |
| `scripts/uniswap-calldata.py` | `<from> [amount_wei] [token_out] [fee] [--multicall] [--slippage-bps N]` | read |
| `demo/agent/run.sh` | none, env `MODEL` | **send** |
| `demo/agent/compromised.sh` | none | **sign** requested, must be refused |
| `demo/postcondition/run.sh` | `[honest]` | **send** |
| `demo/postcondition/switch.sh` | `true` or `false` | **send** |

`<from>` must hold the ETH being swapped, because the quote is simulated from it. The examples
use the dead address, which holds test ETH.

```sh
scripts/uniswap-calldata.py $DEAD 10000000000
scripts/uniswap-calldata.py $DEAD 10000000000 --multicall --slippage-bps 50
scripts/flash-and-log.py --help
```

Builds (normal, with a USB console, the BLS benchmark, the first engine experiment):

```sh
scripts/build-device.sh
GENERIC_HID=0 scripts/build-device.sh
SERVICE=lc-bench GENERIC_HID=0 scripts/build-device.sh dabao-console
SERVICE=engine-spike GENERIC_HID=0 scripts/build-device.sh dabao-console
```

Demos (these send):

```sh
demo/agent/run.sh
MODEL=haiku demo/agent/run.sh
demo/agent/compromised.sh
demo/postcondition/run.sh honest
demo/postcondition/run.sh
demo/postcondition/switch.sh false
```

### 15.11 The MCP server's tools

| Tool | Arguments | Mark |
|---|---|---|
| `wallet_info` | none | read |
| `device_policy` | none | read |
| `propose_tx` | `to` (required), `reason` (required), `value_eth` (decimal ETH, not wei), `data` (hex) | **sign**, **send** unless `BAO_MCP_DRY_RUN=1` |

```sh
scripts/mcp-call.py
scripts/mcp-call.py wallet_info
scripts/mcp-call.py device_policy
BAO_MCP_DRY_RUN=1 scripts/mcp-call.py propose_tx '{"to":"0x000000000000000000000000000000000000dEaD","value_eth":"0.0001","reason":"test"}'
```

Adding it to Claude Code:

```sh
claude mcp add dabao-wallet -- $PWD/target/debug/bao-mcp
claude mcp remove dabao-wallet
```

### 15.12 Build, test and contract commands

```sh
git submodule update --init vendor/xous-core
(cd vendor/xous-core && cargo xtask install-toolkit)
cargo build --locked -p dabao-host -p bao-mcp
cargo test --locked -p sim-types -p xous-evm -p clear-sign -p policy -p light-client -p bao-mcp
cargo test --locked -p policy a_router_is_not_a_recipient
(cd contracts && forge build)
(cd contracts && forge test --fork-url https://ethereum-sepolia-rpc.publicnode.com)
cast calldata "pay(address,uint256)" $DEAD 100000000000000
cast call 0x1ab73Bb30Da0a020bDa2F942F524F3CA75ab5Fc7 "keepChange()(bool)" --rpc-url https://ethereum-sepolia-rpc.publicnode.com
```

Where a changed postcondition contract would be deployed:

```sh
(cd contracts && forge build)
INIT=$(cd contracts && forge inspect DabaoPostcondition bytecode)
cast create2 --deployer 0x4e59b44847b379578588920cA78FbF26c0B4956C --salt 0x0000000000000000000000000000000000000000000000000000000000000000 --init-code $INIT
```

### 15.13 boot1 console commands

These come from xous-core's bootloader. Type them on the board's boot1 serial port.

**Safe to use**

| Command | Does |
|---|---|
| `boot` | start the installed firmware |
| `audit` | print the security state |
| `reset` | restart the chip |
| `echo TEXT` | print it back |
| `ifr` | print the factory information region (zeros in user mode) |
| `localecho on` or `localecho off` | echo what you type |
| `bootwait check`, `paranoid check`, `skipping check` | show that setting |

**They change the chip. Don't experiment with these.**

| Command | Effect |
|---|---|
| `uf2 BASE64` | write one firmware block. The flash script uses it |
| `bootwait enable`, `disable` or `toggle` | stop in boot1 at reset or not. Uses a one-way counter |
| `skipping enable` or `disable` | clock-skipping countermeasure |
| `boardtype TYPE` | change the board type. Uses a one-way counter |
| `usb_speed SPEED` | change the default USB speed. Uses a one-way counter |
| `idmode toggle` | change the external identifiers. Uses a one-way counter |
| `altboot toggle` | change the boot partition. Uses a one-way counter |
| `paranoid enable` | **permanent.** Detected attacks can then wipe the chip |
| `require-pq` | **permanent.** Requires post-quantum signatures to boot |
| `lockdown` | **permanent**, and can brick the chip |
| `self_destruct` | **destroys the chip's secrets or the chip** |

### 15.14 Environment variables

| Variable | Used by | Meaning |
|---|---|---|
| `RPC_URL` | host, scripts | Ethereum node. May hold an API key, so never commit it. |
| `BEACON_URL` | host | Beacon node with light-client data (default: Lodestar Sepolia). |
| `BEACON_URL_2` | `lc-anchor` | Second node to cross-check against. |
| `DABAO_KEYS` | host | Key folder (default `.dabao-keys/`). |
| `DABAO_VERBOSE` | host | Also print raw logs and storage changes. |
| `DABAO_DUMP` | host | Save the raw reply to this path. |
| `DABAO_NO_LC` | host | Test: send no proof. The board must refuse. |
| `DABAO_LC_REPLAY` | host | Test: send an old proof from this file. The board must refuse. |
| `DABAO_HOST` | `bao-mcp` | Path to `dabao-host`. |
| `BAO_MCP_CHAIN` | `bao-mcp` | Default `sepolia`. |
| `BAO_MCP_DRY_RUN` | `bao-mcp` | Co-sign but don't execute. |
| `MODEL` | agent demo | `sonnet` (default) or `haiku`. |
| `DABAO_PORT` | emulator | TCP port (default 7610). |
| `DABAO_SIGNER_KEY` | emulator | Key file (default `crates/signer/target/dabao-signer-key.bin`). |
| `DABAO_SLOTS_DIR` | emulator | Folder for fake slots (default `crates/signer/target/`). |
| `DABAO_SIGNER_ADDRESS` | build script | The signer then never creates a key and refuses to run unless the slots hold this address's key. Use it when changing storage code on a board with a funded key. |
| `DABAO_XOUS_CORE` | scripts | A different xous-core checkout. (A plain `XOUS_CORE` is ignored on purpose.) |
| `SERVICE` | build script | Program for the system image (default `verifier`). |
| `GENERIC_HID` | build script | `0` gives a USB console instead of the HID transport. |
| `PYTHON` | flash script | Python that has pyserial. |

```sh
DABAO_NO_LC=1 $H send-tx --chain sepolia --to $DEAD --value 1
DABAO_DUMP=/tmp/reply.bin $H status
BEACON_URL=https://lodestar-sepolia.chainsafe.io $H lc-sync
```

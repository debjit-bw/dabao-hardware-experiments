# Dabao: an Ethereum signer that verifies before it signs

A hardware signer on the Baochip Dabao (Baochip-1x, Xous) that refuses to sign what it hasn't
checked itself. Before every signature it:

1. **gets a trusted state root**: a light client on the chip verifies the Ethereum sync
   committee's BLS signature over the parent block (docs/light-client.md);
2. **simulates the transaction** on state proven against that root (Merkle proofs, revm);
   anything the witness doesn't prove fails closed (docs/effects-inspector.md);
3. **checks that the user sees what it does**: every effect (transfers, approvals, swaps,
   ownership changes) must be explained by an ERC-7730 field on the display
   (docs/clear-signing.md);
4. **applies the owner's policy**: daily limits kept in RRAM, an allowlist, fee and slippage
   caps, compiled into the firmware (docs/policy.md);
5. **signs a digest it built itself**, in a separate MMU-isolated process whose key no other
   process can read (docs/keystore-slot-claims.md).

On top of that it is the hardware **co-signer of a 2-of-3 Safe** for an AI agent
(docs/safe-cosigner.md, docs/agent-wallet.md). The agent proposes through an MCP server; the
device simulates as the Safe and co-signs only a batch that ends in an **on-chain
postcondition**, so the transaction reverts if the state changes before inclusion
(docs/postcondition.md).

Everything above runs on the board and has been exercised on Sepolia; PROGRESS.md logs each
milestone with measurements and transaction links.

## Layout

```
crates/transport     process 1: USB HID framing (untrusted)
crates/verifier      process 2: light client, witness verification, revm, 7730, policy, postcondition
crates/signer        process 3: the key (keystore app slots), signs only verifier-approved jobs
crates/xous-evm      witness-verified simulation + effects inspector + postcondition (no Xous deps)
crates/light-client  sync-committee verification (BLS12-381, SSZ proofs)
crates/clear-sign    ERC-7730 checker;   descriptors/  the descriptors compiled into the firmware
crates/policy        signing policy;     policy/       the policy compiled into the firmware
crates/sim-types     wire format, Safe and MultiSend encoding
contracts/           DabaoPostcondition (on-chain check), DemoPayRouter (demo); foundry
host/dabao-host      host companion: witness building (eth_getProof), light-client sync, Safe flow
tools/bao-mcp        MCP server: an agent's wallet that only the device can co-sign
demo/                agent (poisoned invoice) and postcondition demos
patches/             our changes to xous-core (applied on the pinned submodule)
vendor/xous-core     submodule: xous-core, pinned
```

## Build from source

Requirements: macOS or Linux, Rust **1.100.0** (stable), and the Xous target sysroot.

```sh
git clone --recursive <this repo> && cd dabao-hackathon
scripts/setup-xous-core.sh            # pinned xous-core + patches/ (idempotent)
(cd vendor/xous-core && cargo xtask install-toolkit)   # Xous sysroot for riscv32imac-unknown-xous-elf

cargo test -p sim-types -p xous-evm -p clear-sign -p policy -p light-client -p bao-mcp
scripts/build-device.sh               # -> vendor/xous-core/target/riscv32imac-unknown-xous-elf/release/{loader,xous,apps}.uf2
scripts/run-emu.sh                    # or: the whole system under hosted Xous, on TCP 127.0.0.1:7610
```

`vendor/xous-core` is debjit-bw/xous-core at `36861b013`: btchip/xous-core `devcon8-workshop`
plus the Rust 1.100 `SVD_PATH` fix (upstream betrusted-io/xous-core#1023, backport PR
btchip/xous-core#1). `scripts/setup-xous-core.sh` adds the keystore app-slot claim patch
(patches/README.md). A clean build from the submodule takes ~1.5 min and produces images of exactly the flashed sizes. They are not bit-identical to a build from another checkout path (paths end up in the binaries), so the build is reproducible from source but not bit for bit. The descriptors and the policy are compiled into the firmware from
`descriptors/` and `policy/` by `scripts/compile-descriptors.sh`; the compiled blobs are checked
in.

**Warning:** the first self-built image puts a Dabao into developer mode and permanently erases
its factory secrets. `scripts/board-audit.py` audits the boot chain first.

## Flash and run

```sh
scripts/flash-and-log.py vendor/xous-core/target/riscv32imac-unknown-xous-elf/release/{xous,apps}.uf2
                                      # board in boot1 (press RESET); needs pyserial + progressbar2

cargo run -p dabao-host -- lc-sync    # upload the sync committee, follow hand-offs
cargo run -p dabao-host -- send-tx --chain sepolia --to 0x000000000000000000000000000000000000dEaD --value 1 --broadcast
cargo run -p dabao-host -- safe send --chain sepolia --to ... [--broadcast]
demo/agent/run.sh                     # Claude Code as a treasury agent; demo/agent/compromised.sh
demo/postcondition/run.sh             # state changes between co-signing and execution -> revert
```

`RPC_URL` selects the JSON-RPC node (default: publicnode). The Safe flow needs the demo keys
(`dabao-host safe keys` creates them in `.dabao-keys/`, which is gitignored).

## Status and limits

See PROGRESS.md for the log and each doc's "Limits" section. In short: there's no
on-device confirmation button yet (waiting for hardware). The light client trusts the sync
committee (the standard light-client assumption) and can't know a header is the very newest.
The postcondition checks balances and the Safe's configuration, not allowances.

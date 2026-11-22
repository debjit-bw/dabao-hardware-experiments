# Dabao: an Ethereum signer that checks before it signs

A signer for the Baochip Dabao (Baochip-1x, Xous). Before every signature, the board:

1. **gets a trusted state root**: a light client on the chip verifies the sync committee's BLS
   signature over the parent block (docs/light-client.md);
2. **simulates the transaction** on state proven against that root (Merkle proofs, revm);
   missing state fails closed (docs/effects-inspector.md);
3. **checks that every effect it recognises is explained** by an ERC-7730 field
   (docs/clear-signing.md);
4. **applies the owner's policy**: daily limits in RRAM, who may be called or paid, fee and slippage caps,
   compiled into the firmware (docs/policy.md);
5. **signs a digest it built itself**, in a separate process. A keystore patch denies that
   process's key slots to other processes (docs/keystore-slot-claims.md).

**The board has no display and no confirmation button yet.** The host prints what would be
shown, and the host is untrusted, so today the policy in the firmware is the only approval.

The board can also **co-sign for a 2-of-3 Safe** used by an AI agent (docs/safe-cosigner.md,
docs/agent-wallet.md). It co-signs only a batch that ends in an **on-chain postcondition**,
which reverts at inclusion if a tracked balance changes worse than simulated, a checked Safe
setting changed, or the co-signature expired (docs/postcondition.md).

This is a hackathon prototype, tested on Sepolia with tiny amounts and not audited. Each doc
has measurements, transaction links and limits. Don't put real funds behind it.

**New here? Read [docs/GUIDE.md](docs/GUIDE.md):** the architecture, every file, and how to build, run
and change everything, in plain English.

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
tools/bao-mcp        MCP server: lets an agent propose Safe transactions to the board
demo/                agent (poisoned invoice) and postcondition demos
vendor/xous-core     submodule: xous-core fork (two commits on upstream)
```

## Build from source

Requirements: Rust **1.100.0** and the Xous sysroot for that version. Tested on macOS (Apple
silicon) only.

```sh
git clone --recursive https://github.com/debjit-bw/dabao-hackathon.git && cd dabao-hackathon
rustup default 1.100.0
(cd vendor/xous-core && cargo xtask install-toolkit)   # Xous sysroot

cargo test --locked -p sim-types -p xous-evm -p clear-sign -p policy -p light-client -p bao-mcp
scripts/build-device.sh               # -> vendor/xous-core/target/riscv32imac-unknown-xous-elf/release/{loader,xous,apps}.uf2
```

`vendor/xous-core` is the `dabao-hackathon` branch of debjit-bw/xous-core: btchip/xous-core
`devcon8-workshop` at `d1d4b9bca` plus two commits, which `git -C vendor/xous-core log -p -2`
shows in full:

- the Rust 1.100 `SVD_PATH` fix (betrusted-io/xous-core#1023, backported in btchip/xous-core#1);
- per-boot keystore app-slot claims (docs/keystore-slot-claims.md).

Builds are not bit-for-bit reproducible across checkout paths. The descriptors and the policy
are compiled into the firmware by `scripts/compile-descriptors.sh`; the blobs are checked in.

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

- **No trusted display, no on-device confirmation.**
- **The host chooses part of the simulated block**: base fee, gas limit, beneficiary and
  prevrandao aren't checked against the proven parent, so a contract that reads them can
  behave differently in the simulation.
- **The light client is Sepolia-only and its proof isn't bound to the request's chain id.**
  Other chains are refused by the built-in policy, not by the proof.
- **The light client follows optimistic (unfinalized) headers**, trusts 2/3 of the sync
  committee and can't know that a header is the newest.
- **Transactions from the board's own account have no postcondition.**
- **Safe swaps don't fit on the board yet**: their witness is ~158 KB, over the 140 KiB limit.
- **The postcondition checks only the tracked balances and some Safe settings.** It doesn't
  check approvals, NFTs or other assets.
- **The demo Safe's agent and recovery keys are files on the same machine.** Whoever controls
  that machine has 2 of 3 signatures and doesn't need the board. A real deployment must keep
  the recovery key elsewhere.

## License

MIT ([LICENSE-MIT](LICENSE-MIT)) or Apache-2.0 ([LICENSE-APACHE](LICENSE-APACHE)), at your
option. `vendor/xous-core` and files copied from other projects (the registry descriptors,
test fixtures) keep their own licenses.

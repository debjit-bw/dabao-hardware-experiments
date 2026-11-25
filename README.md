# Dabao: an Ethereum signer that checks before it signs

> Experiments pushing the Baochip Dabao to its limits: a light client, an EVM and a policy-enforcing Ethereum signer on a 2 MiB RAM microcontroller. Not audited.

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

**How it uses the chip** (MMU, RRAM, TRNG, the RTL, and what it doesn't use): [docs/hardware.md](docs/hardware.md).

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
vendor/xous-core     submodule: xous-core fork (three commits on upstream)
```

## Build from source

Requirements: Rust **1.100.0** and the Xous sysroot for that version. Tested on macOS (Apple
silicon) only.

```sh
git clone --recursive https://github.com/debjit-bw/dabao-hardware-experiments.git && cd dabao-hardware-experiments
rustup default 1.100.0
(cd vendor/xous-core && cargo xtask install-toolkit)
cargo test --locked -p sim-types -p xous-evm -p clear-sign -p policy -p light-client -p bao-mcp
cargo build --locked -p dabao-host -p bao-mcp
scripts/build-device.sh
```

`install-toolkit` installs the Xous sysroot. The firmware ends up in
`vendor/xous-core/target/riscv32imac-unknown-xous-elf/release/{loader,xous,apps}.uf2`.

`vendor/xous-core` is the `dabao-hackathon` branch of debjit-bw/xous-core: btchip/xous-core
`devcon8-workshop` at `d1d4b9bca` plus three commits, which `git -C vendor/xous-core log -p -3`
shows in full. [docs/xous-core-fork.md](docs/xous-core-fork.md) explains each one:

- the Rust 1.100 `SVD_PATH` fix (betrusted-io/xous-core#1023, backported in btchip/xous-core#1);
- per-boot keystore app-slot claims (docs/keystore-slot-claims.md);
- BIO DMA windows only inside IFRAM, so no program can read other programs' memory through the BIO.

**Builds are reproducible:** the same commit gives byte-identical `loader.uf2`, `xous.uf2` and
`apps.uf2`, wherever it's checked out and whatever the Cargo home. `build-device.sh` sets
`SOURCE_DATE_EPOCH` to the commit's time and maps local paths to fixed names. Tested on one
Mac: two clones in different folders with different Cargo homes. Not yet tested on a second
machine or OS.

To check what a board runs, put it in boot1 (press RESET), then compare it with your own build.
This reads the board's memory back with boot1's read-only `peek`:

```sh
scripts/board-audit.py
R=vendor/xous-core/target/riscv32imac-unknown-xous-elf/release
scripts/firmware-verify.py $R/loader.uf2 $R/xous.uf2 $R/apps.uf2
```

The descriptors and the policy are compiled into the firmware by
`scripts/compile-descriptors.sh`; the blobs are checked in.

**Warning:** the first self-built image puts a Dabao into developer mode and permanently erases
its factory secrets. `scripts/board-audit.py` audits the boot chain first.

## Flash and run

Run the flash script, then press RESET. It needs `pyserial` and `progressbar2`. A board's
first flash needs all three images; later ones only `xous.uf2` and `apps.uf2`.

```sh
R=vendor/xous-core/target/riscv32imac-unknown-xous-elf/release
scripts/flash-and-log.py $R/loader.uf2 $R/xous.uf2 $R/apps.uf2
H=target/debug/dabao-host
$H lc-sync
$H address
$H send-tx --chain sepolia --to 0x000000000000000000000000000000000000dEaD --value 1
```

A new board makes its own key: fund that address on Sepolia first, and add `--broadcast` to
really send. [Every command, option and script, with examples](docs/GUIDE.md#15-command-reference).
Demos: `demo/agent/run.sh`, `demo/agent/compromised.sh`, `demo/postcondition/run.sh`.

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

## Built on

- [btchip/ethereum-app](https://github.com/btchip/ethereum-app) `dabao-app-eth-burner` (MIT OR
  Apache-2.0): the key storage in `crates/signer/src/store.rs`, the HID / TCP framing in
  `crates/transport`, and the keystore calls in `crates/verifier/src/slots.rs` are adapted from it.
- [xous-core](https://github.com/betrusted-io/xous-core): the OS, plus our keystore commit.
- [paradigmxyz/stateless](https://github.com/paradigmxyz/stateless) and
  [reth](https://github.com/paradigmxyz/reth): witness tries; the witness database and chain
  specs mirror theirs. [revm](https://github.com/bluealloy/revm): the EVM.
  [alloy](https://github.com/alloy-rs): types. [arkworks](https://github.com/arkworks-rs): BLS12-381.
- Safe 1.4.1 contracts (used as deployed) and the Uniswap descriptor from the
  [ERC-7730 registry](https://github.com/ethereum/clear-signing-erc7730-registry) (CC0).

## License

MIT ([LICENSE-MIT](LICENSE-MIT)) or Apache-2.0 ([LICENSE-APACHE](LICENSE-APACHE)), at your
option. `vendor/xous-core` and files copied from other projects (the registry descriptors,
test fixtures) keep their own licenses.

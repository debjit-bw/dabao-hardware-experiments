# xous-core patches

Changes to upstream xous-core that this project needs. They live here, not in a fork, so the
whole delta is visible in one place; apply them on top of the pinned xous-core before building.

**Base:** btchip/xous-core, branch `devcon8-workshop` at `d1d4b9bca`.
Patch 1 is also commit `36861b013` (branch `backport-rust-1.100-svd-path` on
debjit-bw/xous-core, PR btchip/xous-core#1); patch 2 applies on top of it.

| # | Patch | What | Why |
|---|---|---|---|
| 1 | [xous-core-backport-pr1023-svd-path.patch](xous-core-backport-pr1023-svd-path.patch) | utralib writes / xtask reads `SVD_PATH` at `target/SVD_PATH` | Rust 1.100's build-dir layout broke device image builds (`NotFound` after the kernel build). Exact hunks of betrusted-io/xous-core#1023. |
| 2 | [xous-core-keystore-app-slot-claims.patch](xous-core-keystore-app-slot-claims.patch) | keystore: `AppKey::Claim` — first process to claim an app-slot range owns it until reboot | Stock dabao keystore lets any process read/write any app slot, so a compromised process could read the signer's key. Design and tests: [docs/keystore-slot-claims.md](../docs/keystore-slot-claims.md). |

## Apply

xous-core is the submodule `vendor/xous-core`, pinned at `36861b013` (patch 1 is that commit).
`scripts/setup-xous-core.sh` checks it out and applies patch 2 (idempotent). By hand:

```sh
git submodule update --init vendor/xous-core
git -C vendor/xous-core apply ../../patches/xous-core-keystore-app-slot-claims.patch
```

Check: `git apply --check` on a clean tree; after applying, `strings
target/riscv32imac-unknown-xous-elf/release/keystore | grep "claimed by PID"` (once built)
confirms patch 2 is in the image.

## Files touched

- Patch 1: `utralib/build.rs`, `xtask/src/builder.rs`
- Patch 2: `libs/keystore-api/src/rkyv_enum.rs` (API: new enum variant, appended last),
  `services/keystore/src/platform/baosec/server.rs` (server: claim table + checks; compiled
  only with the keystore's `app-keys` feature, which dabao builds enable)

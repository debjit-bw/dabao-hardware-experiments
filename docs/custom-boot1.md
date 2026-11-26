# Plan: our own boot1, for a key the hardware protects

Status: **built and checked on the laptop, nothing flashed. Not possible on our board:**
its boot0 (v0.10.0) erases the collateral whenever boot1 is signed with the developer key, the
only key we can sign boot1 with (next section). It needs a board whose boot0 has the later
logic, or a boot1 signed by Baochip. This page explains why we'd replace boot1, what
upstream already provides, what we'd have to change, which permanent settings it touches,
and what could go wrong. Background: [hardware.md](hardware.md#the-key-store-what-the-hardware-protects-and-why-our-key-doesnt-use-it).

## Why

Today the signing key sits in an "open" storage slot. The hardware doesn't check who reads
it, and anyone who can reflash the board can read it. The chip has a mechanism for exactly
this: "collateral" secrets in slots 261–263. Boot1 generates them on the chip from the TRNG,
only process 3 can read them (checked by the RRAM hardware on every load), and they survive
developer mode. But they're kept only when boot1 carries a third party's own keys. With the
stock boot1, boot0 erases them on every boot.

With our own boot1:

1. the signing key is derived from the collateral, so it never exists outside the chip and
   can't be read out, not even by us;
2. only firmware signed with our key runs, where today anyone's developer-signed firmware does;
3. installing a boot1 with different keys makes boot0 erase the collateral first, so the key
   is destroyed rather than stolen.

## Our board's boot0 (v0.10.0) rules it out

Boot0 is the part we never change, and ours is the released v0.10.0. That version's
`mutual_distrust` erases the collateral whenever boot1 is signed with the developer key:

> "In all cases - if developer key is active - erase the collateral. This plugs a hole where it
> could be possible to bypass checks by stitching a third party header onto a developer-signed
> image."

Upstream removed that rule later (commit `012ace556`, "remove collateral erase on developer
mode"), after adding the counter-signature (`1b3a02603`) that closes the same hole another way.
Boot0 accepts a boot1 signed with Baochip's keys or with the developer key, and only Baochip
holds theirs. So on our board, any boot1 we make is developer-signed, and the collateral is
erased on every boot. The source we read (and our earlier plan) describes the newer boot0.

What still works with this boot0, if we installed our boot1 anyway:

- only firmware signed with our key boots;
- `audit` reports firmware hashes (below).

What doesn't: a persistent, hardware-protected key, and "replacing boot1 destroys the key".

**Unknown:** which boot0 production A1 boards ship with.

## Our chip is A0, and that changes two things

Boot1's `audit` reports `Stepping is: A0` for our board.

1. **The recovery image can rewrite boot0 on A0.** Upstream builds `bao1x-boot-updater` with
   a `boot0` feature by default. On A0 (and only there), it rewrites boot0, the first stage
   that is permanent on A1, and says "device likely bricked" if that write fails. **We must
   build it without that feature** (`--no-default-features`, then the needed features by name)
   and check the built image for the boot0 payload before using it.
2. **The RRAM hardware check is switchable on A0.** The access checks are gated by enable bits
   in an unlocked register (see [hardware.md](hardware.md)). So "only process 3 can read the
   collateral" holds while nothing else can write that register. That's kernel page
   ownership, as for everything else. What A0 doesn't weaken:
   - only firmware signed with our key runs (boot1's signature check);
   - replacing boot1 with other keys makes boot0 erase the collateral.

   Open question: A0's boot0 is writable (that's what the recovery image's boot0 update relies
   on). Whether software that isn't boot code can write it, for example after clearing the code
   check, decides whether a physical attacker could replace boot0 itself and skip the erase.
   Read before step 3.

## What upstream already has

| Piece | Where | Ready to use? |
|---|---|---|
| Boot1 code that generates the collateral from the TRNG and sets `OEM_MODE` | `bao1x-boot/boot1/src/main.rs`, `thirdparty_init` (feature `thirdparty`) | Yes. Upstream calls it a demonstration that is "fine to use" |
| Boot0 keeping or erasing the collateral | `bao1x-boot/boot0/src/main.rs`, `mutual_distrust` | Yes. It's in the chip and can't change |
| Signing a boot1 that carries third-party keys, plus the counter-signature boot0 checks | `tools/src/sign_image.rs`, `--fake-pubkeys` | **No.** It embeds a public **test** key whose private key is in the source ("KindlyNoteThisIsTestKeyDontUseForProduction"). It shows the mechanism and protects nothing |
| A recovery image that installs a new boot1 | `bao1x-boot/boot-updater` (`cargo xtask bao1x-boot-updater`) | Yes. It contains the new boot1 and writes it, with a staged-test state |

## What we'd change (all in our fork, all build-side)

Status: items 1–4 are done in the fork (built, not pushed); item 5 isn't started.

1. **The signing tool** (`tools/src/sign_image.rs`, when `XOUS_THIRDPARTY_KEY` names our
   key): our public key in **all four** key slots (`tpk0`–`tpk3`), counter-signed with our
   private key, and the post-quantum slots left empty. Upstream puts fresh random keys in slots
   1–3, so boot1 is different on every build. Empty ed25519 slots would be dangerous: an
   all-zero key is a small-order point, and boot0's counter-signature check (non-strict
   `verify_prehashed`, no skip for empty slots) would accept forged signatures for it. Empty
   post-quantum slots are skipped by tag, and post-quantum isn't required. Result: the same
   boot1 bytes on every build (checked twice).
2. **The build:** `cargo xtask bao1x-boot1 --thirdparty` turns on boot1's `thirdparty` feature.
   Upstream's `--thirdparty-test` only changes how the image is signed, not the boot1 code.
3. **Signing the firmware:** `FIRMWARE_KEY=.dabao-firmware-key/firmware.key scripts/build-device.sh`
   signs loader, Xous and apps with our key (xtask `--lkey`/`--kkey`). Checked with OpenSSL:
   all three verify with our key and not with the developer key. The new boot1 accepts only
   images signed with the keys it carries, and the stock boot1 refuses these, so never flash
   them on a board with the stock boot1.
4. **Firmware hashes in `audit`.** Stock boot1's `audit` hashes only boot0 and boot1, and its
   memory-reading `peek` exists only in debug builds. Ours would also print the SHA-512 of
   the loader, Xous and apps images (each image's length comes from its signature block).
   With reproducible builds, anyone can then check that a board holds exactly the firmware a
   given commit builds to. Done in `bao1x-boot/boot1/src/audit.rs` (`loader code only`,
   `kernel code only`, `apps code only`). `scripts/firmware-verify.py --hashes` prints the
   expected values from UF2 files. Not compared with a real board yet. Like the rest of `audit`, it's boot1 reporting, so it's as
   trustworthy as boot1. A replaced boot1 could lie, but replacing it also erases the
   collateral, which changes the device's address.
5. **The signer:** derive the signing key from the collateral (HKDF-SHA256 over slots 261–263,
   salted with the chip's UUID). Only process 3 can read the collateral, so this goes with
   making the signer process 3. That part is done and running
   ([xous-core-fork.md](xous-core-fork.md#4-the-signer-as-process-3-ec255a6cf)).

## Permanent settings it touches

All are one-way counters: they can only go up. Each one tops out at 10,000.

| Counter | What happens | Effect afterwards |
|---|---|---|
| `AltBootCoding` | +1 to boot the recovery image, +1 to go back to boot1 | None: only the count grows |
| `Boot1DeveloperState` | Steps through Good → Staged → Attempted → Good during the update | None, if the new boot1 boots. If it doesn't, the recovery image skips future automatic updates until a good boot1 is restored |
| `BootWaitCoding` | The recovery image forces it to "wait in boot1 at reset", to avoid a boot loop | The board then stops in boot1 at every reset until it's toggled back: another +1 |
| `OEM_MODE` | Set to 1 the first time our boot1 runs | `audit` prints `THIRD PARTY MODE ACTIVE` and the public collateral evidence. Keystore-derived keys change; we don't use them |

`DEVELOPER_MODE` is already set and stays set.

## What could go wrong

- **Bricking.** Boot0 always runs. If boot1 is invalid, it starts the loader region instead.
  If *that* is invalid too, it has nothing to run and hangs. Rule: never write boot1 unless a
  working recovery image is in the loader region. We don't know whether the chip has a debug
  port that could rescue it beyond that.
- **A boot1 that boots but refuses our firmware**, for example because of a signing mistake.
  The recovery image's staged state is for this case. We'd recover by restoring a known-good
  boot1 over USB from the recovery shell.
- **Post-quantum signatures.** The third-party signing path also fills post-quantum key
  slots. **Unverified:** whether boot1 then requires post-quantum signatures on the next stage,
  which we don't make today. Read before building.
- **Losing the collateral** after the key depends on it. The key and everything at its
  address are lost for good. That's the anti-tamper design. On the Safe it's survivable: the
  other two owners swap the device out.
- **The firmware signing key becomes the most valuable secret.** Whoever holds it can sign
  firmware that runs as process 3 and uses the collateral. It must not live on the laptop
  that runs the host software.

## Steps, with a stop after each

1. **No board changes.** *Done (2026-11-26):* items 1–4 above, built and checked. Boot1 is
   reproducible, with our key in all four ed25519 slots and the developer key absent.
   Post-quantum signatures aren't required (only if the `REQUIRE_PQ` counter is set, and it
   isn't). The recovery image (`cargo xtask bao1x-boot-updater --boot1 <our boot1.img>`)
   builds without its `boot0` feature: no boot0-writing code in it, and our boot1 embedded
   whole. Firmware signed with our key verifies with our key and fails with the developer key.
2. **The signer as process 3** on the current boot chain. *Done and running on the board
   (2026-11-26):* the keystore and its patch are out of our image
   ([xous-core-fork.md](xous-core-fork.md#4-the-signer-as-process-3-ec255a6cf)).
3. **The boot1 swap,** with the recovery image in place. The key stays as it is. Check that the
   collateral survives reboots, and that developer-signed firmware is refused. *Not done: on
   our board's v0.10.0 boot0 the collateral can't survive (above).*
4. **Decide on the key:** derive it from the collateral, which gives a new address. Move the
   Safe's owner over with `swapOwner` and the board account's ETH beforehand.

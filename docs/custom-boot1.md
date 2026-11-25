# Plan: our own boot1, for a key the hardware protects

Status: **design only, nothing flashed.** This page explains why we'd replace boot1, what
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

## What upstream already has

| Piece | Where | Ready to use? |
|---|---|---|
| Boot1 code that generates the collateral from the TRNG and sets `OEM_MODE` | `bao1x-boot/boot1/src/main.rs`, `thirdparty_init` (feature `thirdparty`) | Yes. Upstream calls it a demonstration that is "fine to use" |
| Boot0 keeping or erasing the collateral | `bao1x-boot/boot0/src/main.rs`, `mutual_distrust` | Yes. It's in the chip and can't change |
| Signing a boot1 that carries third-party keys, plus the counter-signature boot0 checks | `tools/src/sign_image.rs`, `--fake-pubkeys` | **No.** It embeds a public **test** key whose private key is in the source ("KindlyNoteThisIsTestKeyDontUseForProduction"). It shows the mechanism and protects nothing |
| A recovery image that installs a new boot1 | `bao1x-boot/boot-updater` (`cargo xtask bao1x-boot-updater`) | Yes. It contains the new boot1 and writes it, with a staged-test state |

## What we'd change (all in our fork, all build-side)

1. **The signing tool:** in third-party mode, embed *our* public key in key slot 0 and
   counter-sign with *our* private key, instead of the test key.
2. **The build:** have `cargo xtask bao1x-boot1` turn on boot1's `thirdparty` feature. Today
   `--thirdparty-test` only changes how the image is signed, not the boot1 code.
3. **Signing the firmware:** sign loader, Xous and apps with our key (`--loader-key`,
   `--kernel-key`). The new boot1 accepts only images signed with the keys it carries, so our
   current developer-signed images would stop booting until they're re-signed.
4. **The signer:** derive the signing key from the collateral (HKDF-SHA256 over slots 261–263,
   salted with the chip's UUID). Only process 3 can read the collateral, so this goes with
   making the signer process 3 (option B in the chat history; it also removes the keystore
   patch).

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

1. **No board changes.** Make the build changes above. Build boot1, the recovery image and
   re-signed firmware. Read the post-quantum and staging code. Check the built images' headers
   (embedded keys, counter-signature) with a script. *Status: code read, changes listed.
   Waiting on where the firmware signing key lives.*
2. **Option B** on the current boot chain: the signer becomes process 3, the keystore and its
   patch go. Normal flashing.
3. **The boot1 swap,** with the recovery image in place. The key stays as it is. Check that the
   collateral survives reboots, and that developer-signed firmware is refused.
4. **Decide on the key:** derive it from the collateral, which gives a new address. Move the
   Safe's owner over with `swapOwner` and the board account's ETH beforehand.

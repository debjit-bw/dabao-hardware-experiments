# How this project uses the Baochip

This page goes through what the Baochip-1x offers, using the hackathon's own list, and says
for each item what we use, how, and what we don't. "Measured" means shown on our board.
"From the RTL" means read in the chip's published design and not tested. Our crypto runs in
software, and we didn't use IRIS. Both are said plainly below.

The chip's design (RTL) we read is
[baochip/baochip-1x](https://github.com/baochip/baochip-1x): `main` at `750f0e8`, which tracks
the latest die (A1), and the `tapeout-a0` tag. **Our board's chip is stepping A0** (boot1's
`audit` prints `Stepping is: A0`). Where the two differ, this page says so.

## Summary

| The chip offers | Used? | How |
|---|---|---|
| MMU and Xous processes | **Yes, central** | Three isolated processes: USB parser, verifier, signer |
| RRAM (4 MiB, on chip) | **Yes** | A ~1 MB verifier runs straight from it. Spending counters, light-client state and the key persist in it |
| TRNG | **Yes** | The signing key is generated on the chip from it |
| Key store (hardware-checked slots) | **Studied, not used** | Our slots are "open". Developer mode erases protected slots on every boot. The way back is described below |
| Crypto accelerators | **No** | No hardware for secp256k1, Keccak or BLS12-381. All our crypto is software |
| BIO | **Security only** | Found that any program could use BIO DMA to read all memory. Proved it with a BIO program, then fixed it |
| Open RTL | **Yes** | Read the RRAM controller and the BIO DMA filter. Checked both against the board |
| IRIS die inspection | **No** | |
| Glitch sensors, security mesh | **No** | |

## Xous and the MMU: "an app that needs the MMU"

This is the core of the project. Three separate processes, each in its own address space:

1. **transport**: parses USB HID frames from the laptop. It's the part most exposed to attack,
   so it's untrusted and holds nothing secret.
2. **verifier**: the light client, Merkle-proof checking, an EVM (revm), the ERC-7730 check and
   the policy. About 1 MB of code.
3. **signer**: holds the key and signs only what the verifier approved.

A bug in the USB parser can't read the verifier's memory or the signer's key. Other things
we rely on, all measured on the board:

- **Memory lending.** The transport streams a request of up to 140 KiB into a buffer that Xous
  remaps into the verifier for the call, instead of copying it. That matters with 2 MiB of RAM
  shared by everything.
- **Per-process memory limits.** Xous caps each process at 512 KiB of heap. The verifier raises
  its own cap to 1.5 MiB, so a runaway transport can't starve it. Peak use is 379–436 KB for
  real swaps and Safe transactions.
- **Page ownership.** The kernel gives each physical page to one process at a time. That
  is what stops other processes from mapping the key slots directly.

A microcontroller without an MMU (a Pico, say) would run all three in one address space,
and a USB bug would expose the key.

## RRAM

- **Code run in place.** The verifier (~1 MB) is too big for the apps region, so it ships in
  the system image and executes straight from RRAM. The system image is 2.13 MB of 2.49 MB.
- **State that survives a reset**, in the keystore's app slots: daily spending counters
  (measured: a cold reset doesn't refill the budget), the light client's ratchet (so a laptop
  can't roll it back to an older chain after a reboot), and the signing key.

Ordinary flash could hold the state. What's chip-specific is running a megabyte of code in
place with no external memory.

## TRNG

The key is generated on the board on first boot: 32 bytes from Xous's `getrandom`, mixed with
the kernel's entropy pool through SHA-256 (`crates/signer/src/store.rs`). On the Dabao,
`getrandom` reads the TRNG server. That is a ChaCha generator seeded from the kernel's pool,
which comes from the on-chip ring-oscillator TRNG
(`vendor/xous-core/services/bao1x-hal-service/src/trng/dabao.rs`). The key never leaves the
board.

## Crypto accelerators

Not used. The chip has hardware AES, SHA-256 and a public-key engine (PKE), but Ethereum needs
secp256k1 signatures, Keccak hashes and, for the light client, BLS12-381 pairings. None of those
has documented hardware support, so all of them run in software on the main CPU: a sync-committee
check takes about 0.7 s, and checking and signing a simple send about 0.84 s. Whether the PKE
could speed up BLS12-381 is an open question we didn't explore.

## The key store: what the hardware protects, and why our key doesn't use it

**What the hardware does** (from the RTL, `rtl/modules/rrc/rtl/rrc.sv`, and Baochip's
`docs/src/rram.md`). On every load from RRAM, the CPU tells the memory controller which "user"
it is: one of four (boot0, boot1, fw0, fw1). Each storage slot has an owner. If the user
doesn't match the owner, the read returns zeros. Boot1 maps Xous processes to users and then
locks the mapping. Only process 3 (normally the keystore) gets the trusted user; every other
process, the kernel included, gets the untrusted one.

**A0 versus A1.** On A1, an engineering change (`#eco16`) keeps the slot checks always on. On
**A0, our chip,** every check is ANDed with an enable bit in the RRAM controller's `RRCCR`
register (`tapeout-a0`, `rrc.sv` lines 718–790), and that register has no lock. So on A0, code
that can write `RRCCR` can switch the checks off. Upstream's `detect_stepping()` tells the two
apart in exactly that way. Boot code sets the bits on. After that, what keeps them on is that
no other program can map the controller's registers: kernel page ownership again, not
hardware.

**What it can't do:**

- Tell two programs with the same user apart. There are four users and one trusted process.
- Check slots with no owner. The check only runs when the owner field isn't zero, and app slots
  ("open") have none. Only boot code can set an owner.
- On A0, stay on against software that can reach the controller's registers (above).
- Keep protected secrets on a board in developer mode. Boot0 erases the protected slots on
  every boot when developer mode is set (`bao1x-boot/boot0/src/main.rs`). Developer mode is
  permanent, and our board is in it: the first self-built image puts every Dabao there.

So our key sits in an open slot, protected by software: the kernel's page ownership, our
keystore change ([xous-core-fork.md](xous-core-fork.md)) and the BIO fix below. Physical
access is enough to read it (hole F in the [guide](GUIDE.md)).

**The way back (designed, not done).** Boot1 can generate "collateral" secrets in slots
261–263 that belong to the trusted user and survive developer mode. Boot1 makes them from the
ring-oscillator TRNG after a stuck-output health check, folding in 16,384 raw bits
(`bao1x-boot/boot1/src/platform/bao1x/trng.rs`). They're kept only if boot1 carries its own
third-party keys. Boot0 erases them if boot1 is replaced by one with different keys
(`mutual_distrust` in boot0). With our own boot1:

- the signing key would be encrypted with a key derived from the collateral, and only process 3
  could decrypt it, checked by the RRAM hardware;
- reflashing boot1 would destroy the key, not reveal it;
- only firmware signed with our key would run.

We haven't done it, because replacing boot1 is risky on our only board. On A0 the
"checked by the RRAM hardware" part is weaker, as explained above. The boot-chain parts (only
our firmware runs; replacing boot1 destroys the key) don't depend on it. Details:
[custom-boot1.md](custom-boot1.md).

## BIO and DMA: an attack, proved and fixed

The BIO is four small extra processors for pin I/O. They can copy data to and from main
memory on their own (DMA), which doesn't go through the MMU. The chip guards that path with
an address whitelist (from the RTL, `rtl/modules/bio_bdma/rtl/bio_bdma.sv`). Reads outside
the whitelist are redirected to a harmless "gutter" address.

We found that xous-core's BIO server let any process set that whitelist to anything. Our
probe (`crates/bio-dma-probe`) used only public interfaces and loaded a four-instruction
program into a BIO core. It then read back a test value from an app slot, and a page of RAM
by physical address. The fork's third commit fixes it, and after the fix both reads fail.
Full results: [xous-core-fork.md](xous-core-fork.md#3-bio-dma-windows-b08da4ec9).

This is the hackathon's "attack it, then defend it", done with a software interface rather
than fault injection.

## Open RTL: "prove a block behaves as published"

We read the RTL to answer questions the documentation didn't, then checked the answers on the
board:

| From the RTL | On the board |
|---|---|
| The BIO DMA filter sends reads outside the whitelist to the gutter | Reads of a public address with no window return zeros |
| Whitelisted pages are reachable | Whitelisted RRAM and RAM pages read back exactly |
| RRAM slots with no owner skip the access check, even for DMA | An open app slot was read through BIO DMA |

We didn't compare the silicon with the RTL physically. That needs IRIS, and we didn't use it.

## Checking what software the board runs

Before the first flash we ran boot1's read-only `audit` command (`scripts/board-audit.py`).
The boot0 and boot1 SHA-512s matched Baochip's v0.10.0 release, and no warning flags were set.
After that, boot1 checks the signature of every image it starts. In developer mode it accepts
the public developer key, so a signature check says only that *some* developer signed it.

The firmware itself can be checked too:

1. **Our builds are reproducible.** The same commit gives byte-identical images, wherever it's
   checked out (README, "Build from source"). Anyone can rebuild and get the same hashes.
2. **The board can be read back.** Boot1 has a read-only `peek` command that prints any address
   in the code region. `scripts/firmware-verify.py` reads the loader, Xous and apps regions
   back that way and compares them byte for byte with UF2 files you built yourself.

Together: "this published commit, rebuilt by me, is exactly what's on this board."

Limits:

- The read-back and `audit` are both done by boot1, so they're only as trustworthy as boot1.
  `audit` shows boot1's hash, which you compare with Baochip's release. A replaced boot1 could
  lie about both. Boot0 is what can't be replaced (on A1; see above for A0).
- Tested on one Mac with two clones; not yet on a second machine or operating system.

The custom boot1 above would improve this. Firmware signed with other keys wouldn't run, and
replacing boot1 erases the collateral. A signing key derived from the collateral could then
sign challenges, proving that the boot chain hasn't been replaced. That is also design only.

## Not claimed

- That we verified the silicon, or used IRIS.
- Hardware-accelerated crypto.
- That the key is in hardware-protected slots.
- That the chip is fully open. Baochip says some third-party IP is closed.
- That this is impossible on any other board. We know of no other microcontroller with this
  mix.

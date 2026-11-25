# What we changed in xous-core, and why

The board runs Xous, the operating system from
[betrusted-io/xous-core](https://github.com/betrusted-io/xous-core). We build it from a fork:
the `dabao-hackathon` branch of
[debjit-bw/xous-core](https://github.com/debjit-bw/xous-core/tree/dabao-hackathon). The fork
is the `vendor/xous-core` submodule.

The fork is btchip/xous-core's `devcon8-workshop` branch at `d1d4b9bca`, plus three commits.
`git -C vendor/xous-core log -p -3` shows all three in full. None of them changes the chip.
The chip and its published design (RTL) are exactly as Baochip shipped them. We only changed
software that runs on it.

| Commit | Area | In short |
|---|---|---|
| `36861b013` | build tool | Makes the image build work with Rust 1.100 |
| `c8aeac994` | keystore | Lets one program reserve its key slots so other programs can't read them |
| `b08da4ec9` | BIO server | Stops programs from using the BIO's memory access to read other programs' memory |

## 1. The build fix (`36861b013`)

**Problem.** Rust 1.100 changed where Cargo puts build files. The image builder then looked
for a file (`SVD_PATH`) in the old place, didn't find it, and stopped with
`Error: Os { code: 2, kind: NotFound }`.

**Fix.** The same change upstream made in betrusted-io/xous-core#1023, backported to this
branch (btchip/xous-core#1).

**Effect on security:** none. It only affects building.

## 2. Keystore slot claims (`c8aeac994`)

**Background.** The chip has persistent memory (RRAM). Part of it is divided into small
"app slots" of 32 bytes each. Programs don't read these slots directly. They ask the
keystore, a program that owns all the slots and reads and writes them on request.

**Problem.** The keystore answered every request from every program. It doesn't check who
is asking. So any program on the board, for example our USB parser if someone found a bug in
it, could ask for the slots that hold the signing key and get the key back.

**Fix.** A new request, `AppKey::Claim`: a program can reserve a range of slots until the
next reboot. After that, the keystore refuses those slots to every other program. Our
signer reserves its slots at startup, before it reads any input, and refuses to run if the
reservation fails. Details and board tests: [keystore-slot-claims.md](keystore-slot-claims.md).

**Why the chip's own protection doesn't do this.** The chip can protect storage slots in
hardware: the memory controller checks every read against the slot's owner. But it knows
only four kinds of reader ("users"), and the boot code gives the trusted kind to a single
program, the keystore. Every program reads its slots through the keystore, so to the hardware
every read looks like the keystore. The hardware can't tell our signer from an attacker.
Telling programs apart has to happen in the keystore, which is what this commit adds.

App slots are also marked "open" (no owner), so the hardware check doesn't run on them at
all, and only boot code can change a slot's owner. On a board in developer mode, the boot
code also erases the slots that do have an owner on every startup.

## 3. BIO DMA windows (`b08da4ec9`)

**Background.** The BIO is a set of four tiny extra processors on the chip, separate from the
main processor that runs Xous. They exist to drive pins with precise timing (LED strips,
unusual serial protocols, touch sensing). They can also copy data to and from main memory on
their own. That is called DMA, "direct memory access".

DMA matters because the MMU, the hardware that keeps programs apart, only checks the main
processor's accesses. BIO DMA doesn't go through it. The chip guards that path with its own
filter: the BIO may only touch address ranges that software has whitelisted. Baochip's
documentation says this filter "helps prevent abuse of the BDMA as a method for bypassing
host CPU security features".

**Problem.** The whitelist is set by the BIO server in `bao1x-hal-service`, and it accepted
any range from any program. So any program could whitelist all of memory, load a small
program into a BIO core, and read whatever it wanted.

**Shown on the board (2026-11-25).** A test program, [`crates/bio-dma-probe`](../crates/bio-dma-probe),
used only public interfaces:

1. It wrote a random test value into app slot 170 through the keystore, and another into a
   page of its own memory.
2. It asked the BIO server to whitelist those two pages. The server accepted.
3. It loaded a four-instruction program into a BIO core that reads a word from an address
   and sends it back.

| | Before the fix | After the fix |
|---|---|---|
| App slot 170 (RRAM) | all 8 words read back | not read (zeros) |
| A page of RAM, by physical address | all 8 words read back | not read (zeros) |
| A control address with no window | zeros | zeros |
| BIO server log | | `BIO DMA windows refused for Some(9): only IFRAM is allowed` |

Slot 170 holds only the test value, and the probe never touched the signer's slots. The same
read works on any slot, and on any program's memory, including a key the signer has loaded
into RAM to sign.

**Fix.** The BIO server now applies a request only if every window lies inside IFRAM, the
memory the BIO is meant to work with. Otherwise it refuses the whole request and logs which
program asked. Our firmware doesn't use the BIO, so it loses nothing.

**Limits.** The server's interface sends no answer back for this request, so a refused
program isn't told. It only sees that its reads don't work. Changing that would mean changing
the interface. A firmware that needs BIO DMA into main memory needs a finer rule. For
example, the server could allow windows only over memory that belongs to the program asking.

## Reproducing the tests

Both fixes were tested on a physical Dabao (the keystore claims on 2026-11-21, the BIO fix on
2026-11-25). The steps below rebuild those test images. Each one runs a probe that plays a
compromised process and prints `PROBE` lines on the USB serial console. Test images contain a
probe and no USB transport, so the board can't sign anything until the normal image goes back
on (last section).

You need a board that was flashed with this repo's firmware before, the build requirements in
the [README](../README.md#build-from-source), and a Python with pyserial for flashing:

```sh
python3 -m venv .venv-flash
.venv-flash/bin/pip install pyserial progressbar2
export PYTHON="$PWD/.venv-flash/bin/python"
T=riscv32imac-unknown-xous-elf
R=vendor/xous-core/target/$T/release
```

Each flash step waits for the board's bootloader: press RESET when it says
`waiting ... for boot1`. The flash script then boots the image and prints its log for 120
seconds. The probe repeats its lines every 5 seconds, so they all appear.

### Keystore slot claims

```sh
cargo build --release -p keystore-probe --target $T --features board-dabao,bao1x
GENERIC_HID=0 scripts/build-device.sh target/$T/release/keystore-probe
scripts/flash-and-log.py --log-secs 120 $R/xous.uf2 $R/apps.uf2
```

Expected: `PROBE summary: 8/8 as expected`, and keystore warnings such as
`app slot 160: access by Some(9) denied (claimed)`. The full table is in
[keystore-slot-claims.md](keystore-slot-claims.md#tests).

There is no "before" image for this one: the signer itself needs `AppKey::Claim`, so it
doesn't build against the stock keystore. The probe's `read unclaimed slot 170` line shows
the stock behaviour: a slot nobody claimed is still served to any process.

### BIO DMA windows: with the fix

```sh
cargo build --release -p bio-dma-probe --target $T --features board-dabao,bao1x
GENERIC_HID=0 scripts/build-device.sh target/$T/release/bio-dma-probe
scripts/flash-and-log.py --log-secs 120 $R/xous.uf2 $R/apps.uf2
```

Expected: `PROBE summary: RRAM slot blocked / SRAM blocked`, and the BIO server's warning
`BIO DMA windows refused for Some(9): only IFRAM is allowed`.

### BIO DMA windows: without the fix

This puts back the stock BIO server for one build, then restores it:

```sh
git -C vendor/xous-core checkout c8aeac994 -- services/bao1x-hal-service/src/servers/bio.rs
GENERIC_HID=0 scripts/build-device.sh target/$T/release/bio-dma-probe
git -C vendor/xous-core checkout HEAD -- services/bao1x-hal-service/src/servers/bio.rs
scripts/flash-and-log.py --log-secs 120 $R/xous.uf2 $R/apps.uf2
```

Expected: `PROBE RRAM app slot: 8/8 words returned, 8/8 match the canary -> READ THROUGH BIO DMA`,
the same for the SRAM page, and `PROBE summary: RRAM slot READ / SRAM READ`.
`git -C vendor/xous-core status` must be clean again afterwards.

### Back to the normal image

```sh
scripts/build-device.sh
scripts/flash-and-log.py --log-secs 20 $R/xous.uf2 $R/apps.uf2
target/debug/dabao-host policy
```

Check that `policy` prints the expected policy name before any signing request.

### Not tested yet

- Mapping the slot region directly (`map_memory` at `0x603E_0000`) from another process. The
  kernel's page ownership should refuse it with `MemoryInUse`. That's read in the kernel source,
  not run on the board.
- BIO DMA into IFRAM. The fix still allows it. Our firmware doesn't use the BIO, so we didn't
  check that IFRAM holds nothing sensitive.

## Not sent upstream

None of the three is in betrusted-io/xous-core. The build fix is upstream already (#1023);
the backport to btchip's branch is btchip/xous-core#1. The other two haven't been reported.

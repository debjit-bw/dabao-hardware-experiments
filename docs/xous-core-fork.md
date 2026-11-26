# What we changed in xous-core, and why

The board runs Xous, the operating system from
[betrusted-io/xous-core](https://github.com/betrusted-io/xous-core). We build it from a fork:
the `dabao-hackathon` branch of
[debjit-bw/xous-core](https://github.com/debjit-bw/xous-core/tree/dabao-hackathon). The fork
is the `vendor/xous-core` submodule.

The fork is btchip/xous-core's `devcon8-workshop` branch at `d1d4b9bca`, plus six commits.
`git -C vendor/xous-core log -p d1d4b9bca..HEAD` shows them in full. None of them changes the
chip. The chip and its published design (RTL) are exactly as Baochip shipped them. We only
changed software that runs on it.

| Commit | Area | In short | In our firmware? |
|---|---|---|---|
| `36861b013` | build tool | Makes the image build work with Rust 1.100 | yes (build only) |
| `c8aeac994` | keystore | Lets one program reserve its key slots so other programs can't read them | no longer: since `ec255a6cf` our image has no keystore |
| `b08da4ec9` | BIO server | Stops programs from using the BIO's memory access to read other programs' memory | yes |
| `41d45d5a8`, `9adce6849` | boot1 build tools | Build our own boot1 with our own firmware key; firmware hashes in `audit` | no: built and checked, never installed ([custom-boot1.md](custom-boot1.md)) |
| `ec255a6cf` | build tool | Runs our signer as process 3, in place of the keystore | yes |

The board runs firmware built with `36861b013`, `b08da4ec9` and `ec255a6cf`. Its boot0 and boot1 are Baochip's
released v0.10.0, untouched.

## 1. The build fix (`36861b013`)

**Problem.** Rust 1.100 changed where Cargo puts build files. The image builder then looked
for a file (`SVD_PATH`) in the old place, didn't find it, and stopped with
`Error: Os { code: 2, kind: NotFound }`.

**Fix.** The same change upstream made in betrusted-io/xous-core#1023, backported to this
branch (btchip/xous-core#1).

**Effect on security:** none. It only affects building.

## 2. Keystore slot claims (`c8aeac994`), no longer used

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

**Now replaced.** Since 2026-11-26 our image leaves the keystore out and the signer itself is
the trusted program (section 4). There's then nobody to ask for the slots, so this commit is
no longer used by our firmware. It stays in the fork's history: the branch is public, and
rewriting it would break anyone who fetched it.

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

## 4. The signer as process 3 (`ec255a6cf`)

**Background.** Boot1 tells the RRAM hardware which program is the trusted reader: process
number 3, and only that one. It then locks that setting. The kernel never gives number 3 to
another program, even if process 3 crashes. Upstream, process 3 is the keystore, and every
other program reaches the slots through it (section 2).

**Change.** A build flag, `--trusted-service name~flash:path` (dabao only), that leaves the
keystore out of the image and puts the given program in its place as process 3. Xous numbers
programs in image order from 2, and the build put our own programs last, so the flag moves
this one right after the timer service (process 2) and stops if process 2 is anything else.
`xous-create-image` prints the result in the build log:

```
PID 2: xous-ticktimer
PID 3: signer
PID 4: xous-log ...
PID 8: verifier
```

Our signer (`crates/signer`) then does itself what it used to ask the keystore for:

- It maps the RRAM slot region, the slots' access-control region and the RRAM controller,
  with the same Baochip library code the keystore uses (`bao1x_hal::acram::SlotManager`,
  `bao1x_hal::rram::Reram`). The kernel gives each physical page to one program only, so once
  the signer has them, no other program can map them.
- It finds the key where the keystore kept it: app slot `i` is data slot
  `APPLICATION.base + i`, as in the keystore's own code.
- It refuses to run unless it is process 3.
- It switches the scheduler's time-slicing on. The HAL starts with the timer off, and upstream
  the keystore's startup turns it on. Without that, one busy program would stall all others.
- The verifier's spending counters and light-client state share a memory page with the key,
  so the verifier can't map them separately. The signer keeps them for it, through a small
  server (`_dabao signer slots_`) that:
  - answers only requests carrying a random per-boot token, which the signer hands only to
    the verifier, inside the verifier's own private channel;
  - answers only the first program that used the token;
  - serves only the verifier's slots (176–209), never the key's (160–161).

**What it removes.** The keystore, and so the need for section 2's patch, from our image. One
program, ours, is between the key and the hardware, instead of a shared server and a
reservation scheme.

**What it doesn't change.** The slots are still "open", so the hardware's per-slot check still
doesn't run on them, and it's still the kernel's page ownership that keeps other programs out.
Someone who holds the board can still flash their own firmware and read the slot (hole F in
the [guide](GUIDE.md)). Being process 3 only matters for slots the hardware owns, which is
what [custom-boot1.md](custom-boot1.md) was for.

**Shown on the board (2026-11-26).** A test program, [`crates/slot-probe`](../crates/slot-probe),
playing a compromised process (process 9):

| Attempt | Result |
|---|---|
| connect to the keystore | `ServerNotFound`: there is none |
| read key slots 160 and 161 through the signer's slot server, no token | refused (the signer logs `bad token` from PID 9) |
| write key slot 160, no token | refused |
| read or write counter slot 176, read light-client slot 208, no token | refused |
| map the RRAM data slots (`0x603E_0000`) | `MemoryInUse` |
| map the slot access-control region (`0x603D_C000`) | `MemoryInUse` |
| map the RRAM controller (`0x4000_0000`) | `MemoryInUse` |

10 of 10 as expected, with the signer attached to the verifier. On the normal image: the same
address (`0x7813…F986`), policy, and spending counter as before the change; a Sepolia send
signed and landed, the counter and the light client's position were written, and both survived
a cold reset.

The key's address is guarded during such changes: built with
`DABAO_SIGNER_ADDRESS=0x…`, the signer never creates a key and refuses to run unless the slots
hold the key for that address. A bug in the new storage code can't make it write a new key
over the old one.

## Reproducing the tests

The fixes were tested on a physical Dabao (the keystore claims on 2026-11-21, the BIO fix on
2026-11-25, the signer as process 3 on 2026-11-26). The steps below rebuild those test images. Each one runs a probe that plays a
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

### The signer as process 3

```sh
cargo build --release -p slot-probe --target $T --features board-dabao,bao1x
GENERIC_HID=0 scripts/build-device.sh target/$T/release/slot-probe
scripts/flash-and-log.py --log-secs 120 $R/loader.uf2 $R/xous.uf2 $R/apps.uf2
```

Expected: `PROBE summary: 10/10 as expected`, `signer attached to verifier: true`, and the
signer's warnings `slot server: refused ... from PID Some(9): bad token`.

### Keystore slot claims (the old image)

This one tests commit 2, which our image no longer uses. Its probe and the old signer need the
keystore, so check out the main repo at `5181823` (the last commit before the signer became
process 3) to run it.

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
`BIO DMA windows refused for Some(9): only IFRAM is allowed`. The probe writes its test value
through the keystore, so like the claims test it needs the main repo at `5181823`.

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
scripts/flash-and-log.py --log-secs 20 $R/loader.uf2 $R/xous.uf2 $R/apps.uf2
target/debug/dabao-host address
target/debug/dabao-host policy
```

Check that `address` prints the board's usual address, and `policy` the expected policy name,
before any signing request.

### Not tested yet

- BIO DMA into IFRAM. The fix still allows it. Our firmware doesn't use the BIO, so we didn't
  check that IFRAM holds nothing sensitive.

## Not sent upstream

None of the six is in betrusted-io/xous-core. The build fix is upstream already (#1023);
the backport to btchip's branch is btchip/xous-core#1. The others haven't been reported.

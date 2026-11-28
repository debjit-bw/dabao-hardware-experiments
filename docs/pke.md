# The public-key engine (PKE): tried, doesn't run

We tried to use the Baochip's public-key engine for the light client's BLS12-381 work. On our
board, as xous-core sets the chip up, its compute core doesn't finish any job. This page records
what we found, so the next person starts from here. Nothing in the firmware uses the PKE.

Code: `crates/pke-bench` (test image). Measured on our A0 board on 2026-11-28.

## What the RTL says it does

Nothing in xous-core drives the PKE: it has the register map (`utralib`) and the clock setup,
and no driver. Baochip's repository has a test bench for the hash engine but none for the PKE,
and no documentation of it. So everything below comes from the RTL
([baochip/baochip-1x](https://github.com/baochip/baochip-1x) at `tapeout-a0`,
`rtl/modules/crypto_top/rtl/pke.sv` and `rtl/modules/crypto_pke/`).

- **A hardwired engine, not a programmable one.** `PkeCtrl` is a fixed state machine. The
  `PCON` segment carries constants, not a program.
- **Operations** (`SFR_CRFUNC`): modular add `0x09`, subtract `0x0a` and Montgomery multiply
  `0x02` over a prime loaded by `ECINIT` (`0x01`); short-Weierstrass point add `0x05`, double
  `0x06` and multiply `0x0b`; Ed25519 point operations; X25519; RSA Montgomery multiply and
  exponentiation; modular inverse; GCD (`0x51`).
- **Any prime up to 576 bits.** `ECINIT` loads the prime, the curve's `a` and R² from `PCON`,
  and can compute R² and the Montgomery constant itself. BLS12-381's 381-bit prime fits.
- **Memory.** `PCON` at `0x4002_0800`, inputs (`PIB`) at `0x4002_0c00`, outputs (`POB`) at
  `0x4002_1400`. A job starts with `0x5a` written to `0x4002_c004` and is done when bit 0 of
  `SFR_FR` is set.

## Where it could have helped

The light client's 0.71 s per header, measured on the board:

| Step | Time | Could the PKE do it? |
|---|---|---|
| aggregate ~494 public keys | 122 ms | yes: G1 point additions over the 381-bit field |
| hash-to-G2 | 144 ms | no: Fp2 arithmetic |
| decompress the signature | 52 ms | no: Fp2 |
| pairing check | 390 ms | no: Fp12 |
| load a new committee (once per ~27 h) | 16.2 s | yes: square roots and G1 scalar multiplications |

So the best case was about 0.1 s off each header, plus a faster committee load. Sending single
field multiplications to it would have lost to the cost of moving data over the bus, as it nearly
did for the hash engine.

## What happened on the board

| Run | Result |
|---|---|
| `ECINIT` with BLS12-381's prime | hangs in state `J0` (`SFR_SRMFSM` = `0x71`), where the core computes the Montgomery constant. The input channel reports done (`SFR_FR` = `0x8`) |
| `GCD(12, 18)`, which needs no `ECINIT` | hangs in the compute state (`0x70`), inputs loaded (`SFR_FR` = `0x8`) |

What we ruled out:

- **The clock.** The PKE core runs on its own clock, from the second PLL output through a
  divider. A temporary readout in the HAL service (not committed) measured it with the chip's
  frequency counter: 41 MHz, divider `SFR_CGUFDPKE` = `0xff` (its reset value), no clock
  skipping (`SFR_CGUSEC` = 0). The bus clock was 696 MHz.
- **The clock crossing.** The start and done signals cross between the two clocks through a
  toggle synchroniser (`gnrl_sync.sv`, `sync_pulse`), which works at any clock ratio.
- **The engine's enable.** The loader enables every SCE sub-engine (`SUBEN` = `0xff`), and the
  input channel, which runs on the bus clock, works.

The engine has no soft reset. The SCE's `ARCLR` only clears RAM, so after a hang nothing starts
until the chip is reset, and each attempt costs a reset.

## What would come next

We stopped because the payoff was small and every attempt needed a reset. The next step would
be to simulate `pke.sv` and `crypto_pke/` from the RTL (Verilator), with stub clock and RAM cells.
That would show what the core waits for. Our guesses, all untested: a RAM or power setting the
core's RAM needs (it has its own SRAM macro, `SCEPKERAM4K`), a register the core needs that
xous-core never sets (`SFR_MIMMCR`), or a clock the design expects to be faster than 41 MHz.

## Reproduce

```sh
SERVICE=pke-bench GENERIC_HID=0 scripts/build-device.sh dabao-console
scripts/flash-and-log.py --until "PKE DONE" vendor/xous-core/target/riscv32imac-unknown-xous-elf/release/{loader,xous,apps}.uf2
```

`pke-bench` runs GCD first. If that completes, it goes on to find the word layout (from
modular addition), the Montgomery R (from multiplication) and the point coordinates (from
doubling and adding the G1 generator), then times the engine against arkworks. Every result is
checked against software. It's a test image with the stock keystore and no signer: flash the
normal image again afterwards.

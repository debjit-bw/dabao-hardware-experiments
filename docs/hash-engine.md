# Keccak-256 and SHA-256 on the chip's hash engine

The Baochip's crypto block (SCE) has a hash engine called "combohash". The verifier uses it for
every Keccak-256 hash (Ethereum's hash) and the light client uses it for SHA-256. Each boot
starts with a self-test, and an engine that fails it isn't used. On the board, simulating a swap
got 37% faster.

Code: `crates/sce-hash` (the driver, self-test and software fallback), `crates/hash-bench`
(test image: known answers and timings), the hook in `crates/verifier/Cargo.toml`.

## Keccak on an engine that says "SHA3"

The chip's documentation lists the engine's modes as SHA-256, SHA-512, RIPEMD, BLAKE2/3 and
SHA3. Ethereum's Keccak-256 isn't SHA3: the two use the same permutation (Keccak-f[1600]) but
pad the last block differently. So a SHA3 engine is only useful to Ethereum if the padding is
left to software.

The RTL shows it is ([baochip/baochip-1x](https://github.com/baochip/baochip-1x),
`rtl/modules/crypto_top/rtl/combohasha.sv` and `rtl/modules/crypto_hash/rtl/hashcore_sha3.sv`,
unchanged since the `tapeout-a0` tag). In SHA3 mode the engine:

1. loads 50 32-bit words from its MSG segment: the whole 200-byte Keccak state;
2. runs the 24 rounds (the round constants are loaded at boot by boot0, `RAMSEG_SHA3`);
3. writes the 50 words of the new state to its HOUT segment.

There is no padding and no absorbing in hardware: the engine is a raw Keccak-f[1600]. So
`sce-hash` runs the sponge in software (XOR each 136-byte block into the state, Ethereum's
`0x01 .. 0x80` padding) and does every permutation on the engine.

The word layout isn't documented. `hash-bench` found it by running the engine on the all-zero
state and comparing with the Keccak team's published permutation of it: lane *i* is
`(word[2i] << 32) | word[2i+1]`, with no byte swap. SHA-256 uses the engine's compression
function the way boot1's own driver does (`bao1x-boot/sha2-bao1x`), with padding in software.

## How it is plugged in

- **Ownership.** At boot the verifier maps the engine's registers (`0x4002_b000`) and its
  segment memory (`0x4002_0000`). The kernel then refuses those pages to every other process,
  as it does for the signer's RRAM pages. Nothing else in our image uses the engine. The loader
  already switches the SCE's sub-engines on.
- **Self-test, every boot** (`sce_hash::init`). The permutation of the all-zero state must
  match the published vector. Keccak-256 and SHA-256 must match software on 25 input lengths,
  chosen around every block and padding boundary (0, 55, 56, 64, 135, 136, 137, 512, 9000 and
  more). Each engine is switched on only if all of its checks pass. Otherwise it stays in
  software.
- **Fallback.** If the engine ever doesn't finish (a bounded wait), it is switched off until
  the next boot and the hash is done in software. A wrong hash can't slip through: the
  self-test checks the engine first, and a wrong hash in a Merkle proof fails the proof.
- **Keccak everywhere.** alloy-primitives has a `native-keccak` feature for platforms that
  bring their own Keccak: `alloy_primitives::keccak256` then calls an external
  `native_keccak256`. `sce-hash` provides it. The verifier switches the feature on for the
  device target only, so every Keccak in the verifier goes to the engine: the Merkle-trie checks
  (`tries`, `zeth-mpt`), revm's `KECCAK256` opcode and CREATE2 addresses, and our own code.
  Host and emulator builds keep software Keccak.
- **SHA-256 in the light client.** `sce_hash::Sha256Hw` is a `digest`-compatible type, used for
  the SSZ roots and for hashing to the BLS curve. It buffers the message and hashes it in one
  call, because the engine keeps only one chaining state.
- **Reporting.** `dabao-host status` prints which backend is in use and the self-test result:

  ```
  hashing: Keccak-256 on the chip's hash engine, SHA-256 on the chip's hash engine (combohash
  self-test: Keccak-f(0) ok, Keccak-256 25/25 lengths match software; SHA-256 25/25 match)
  ```

## Measured on the board (2026-11-26)

`hash-bench` checked every result against software before timing anything. SHA-256: "abc" and
102 random lengths up to 16 KiB, 0 mismatches. Keccak-256: the empty string and 116 random
lengths (including 135, 136, 137, 272 and 16 KiB), 0 mismatches.

| Hash | Software | Engine | Speedup |
|---|---|---|---|
| SHA-256, 64 B | 69.5 µs | 44.1 µs | 1.6× |
| SHA-256, 1 KiB | 362 µs | 111 µs | 3.3× |
| SHA-256, 16 KiB | 5,067 µs | 1,277 µs | 4.0× |
| Keccak-256, 32 B | 172 µs | 103 µs | 1.7× |
| Keccak-256, 136 B | 316 µs | 181 µs | 1.7× |
| Keccak-256, 532 B (a typical trie node) | 605 µs | 338 µs | 1.8× |
| Keccak-256, 16 KiB | 17.4 ms | 9.5 ms | 1.8× |

The whole verifier, the same inputs before (software) and after (engine), same day:

| Request | Software | Engine | Change |
|---|---|---|---|
| Simulate a Sepolia swap (117 KB witness) | 201 ms | 124–129 ms | −37% |
| Sign a 1 µETH send on a light-client-proven block | 835 ms | 826 ms | −1% |
| Co-sign a Safe payment (97 KB witness) | 979 ms | 918 ms | −6% |

The results are identical: the swap still uses 252,708 gas, a proof with one byte changed is
still rejected, and both signed transactions landed on Sepolia with logs identical to the
device's prediction
([send](https://sepolia.etherscan.io/tx/0x6596492c1c4dd16615c404f67d21b9169884d7e31a301202cebe0ce1829f07a3)).
Light-client requests barely move: about 0.7 s of each is the BLS pairing check, which isn't
hashing.

## Limits

- **The engine waits on the bus.** Its rounds are fast. Most of the 95 µs per permutation is
  ~100 uncached 32-bit register accesses to move the state in and out. The SCE has its own DMA,
  which could do that copying; we haven't tried it.
- **One user at a time.** The verifier owns the engine. Another process that needs hashing
  does it in software.
- **The documentation doesn't promise this mode.** The word layout and SHA3 behaviour come
  from the RTL and the board, not from documentation, which is why the self-test runs at every
  boot.
- **Not used:** AES (we don't encrypt anything), the PKE big-number engine (it might speed up
  BLS12-381, but we haven't tried) and secp256k1 (no hardware for it; signing stays in software).

## Reproduce

```sh
SERVICE=hash-bench GENERIC_HID=0 scripts/build-device.sh dabao-console
scripts/flash-and-log.py --until "HASH DONE" vendor/xous-core/target/riscv32imac-unknown-xous-elf/release/{loader,xous,apps}.uf2
```

`hash-bench` repeats its results every 10 s on the USB console. It's a test image with the
stock keystore and no signer: flash the normal image again afterwards.

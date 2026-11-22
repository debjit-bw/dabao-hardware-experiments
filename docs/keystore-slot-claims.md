# Keystore app-slot claims (keeping the signing key away from other processes)

## Problem

The device runs three MMU-isolated Xous processes:

| Process | Trust | Holds |
|---|---|---|
| 1. transport (apps image) | **untrusted**: parses host input from USB | nothing |
| 2. verifier (system image) | trusted: witness verification, EVM, policy | no keys |
| 3. signer (apps image) | trusted: signs only verifier-approved txs | **the private key** |

The signer's secp256k1 key is stored in two keystore *app slots* (160 and 161) so it survives
reboots. On dabao the stock keystore:

- registers its server with **unlimited connections** (`register_name(SERVER_NAME_KEYS, None)`,
  "permissive default for e.g. Dabao", `services/keystore/src/main.rs`), and
- serves `AppKeyOp` reads and writes **without checking the caller**: the only check is a
  fixed, public guard constant (`APPKEY_GUARD`, "prevents accidents", not attacks).

So the MMU kept the key out of the transport's *memory*, but not out of its *reach*: a
transport compromised through a malformed USB frame could connect to the keystore and read
slot 160. Isolation that the attacker can step around by asking politely isn't isolation.

## Threat model

- In scope: one of our non-signer processes (realistically the transport, the only one parsing
  host input) is compromised *after* boot, and tries to read, overwrite or claim the signer's
  slots.
- Out of scope: a compromised kernel, keystore, loader or signed image; physical attacks;
  code that runs before the signer's claim (see "Ordering" for why our image has none).

## Design (option "A1": first claim wins, per boot)

New keystore request `AppKey::Claim { guard, start, len }` (the top commit
of the `vendor/xous-core` submodule):

- The keystore keeps an in-RAM table of `(slot range, owner PID)`, empty at every boot.
- **Claim** of a range succeeds if it doesn't overlap any claimed range, or if it is exactly a
  range the caller already owns (idempotent). Otherwise `AccessDenied`, logged as a warning.
- **ReadRequest / Write** on a slot inside a range claimed by *another* PID → `AccessDenied`,
  logged. The caller's identity is the PID the kernel attaches to the message
  (`MessageEnvelope::sender.pid()`), which a process can't forge.
- **Unclaimed slots behave exactly as before**, so existing apps (eth-burner, BIO config) are
  unaffected.
- The new enum variant is appended last, so the existing variants keep their encoding.

Signer side (`crates/signer/src/store.rs`): the very first keystore call is
`Claim(160, 2)`. If it is refused, the signer **panics instead of using the key**: a refused
claim means another process owns the slots and may have read or replaced the key.

## Other claimants

The verifier claims slots **176–207** for the policy's daily-spending counters
(`crates/verifier/src/counters.rs`, docs/policy.md), at boot and before it registers its
server. A refused claim disables signing (fail closed) rather than stopping the verifier.

## Ordering: why the signer always claims first

"First claim wins" is only safe if the signer's claim happens before any attacker-controlled
code could run. In this image:

1. The attacker's only way in is host input over USB, and only the transport reads it.
2. The transport doesn't read any USB input until the verifier reports a signer is attached
   (`crates/transport/src/main.rs`: it polls `OP_ADDRESS` before `serve`).
3. The signer attaches to the verifier only after `load_or_create_key`, which starts with the
   claim.

So by the time any untrusted byte is processed, slots 160–161 are already claimed. If the
order were ever broken (a process racing the signer), the failure mode is the signer refusing
to start — fail closed, no key use — not a leak.

## Limits (known, accepted)

- **Per boot only.** Claims live in RAM; a reboot clears them and the signer reclaims at
  startup. That's intended (the order argument above is per boot).
- **Signer restart.** If the signer crashes and restarts within a boot it gets a new PID and
  can't reclaim its own slots: it refuses to start until the next reboot (fail closed).
- **Any process added to the image** that talks to the keystore before the signer and is
  exposed to untrusted input would break the ordering argument. Today there is none.
- **Not hardware-enforced.** The keystore server is the policy point; a compromised keystore,
  kernel or loader is out of scope (all are in the signed system image).
- PIDs are not stable across builds; nothing here depends on specific PID values (the stricter
  "fixed-PID allowlist" option A2 would, and was not chosen for that reason).

## Tests

On the board, with a **test image** (`GENERIC_HID=0`, so logs reach the USB serial console):
verifier in the system image, signer + `crates/keystore-probe` in the apps image. The probe
plays the compromised process and, after the signer has started, tries every way in:

| Probe action | Expected |
|---|---|
| read signer slot 160 / 161 | `AccessDenied` |
| write signer slot 160 | `AccessDenied` |
| claim 160..162 | `AccessDenied` |
| claim overlapping 161..163 | `AccessDenied` |
| read unclaimed slot 170 | `ReadResponse` (unchanged behaviour) |
| claim free 170..171, then again | `Success`, `Success` (idempotent for the owner) |

Feature `steal` builds a probe that claims 160..162 at boot, racing the signer: the signer must
then refuse to start ("can't claim keystore app slots").

Build and run:

```sh
GENERIC_HID=0 scripts/build-device.sh target/riscv32imac-unknown-xous-elf/release/keystore-probe
# press RESET on the board, then:
PYTHON=<python with pyserial, progressbar2> scripts/flash-and-log.py --until "PROBE summary" \
    vendor/xous-core/target/riscv32imac-unknown-xous-elf/release/{xous,apps}.uf2
```

## Results (board, 2026-11-21)

Test image: verifier (system image), keystore-probe as PID 9 and signer as PID 10 (apps image).

**Probe after the signer (normal order): 8/8 as expected.** The keystore logged:

```
WARN keystore: app slot 160: access by Some(9) denied (claimed)
WARN keystore: app slot 161: access by Some(9) denied (claimed)
WARN keystore: app slots 160..162: claim by PID 9 denied, held by PID 10
WARN keystore: app slots 161..163: claim by PID 9 denied, held by PID 10
INFO keystore: app slots 170..171 claimed by PID 9
```

and the probe: read 160 / read 161 / write 160 / claim 160..162 / claim 161..163 all
`AccessDenied`; read unclaimed 170 `ReadResponse`; claim 170..171 `Success` twice.

**Probe racing the signer (`steal`): fail closed.** The probe won the race
(`claimed 160..162 at boot -> Success`), and the signer refused to start: the verifier never
saw a signer attach (`signer attached to verifier: false`), so nothing can be signed.
Note what this does and doesn't show: in that forced race the probe *owns* the slots and could
read the key; the test shows the signer won't operate on slots it doesn't own. What prevents
the race in the real image is the ordering above (no untrusted input before the claim).

Gotcha found while testing: log lines reach the USB serial console only after some app calls
`usb_bao1x::UsbHid::serial_console_input_injection()` (usb-bao1x `SerialHookConsole` → xous-log
`TryHookUsbMirror`); `dabao-console` does this, the probe does it too. Lines logged before the
hook (e.g. the signer's own "claimed" line at boot) only go to the DUART.

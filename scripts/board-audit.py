#!/usr/bin/env python3
"""Run boot1's read-only `audit` command on a Dabao and check the result.

Usage: scripts/board-audit.py [/dev/cu.usbmodemXXXX]

The board must be in boot1 (boot-wait mode, BAOCHIP volume mounted). Only the
`audit` command is sent; it only reads slots and counters (see
xous-core/bao1x-boot/boot1/src/audit.rs). Raw output is saved under audit/.

Checks:
  * boot0/boot1 partition and code-only SHA-512s, and both baobit toolchain ids,
    against the "Baobit Audit References" in xous-core/bao1x-boot/README.md
    (the hex there is wrapped mid-digest; whitespace is joined before comparing);
  * every warning audit() can print, including the overall
    "System did not meet minimum requirements for security".
Stdlib only (no pyserial).
"""
import glob, os, re, select, sys, termios, time, tty
from datetime import datetime

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XOUS_CORE = os.environ.get("XOUS_CORE", os.path.join(HERE, "..", "dabao-workshop", "xous-core"))
LABELS = ["boot0 partition", "boot0 code only", "boot0 baobit toolchain",
          "boot1 partition", "boot1 code only", "boot1 baobit toolchain"]
RED_FLAGS = [
    "== IN DEVELOPER MODE ==", "== BOOT1 FAILED PUBKEY CHECK ==", "== THIRD PARTY MODE ACTIVE ==",
    "== BOOT0 REPORTED PUBKEY CHECK FAILURE ==", "== BOOT1 REPORTED PUBKEY CHECK FAILURE ==",
    "== CP SETUP FAILED ==", "Factory configuration error", "did not validate",
    "Anti-rollback counter offset invalid", "System did not meet minimum requirements for security",
]


def references():
    """{version: {label: hex}} from the README's audit reference blocks."""
    text = open(os.path.join(XOUS_CORE, "bao1x-boot", "README.md")).read()
    refs = {}
    for ver, block in re.findall(r"#### (v[\d.]+)\s*```(.*?)```", text, re.S):
        refs[ver] = {}
        for line in block.strip().splitlines():
            label, _, val = line.partition(":")
            refs[ver][label.strip()] = "".join(val.split()).lower()
    return refs


def run_audit(port, idle=2.0, limit=30.0):
    fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    try:
        tty.setraw(fd)
        attrs = termios.tcgetattr(fd)
        attrs[4] = attrs[5] = termios.B115200  # ignored by USB CDC, used on real UARTs
        termios.tcsetattr(fd, termios.TCSANOW, attrs)
        os.write(fd, b"\r")
        time.sleep(0.3)
        drain(fd, 0.5, 2)
        os.write(fd, b"audit\r")
        return drain(fd, idle, limit)
    finally:
        os.close(fd)


def drain(fd, idle, limit):
    out, start, last = b"", time.time(), time.time()
    while time.time() - start < limit and time.time() - last < idle:
        r, _, _ = select.select([fd], [], [], 0.1)
        if r:
            chunk = os.read(fd, 4096)
            if chunk:
                out, last = out + chunk, time.time()
    return out.decode("utf-8", "replace")


def main():
    ports = sys.argv[1:] or sorted(glob.glob("/dev/cu.usbmodem*"))
    if not ports:
        sys.exit("No /dev/cu.usbmodem* found. Is the board plugged in and in boot1 (BAOCHIP volume)?")
    port = ports[0]
    print(f"Running `audit` on {port} ...")
    text = run_audit(port)
    os.makedirs(os.path.join(HERE, "audit"), exist_ok=True)
    path = os.path.join(HERE, "audit", f"audit-{datetime.now():%Y%m%d-%H%M%S}.txt")
    open(path, "w").write(text)
    print(f"Raw output saved to {path}\n")
    if "boot0 partition" not in text:
        print(text)
        sys.exit("Did not see audit output (wrong port, or not in boot1?). Raw output above.")

    got = {}
    for label in LABELS:
        m = re.search(re.escape(label) + r":\s*([0-9a-fA-F]+|unspecified)", text)
        got[label] = m.group(1).lower() if m else None
    semver = (re.search(r"Semver is:\s*(\S+)", text) or [None, "?"])[1]
    refs = references()
    print(f"boot1 semver: {semver}; references available for: {', '.join(refs)}")

    ok = True
    for ver, ref in refs.items():
        results = [(label, got[label], ref.get(label)) for label in LABELS]
        if all(g == r for _, g, r in results):
            print(f"PASS  all 6 boot0/boot1 measurements match the {ver} references")
            break
    else:
        ok = False
        ver, ref = list(refs.items())[-1]
        print(f"FAIL  measurements do not match any reference; diff vs {ver}:")
        for label in LABELS:
            mark = "ok  " if got[label] == ref.get(label) else "DIFF"
            print(f"  {mark} {label}\n        device: {got[label]}\n        ref:    {ref.get(label)}")

    flags = [f for f in RED_FLAGS if f in text]
    attacks = re.search(r"Possible attack attempts:\s*(\d+)", text)
    if attacks and int(attacks.group(1)) > 0:
        flags.append(f"Possible attack attempts: {attacks.group(1)}")
    for f in flags:
        print(f"FLAG  {f}")
    ok = ok and not flags

    for key in ("Board type reads as", "Stepping is", "In-system keys", "CM7 & debug", "Erase proof",
                "Collateral", "Public serial number"):
        m = re.search(r"^.*" + re.escape(key) + r".*$", text, re.M)
        if m:
            print(f"info  {m.group(0).strip()}")
    print("\nRESULT:", "PASS: factory state looks genuine" if ok else "NOT CLEAN: read the flags above before flashing")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()

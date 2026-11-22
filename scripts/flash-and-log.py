#!/usr/bin/env python3
"""Wait for a Dabao in boot1, flash UF2s over the serial console, boot, and print the log.

Usage: scripts/flash-and-log.py [--wait SECS] [--log-secs SECS] [--until TEXT] file.uf2 [...]

Flashing over the boot1 serial console (bao1x-boot/uf2send.py: one `uf2 <base64>` command per
block, each acknowledged) instead of copying to the BAOCHIP volume: on macOS the mass-storage
copy of xous.uf2 hung for 15+ minutes. boot1's serial port is /dev/cu.usbmodem<serial>1; the
booted Xous USB console is .../<serial>3 (only with GENERIC_HID=0 builds).
Needs pyserial + progressbar2 for uf2send.py; set PYTHON to an interpreter that has them.
"""
import argparse, glob, os, select, subprocess, sys, time, tty

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XOUS_CORE = os.environ.get("DABAO_XOUS_CORE", os.path.join(HERE, "vendor", "xous-core"))
PYTHON = os.environ.get("PYTHON", sys.executable)


def read(fd, secs):
    out, t = b"", time.time()
    while time.time() - t < secs:
        try:
            r, _, _ = select.select([fd], [], [], 0.2)
            if r:
                c = os.read(fd, 4096)
                if not c:
                    break
                out += c
        except BlockingIOError:
            pass
        except OSError:
            break
    return out


def is_boot1(port):
    """boot1 answers an empty line with its command list (harmless)."""
    try:
        fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    except OSError:
        return False
    try:
        tty.setraw(fd)
        os.write(fd, b"\r")
        return b"Commands include" in read(fd, 2)
    finally:
        os.close(fd)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("uf2", nargs="+")
    ap.add_argument("--wait", type=float, default=600)
    ap.add_argument("--log-secs", type=float, default=90)
    ap.add_argument("--until", action="append", default=[], help="stop logging once all these strings are seen")
    a = ap.parse_args()

    print(f"waiting up to {a.wait:.0f}s for boot1 (hold PROG while plugging in)...", flush=True)
    t0, port = time.time(), None
    while time.time() - t0 < a.wait and not port:
        port = next((p for p in sorted(glob.glob("/dev/cu.usbmodem*")) if is_boot1(p)), None)
        time.sleep(1)
    if not port:
        sys.exit("boot1 not found")
    print(f"boot1 on {port}", flush=True)

    for f in a.uf2:
        print(f"flashing {f}", flush=True)
        r = subprocess.run([PYTHON, "-I", os.path.join(XOUS_CORE, "bao1x-boot", "uf2send.py"), "-p", port, f],
                           capture_output=True, text=True)
        tail = [l for l in r.stdout.replace("\r", "\n").splitlines() if any(k in l for k in ("Successful", "Failed", "SUCCESS", "ERROR"))]
        print("\n".join(tail[-3:]), flush=True)
        if r.returncode != 0 or "SUCCESS" not in r.stdout:
            sys.exit(f"flashing {f} failed:\n{r.stdout[-2000:]}\n{r.stderr[-2000:]}")

    fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    tty.setraw(fd)
    os.write(fd, b"boot\r")
    read(fd, 1)
    try:
        os.close(fd)
    except OSError:
        pass
    print("booting; reading Xous USB console...", flush=True)

    t0, buf = time.time(), b""
    while time.time() - t0 < a.log_secs:
        for p in sorted(glob.glob("/dev/cu.usbmodem*")):
            if p == port:
                continue
            try:
                fd = os.open(p, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
                tty.setraw(fd)
            except OSError:
                continue
            chunk = read(fd, 3)
            try:
                os.close(fd)
            except OSError:
                pass
            if chunk:
                buf += chunk
                sys.stdout.write(chunk.decode("utf-8", "replace"))
                sys.stdout.flush()
        if a.until and all(u.encode() in buf for u in a.until):
            break
        time.sleep(0.5)
    print(f"\n[log done after {time.time() - t0:.0f}s]")


if __name__ == "__main__":
    main()

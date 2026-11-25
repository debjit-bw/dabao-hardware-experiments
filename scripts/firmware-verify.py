#!/usr/bin/env python3
"""Check that a Dabao runs exactly the firmware in the given UF2 files.

Usage: scripts/firmware-verify.py [--port /dev/cu.usbmodemXXXX1] file.uf2 [...]

The board must be in boot1 (press RESET; the flash script's "waiting for boot1" state), and
that boot1 must have the `peek` command. Baochip's released boot1 doesn't: `peek` is only in
builds with the `unsafe-debug` feature.
For every UF2 file, this reads the same addresses back from the board with boot1's
read-only `peek` command and compares them byte for byte. It never writes to the board.

What a match proves: the bytes in the board's RRAM at those addresses are the bytes in the
UF2 files. Build the UF2s yourself from the published source (the builds are reproducible),
and run scripts/board-audit.py first: the read-back is done by boot1, so it is only as
trustworthy as boot1, and audit checks boot1 against Baochip's published hashes.

With --hashes, it doesn't talk to the board: it prints the "code only" SHA-512 of each
image, exactly as our own boot1's `audit` reports them ("loader code only", "kernel code only",
"apps code only"). Compare those lines with the board's `audit` output.

Stdlib only (no pyserial).
"""
import argparse, glob, hashlib, os, re, select, struct, sys, termios, time, tty

# xous-sign-image's signature block: MAGIC_NUMBER is b"yumy", b"Bao3" stored as little-endian u32s
SIG_MAGIC = b"yumy"[::-1] + b"Bao3"[::-1]
SIGBLOCK_LEN = 768
IMAGE_NAMES = {0x60060000: "loader", 0x600A0000 - SIGBLOCK_LEN: "kernel", 0x60300000 - SIGBLOCK_LEN: "apps"}
UF2_MAGIC = (0x0A324655, 0x9E5D5157)
UF2_END = 0x0AB16F30
WORDS_PER_PEEK = 1024
LINE = re.compile(r"([0-9a-f]{8}): ((?:[0-9a-f]{8} ?)+)")


def uf2_ranges(path):
    """Contiguous (address, bytes) ranges covered by a UF2 file."""
    data = open(path, "rb").read()
    if len(data) % 512:
        sys.exit(f"{path}: not a UF2 file (size {len(data)} isn't a multiple of 512)")
    blocks = []
    for off in range(0, len(data), 512):
        m0, m1, _flags, addr, size, _no, _n, _fam = struct.unpack_from("<8I", data, off)
        (end,) = struct.unpack_from("<I", data, off + 508)
        if (m0, m1) != UF2_MAGIC or end != UF2_END or size > 476:
            sys.exit(f"{path}: bad UF2 block at offset {off}")
        blocks.append((addr, data[off + 32: off + 32 + size]))
    blocks.sort()
    ranges = []
    for addr, payload in blocks:
        if ranges and ranges[-1][0] + len(ranges[-1][1]) == addr:
            ranges[-1][1].extend(payload)
        elif ranges and addr < ranges[-1][0] + len(ranges[-1][1]):
            sys.exit(f"{path}: overlapping blocks at {addr:#x}")
        else:
            ranges.append([addr, bytearray(payload)])
    return [(a, bytes(b)) for a, b in ranges]


def is_boot1(port):
    """boot1 answers an empty line with its command list."""
    try:
        fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    except OSError:
        return False
    try:
        tty.setraw(fd)
        os.write(fd, b"\r")
        out, t = b"", time.time()
        while time.time() - t < 2:
            r, _, _ = select.select([fd], [], [], 0.2)
            if r:
                try:
                    out += os.read(fd, 4096)
                except OSError:
                    break
        return b"Commands include" in out
    finally:
        os.close(fd)


def code_only_hash(image):
    """boot1 audit's "code only" hash: the signed bytes after the signature block."""
    magic_at = image.find(SIG_MAGIC, 0, SIGBLOCK_LEN)
    if magic_at < 4:
        return None
    unsigned_len = magic_at - 4                 # sealed_data starts with a u32 version, then the magic
    (signed_len,) = struct.unpack_from("<I", image, magic_at + 8)
    n = signed_len - (SIGBLOCK_LEN - unsigned_len)
    if n <= 0 or SIGBLOCK_LEN + n > len(image):
        return None
    return hashlib.sha512(image[SIGBLOCK_LEN:SIGBLOCK_LEN + n]).hexdigest()


class Boot1:
    def __init__(self, port):
        self.fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        tty.setraw(self.fd)
        attrs = termios.tcgetattr(self.fd)
        attrs[4] = attrs[5] = termios.B115200  # ignored by USB CDC
        termios.tcsetattr(self.fd, termios.TCSANOW, attrs)
        os.write(self.fd, b"\r")
        time.sleep(0.3)
        self._read_until(lambda t: False, idle=0.5, limit=2)

    def _read_until(self, done, idle=1.0, limit=20.0):
        out, start, last = "", time.time(), time.time()
        while time.time() - start < limit and time.time() - last < idle:
            r, _, _ = select.select([self.fd], [], [], 0.05)
            if r:
                chunk = os.read(self.fd, 65536)
                if chunk:
                    out, last = out + chunk.decode("ascii", "replace"), time.time()
                    if done(out):
                        break
        return out

    def peek(self, addr, words):
        """`words` 32-bit words from `addr`, as bytes (little-endian, as stored)."""
        os.write(self.fd, f"peek {addr:x} {words}\r".encode())
        want = {}

        def parse(text):
            for a, ws in LINE.findall(text):
                for i, w in enumerate(ws.split()):
                    want[int(a, 16) + 4 * i] = int(w, 16)
            return all(addr + 4 * i in want for i in range(words))

        text = self._read_until(parse)
        if "disallowed" in text:
            sys.exit(f"boot1 refused to peek {addr:#x}: {text.strip()}")
        missing = [addr + 4 * i for i in range(words) if addr + 4 * i not in want]
        if missing:
            sys.exit(f"incomplete peek answer at {missing[0]:#x} (is the board in boot1?)\n{text[-300:]}")
        return b"".join(struct.pack("<I", want[addr + 4 * i]) for i in range(words))

    def read(self, addr, length, progress):
        start, end = addr & ~3, (addr + length + 3) & ~3
        out = bytearray()
        a = start
        while a < end:
            n = min(WORDS_PER_PEEK, (end - a) // 4)
            out += self.peek(a, n)
            a += 4 * n
            progress(a - start, end - start)
        return bytes(out[addr - start: addr - start + length])


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--port", help="boot1's serial port (default: whichever port answers as boot1)")
    ap.add_argument("--wait", type=float, default=180, help="seconds to wait for boot1 (default 180)")
    ap.add_argument("--hashes", action="store_true", help="only print the images' audit hashes")
    ap.add_argument("uf2", nargs="+")
    a = ap.parse_args()
    if a.hashes:
        for f in a.uf2:
            ranges = uf2_ranges(f)
            start, image = ranges[0]
            name = IMAGE_NAMES.get(start, f"image at {start:#x}")
            h = code_only_hash(image) if len(ranges) == 1 else None
            print(f"{name} code only: {h or 'no signature block found'}")
        return
    images = [(f, uf2_ranges(f)) for f in a.uf2]
    print(f"waiting up to {a.wait:.0f}s for boot1 (press RESET)...", flush=True)
    port, t0 = None, time.time()
    while not port and time.time() - t0 < a.wait:
        port = next((p for p in ([a.port] if a.port else sorted(glob.glob("/dev/cu.usbmodem*"))) if is_boot1(p)), None)
        if not port:
            time.sleep(1)
    if not port:
        sys.exit("boot1 not found")
    print(f"boot1 on {port}")
    board = Boot1(port)
    ok = True
    for path, ranges in images:
        name, t0 = os.path.basename(path), time.time()
        local, remote = hashlib.sha256(), hashlib.sha256()
        first_diff, total = None, sum(len(b) for _, b in ranges)
        done = 0
        for addr, want in ranges:
            def progress(n, _all, base=done):
                print(f"\r  {name}: {(base + n) * 100 // total:3d}%", end="", flush=True)
            got = board.read(addr, len(want), progress)
            done += len(want)
            local.update(want)
            remote.update(got)
            if got != want and first_diff is None:
                i = next(i for i in range(len(want)) if got[i] != want[i])
                first_diff = addr + i
        match = first_diff is None
        ok &= match
        span = ", ".join(f"{a:#010x}+{len(b):#x}" for a, b in ranges)
        print(f"\r{'MATCH' if match else 'DIFF '} {name}: {total} bytes at {span}, {time.time() - t0:.0f} s")
        print(f"      file  sha256 {local.hexdigest()}")
        print(f"      board sha256 {remote.hexdigest()}")
        if not match:
            print(f"      first difference at {first_diff:#x}")
    print("RESULT:", "the board holds exactly these images" if ok else "the board does NOT hold these images")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()

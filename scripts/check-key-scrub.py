#!/usr/bin/env python3
"""Boot the boot-key scenario in pimu and look through the VPU's memory, as the
VPU sees it through the cached and the uncached alias, for what the key left
behind: the fused rows, the pads they make, the hash states on the way and the
key itself. Anything left in SDRAM or the L2 is readable from the ARM.

    check-key-scrub.py

Exits 1 and says where when it finds any of it. A run that finds nothing
says how much memory it read.
"""

import hashlib
import os
import re
import struct
import subprocess
import sys

ROWS = [0xC0DE2001 + 0x1111 * i for i in range(8)]
LABEL = b"pi4-server-firmware boot key v1"
IMAGE = 0x3EC00000
SHA_ENV = {**os.environ}
SPAN = 0x200000

K = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
]
H0 = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
M = 0xFFFFFFFF


def ror(x, n):
    return ((x >> n) | (x << (32 - n))) & M


def schedule(block):
    w = list(struct.unpack(">16I", block))
    for i in range(16, 64):
        s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & M)
    return w


def compress(h, block):
    w = schedule(block)
    a, b, c, d, e, f, g, hh = h
    for i in range(64):
        t1 = (hh + (ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i]) & M
        t2 = ((ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) & M
        hh, g, f, e, d, c, b, a = g, f, e, (d + t1) & M, c, b, a, (t1 + t2) & M
    return [(x + y) & M for x, y in zip(h, [a, b, c, d, e, f, g, hh])]


def sha_blocks(data):
    """The padded `data` as blocks, each with the state it starts from, and
    the digest as words."""
    padded = data + b"\x80" + bytes(-(len(data) + 9) % 64) + struct.pack(">Q", len(data) * 8)
    state, steps = list(H0), []
    for at in range(0, len(padded), 64):
        block = padded[at:at + 64]
        steps.append((list(state), block))
        state = compress(state, block)
    return steps, state


def authenticode(path):
    """The image's Authenticode SHA-256, as uefi/src/secure.rs takes it."""
    img = open(path, "rb").read()
    pe = struct.unpack_from("<I", img, 0x3C)[0]
    coff = pe + 4
    sections = struct.unpack_from("<H", img, coff + 2)[0]
    opt = coff + 20
    opt_size = struct.unpack_from("<H", img, coff + 16)[0]
    headers = struct.unpack_from("<I", img, opt + 60)[0]
    checksum = opt + 64
    directory = opt + 112 + 4 * 8
    cert_at, cert_size = struct.unpack_from("<II", img, directory)
    data = img[:checksum] + img[checksum + 4:directory] + img[directory + 8:headers]
    table = opt + opt_size
    raw = sorted(
        (struct.unpack_from("<I", img, table + 40 * i + 20)[0], struct.unpack_from("<I", img, table + 40 * i + 16)[0])
        for i in range(sections)
    )
    hashed = headers
    for at, size in raw:
        if size:
            data += img[at:at + size]
            hashed += size
    end = len(img) - cert_size
    if end > hashed:
        data += img[hashed:end]
    return hashlib.sha256(data).digest()


def secrets(image):
    """The key, what it derives and every value on the way."""
    key = b"".join(struct.pack("<I", r) for r in ROWS)
    measurement = hashlib.sha256(bytes(32) + authenticode(image)).digest()
    message = LABEL + measurement
    pad = key + bytes(32)
    ipad = bytes(b ^ 0x36 for b in pad)
    opad = bytes(b ^ 0x5C for b in pad)
    values = {"fused rows": ROWS}
    inner_steps, inner = sha_blocks(ipad + message)
    inner_bytes = b"".join(struct.pack(">I", x) for x in inner)
    outer_steps, outer = sha_blocks(opad + inner_bytes)
    for name, steps in (("inner", inner_steps), ("outer", outer_steps)):
        for n, (state, block) in enumerate(steps):
            values[f"{name} state {n}"] = state
            values[f"{name} schedule {n}"] = schedule(block)[16:]
            if n < 1:
                values[f"{name} pad block"] = list(struct.unpack("<16I", block)) + list(struct.unpack(">16I", block))
    values["inner digest"] = inner
    derived_be = b"".join(struct.pack(">I", x) for x in outer)
    values["derived key"] = outer + list(struct.unpack("<8I", derived_be))
    return values, derived_be.hex()


def dump():
    """The image's span through both aliases, from one boot."""
    args = ["pimu", "boot", "--scenario", "scenarios/boot-key.yaml"]
    for alias in (0, 0xC0000000):
        args += ["--dump", f"{alias | IMAGE:#x}:{SPAN}"]
    text = subprocess.run(args, capture_output=True, text=True, check=True, env=SHA_ENV).stdout
    spans, current = [], None
    for line in text.splitlines():
        if line.startswith("dump "):
            current = bytearray()
            spans.append(current)
            continue
        m = re.match(r"\s+0x[0-9a-f]+ ([0-9a-f]+)$", line)
        if m and current is not None:
            current += bytes.fromhex(m.group(1))
    return [bytes(s) for s in spans], text


def main():
    words, expected = secrets("out/boot-key.efi")
    needles = {}
    for name, ws in words.items():
        for w in ws:
            if w >= 0x10000 and 4 <= bin(w).count("1") <= 28:
                needles.setdefault(struct.pack("<I", w), name)
    # One word is a 1 in 2**32 coincidence per word of memory, so two words
    # side by side name a leak.
    found = []
    read = 0
    spans, console = dump()
    answer = re.search(r"boot key test: first answer ([0-9a-f]{64})", console)
    if not answer or answer.group(1) != expected:
        print(f"the application did not get the key computed from the rows: {answer and answer.group(1)} != {expected}")
        sys.exit(1)
    for label, data in zip(("cached alias", "uncached alias"), spans):
        read += len(data)
        for off in range(0, len(data) - 8, 4):
            first = needles.get(data[off:off + 4])
            second = needles.get(data[off + 4:off + 8])
            if first and second:
                found.append(f"{label} {IMAGE + off:#x}: {first} / {second}")
    if found:
        print("\n".join(found))
        sys.exit(1)
    print(f"the key is the one the rows make, and none of its material is in {read} bytes of the VPU's memory")


if __name__ == "__main__":
    main()

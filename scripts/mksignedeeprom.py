#!/usr/bin/env python3
"""Make the EEPROM of a board with signed boot: a copy of an EEPROM image with
the customer's public key as `pubkey.bin`, `bootconf.txt` extended by the given
lines, and `bootconf.sig`, the signature over that `bootconf.txt` which the
bootloader of a board with signed boot checks, as
`rpi-eeprom-config --config --pubkey --key` writes it.

    mksignedeeprom.py KEY PIEEPROM OUT [--timestamp TS] [LINE]...

KEY is the customer's private key, PEM. Each LINE is appended to the
configuration (`BOOT_ORDER=0x1`). The OTP rows of such a board come from
pimu's `otp_signed_boot` with the same key's `pubkey.bin`.
"""

import hashlib
import os
import struct
import subprocess
import sys
import tempfile
import time

MAGIC_FILE = 0x55AAF11F
MAGIC_PAD = 0x55AAFEEF
NAME_FIELD = 16


def sections(image):
    at = 0
    while at + 8 <= len(image):
        magic, length = struct.unpack(">II", image[at : at + 8])
        if magic & 0xFFFFF00F != 0x55AAF00F or length >> 24:
            return
        name = image[at + 8 : at + 8 + NAME_FIELD].split(b"\0")[0].decode("latin-1") if magic == MAGIC_FILE else None
        yield at, magic, length, name
        at = (at + length + 0xF) & ~7


def find(image, name):
    for at, magic, length, found in sections(image):
        if found == name:
            return at
    sys.exit(f"{name}: not in the EEPROM image")


def next_section(image, at):
    for other, magic, length, _ in sections(image):
        if other > at and magic != MAGIC_PAD:
            return other
    return len(image)


def replace_file(image, name, data):
    at = find(image, name)
    end = next_section(image, at)
    start = at + 8 + NAME_FIELD
    if start + len(data) > end:
        sys.exit(f"{name}: {len(data)} bytes do not fit the {end - start}-byte slot")
    image[at + 4 : at + 8] = struct.pack(">I", len(data) + NAME_FIELD)
    image[start : start + len(data)] = data
    tail = start + len(data)
    while tail % 8:
        image[tail] = 0xFF
        tail += 1
    if end - tail >= 8:
        image[tail : tail + 8] = struct.pack(">II", MAGIC_PAD, end - tail - 8)
        tail += 8
    image[tail:end] = b"\xff" * (end - tail)


def pubkey_bin(key):
    text = subprocess.run(["openssl", "rsa", "-in", key, "-noout", "-modulus"], check=True, capture_output=True, text=True).stdout
    n = int(text.strip().split("=")[1], 16)
    return n.to_bytes(256, "little") + (65537).to_bytes(8, "little")


def main():
    args = sys.argv[1:]
    stamp = int(os.environ.get("SOURCE_DATE_EPOCH", time.time()))
    if "--timestamp" in args:
        at = args.index("--timestamp")
        stamp = int(args[at + 1])
        del args[at : at + 2]
    if len(args) < 3:
        sys.exit(__doc__)
    key, source, out, *lines = args
    image = bytearray(open(source, "rb").read())

    at = find(image, "bootconf.txt")
    start = at + 8 + NAME_FIELD
    (length,) = struct.unpack(">I", image[at + 4 : at + 8])
    config = bytes(image[start : at + 8 + length]) + "".join(f"{line}\n" for line in lines).encode()
    if next_section(image, at) != len(image):
        sys.exit("bootconf.txt is not the last section")
    image[at + 4 : at + 8] = struct.pack(">I", NAME_FIELD + len(config))
    image[start : start + len(config)] = config

    replace_file(image, "pubkey.bin", pubkey_bin(key))
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "bootconf.txt")
        open(path, "wb").write(config)
        sig = os.path.join(tmp, "sig")
        subprocess.run(["openssl", "dgst", "-sign", key, "-sha256", "-out", sig, path], check=True)
        signature = open(sig, "rb").read().hex()
    text = f"{hashlib.sha256(config).hexdigest()}\nts: {stamp}\nrsa2048: {signature}\n"
    replace_file(image, "bootconf.sig", text.encode())
    open(out, "wb").write(image)


main()

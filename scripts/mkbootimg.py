#!/usr/bin/env python3
"""Put start4.elf in a signed boot.img, as the stock bootloader takes it on a
board with signed boot: a FAT image holding the firmware, and boot.sig with the
image's SHA-256, a timestamp and an RSA-2048 signature over the image, the file
`rpi-eeprom-digest -k KEY -i boot.img -o boot.sig` writes.

    mkbootimg.py KEY START4_ELF OUT_DIR [--prefix boot|tryboot] [--pubkey FILE]

KEY is the customer's private key, PEM. OUT_DIR gets <prefix>.img and
<prefix>.sig (boot by default). --pubkey writes the public key as the
EEPROM's pubkey.bin has it: n, then e, each little-endian, 264 bytes.
"""

import hashlib
import os
import subprocess
import sys
import tempfile
import time


def pubkey_bin(key):
    text = subprocess.run(["openssl", "rsa", "-in", key, "-noout", "-modulus"], check=True, capture_output=True, text=True).stdout
    n = int(text.strip().split("=")[1], 16)
    return n.to_bytes(256, "little") + (65537).to_bytes(8, "little")


def main():
    args = sys.argv[1:]
    prefix = "boot"
    pubkey = None
    for flag in ("--prefix", "--pubkey"):
        if flag in args:
            at = args.index(flag)
            value = args[at + 1]
            del args[at : at + 2]
            if flag == "--prefix":
                prefix = value
            else:
                pubkey = value
    if len(args) != 3:
        sys.exit(__doc__)
    key, start4, out = args
    os.makedirs(out, exist_ok=True)
    image = os.path.join(out, f"{prefix}.img")
    kib = (os.path.getsize(start4) // 1024 + 1024) // 512 * 512
    if os.path.exists(image):
        os.remove(image)
    subprocess.run(["mkfs.vfat", "-C", image, str(max(kib, 4096))], check=True, capture_output=True)
    subprocess.run(["mcopy", "-i", image, start4, "::start4.elf"], check=True)
    data = open(image, "rb").read()
    stamp = int(os.environ.get("SOURCE_DATE_EPOCH", time.time()))
    with tempfile.TemporaryDirectory() as tmp:
        sig = os.path.join(tmp, "sig")
        subprocess.run(["openssl", "dgst", "-sign", key, "-sha256", "-out", sig, image], check=True)
        signature = open(sig, "rb").read().hex()
    open(os.path.join(out, f"{prefix}.sig"), "w").write(f"{hashlib.sha256(data).hexdigest()}\nts: {stamp}\nrsa2048: {signature}\n")
    if pubkey:
        open(pubkey, "wb").write(pubkey_bin(key))


main()

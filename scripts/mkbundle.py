#!/usr/bin/env python3
"""Sign an update bundle: the firmware image linked for the update slot
(out/start4-update.bin), with the version it reports and a signature by the
update key, in the layout src/update.rs describes.

    mkbundle.py KEY IMAGE VERSION OUT

KEY is the update key (PEM, P-256). VERSION is what the image was built with:
a release `X.Y.Z`, or the number `FIRMWARE_TIME` gave it, the commit's time
when it has none. The bundle is what a capsule carries, and what the UEFI
firmware stages in RAM for the next boot.
"""

import struct
import subprocess
import sys

import fwversion

MAGIC = b"P4UB"
FORMAT = 1
SLOT_BASE = 0x3EE00200
MAX_IMAGE = 2 << 20
LABEL = b"pi4-server-firmware update\0"


def der_signature(key, message):
    der = subprocess.run(["openssl", "dgst", "-sha256", "-sign", key], input=message, check=True, capture_output=True).stdout
    assert der[0] == 0x30
    at = 2 if der[1] < 0x80 else 2 + (der[1] & 0x7F)
    numbers = []
    for _ in range(2):
        assert der[at] == 0x02
        length = der[at + 1]
        number = der[at + 2 : at + 2 + length].lstrip(b"\0")
        assert len(number) <= 32
        numbers.append(number.rjust(32, b"\0"))
        at += 2 + length
    return numbers[0] + numbers[1]


def main():
    if len(sys.argv) != 5:
        sys.exit(__doc__)
    key, image_path, out = sys.argv[1], sys.argv[2], sys.argv[4]
    version, release = fwversion.parse(sys.argv[3])
    image = open(image_path, "rb").read()
    if not image or len(image) > MAX_IMAGE:
        sys.exit(f"{image_path}: an image is 1 to {MAX_IMAGE} bytes")
    header = MAGIC + struct.pack("<IIIII", FORMAT, version, SLOT_BASE, len(image), 0) + (release or "").encode().ljust(16, b"\0")
    signature = der_signature(key, LABEL + header + image)
    open(out, "wb").write(header + signature + image)


main()

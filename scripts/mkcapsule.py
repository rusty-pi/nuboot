#!/usr/bin/env python3
"""Build a firmware update capsule, the file fwupd puts in \\EFI\\UpdateCapsule.

    mkcapsule.py KEY CERT VERSION OUT [--image FILE] [--corrupt]

KEY and CERT (PEM) are the signer's: a key one of the firmware's own `db`
entries holds. VERSION is the number the ESRT carries once the capsule is
applied. FILE is the flash region the firmware owns (up to 0x70000 bytes, from
offset 0); without it a short test pattern. --corrupt flips a byte after the
signing.
"""

import os
import struct
import subprocess
import sys
import tempfile
import uuid

FIRMWARE_CLASS = uuid.UUID("7d1c0a4e-5b83-4f2a-9c61-e2084a3d95b7")
CERT_TYPE_PKCS7 = uuid.UUID("4aafd29d-68df-49ee-8aa9-347d375665a7")
HEADER = 28


def main():
    args = sys.argv[1:]
    corrupt = "--corrupt" in args
    args = [a for a in args if a != "--corrupt"]
    region = bytes(range(256)) * 16
    if "--image" in args:
        at = args.index("--image")
        region = open(args[at + 1], "rb").read()
        del args[at : at + 2]
    if len(args) != 4:
        sys.exit(__doc__)
    key, cert, version, out = args
    image = b"P4FW" + struct.pack("<I", int(version, 0)) + region
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "image")
        open(path, "wb").write(image)
        pkcs7 = subprocess.run(
            ["openssl", "smime", "-sign", "-binary", "-md", "sha256", "-in", path, "-signer", cert, "-inkey", key, "-outform", "DER"],
            check=True,
            capture_output=True,
        ).stdout
    descriptor = struct.pack("<IHH", 8 + 16 + len(pkcs7), 0x0200, 0x0EF1) + CERT_TYPE_PKCS7.bytes_le + pkcs7
    if corrupt:
        image = image[:-1] + bytes([image[-1] ^ 1])
    body = descriptor + image
    capsule = FIRMWARE_CLASS.bytes_le + struct.pack("<III", HEADER, 0x00010000, HEADER + len(body)) + body
    open(out, "wb").write(capsule)


main()

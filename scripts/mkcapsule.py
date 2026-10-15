#!/usr/bin/env python3
"""Build a firmware update capsule, the file fwupd puts in \\EFI\\UpdateCapsule.

    mkcapsule.py KEY CERT VERSION OUT [--class firmware|eeprom] [--header-class firmware|eeprom] [--boot-img FILE --boot-sig FILE] [--corrupt]
    mkcapsule.py KEY CERT VERSION OUT --class update --bundle FILE [--corrupt]

An update capsule carries a bundle (scripts/mkbundle.py), which the update key
signs and the board owner does not: VERSION is the one the bundle carries.

KEY and CERT (PEM) are the signer's: a key one of the firmware's own `db`
entries holds. VERSION is the number the ESRT carries once the capsule is
applied: for the EEPROM the time in the pieeprom.sig its boot.img carries.
--class says which resource the capsule is for. --header-class puts the other
resource's class in the capsule header only, which the firmware refuses (the
class is signed). The capsule carries a boot.img and its boot.sig
(scripts/mkbootimg.py); without them a short test pattern with a signature
line of the right shape that no bootloader would accept. --corrupt flips a
byte after the signing.
"""

import hashlib
import os
import struct
import subprocess
import sys
import tempfile
import uuid

CLASSES = {
    "firmware": uuid.UUID("7d1c0a4e-5b83-4f2a-9c61-e2084a3d95b7"),
    "eeprom": uuid.UUID("3f8a0c5e-91d2-4b7a-a6c3-5d1e08f2b947"),
    "update": uuid.UUID("b4c1e7a2-6d39-4f58-8e10-72a9c5d3f0b6"),
}
CERT_TYPE_PKCS7 = uuid.UUID("4aafd29d-68df-49ee-8aa9-347d375665a7")
HEADER = 28


def main():
    args = sys.argv[1:]
    corrupt = "--corrupt" in args
    args = [a for a in args if a != "--corrupt"]
    img = bytes(range(256)) * 16
    sig = None
    resource = "firmware"
    if "--class" in args:
        at = args.index("--class")
        resource = args[at + 1]
        del args[at : at + 2]
    header = None
    if "--header-class" in args:
        at = args.index("--header-class")
        header = args[at + 1]
        del args[at : at + 2]
    bundle = None
    if "--bundle" in args:
        at = args.index("--bundle")
        bundle = open(args[at + 1], "rb").read()
        del args[at : at + 2]
    for flag in ("--boot-img", "--boot-sig"):
        if flag in args:
            at = args.index(flag)
            data = open(args[at + 1], "rb").read()
            del args[at : at + 2]
            if flag == "--boot-img":
                img = data
            else:
                sig = data
    if sig is None:
        sig = f"{hashlib.sha256(img).hexdigest()}\nts: 1\nrsa2048: {'00' * 256}\n".encode()
    if len(args) != 4:
        sys.exit(__doc__)
    key, cert, version, out = args
    if bundle is not None:
        image = b"P4FW" + CLASSES[resource].bytes_le + struct.pack("<I", int(version, 0)) + bundle
    else:
        image = b"P4FW" + CLASSES[resource].bytes_le + struct.pack("<II", int(version, 0), len(sig)) + sig + img
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
    capsule = CLASSES[header or resource].bytes_le + struct.pack("<III", HEADER, 0x00010000, HEADER + len(body)) + body
    open(out, "wb").write(capsule)


main()

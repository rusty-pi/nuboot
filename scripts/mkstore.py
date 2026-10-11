#!/usr/bin/env python3
"""Put a variable store in a copy of an EEPROM image, for the scenarios that
start from what an earlier boot left in it. The device key is the test key
they fuse.

    mkstore.py PIEEPROM OUT [--update pending|proven VERSION [--eeprom]] [--stamp TS] [--backup FILE] [--empty]

By default the store is the tamper scenario's, with known damage in it: what a
board's OS could do to the flash, done to it. It holds, in order: Good and Fresh, signed and in sequence; Forged, whose seal is
wrong; Stale, signed but numbered below what came before it; Torn, whose
digest does not match; and AfterTorn, sealed and in sequence, behind it.

With --update the store holds one sealed record, what the firmware keeps while
a capsule's update is under way: its state, and the version it carries. With
--eeprom the update is the EEPROM's. --stamp puts the time of an EEPROM update in
the flash's last 8 bytes, as the bootloader does, and --backup writes the
store's region of the result to a file, as the firmware copies it before an
EEPROM update. With --empty the store holds nothing.
"""

import hashlib
import struct
import sys
import uuid

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature

BASE = 0x74000
BANK = 0x5000
BANK_MAGIC = 0x56344950
RECORD_MAGIC = 0x52454331
SET = 1
ATTRIBUTES = 0x1 | 0x2 | 0x4
GUID = uuid.UUID("5d0f3a58-1c0e-4d1b-9a44-0123456789ab").bytes_le
ROWS = [0xC0DE2001, 0xC0DE3112, 0xC0DE4223, 0xC0DE5334, 0xC0DE6445, 0xC0DE7556, 0xC0DE8667, 0xC0DE9778]
LABEL = b"pi4-server-firmware variable store record v2"


def device_key():
    private = b"".join(struct.pack("<I", r) for r in ROWS)
    return ec.derive_private_key(int.from_bytes(private, "big"), ec.SECP256R1())


def sign(digest):
    r, s = decode_dss_signature(device_key().sign(digest, ec.ECDSA(Prehashed(hashes.SHA256()))))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def record(name, data, seq, seal=True, torn=False, guid=GUID, attributes=ATTRIBUTES):
    time = struct.pack("<Q", seq) + bytes(8)
    utf16 = name.encode("utf-16-le")
    signed = LABEL + struct.pack("<II", SET, attributes) + guid + time + utf16 + data
    mac = sign(hashlib.sha256(signed).digest()) if seal else bytes(64)
    body_len = 60 + len(utf16) + len(data) + len(mac)
    padded = -(-body_len // 4) * 4
    total = padded + 32
    out = struct.pack("<IIII", RECORD_MAGIC, total, SET, attributes) + guid + time
    out += struct.pack("<III", len(name), len(data), len(mac)) + utf16 + data + mac
    out += bytes(padded - len(out))
    digest = hashlib.sha256(out).digest()
    if torn:
        digest = bytes([digest[0] ^ 1]) + digest[1:]
    return out + digest


FIRMWARE_CLASS = uuid.UUID("7d1c0a4e-5b83-4f2a-9c61-e2084a3d95b7").bytes_le
STATES = {"pending": 1, "proven": 2}


def main():
    args = sys.argv[1:]
    update = None
    eeprom = "--eeprom" in args
    empty = "--empty" in args
    args = [a for a in args if a not in ("--eeprom", "--empty")]
    stamp = backup = None
    if "--stamp" in args:
        at = args.index("--stamp")
        stamp = int(args[at + 1], 0)
        del args[at : at + 2]
    if "--backup" in args:
        at = args.index("--backup")
        backup = args[at + 1]
        del args[at : at + 2]
    if "--update" in args:
        at = args.index("--update")
        update = (STATES[args[at + 1]], int(args[at + 2], 0))
        del args[at : at + 3]
    if len(args) != 2:
        sys.exit(__doc__)
    image = bytearray(open(args[0], "rb").read())
    if empty:
        records = []
    elif update:
        data = bytes([update[0], int(eeprom)]) + struct.pack("<I", update[1])
        records = [record("FwUpdate", data, 0, guid=FIRMWARE_CLASS, attributes=0x1 | 0x2)]
    else:
        records = [
            record("Good", b"good", 0),
            record("Fresh", b"fresh", 1),
            record("Forged", b"forged", 2, seal=False),
            record("Stale", b"stale", 0),
            record("Torn", b"torn", 3, torn=True),
            record("AfterTorn", b"after", 4),
        ]
    log = b"".join(records)
    head = struct.pack("<II", BANK_MAGIC, 1)
    if any(b != 0xFF for b in image[BASE : BASE + len(head) + len(log)]):
        sys.exit("the image's variable store is not empty")
    if records:
        image[BASE : BASE + len(head)] = head
        image[BASE + 8 : BASE + 8 + len(log)] = log
    if stamp is not None:
        image[-8:] = struct.pack("<II", ~stamp & 0xFFFFFFFF, stamp)
    if backup:
        open(backup, "wb").write(image[BASE : BASE + 2 * BANK])
    open(args[1], "wb").write(image)


main()

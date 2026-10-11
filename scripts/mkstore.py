#!/usr/bin/env python3
"""Put a variable store in a copy of an EEPROM image, for the scenarios that
start from what an earlier boot left in it. The device key is the test key
they fuse.

    mkstore.py PIEEPROM OUT [--update pending|proven VERSION]

By default the store is the tamper scenario's, with known damage in it: what a
board's OS could do to the flash, done to it. It holds, in order: Good and Fresh, sealed and in sequence; Forged, whose seal is
wrong; Stale, sealed but numbered below what came before it; Torn, whose
digest does not match; and AfterTorn, sealed and in sequence, behind it.

With --update the store holds one sealed record, what the firmware keeps while
a capsule's update is under way: its state, and the version it carries.
"""

import hashlib
import hmac
import struct
import sys
import uuid

BASE = 0x74000
BANK = 0x5000
BANK_MAGIC = 0x56344950
RECORD_MAGIC = 0x52454331
SET = 1
ATTRIBUTES = 0x1 | 0x2 | 0x4
GUID = uuid.UUID("5d0f3a58-1c0e-4d1b-9a44-0123456789ab").bytes_le
ROWS = [0xC0DE2001, 0xC0DE3112, 0xC0DE4223, 0xC0DE5334, 0xC0DE6445, 0xC0DE7556, 0xC0DE8667, 0xC0DE9778]
LABEL = b"pi4-server-firmware variable store key v1"


def store_key():
    private = b"".join(struct.pack("<I", r) for r in ROWS)
    return hmac.new(private, LABEL, hashlib.sha256).digest()


def record(name, data, seq, seal=True, torn=False, guid=GUID, attributes=ATTRIBUTES):
    time = struct.pack("<Q", seq) + bytes(8)
    utf16 = name.encode("utf-16-le")
    signed = struct.pack("<II", SET, attributes) + guid + time + utf16 + data
    mac = hmac.new(store_key(), signed, hashlib.sha256).digest() if seal else bytes(32)
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
    if "--update" in args:
        at = args.index("--update")
        update = (STATES[args[at + 1]], int(args[at + 2], 0))
        del args[at : at + 3]
    if len(args) != 2:
        sys.exit(__doc__)
    image = bytearray(open(args[0], "rb").read())
    if update:
        data = bytes([update[0]]) + struct.pack("<I", update[1])
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
    image[BASE : BASE + len(head)] = head
    image[BASE + 8 : BASE + 8 + len(log)] = log
    open(args[1], "wb").write(image)


main()

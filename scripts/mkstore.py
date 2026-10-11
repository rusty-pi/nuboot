#!/usr/bin/env python3
"""Put a variable store with known damage into a copy of an EEPROM image, for
the tamper scenario: what a board's OS could do to the flash, done to it.

    mkstore.py PIEEPROM OUT

The device key is the test key scenarios/store-tamper.yaml fuses. The store
holds, in order: Good and Fresh, sealed and in sequence; Forged, whose seal is
wrong; Stale, sealed but numbered below what came before it; Torn, whose
digest does not match; and AfterTorn, sealed and in sequence, behind it.
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


def record(name, data, seq, seal=True, torn=False):
    time = struct.pack("<Q", seq) + bytes(8)
    utf16 = name.encode("utf-16-le")
    signed = struct.pack("<II", SET, ATTRIBUTES) + GUID + time + utf16 + data
    mac = hmac.new(store_key(), signed, hashlib.sha256).digest() if seal else bytes(32)
    body_len = 60 + len(utf16) + len(data) + len(mac)
    padded = -(-body_len // 4) * 4
    total = padded + 32
    out = struct.pack("<IIII", RECORD_MAGIC, total, SET, ATTRIBUTES) + GUID + time
    out += struct.pack("<III", len(name), len(data), len(mac)) + utf16 + data + mac
    out += bytes(padded - len(out))
    digest = hashlib.sha256(out).digest()
    if torn:
        digest = bytes([digest[0] ^ 1]) + digest[1:]
    return out + digest


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    image = bytearray(open(sys.argv[1], "rb").read())
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
    open(sys.argv[2], "wb").write(image)


main()

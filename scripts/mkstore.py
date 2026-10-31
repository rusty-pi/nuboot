#!/usr/bin/env python3
"""Make the variable store's window, for the scenarios that start from what an
earlier boot left in it. The device key is the test key they fuse, and a
record is sealed with an HMAC-SHA256 of its digest by it.

    mkstore.py OUT [--update pending|proven VERSION [--eeprom]] [--empty]

By default the store is the tamper scenario's, with known damage in it: what a
board's OS could do to the disk, done to it. It holds, in order: Good and Fresh, sealed and in sequence; Forged, whose seal is
wrong; Stale, sealed but numbered below what came before it; Torn, whose
digest does not match; and AfterTorn, sealed and in sequence, behind it. Then what the OS had the VPU
seal: a hidden variable's deletion, a variable of its own, SecureBoot's deletion and a record under the
firmware's own class, FwUpdateResult.

With --update the store holds one sealed record, what the firmware keeps while
a capsule's update is under way: its state, and the version it carries. With
--eeprom the update is the EEPROM's. With --empty the store holds nothing.

OUT is the window as it is on the disk, 512 KiB: two banks of 256 KiB, the
first holding the records. scripts/mkcard.py puts it on a card.
"""

import hashlib
import hmac
import struct
import sys
import uuid

BANK = 0x40000
BANK_MAGIC = 0x56344950
RECORD_MAGIC = 0x52454331
SET = 1
ATTRIBUTES = 0x1 | 0x2 | 0x4
GUID = uuid.UUID("5d0f3a58-1c0e-4d1b-9a44-0123456789ab").bytes_le
ROWS = [0xC0DE2001, 0xC0DE3112, 0xC0DE4223, 0xC0DE5334, 0xC0DE6445, 0xC0DE7556, 0xC0DE8667, 0xC0DE9778]
LABEL = b"nuboot variable store record v4"
RUNTIME_LABEL = b"nuboot runtime variable record v2"
DELETE = 2
GLOBAL = uuid.UUID("8be4df61-93ca-11d2-aa0d-00e098032b8c").bytes_le


def seal_of(digest):
    private = b"".join(struct.pack("<I", r) for r in ROWS)
    return hmac.new(private, digest, hashlib.sha256).digest()


def record(name, data, seq, seal=True, torn=False, guid=GUID, attributes=ATTRIBUTES, kind=SET, label=LABEL):
    time = struct.pack("<Q", seq) + bytes(8)
    utf16 = name.encode("utf-16-le")
    signed = label + struct.pack("<II", kind, attributes) + guid + time + struct.pack("<II", len(name), len(data)) + utf16 + data
    mac = seal_of(hashlib.sha256(signed).digest()) if seal else bytes(32)
    body_len = 60 + len(utf16) + len(data) + len(mac)
    padded = -(-body_len // 4) * 4
    total = padded + 32
    out = struct.pack("<IIII", RECORD_MAGIC, total, kind, attributes) + guid + time
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
    if "--update" in args:
        at = args.index("--update")
        update = (STATES[args[at + 1]], int(args[at + 2], 0))
        del args[at : at + 3]
    if len(args) != 1:
        sys.exit(__doc__)
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
            # What the OS had the VPU seal: a variable of its own is read, and
            # the deletion of a hidden one, of a firmware one and a record of
            # the firmware's own are not.
            record("Hidden", b"hidden", 5, attributes=0x1 | 0x2),
            record("Hidden", b"", 6, attributes=ATTRIBUTES, kind=DELETE, label=RUNTIME_LABEL),
            record("RuntimeOk", b"ok", 7, attributes=ATTRIBUTES, label=RUNTIME_LABEL),
            record("SecureBoot", b"", 8, guid=GLOBAL, attributes=ATTRIBUTES, kind=DELETE, label=RUNTIME_LABEL),
            record("FwUpdateResult", struct.pack("<II", 1, 0), 9, guid=FIRMWARE_CLASS, attributes=ATTRIBUTES, label=RUNTIME_LABEL),
        ]
    window = bytearray(b"\xff" * (2 * BANK))
    if records:
        log = b"".join(records)
        window[:8] = struct.pack("<II", BANK_MAGIC, 1)
        window[8 : 8 + len(log)] = log
    open(args[0], "wb").write(window)


main()

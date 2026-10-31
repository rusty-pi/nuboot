#!/usr/bin/env python3
"""Make a GPT card image for a scenario: a boot partition from LBA 2048 with
the files, and, when there is a variable store to start from, the store's
window listed as a partition of its own, as the firmware lists it.

    mkcard.py OUT [--store STORE] NAME=FILE...

Each NAME=FILE puts FILE on the boot partition as NAME (a `/` in it makes a
directory). STORE is a window scripts/mkstore.py made. Without it the window
is blank and unlisted, and the firmware lists it at the first boot, moving the
first usable block of the GPT down to it, since this makes the table the way
`sfdisk` does, with the first usable block at 2048.
"""

import os
import struct
import subprocess
import sys
import tempfile
import uuid
import zlib

SECTOR = 512
ENTRIES = 128
ENTRY_SIZE = 128
TABLE_SECTORS = ENTRIES * ENTRY_SIZE // SECTOR
WINDOW_FIRST = 512 * 1024 // SECTOR
WINDOW_SECTORS = 512 * 1024 // SECTOR
BOOT_FIRST = 2048
# The type the Raspberry Pi bootloader boots a GPT disk from: "Microsoft basic
# data", not the EFI system partition.
BOOT_TYPE = uuid.UUID("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7").bytes_le
STORE = bytes.fromhex("c0cda90c286ca649a041eeec6123df3a")


def entry(kind, first, last, name, attributes=0):
    unique = uuid.uuid4().bytes_le
    label = name.encode("utf-16-le")
    return (kind + unique + struct.pack("<QQQ", first, last, attributes) + label).ljust(ENTRY_SIZE, b"\0")


def header(this, other, table_lba, first_usable, last_usable, disk_guid, table):
    h = bytearray(SECTOR)
    h[0:8] = b"EFI PART"
    h[8:12] = struct.pack("<I", 0x00010000)
    h[12:16] = struct.pack("<I", 92)
    h[24:48] = struct.pack("<QQQ", this, other, first_usable)
    h[48:56] = struct.pack("<Q", last_usable)
    h[56:72] = disk_guid
    h[72:80] = struct.pack("<Q", table_lba)
    h[80:88] = struct.pack("<II", ENTRIES, ENTRY_SIZE)
    h[88:92] = struct.pack("<I", zlib.crc32(table))
    h[16:20] = struct.pack("<I", zlib.crc32(bytes(h[:92])))
    return bytes(h)


def fat_image(files, directory):
    kib = max(16 * 1024, (sum(os.path.getsize(path) for _, path in files) * 115 // 100 // 1024 + 4096) // 512 * 512)
    boot = os.path.join(directory, "boot.img")
    subprocess.run(["mkfs.vfat", "-C", boot, str(kib)], check=True, capture_output=True)
    for name, path in files:
        parts = name.split("/")[:-1]
        for n in range(1, len(parts) + 1):
            subprocess.run(["mmd", "-i", boot, "::" + "/".join(parts[:n])], capture_output=True)
        subprocess.run(["mcopy", "-i", boot, path, "::" + name], check=True)
    return boot


def main():
    args = sys.argv[1:]
    store = None
    if "--store" in args:
        at = args.index("--store")
        store = open(args[at + 1], "rb").read()
        del args[at : at + 2]
        if len(store) != WINDOW_SECTORS * SECTOR:
            sys.exit("the store is not a window of 512 KiB")
    if len(args) < 2:
        sys.exit(__doc__)
    out = args[0]
    files = [tuple(item.split("=", 1)) for item in args[1:]]
    with tempfile.TemporaryDirectory() as tmp:
        boot = fat_image(files, tmp)
        fat = open(boot, "rb").read()

    boot_sectors = len(fat) // SECTOR
    total = BOOT_FIRST + boot_sectors + TABLE_SECTORS + 2048
    first_usable = WINDOW_FIRST if store else BOOT_FIRST
    last_usable = total - 1 - TABLE_SECTORS - 1
    table = bytearray(ENTRIES * ENTRY_SIZE)
    table[0:ENTRY_SIZE] = entry(BOOT_TYPE, BOOT_FIRST, BOOT_FIRST + boot_sectors - 1, "boot")
    if store:
        table[ENTRY_SIZE : 2 * ENTRY_SIZE] = entry(STORE, WINDOW_FIRST, WINDOW_FIRST + WINDOW_SECTORS - 1, "nuboot store")
    table = bytes(table)
    disk_guid = uuid.uuid4().bytes_le

    mbr = bytearray(SECTOR)
    mbr[446 + 4] = 0xEE
    mbr[446 + 1 : 446 + 4] = bytes([0x00, 0x02, 0x00])
    mbr[446 + 5 : 446 + 8] = bytes([0xFF, 0xFF, 0xFF])
    mbr[446 + 8 : 446 + 16] = struct.pack("<II", 1, min(total - 1, 0xFFFFFFFF))
    mbr[510:512] = b"\x55\xaa"

    with open(out, "wb") as f:
        f.truncate(total * SECTOR)
        f.write(mbr)
        f.seek(SECTOR)
        f.write(header(1, total - 1, 2, first_usable, last_usable, disk_guid, table))
        f.write(table)
        if store:
            f.seek(WINDOW_FIRST * SECTOR)
            f.write(store)
        f.seek(BOOT_FIRST * SECTOR)
        f.write(fat)
        f.seek((total - 1 - TABLE_SECTORS) * SECTOR)
        f.write(table)
        f.write(header(total - 1, 1, total - 1 - TABLE_SECTORS, first_usable, last_usable, disk_guid, table))


main()

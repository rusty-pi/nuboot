#!/usr/bin/env python3
"""Build pieeprom.bin from this tree's first stage and start4.elf, and the
SDRAM training firmware (memsys00..08.bin, mcb.bin) and the VL805's firmware
(vl805hub.bin, vl805mcu.bin) out of a stock image.

    mkeeprom.py BOOTCODE START4_ELF STOCK_PIEEPROM OUT

BOOTCODE is the first stage as a flat binary from 0x80000000. Its HMAC is
left zero: a board's boot ROM refuses it until it is signed with the board's
key, which this script does not do.
"""

import struct
import sys

SIZE = 512 * 1024
STORE = 0x62000
MAGIC_BOOTCODE = 0x55AAF00F
MAGIC_FILE = 0x55AAF11F
MAGIC_MASK = 0xFFFFF00F
HMAC_LEN = 20
FROM_STOCK = [f"memsys{i:02d}.bin".encode() for i in range(9)] + [b"mcb.bin", b"vl805hub.bin", b"vl805mcu.bin"]
PT_LOAD = 1


def sections(image):
    """(name, raw section bytes with its header) for each section in a stock image."""
    off = 0
    while off + 8 <= len(image):
        magic, length = struct.unpack_from(">II", image, off)
        if magic & MAGIC_MASK != MAGIC_BOOTCODE:
            return
        name = image[off + 8:off + 24].split(b"\0")[0] if magic != MAGIC_BOOTCODE else b""
        yield name, image[off:off + 8 + length]
        off = (off + length + 0xF) & ~7


def strip_elf(elf):
    """The ELF up to the end of its loadable data, without section headers."""
    if elf[:6] != b"\x7fELF\x01\x01":
        sys.exit("start4.elf is not a 32-bit little-endian ELF")
    phoff, = struct.unpack_from("<I", elf, 28)
    phentsize, phnum = struct.unpack_from("<HH", elf, 42)
    end = phoff + phentsize * phnum
    for i in range(phnum):
        p_type, p_offset, _, _, p_filesz = struct.unpack_from("<5I", elf, phoff + i * phentsize)
        if p_type == PT_LOAD:
            end = max(end, p_offset + p_filesz)
    out = bytearray(elf[:end])
    struct.pack_into("<I", out, 32, 0)  # e_shoff
    struct.pack_into("<HHH", out, 46, 0, 0, 0)  # e_shentsize, e_shnum, e_shstrndx
    return bytes(out)


def file_section(name, data):
    return struct.pack(">II", MAGIC_FILE, 16 + len(data)) + name.ljust(16, b"\0") + data


def main():
    if len(sys.argv) != 5:
        sys.exit(__doc__)
    bootcode_path, elf_path, stock_path, out_path = sys.argv[1:]
    bootcode = open(bootcode_path, "rb").read()
    elf = open(elf_path, "rb").read()
    stock = dict(sections(open(stock_path, "rb").read()))

    parts = [struct.pack(">II", MAGIC_BOOTCODE, len(bootcode) + HMAC_LEN) + bootcode + bytes(HMAC_LEN)]
    for name in FROM_STOCK:
        if name not in stock:
            sys.exit(f"{stock_path} has no {name.decode()}")
        parts.append(stock[name])
    parts.append(file_section(b"start4.elf", strip_elf(elf)))

    image = bytearray()
    for part in parts:
        image += part
        image += b"\xff" * (-len(image) % 8)
    if len(image) > SIZE:
        sys.exit(f"the image is {len(image)} bytes, {len(image) - SIZE} over the EEPROM's {SIZE}")
    if len(image) > STORE:
        sys.exit(f"the image is {len(image)} bytes, {len(image) - STORE} into the variable store at {STORE:#x}")
    free = SIZE - len(image)
    image += b"\xff" * free
    open(out_path, "wb").write(image)
    print(f"{out_path}: {SIZE - free} bytes used, {STORE - (SIZE - free)} free below the variable store")


main()

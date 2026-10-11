#!/usr/bin/env python3
"""Build pieeprom.bin from this tree's first stage and start4.elf, and the
SDRAM training firmware (memsys00..08.bin, mcb.bin) and the VL805's firmware
(vl805hub.bin, vl805mcu.bin) out of a stock image.

    mkeeprom.py BOOTCODE START4_ELF STOCK_PIEEPROM OUT

BOOTCODE is the first stage as a flat binary from 0x80000000. Its HMAC is
left zero: a board's boot ROM refuses it until it is signed with the board's
key, which this script does not do.
"""

import hashlib
import struct
import sys

SIZE = 512 * 1024
STORE = 0x70000
MAGIC_BOOTCODE = 0x55AAF00F
MAGIC_FILE = 0x55AAF11F
MAGIC_PACKED_B = 0x55AAF44F
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


def xxh32(data):
    """xxHash32 with seed 0, which an LZ4 frame's header checksum is."""
    p1, p2, p3, p4, p5 = 2654435761, 2246822519, 3266489917, 668265263, 374761393
    mask = 0xFFFFFFFF
    rotl = lambda x, r: ((x << r) | (x >> (32 - r))) & mask
    n = len(data)
    at = 0
    if n >= 16:
        v = [(p1 + p2) & mask, p2, 0, (-p1) & mask]
        while at <= n - 16:
            for i in range(4):
                (lane,) = struct.unpack_from("<I", data, at + 4 * i)
                v[i] = (rotl((v[i] + lane * p2) & mask, 13) * p1) & mask
            at += 16
        h = (rotl(v[0], 1) + rotl(v[1], 7) + rotl(v[2], 12) + rotl(v[3], 18)) & mask
    else:
        h = p5
    h = (h + n) & mask
    while at + 4 <= n:
        (lane,) = struct.unpack_from("<I", data, at)
        h = (rotl((h + lane * p3) & mask, 17) * p4) & mask
        at += 4
    while at < n:
        h = (rotl((h + data[at] * p5) & mask, 11) * p1) & mask
        at += 1
    h ^= h >> 15
    h = (h * p2) & mask
    h ^= h >> 13
    h = (h * p3) & mask
    h ^= h >> 16
    return h


def lz4_block(src):
    """One LZ4 block, greedy: matches of four bytes or more, within 64 KiB."""
    n = len(src)
    out = bytearray()
    table = {}
    anchor = 0
    i = 0

    def length(nibble_value, extra):
        if extra >= 15:
            rest = extra - 15
            return bytes([255] * (rest // 255) + [rest % 255])
        return b""

    while i + 12 < n:
        key = src[i : i + 4]
        cand = table.get(key)
        table[key] = i
        if cand is not None and i - cand <= 0xFFFF:
            m = 4
            while i + m < n - 5 and src[cand + m] == src[i + m]:
                m += 1
            literals = i - anchor
            out.append(min(literals, 15) << 4 | min(m - 4, 15))
            out += length(0, literals)
            out += src[anchor:i]
            out += struct.pack("<H", i - cand)
            out += length(0, m - 4)
            i += m
            anchor = i
        else:
            i += 1
    literals = n - anchor
    out.append(min(literals, 15) << 4)
    out += length(0, literals)
    out += src[anchor:]
    return bytes(out)


def lz4_frame(data, block_size=64 * 1024):
    """An LZ4 frame of independent blocks, as the bootcode's decoder reads."""
    descriptor = bytes([0x60, 0x40])  # version 1, independent blocks; 64 KiB blocks
    frame = bytearray(struct.pack("<I", 0x184D2204) + descriptor + bytes([(xxh32(descriptor) >> 8) & 0xFF]))
    for at in range(0, len(data), block_size):
        raw = data[at : at + block_size]
        packed = lz4_block(raw)
        if len(packed) < len(raw):
            frame += struct.pack("<I", len(packed)) + packed
        else:
            frame += struct.pack("<I", 0x80000000 | len(raw)) + raw
    frame += struct.pack("<I", 0)
    return bytes(frame)


def lz4_unframe(frame):
    """The data of an LZ4 frame, for checking one: written from the format's
    description, not from the bootcode's decoder."""
    assert struct.unpack_from("<I", frame, 0)[0] == 0x184D2204
    flg = frame[4]
    assert flg >> 6 == 1 and not flg & 0b00011101, "only the frames lz4_frame makes"
    at = 7
    out = bytearray()
    while True:
        (size,) = struct.unpack_from("<I", frame, at)
        at += 4
        if size == 0:
            return bytes(out)
        length = size & 0x7FFFFFFF
        block = frame[at : at + length]
        at += length
        if size & 0x80000000:
            out += block
            continue
        base = len(out)
        j = 0
        while j < len(block):
            token = block[j]
            j += 1
            literals = token >> 4
            if literals == 15:
                while True:
                    literals += block[j]
                    j += 1
                    if block[j - 1] != 255:
                        break
            out += block[j : j + literals]
            j += literals
            if j >= len(block):
                break
            (offset,) = struct.unpack_from("<H", block, j)
            j += 2
            match = (token & 15) + 4
            if token & 15 == 15:
                while True:
                    match += block[j]
                    j += 1
                    if block[j - 1] != 255:
                        break
            for _ in range(match):
                out.append(out[-offset])
        assert len(out) - base <= 64 * 1024


def packed_section(name, data):
    """A section the bootcode unpacks: the name, an LZ4 frame, and the SHA-256
    of the data."""
    frame = lz4_frame(data)
    assert lz4_unframe(frame) == data, "the LZ4 frame does not unpack to its data"
    body = name.ljust(16, b"\0") + frame + hashlib.sha256(data).digest()
    return struct.pack(">II", MAGIC_PACKED_B, len(body)) + body


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
    parts.append(packed_section(b"start4.elf", strip_elf(elf)))

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

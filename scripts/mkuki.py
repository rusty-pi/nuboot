#!/usr/bin/env python3
"""Put sections on a systemd-stub: a unified kernel image, without ukify.

    mkuki.py STUB OUT [--section NAME=FILE ...]

Each section goes after the last one the stub has, in the order given, as
initialised read-only data. The kernel the stub starts is `.linux`; any PE
image will do for a test.
"""

import struct
import sys


def align(n, to):
    return (n + to - 1) // to * to


def main():
    args = sys.argv[1:]
    stub, out = args[0], args[1]
    sections = []
    it = iter(args[2:])
    for flag in it:
        if flag != "--section":
            sys.exit(f"unknown option {flag}")
        name, _, path = next(it).partition("=")
        sections.append((name, open(path, "rb").read()))

    pe = bytearray(open(stub, "rb").read())
    (peoff,) = struct.unpack_from("<I", pe, 0x3C)
    coff = peoff + 4
    (count,) = struct.unpack_from("<H", pe, coff + 2)
    (opt_size,) = struct.unpack_from("<H", pe, coff + 16)
    opt = coff + 20
    section_alignment, file_alignment = struct.unpack_from("<II", pe, opt + 32)
    headers_size = struct.unpack_from("<I", pe, opt + 60)[0]
    table = opt + opt_size
    last_end = 0
    for i in range(count):
        va, size, raw = struct.unpack_from("<III", pe, table + 40 * i + 8)
        vsize = struct.unpack_from("<I", pe, table + 40 * i + 8)[0]
        va = struct.unpack_from("<I", pe, table + 40 * i + 12)[0]
        last_end = max(last_end, va + align(vsize, section_alignment))
    if table + 40 * (count + len(sections)) > headers_size:
        sys.exit("no room in the headers for more sections")
    for name, data in sections:
        pad = align(len(pe), file_alignment) - len(pe)
        pe += bytes(pad)
        raw = len(pe)
        pe += data + bytes(align(len(data), file_alignment) - len(data))
        header = name.encode().ljust(8, b"\0") + struct.pack(
            "<IIIIIIHHI", len(data), last_end, align(len(data), file_alignment), raw, 0, 0, 0, 0, 0x4000_0040
        )
        pe[table + 40 * count:table + 40 * count + 40] = header
        count += 1
        last_end += align(len(data), section_alignment)
    struct.pack_into("<H", pe, coff + 2, count)
    struct.pack_into("<I", pe, opt + 56, last_end)
    open(out, "wb").write(pe)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Write an initramfs, a gzip-compressed `newc` cpio archive, out of a
directory, with the `/dev/console` and `/dev/null` nodes a kernel needs to open
its first console, which an unprivileged user cannot `mknod`.

    mkinitramfs.py DIR OUT
"""

import gzip
import os
import stat
import sys


def entry(name, mode, data=b"", nlink=1, rdev=(0, 0), ino=[0]):
    ino[0] += 1
    name = name.encode() + b"\0"
    header = "070701" + "".join(
        f"{v:08x}" for v in (ino[0], mode, 0, 0, nlink, 0, len(data), 0, 0, rdev[0], rdev[1], len(name), 0)
    )
    out = header.encode() + name
    out += b"\0" * (-len(out) % 4)
    out += data
    out += b"\0" * (-len(data) % 4)
    return out


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    root, out = sys.argv[1:]
    archive = b""
    for here, dirs, files in os.walk(root):
        dirs.sort()
        rel = os.path.relpath(here, root)
        if rel != ".":
            archive += entry(rel, stat.S_IFDIR | 0o755, nlink=2)
        for name in sorted(files):
            path = os.path.join(here, name)
            name = os.path.normpath(os.path.join(rel, name))
            if os.path.islink(path):
                archive += entry(name, stat.S_IFLNK | 0o777, os.readlink(path).encode())
            else:
                mode = stat.S_IFREG | (0o755 if os.access(path, os.X_OK) else 0o644)
                archive += entry(name, mode, open(path, "rb").read())
    archive += entry("dev", stat.S_IFDIR | 0o755, nlink=2)
    archive += entry("dev/console", stat.S_IFCHR | 0o600, rdev=(5, 1))
    archive += entry("dev/null", stat.S_IFCHR | 0o666, rdev=(1, 3))
    archive += entry("TRAILER!!!", 0)
    open(out, "wb").write(gzip.compress(archive, 9, mtime=0))


main()

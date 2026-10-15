"""The firmware's version number, as the scripts that make an update read it.

A release is `X.Y.Z`, the release tag, and its number is `X<<24 | Y<<16 | Z`:
the order of two releases is the order of their numbers, and fwupd shows the
number as `X.Y.Z` in its `triplet` format. A build that is no release has the
number it is given, or the commit's time, which no release is above.
"""

import re

RELEASE = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")


def pack(release):
    major, minor, patch = (int(part) for part in release.split("."))
    if major > 0xFF or minor > 0xFF or patch > 0xFFFF:
        raise ValueError(f"{release}: a release is at most 255.255.65535")
    return major << 24 | minor << 16 | patch


def parse(text):
    """The number and the release text, or None for a build with no release,
    that `text` names: `X.Y.Z`, or a number."""
    if RELEASE.fullmatch(text):
        return pack(text), text
    return int(text, 0), None

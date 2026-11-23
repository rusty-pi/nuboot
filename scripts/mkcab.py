#!/usr/bin/env python3
"""Put a firmware update capsule in the cabinet fwupd installs, with the
metadata that says which device it is for.

    mkcab.py CAPSULE OUT.cab VERSION [--class firmware|eeprom|update] [--date YYYY-MM-DD] [--notes TEXT]
        [--sign CERT KEY]

CAPSULE is what scripts/mkcapsule.py wrote and VERSION what it carries, a
release `X.Y.Z` or a number, which the ESRT reports once the update is applied. `fwupdmgr install OUT.cab`
installs it, and `fwupdtool get-details OUT.cab` shows what fwupd makes of it.
Needs `gcab`. `--sign` adds the `firmware.jcat` that fwupd checks against the certificates in
`/etc/pki/fwupd` (a signature and the SHA-256 and SHA-512 checksums of both files), which needs `jcat-tool`.
"""

import datetime
import hashlib
import os
import subprocess
import sys
import tempfile
from xml.sax.saxutils import escape

import fwversion

RESOURCES = {
    "firmware": (
        "org.rusty-pi.nuboot.firmware",
        "nuboot",
        "The UEFI firmware for headless Raspberry Pi 4 servers, in start4.elf",
        "7d1c0a4e-5b83-4f2a-9c61-e2084a3d95b7",
    ),
    "eeprom": (
        "org.rusty-pi.nuboot.eeprom",
        "Raspberry Pi 4 EEPROM bootloader",
        "The stock EEPROM bootloader, updated with its configuration and keys kept",
        "3f8a0c5e-91d2-4b7a-a6c3-5d1e08f2b947",
    ),
    "update": (
        "org.rusty-pi.nuboot.update",
        "nuboot",
        "The VPU and UEFI firmware for headless Raspberry Pi 4 servers, signed by the update key",
        "b4c1e7a2-6d39-4f58-8e10-72a9c5d3f0b6",
    ),
}


def metainfo(resource, version, date, notes, release):
    component, name, summary, guid = RESOURCES[resource]
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<component type="firmware">
  <id>{component}</id>
  <name>{escape(name)}</name>
  <summary>{escape(summary)}</summary>
  <description>
    <p>{escape(summary)}.</p>
  </description>
  <provides>
    <firmware type="flashed">{guid}</firmware>
  </provides>
  <url type="homepage">https://github.com/rusty-pi/nuboot</url>
  <metadata_license>CC0-1.0</metadata_license>
  <project_license>MIT</project_license>
  <developer_name>rusty-pi</developer_name>
  <releases>
    <release version="{release or version}" date="{date}">
      <description>
        <p>{escape(notes)}</p>
      </description>
    </release>
  </releases>
  <custom>
    <value key="LVFS::UpdateProtocol">org.uefi.capsule</value>
    <value key="LVFS::VersionFormat">{"triplet" if release else "number"}</value>
  </custom>
</component>
"""


def jcat(tmp, names, cert, key):
    catalog = os.path.join(tmp, "firmware.jcat")
    for name in names:
        subprocess.run(["jcat-tool", "sign", catalog, name, cert, key], cwd=tmp, check=True)
        for algorithm in ("sha256", "sha512"):
            digest = hashlib.new(algorithm, open(os.path.join(tmp, name), "rb").read()).hexdigest()
            checksum = os.path.join(tmp, f"{name}.{algorithm}")
            open(checksum, "w").write(digest)
            subprocess.run(["jcat-tool", "--kind", algorithm, "import", catalog, name, checksum], cwd=tmp, check=True)
            os.remove(checksum)
    return "firmware.jcat"


def main():
    args = sys.argv[1:]
    signer = None
    if "--sign" in args:
        at = args.index("--sign")
        signer = [os.path.abspath(path) for path in args[at + 1 : at + 3]]
        del args[at : at + 3]
    options = {"--class": "firmware", "--date": None, "--notes": None}
    for flag in options:
        if flag in args:
            at = args.index(flag)
            options[flag] = args[at + 1]
            del args[at : at + 2]
    if len(args) != 3 or options["--class"] not in RESOURCES:
        sys.exit(__doc__)
    capsule, out, version = args
    number, release = fwversion.parse(version)
    resource = options["--class"]
    today = datetime.datetime.now(datetime.timezone.utc)
    date = options["--date"] or (today if release else datetime.datetime.fromtimestamp(number, datetime.timezone.utc)).strftime("%Y-%m-%d")
    notes = options["--notes"] or f"Version {release or number}."
    stamp = datetime.datetime.fromisoformat(date).replace(tzinfo=datetime.timezone.utc).timestamp()
    with tempfile.TemporaryDirectory() as tmp:
        files = {"firmware.bin": open(capsule, "rb").read(), "firmware.metainfo.xml": metainfo(resource, number, date, notes, release).encode()}
        for name, data in files.items():
            path = os.path.join(tmp, name)
            open(path, "wb").write(data)
            os.utime(path, (stamp, stamp))
        members = list(files)
        if signer:
            members.append(jcat(tmp, files, *signer))
        subprocess.run(["gcab", "--create", "--nopath", os.path.abspath(out), *members], cwd=tmp, check=True)


main()

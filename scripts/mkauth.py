#!/usr/bin/env python3
"""Build a signed update for a Secure Boot variable, the content a
SetVariable call with EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS takes.

    mkauth.py KEY CERT VARIABLE CERT_TO_ENROL OUT [--replace] [--microsoft] [--time YYYY-MM-DDTHH:MM:SS]

VARIABLE is KEK, db or dbx; KEY and CERT (PEM) are the signer's, a key that
PK signs for KEK and that PK or a KEK entry holds for the others. The new
value is CERT_TO_ENROL (PEM) as an X.509 signature list, appended to what the
variable holds unless --replace is given. CERT_TO_ENROL may be DER. With
--microsoft the entry has Microsoft's owner GUID, which the firmware takes as
one that does not sign firmware updates: what one of Microsoft's UEFI CAs
enrolled in db should have.
"""

import datetime
import os
import struct
import subprocess
import sys
import tempfile
import uuid

GLOBAL = uuid.UUID("8be4df61-93ca-11d2-aa0d-00e098032b8c")
SECURITY_DB = uuid.UUID("d719b2cb-3d3a-4596-a3bc-dad00e67656f")
CERT_X509 = uuid.UUID("a5c059a1-94e4-4aa7-87b5-ab155c2bf072")
CERT_TYPE_PKCS7 = uuid.UUID("4aafd29d-68df-49ee-8aa9-347d375665a7")
OWNER = uuid.UUID("284518fd-2e62-4bc2-bd62-ddff8fa8bd70")
MICROSOFT = uuid.UUID("77fa9abd-0359-4d32-bd60-28f4e78f784b")

NON_VOLATILE, BOOT_SERVICE, RUNTIME, TIME_BASED, APPEND = 0x1, 0x2, 0x4, 0x20, 0x40
VARIABLES = {"KEK": GLOBAL, "db": SECURITY_DB, "dbx": SECURITY_DB}


def pem_to_der(path):
    return subprocess.run(["openssl", "x509", "-in", path, "-outform", "DER"], check=True, capture_output=True).stdout


def signature_list(owner, der):
    entry = owner.bytes_le + der
    return CERT_X509.bytes_le + struct.pack("<III", 28 + len(entry), 0, len(entry)) + entry


def main():
    args = sys.argv[1:]
    replace = "--replace" in args
    owner = MICROSOFT if "--microsoft" in args else OWNER
    when = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    if "--time" in args:
        at = args.index("--time")
        when = datetime.datetime.fromisoformat(args[at + 1])
        del args[at : at + 2]
    args = [a for a in args if a not in ("--replace", "--microsoft")]
    if len(args) != 5 or args[2] not in VARIABLES:
        sys.exit(__doc__)
    key, cert, variable, enrol, out = args
    guid = VARIABLES[variable]
    attributes = NON_VOLATILE | BOOT_SERVICE | RUNTIME | TIME_BASED | (0 if replace else APPEND)
    time = struct.pack("<HBBBBBxIhBx", when.year, when.month, when.day, when.hour, when.minute, when.second, 0, 0, 0)
    payload = signature_list(owner, pem_to_der(enrol))
    content = variable.encode("utf-16-le") + guid.bytes_le + struct.pack("<I", attributes) + time + payload
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "content")
        open(path, "wb").write(content)
        pkcs7 = subprocess.run(
            ["openssl", "smime", "-sign", "-binary", "-md", "sha256", "-in", path, "-signer", cert, "-inkey", key, "-outform", "DER"],
            check=True,
            capture_output=True,
        ).stdout
    descriptor = struct.pack("<IHH", 8 + 16 + len(pkcs7), 0x0200, 0x0EF1) + CERT_TYPE_PKCS7.bytes_le + pkcs7
    open(out, "wb").write(time + descriptor + payload)


main()

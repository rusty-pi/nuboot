#!/usr/bin/env python3
"""Boot the tpm2-commands scenario in pimu and check what the TPM on the VPU
answered: its fixed properties, the algorithms and commands it lists, that the
PCRs it reads back are the ones SHA-256 makes of what was extended, the error
codes of the commands it refuses, and a hash.

    check-tpm2.py
"""

import hashlib
import re
import struct
import subprocess
import sys

TPM_RC = {"initialize": 0x100, "locality": 0x107, "auth_missing": 0x125, "command_code": 0x143, "command_size": 0x142}


def sha256(*parts):
    return hashlib.sha256(b"".join(parts)).digest()


def extend(pcr, digest):
    return sha256(pcr, digest)


def responses():
    text = subprocess.run(
        ["pimu", "boot", "--scenario", "scenarios/tpm2-commands.yaml"], capture_output=True, text=True, check=True
    ).stdout
    found = {}
    for name, hexed in re.findall(r"tpm2 test: (\S+) ([0-9a-f]+)\s*$", text, re.M):
        found[name] = bytes.fromhex(hexed)
    return found


def header(response):
    tag, size, rc = struct.unpack(">HII", response[:10])
    if size != len(response):
        fail(f"response says {size} bytes, it has {len(response)}")
    return tag, rc, response[10:]


def fail(why):
    print(why)
    sys.exit(1)


def expect_rc(r, name, rc):
    tag, got, body = header(r[name])
    if got != rc or body:
        fail(f"{name}: response code {got:#x}, wanted {rc:#x}")


def pcr_read_selection(response):
    """The PCRs a PCR_Read response says it read, as a mask."""
    tag, rc, body = header(response)
    (count,) = struct.unpack(">I", body[4:8])
    if count != 1 or body[8:10] != b"\x00\x0b" or body[10] != 3:
        fail(f"PCR_Read: selection {body[4:15].hex()}")
    return int.from_bytes(body[11:14], "little")


def pcr_read(response):
    """The counter and the digests in a PCR_Read response."""
    tag, rc, body = header(response)
    if rc != 0:
        fail(f"PCR_Read: response code {rc:#x}")
    counter, count = struct.unpack(">II", body[:8])
    at = 8
    for _ in range(count):
        size = body[at + 2]
        at += 3 + size
    (n,) = struct.unpack(">I", body[at:at + 4])
    at += 4
    digests = []
    for _ in range(n):
        (size,) = struct.unpack(">H", body[at:at + 2])
        digests.append(body[at + 2:at + 2 + size])
        at += 2 + size
    return counter, digests


def replay(log):
    """The PCRs an event log makes, and its events: (pcr, type, digest, data)."""
    if log[:4] != bytes(4) or log[8:28] != bytes(20) or log[32:48] != b"Spec ID Event03\0":
        fail("the log does not start with a Spec ID event")
    (first,) = struct.unpack("<I", log[28:32])
    at = 32 + first
    pcrs = [bytes(32)] * 24
    events = []
    while at < len(log):
        pcr, kind, count = struct.unpack("<III", log[at:at + 12])
        at += 12
        if count != 1 or struct.unpack("<H", log[at:at + 2])[0] != 0xB:
            fail(f"event {len(events)}: not one SHA-256 digest")
        digest = log[at + 2:at + 34]
        at += 34
        (size,) = struct.unpack("<I", log[at:at + 4])
        data = log[at + 4:at + 4 + size]
        at += 4 + size
        if kind != 3:
            pcrs[pcr] = extend(pcrs[pcr], digest)
        events.append((pcr, kind, digest, data))
    return pcrs, events


def main():
    r = responses()
    for name in ("startup", "pcr-extend-drtm", "pcr-extend-sha1", "pcr-extend-no-session", "unknown-command", "short-command"):
        if name not in r:
            fail(f"no response for {name}")
    expect_rc(r, "startup", TPM_RC["initialize"])
    expect_rc(r, "pcr-extend-drtm", TPM_RC["locality"])
    expect_rc(r, "pcr-extend-sha1", 0x83 | 0x40 | 0x100)
    expect_rc(r, "pcr-extend-no-session", TPM_RC["auth_missing"])
    expect_rc(r, "unknown-command", TPM_RC["command_code"])
    expect_rc(r, "short-command", TPM_RC["command_size"])

    log = r.get("eventlog")
    if not log or "pcr-read-all" not in r:
        fail("no event log or no PCR read of all registers")
    pcrs, events = replay(log)
    counter, first = pcr_read(r["pcr-read-all"])
    if pcr_read_selection(r["pcr-read-all"]) != 0xFF or len(first) != 8:
        fail("a PCR_Read of all 24 registers does not answer with the first eight")
    if pcr_read_selection(r["pcr-read-mid"]) != 0xFF00 or pcr_read_selection(r["pcr-read-high"]) != 0xFF0000:
        fail("PCR_Read does not answer a selection of eight registers with those eight")
    all_pcrs = first + pcr_read(r["pcr-read-mid"])[1] + pcr_read(r["pcr-read-high"])[1]
    if all_pcrs != pcrs:
        for i, (a, b) in enumerate(zip(all_pcrs, pcrs)):
            if a != b:
                fail(f"PCR {i}: the TPM has {a.hex()}, the event log makes {b.hex()}")
    if counter != len([e for e in events if e[1] != 3]):
        fail(f"the update counter is {counter}, the log has {len(events)} events")
    by_text = {}
    for pcr, kind, digest, data in events:
        if kind == 0xA:
            by_text[data.decode()] = pcr
        if kind not in (3, 0x8000000A, 0x80000001, 0x80000003, 0x800000E0) and digest != sha256(data):
            fail(f"event type {kind:#x} in PCR {pcr}: its digest is not the hash of its data")
    needed = ("board.revision=", "board.serial=", "board.ext_revision=", "board.mac_rows=", "otp.bootmode=", "sdram.mib=", "eeprom.bootconf=")
    for want in needed:
        if not any(t.startswith(want) and pcr == 1 for t, pcr in by_text.items()):
            fail(f"the log has no {want} event in PCR 1")
    if not any(pcr == 0 and kind == 0x8000000A and data[1:1 + data[0]] == b"eeprom-bootcode" for pcr, kind, digest, data in events):
        fail("the log has no event for the EEPROM's bootloader in PCR 0")
    separated = sorted(pcr for pcr, kind, digest, data in events if kind == 0x4)
    if separated != list(range(8)):
        fail(f"the log has separators in PCRs {separated}, not in each of 0 to 7")
    handoff = [pcr for pcr, kind, digest, data in events if kind == 0x8000000B]
    if handoff != [1]:
        fail(f"the log has handoff table events in PCRs {handoff}, not one in PCR 1")
    if not any(pcr == 4 and kind == 0x80000007 and data == b"Calling EFI Application from Boot Option" for pcr, kind, digest, data in events):
        fail("the log has no event for calling the boot option in PCR 4")
    versions = [data for pcr, kind, digest, data in events if kind == 0x8]
    if len(versions) != 1 or not versions[0].decode("utf-16-le").startswith("nuboot "):
        fail("the log has no firmware version event")
    print(f"the event log of {len(events)} events replays to the PCRs the TPM holds, with the board's identity in PCR 1")

    tag, rc, body = header(r["getcap-properties"])
    more, capability, count = struct.unpack(">BII", body[:9])
    props = dict(struct.unpack(">II", body[9 + 8 * i:17 + 8 * i]) for i in range(count))
    if (rc, capability, props.get(0x100), props.get(0x102)) != (0, 6, 0x322E3000, 159):
        fail(f"properties: {rc:#x} {capability} {props}")

    tag, rc, body = header(r["getcap-algs"])
    count = struct.unpack(">I", body[5:9])[0]
    algs = [struct.unpack(">HI", body[9 + 6 * i:15 + 6 * i])[0] for i in range(count)]
    if rc != 0 or 0x000B not in algs:
        fail(f"algorithms: {algs}")

    tag, rc, body = header(r["getcap-pcrs"])
    if rc != 0 or body[9:].hex() != "000b03ffffff":
        fail(f"PCR selection: {body.hex()}")

    tag, rc, body = header(r["getcap-commands"])
    count = struct.unpack(">I", body[5:9])[0]
    commands = [struct.unpack(">I", body[9 + 4 * i:13 + 4 * i])[0] & 0xFFFF for i in range(count)]
    if rc != 0 or commands != sorted(commands) or 0x17E not in commands or 0x182 not in commands:
        fail(f"commands: {[hex(c) for c in commands]}")

    c0, before = pcr_read(r["pcr-read-before"])
    if len(before) != 3 or before[2] != bytes(32) or before[1] == bytes(32):
        fail("PCR 7 should be measured and PCR 23 empty at the start")
    digest = b"\x11" * 32
    extended = extend(bytes(32), digest)
    c1, got = pcr_read(r["pcr-read-extended"])
    if got != [extended] or c1 != c0 + 1:
        fail(f"after PCR_Extend: {got[0].hex()} counter {c1}, wanted {extended.hex()} counter {c0 + 1}")
    event_digest = sha256(b"hello")
    tag, rc, body = header(r["pcr-event"])
    if rc != 0 or event_digest not in body:
        fail("PCR_Event did not return the digest of the event")
    evented = extend(extended, event_digest)
    c2, got = pcr_read(r["pcr-read-evented"])
    if got != [evented] or c2 != c1 + 1:
        fail(f"after PCR_Event: {got[0].hex()} counter {c2}")
    expect_rc_session = header(r["pcr-reset"])
    if expect_rc_session[1] != 0:
        fail("PCR_Reset refused")
    c3, got = pcr_read(r["pcr-read-reset"])
    if got != [bytes(32)] or c3 != c2 + 1:
        fail(f"after PCR_Reset: {got[0].hex()} counter {c3}")

    tag, rc, body = header(r["get-random"])
    if rc != 0 or body[:2] != b"\x00\x10" or body[2:] == bytes(16):
        fail(f"GetRandom: {body.hex()}")
    tag, rc, body = header(r["hash"])
    if rc != 0 or body[2:34] != sha256(b"abc"):
        fail(f"Hash: {body.hex()}")
    check_objects(r)
    print("the TPM's properties, PCR reads, extends, event, reset, hash and error codes are as the specification has them")
    print("a primary key is created, a secret sealed under it, loaded and unsealed, and what is refused is refused")


def tpm2b(data, at):
    """The TPM2B at `at` of `data`, and where it ends."""
    (size,) = struct.unpack(">H", data[at : at + 2])
    return data[at + 2 : at + 2 + size], at + 2 + size


def check_objects(r):
    """The key and the sealed data: what they answer and what they refuse."""
    tag, rc, body = header(r["create-primary"])
    if tag != 0x8002 or rc != 0 or body[:4] != struct.pack(">I", 0x80000000):
        fail(f"CreatePrimary: {rc:#x} {body[:8].hex()}")
    public, at = tpm2b(body, 8)
    if public[:4] != struct.pack(">HH", 0x23, 0xB) or len(public) != 90:
        fail(f"CreatePrimary's public area: {public.hex()}")
    name, _ = tpm2b(body, len(body) - 5 - 36)
    if name != struct.pack(">H", 0xB) + sha256(public):
        fail("CreatePrimary's name is not the hash of its public area")
    tag, rc, body = header(r["create-sealed"])
    if rc != 0:
        fail(f"Create: {rc:#x}")
    tag, rc, body = header(r["load"])
    if rc != 0 or len(body) < 4 + 4 + 2 + 34:
        fail(f"Load: {rc:#x} {body.hex()}")
    loaded_name, _ = tpm2b(body, 8)
    tag, rc, body = header(r["unseal"])
    data, _ = tpm2b(body, 4)
    if rc != 0 or data != b"hello":
        fail(f"Unseal: {rc:#x} {body.hex()}")
    expect_rc(r, "unseal-wrong-password", 0xA2 | 0x800 | 0x100)
    tag, rc, body = header(r["read-public"])
    if rc != 0:
        fail(f"ReadPublic: {rc:#x}")
    public, at = tpm2b(body, 0)
    name, at = tpm2b(body, at)
    if name != loaded_name or name != struct.pack(">H", 0xB) + sha256(public):
        fail("ReadPublic's name is not Load's, or not the hash of the public area")
    tag, rc, body = header(r["getcap-transient"])
    if rc != 0 or struct.unpack(">I", body[5:9])[0] != 2:
        fail(f"two objects are loaded: {body.hex()}")
    check_signing(r)
    expect_rc(r, "flush-item", 0)
    expect_rc(r, "flush-primary", 0)
    expect_rc(r, "flush-again", 0x8B | 0x40 | 0x100)


def check_signing(r):
    """A signing key's signature and quote, checked with an independent ECDSA."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, encode_dss_signature

    tag, rc, body = header(r["create-signing"])
    if rc != 0:
        fail(f"Create (signing): {rc:#x}")
    _, at = tpm2b(body, 4)
    public, _ = tpm2b(body, at)
    if public[:4] != struct.pack(">HH", 0x23, 0xB) or len(public) != 88:
        fail(f"signing key's public area: {public.hex()}")
    x, y = public[-66:-34], public[-32:]
    key = ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()).public_key()

    def signature_of(body, at):
        alg, hash_alg = struct.unpack(">HH", body[at : at + 4])
        if (alg, hash_alg) != (0x18, 0xB):
            fail(f"signature algorithm {alg:#x} {hash_alg:#x}")
        rr, at = tpm2b(body, at + 4)
        ss, at = tpm2b(body, at)
        return encode_dss_signature(int.from_bytes(rr, "big"), int.from_bytes(ss, "big")), at

    tag, rc, body = header(r["sign"])
    if rc != 0:
        fail(f"Sign: {rc:#x}")
    der, _ = signature_of(body, 4)
    digest = b"\x11" * 32
    try:
        key.verify(der, digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    except InvalidSignature:
        fail("Sign: the signature does not verify against the key's public area")
    expect_rc(r, "sign-short-digest", 0x95 | 0x40 | 0x100)
    expect_rc(r, "sign-storage-key", 0x9C | 0x100)
    tag, rc, body = header(r["verify-signature"])
    if rc != 0 or struct.unpack(">H", body[:2])[0] != 0x8022:
        fail(f"VerifySignature: {rc:#x} {body.hex()}")
    expect_rc(r, "verify-forged", 0x9B | 0x40 | 0x200)

    tag, rc, body = header(r["quote"])
    if rc != 0:
        fail(f"Quote: {rc:#x}")
    attest, at = tpm2b(body, 4)
    der, _ = signature_of(body, at)
    try:
        key.verify(der, hashlib.sha256(attest).digest(), ec.ECDSA(Prehashed(hashes.SHA256())))
    except InvalidSignature:
        fail("Quote: the signature does not verify the attestation")
    magic, kind = struct.unpack(">IH", attest[:6])
    if magic != 0xFF544347 or kind != 0x8018:
        fail(f"Quote: {attest[:6].hex()}")
    signer, at = tpm2b(attest, 6)
    extra, at = tpm2b(attest, at)
    if extra != b"\x01\x02\x03\x04":
        fail(f"Quote: qualifying data {extra.hex()}")
    at += 8 + 4 + 4 + 1 + 8
    selection = attest[at : at + 4 + 2 + 1 + 3]
    if selection != struct.pack(">IHB", 1, 0xB, 3) + bytes([1, 0, 0]):
        fail(f"Quote: selection {selection.hex()}")
    pcr_digest, at = tpm2b(attest, at + 10)
    _, pcrs = pcr_read(r["pcr-read-all"])
    if pcr_digest != sha256(pcrs[0]) or at != len(attest):
        fail("Quote: the PCR digest is not that of PCR 0")
    tag, rc, body = header(r["hash-ticket"])
    if rc != 0 or body[2:34] != sha256(b"abc") or body[34:36] != b"\x80\x24" or body[36:40] != struct.pack(">I", 0x40000001):
        fail(f"Hash with the owner hierarchy: {body.hex()}")
    expect_rc(r, "flush-signing", 0)

    tag, rc, body = header(r["load-external"])
    if rc != 0 or body[:4] != struct.pack(">I", 0x80000002) or len(body) != 4 + 2 + 34:
        fail(f"LoadExternal: {rc:#x} {body.hex()}")
    tag, rc, body = header(r["verify-rsa"])
    if rc != 0 or struct.unpack(">H", body[:2])[0] != 0x8022 or struct.unpack(">I", body[2:6])[0] != 0x40000001:
        fail(f"VerifySignature with an RSA key: {rc:#x} {body.hex()}")
    expect_rc(r, "verify-rsa-forged", 0x9B | 0x40 | 0x200)
    expect_rc(r, "sign-external", 0x9C | 0x100)
    expect_rc(r, "load-external-long", 0x95 | 0x40 | 0x200)
    expect_rc(r, "flush-external", 0)


if __name__ == "__main__":
    main()

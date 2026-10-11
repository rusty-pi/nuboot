//! Secure Boot, always on: an image runs only when an Authenticode signature
//! on it chains to a certificate in `db` and its hash is not in `dbx`.
//!
//! The keys are built in. `PK` and `KEK` are this firmware's own, and `db`
//! holds its signing key beside Microsoft's UEFI CAs, which sign shim for the
//! distributions. `dbx` holds the AArch64 image hashes Microsoft revokes.
//! `SetupMode` is 0 and the variables cannot be written.

use alloc::vec::Vec;
use core::fmt::Display;

use r_efi::efi;

use crate::pkcs7::{self, Cert};
use crate::sha256::Sha256;
use crate::util::Global;
use crate::var::{self, BS, NV, RT};
use crate::{info, warn};

const DB: [&[u8]; 2] = [
    include_bytes!("../keys/microsoft-uefi-ca-2011.der"),
    include_bytes!("../keys/microsoft-uefi-ca-2023.der"),
];
/// The test build's own certificate (`scripts/build-uefi.sh --test-keys`),
/// empty in a real one.
const TEST_DB: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/test-db.der"));
const PK: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/pk.der"));
const KEK: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/kek.der"));
const DB_OWN: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/db.der"));
const DBX: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/dbx.bin"));

/// `EFI_CERT_X509_GUID`.
const CERT_X509: efi::Guid =
    efi::Guid::from_fields(0xa5c059a1, 0x94e4, 0x4aa7, 0x87, 0xb5, &[0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72]);
/// `EFI_CERT_SHA256_GUID`.
const CERT_SHA256: efi::Guid =
    efi::Guid::from_fields(0xc1c41626, 0x504c, 0x4092, 0xac, 0xa9, &[0x41, 0xf9, 0x36, 0x93, 0x43, 0x28]);
/// The owner Microsoft gives its `db` and `dbx` entries.
const MICROSOFT: efi::Guid =
    efi::Guid::from_fields(0x77fa9abd, 0x0359, 0x4d32, 0xbd, 0x60, &[0x28, 0xf4, 0xe7, 0x8f, 0x78, 0x4b]);

/// The owner this firmware's own `PK`, `KEK` and `db` entries have.
const OWNER: efi::Guid =
    efi::Guid::from_fields(0x284518fd, 0x2e62, 0x4bc2, 0xbd, 0x62, &[0xdd, 0xff, 0x8f, 0xa8, 0xbd, 0x70]);

const WIN_CERT_PKCS_SIGNED_DATA: u16 = 0x0002;
const TIME_AUTH: u32 = efi::VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;

static TRUSTED: Global<Vec<Cert<'static>>> = Global::new(Vec::new());
/// The owner of each entry in [`TRUSTED`], in the same order.
static OWNERS: Global<Vec<[u8; 16]>> = Global::new(Vec::new());
static REVOKED: Global<Vec<[u8; 32]>> = Global::new(Vec::new());

/// An `EFI_SIGNATURE_LIST` of `entries`, each `size` bytes after its owner.
fn signature_list(out: &mut Vec<u8>, owner: efi::Guid, ty: efi::Guid, size: usize, entries: &[&[u8]]) {
    let sig = 16 + size;
    out.extend_from_slice(ty.as_bytes());
    out.extend_from_slice(&((28 + sig * entries.len()) as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(sig as u32).to_le_bytes());
    for e in entries {
        out.extend_from_slice(owner.as_bytes());
        out.extend_from_slice(e);
    }
}

/// The platform key, which no write changes.
pub fn platform_key() -> &'static [u8] {
    PK
}

/// The DER certificates in `EFI_SIGNATURE_LIST`s, each with its owner.
pub fn x509_entries(lists: &[u8]) -> Vec<([u8; 16], &[u8])> {
    let mut out = Vec::new();
    for_each_entry(lists, |ty, owner, body| {
        if ty == CERT_X509.as_bytes() {
            out.push((*owner, body));
        }
    });
    out
}

fn for_each_entry<'a>(mut lists: &'a [u8], mut each: impl FnMut(&[u8], &[u8; 16], &'a [u8])) {
    while lists.len() >= 28 {
        let size = u32_at(lists, 16).unwrap_or(0) as usize;
        let header = u32_at(lists, 20).unwrap_or(0) as usize;
        let entry = u32_at(lists, 24).unwrap_or(0) as usize;
        let Some(list) = lists.get(..size) else { return };
        if entry <= 16 || 28 + header > size {
            return;
        }
        for e in list[28 + header..].chunks_exact(entry) {
            each(&list[..16], e[..16].try_into().unwrap(), &e[16..]);
        }
        lists = &lists[size..];
    }
}

/// Whether `lists` is a run of well-formed `EFI_SIGNATURE_LIST`s of kinds
/// this firmware knows: what an update may not break.
pub fn well_formed(mut lists: &[u8]) -> bool {
    while !lists.is_empty() {
        if lists.len() < 28 {
            return false;
        }
        let size = u32_at(lists, 16).unwrap_or(0) as usize;
        let header = u32_at(lists, 20).unwrap_or(0) as usize;
        let entry = u32_at(lists, 24).unwrap_or(0) as usize;
        let known = lists[..16] == *CERT_X509.as_bytes() || lists[..16] == *CERT_SHA256.as_bytes();
        let Some(body) = size.checked_sub(28 + header) else { return false };
        if !known || size > lists.len() || entry <= 16 || body % entry != 0 {
            return false;
        }
        lists = &lists[size..];
    }
    true
}

/// `PK`, `KEK`, `db` and `dbx` as this firmware ships them.
fn defaults() -> [Vec<u8>; 4] {
    let mut pk = Vec::new();
    signature_list(&mut pk, OWNER, CERT_X509, PK.len(), &[PK]);
    let mut kek = Vec::new();
    signature_list(&mut kek, OWNER, CERT_X509, KEK.len(), &[KEK]);
    if !TEST_DB.is_empty() {
        signature_list(&mut kek, OWNER, CERT_X509, TEST_DB.len(), &[TEST_DB]);
    }
    let mut db = Vec::new();
    let certs = DB.into_iter().map(|der| (MICROSOFT, der));
    let own = core::iter::once((OWNER, DB_OWN));
    let test = (!TEST_DB.is_empty()).then_some((OWNER, TEST_DB));
    for (owner, der) in certs.chain(own).chain(test) {
        signature_list(&mut db, owner, CERT_X509, der.len(), &[der]);
    }
    let mut dbx = Vec::new();
    let hashes: Vec<&[u8]> = DBX.chunks_exact(32).collect();
    signature_list(&mut dbx, MICROSOFT, CERT_SHA256, 32, &hashes);
    [pk, kek, db, dbx]
}

/// Publish the Secure Boot state and the keys as the variables an OS loader
/// reads, with what the flash store holds on top of the built-in keys.
pub fn init() {
    let [pk, kek, db, dbx] = defaults();
    let state = BS | RT;
    var::fixed("SecureBoot", var::GLOBAL, state, alloc::vec![1]);
    var::fixed("SetupMode", var::GLOBAL, state, alloc::vec![0]);
    var::fixed("AuditMode", var::GLOBAL, state, alloc::vec![0]);
    var::fixed("DeployedMode", var::GLOBAL, state, alloc::vec![1]);
    var::fixed("PK", var::GLOBAL, NV | BS | RT | TIME_AUTH, pk);
    var::seed("KEK", var::GLOBAL, NV | BS | RT | TIME_AUTH, kek);
    var::seed("db", var::SECURITY_DB, NV | BS | RT | TIME_AUTH, db);
    var::seed("dbx", var::SECURITY_DB, NV | BS | RT | TIME_AUTH, dbx);
    var::load_store();
    refresh();
    if !TEST_DB.is_empty() {
        warn!("secboot", "test build: its own test key is in db, not for a real board");
    }
    for (name, guid) in [("PK", var::GLOBAL), ("KEK", var::GLOBAL), ("db", var::SECURITY_DB), ("dbx", var::SECURITY_DB)] {
        crate::tcg2::measure_variable(name, &guid, &var::bytes(name, &guid).unwrap_or_default());
    }
    crate::tcg2::measure_variable("SecureBoot", &var::GLOBAL, &[1]);
    info!("secboot", "Secure Boot enforced"; db = TRUSTED.get().len(), dbx = REVOKED.get().len());
}

/// Take the certificates and hashes `db` and `dbx` hold now.
pub fn refresh() {
    let trusted = TRUSTED.get();
    let owners = OWNERS.get();
    trusted.clear();
    owners.clear();
    let db = var::bytes("db", &var::SECURITY_DB).unwrap_or_default();
    for (owner, der) in x509_entries(&db) {
        let der: &'static [u8] = alloc::boxed::Box::leak(der.to_vec().into_boxed_slice());
        match Cert::parse(der) {
            Some(c) => {
                trusted.push(c);
                owners.push(owner);
            }
            None => warn!("secboot", "certificate in db not understood, left out"; bytes = der.len()),
        }
    }
    let revoked = REVOKED.get();
    revoked.clear();
    let dbx = var::bytes("dbx", &var::SECURITY_DB).unwrap_or_default();
    for_each_entry(&dbx, |ty, _, body| {
        if ty == CERT_SHA256.as_bytes() && body.len() == 32 {
            revoked.push(body.try_into().unwrap());
        }
    });
}
fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// The image's Authenticode hash, and its attribute certificate table.
fn authenticode(img: &[u8]) -> Option<([u8; 32], &[u8])> {
    let pe = u32_at(img, 0x3c)? as usize;
    if img.get(pe..pe + 4)? != b"PE\0\0" {
        return None;
    }
    let coff = pe + 4;
    let sections = u16_at(img, coff + 2)? as usize;
    let opt = coff + 20;
    let opt_size = u16_at(img, coff + 16)? as usize;
    if u16_at(img, opt)? != 0x20b || u32_at(img, opt + 108)? < 5 {
        return None;
    }
    let headers = u32_at(img, opt + 60)? as usize;
    let checksum = opt + 64;
    let dir = opt + 112 + 4 * 8;
    let (cert_at, cert_size) = (u32_at(img, dir)? as usize, u32_at(img, dir + 4)? as usize);

    let mut h = Sha256::new();
    h.update(img.get(..checksum)?);
    h.update(img.get(checksum + 4..dir)?);
    h.update(img.get(dir + 8..headers)?);
    let table = opt + opt_size;
    let mut raw: Vec<(usize, usize)> = (0..sections)
        .map(|i| Some((u32_at(img, table + 40 * i + 20)? as usize, u32_at(img, table + 40 * i + 16)? as usize)))
        .collect::<Option<_>>()?;
    raw.retain(|&(_, size)| size != 0);
    raw.sort_unstable();
    let mut hashed = headers;
    for (at, size) in raw {
        h.update(img.get(at..at.checked_add(size)?)?);
        hashed += size;
    }
    // Whatever follows the sections, short of the certificates at the end.
    let end = img.len().checked_sub(cert_size)?;
    if end > hashed {
        h.update(img.get(hashed..end)?);
    }
    let certs = if cert_size == 0 { &[][..] } else { img.get(cert_at..cert_at.checked_add(cert_size)?)? };
    Some((h.finish(), certs))
}

fn in_dbx(hash: &[u8]) -> bool {
    REVOKED.get().iter().any(|h| h == hash)
}

/// An image's Authenticode hash, whether or not it is signed.
pub fn authenticode_hash(image: &[u8]) -> Option<[u8; 32]> {
    authenticode(image).map(|(hash, _)| hash)
}

/// The `EFI_SIGNATURE_DATA` `db` holds for a certificate: its owner, then the
/// certificate.
fn signature_entry(anchor: &Cert) -> Vec<u8> {
    let at = TRUSTED.get().iter().position(|c| core::ptr::eq(c, anchor)).unwrap_or(0);
    let mut out = OWNERS.get().get(at).map_or([0; 16], |o| *o).to_vec();
    out.extend_from_slice(anchor.whole);
    out
}

/// Whether `image` may run: its Authenticode hash and the `db` entry that
/// verified it if so, the reason if not.
pub fn check(image: &[u8], path: &dyn Display) -> Result<([u8; 32], Vec<u8>), &'static str> {
    let (hash, mut table) = authenticode(image).ok_or("not a PE32+ image")?;
    if in_dbx(&hash) {
        return Err("image hash is in dbx");
    }
    let mut why = "not signed";
    // WIN_CERTIFICATE entries, each 8-byte aligned.
    while table.len() >= 8 {
        let len = u32_at(table, 0).unwrap_or(0) as usize;
        let Some(body) = table.get(8..len) else { return Err("certificate table malformed") };
        if u16_at(table, 6) == Some(WIN_CERT_PKCS_SIGNED_DATA) {
            match pkcs7::signed_data(body) {
                Ok(signed) if signed.digest != hash => why = "signed hash does not match the image",
                Ok(signed) => match pkcs7::anchor(&signed, TRUSTED.get()) {
                    Some(anchor) => {
                        info!("secboot", "image verified"; signer = signed.chain[0].name(), db = anchor.name(), path = path);
                        return Ok((hash, signature_entry(anchor)));
                    }
                    None => why = "not signed by a key in db",
                },
                Err(e) => why = e,
            }
        }
        table = table.get(len.next_multiple_of(8)..).unwrap_or(&[]);
    }
    Err(why)
}

/// Whether `signature`, a detached PKCS #7, is over exactly `content` by a key
/// this firmware's own `db` entries (not Microsoft's, whose CA signs for
/// anyone) trust, with a content hash `dbx` does not revoke. The signer's name
/// if so, the reason if not.
pub fn verify_own(signature: &[u8], content: &[u8]) -> Result<alloc::string::String, &'static str> {
    if in_dbx(&crate::sha256::digest(content)) {
        return Err("content hash is in dbx");
    }
    let signed = pkcs7::signed_content(signature, content)?;
    let anchor = pkcs7::anchor(&signed, TRUSTED.get()).ok_or("not signed by a key in db")?;
    let at = TRUSTED.get().iter().position(|c| core::ptr::eq(c, anchor)).ok_or("not signed by a key in db")?;
    if OWNERS.get().get(at) == Some(MICROSOFT.as_bytes()) {
        return Err("signed by a Microsoft key, which does not sign firmware");
    }
    Ok(alloc::string::String::from(signed.chain[0].name()))
}

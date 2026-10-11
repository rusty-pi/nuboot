//! UEFI variables, kept in memory for the boot. `PK` and the Secure Boot state
//! are built in and cannot be written. `KEK`, `db` and `dbx` start as the
//! built-in keys and take authenticated writes: time-based, signed by the
//! platform key for `KEK` and by it or a `KEK` entry for the others. Each
//! accepted write goes to the flash store ([`crate::store`]) and is checked
//! again from the start at every boot, so what a change to the flash can do is
//! take writes away, never make one up.

use alloc::vec::Vec;
use core::ffi::c_void;

use r_efi::efi;

use crate::util::{Global, W, wstr};
use crate::{debug, info, pkcs7, secure, store, warn};

struct Var {
    name: Vec<u16>,
    guid: efi::Guid,
    attributes: u32,
    data: Vec<u8>,
    /// Built in: no `SetVariable` changes it.
    fixed: bool,
    /// The timestamp of the last authenticated write.
    time: [u8; 16],
    /// The authenticated writes since the last one that replaced the value,
    /// each with its place in the order they were made.
    history: Vec<(u64, store::Record)>,
}

static NEXT: Global<u64> = Global::new(0);

static VARS: Global<Vec<Var>> = Global::new(Vec::new());

/// How much the store holds, for `QueryVariableInfo`.
const STORE_BYTES: u64 = 256 * 1024;
const MAX_VARIABLE: u64 = 64 * 1024;

pub const NV: u32 = efi::VARIABLE_NON_VOLATILE;
pub const BS: u32 = efi::VARIABLE_BOOTSERVICE_ACCESS;
pub const RT: u32 = efi::VARIABLE_RUNTIME_ACCESS;
const AUTH: u32 = efi::VARIABLE_AUTHENTICATED_WRITE_ACCESS | efi::VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
const APPEND: u32 = efi::VARIABLE_APPEND_WRITE;

/// `EFI_GLOBAL_VARIABLE`.
pub const GLOBAL: efi::Guid = efi::Guid::from_fields(0x8be4df61, 0x93ca, 0x11d2, 0xaa, 0x0d, &[0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c]);
/// `EFI_IMAGE_SECURITY_DATABASE_GUID`: `db` and `dbx`.
pub const SECURITY_DB: efi::Guid =
    efi::Guid::from_fields(0xd719b2cb, 0x3d3a, 0x4596, 0xa3, 0xbc, &[0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f]);

/// A variable this firmware sets and nothing else may change.
pub fn fixed(name: &str, guid: efi::Guid, attributes: u32, data: Vec<u8>) {
    add(name, guid, attributes, data, true);
}

/// A variable that starts as `data` and takes authenticated writes.
pub fn seed(name: &str, guid: efi::Guid, attributes: u32, data: Vec<u8>) {
    add(name, guid, attributes, data, false);
}

fn add(name: &str, guid: efi::Guid, attributes: u32, data: Vec<u8>, fixed: bool) {
    let name: Vec<u16> = name.encode_utf16().collect();
    let vars = VARS.get();
    vars.retain(|v| !(v.guid == guid && v.name == name));
    vars.push(Var { name, guid, attributes, data, fixed, time: [0; 16], history: Vec::new() });
}

/// What a variable holds, for the firmware's own use.
pub fn bytes(name: &str, guid: &efi::Guid) -> Option<Vec<u8>> {
    let name: Vec<u16> = name.encode_utf16().collect();
    find(&name, guid).map(|i| VARS.get()[i].data.clone())
}

fn is(name: &[u16], text: &str) -> bool {
    name.iter().copied().eq(text.encode_utf16())
}

/// `KEK`, `db` and `dbx`: the variables that take authenticated writes.
fn is_key(name: &[u16], guid: &efi::Guid) -> bool {
    (*guid == GLOBAL && is(name, "KEK")) || (*guid == SECURITY_DB && (is(name, "db") || is(name, "dbx")))
}

/// A key variable an authenticated delete emptied is gone to everyone else.
fn visible(v: &Var) -> bool {
    !v.data.is_empty() || v.fixed
}

fn find(name: &[u16], guid: &efi::Guid) -> Option<usize> {
    VARS.get().iter().position(|v| v.guid == *guid && v.name == name)
}

pub extern "efiapi" fn get_variable(
    name: *mut efi::Char16,
    guid: *mut efi::Guid,
    attributes: *mut u32,
    size: *mut usize,
    data: *mut c_void,
) -> efi::Status {
    if name.is_null() || guid.is_null() || size.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    let name = unsafe { wstr(name) };
    let Some(i) = find(name, unsafe { &*guid }).filter(|&i| visible(&VARS.get()[i])) else { return efi::Status::NOT_FOUND };
    let v = &VARS.get()[i];
    if !attributes.is_null() {
        unsafe { *attributes = v.attributes };
    }
    let room = unsafe { *size };
    unsafe { *size = v.data.len() };
    if room < v.data.len() {
        return efi::Status::BUFFER_TOO_SMALL;
    }
    if data.is_null() && !v.data.is_empty() {
        return efi::Status::INVALID_PARAMETER;
    }
    unsafe { core::ptr::copy_nonoverlapping(v.data.as_ptr(), data as *mut u8, v.data.len()) };
    efi::Status::SUCCESS
}

pub extern "efiapi" fn get_next_variable_name(size: *mut usize, name: *mut efi::Char16, guid: *mut efi::Guid) -> efi::Status {
    if size.is_null() || name.is_null() || guid.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    let current = unsafe { wstr(name) };
    let vars = VARS.get();
    let next = if current.is_empty() {
        0
    } else {
        match find(current, unsafe { &*guid }) {
            Some(i) => i + 1,
            None => return efi::Status::INVALID_PARAMETER,
        }
    };
    let Some(v) = vars.iter().skip(next).find(|v| visible(v)) else { return efi::Status::NOT_FOUND };
    let need = (v.name.len() + 1) * 2;
    let room = unsafe { *size };
    unsafe { *size = need };
    if room < need {
        return efi::Status::BUFFER_TOO_SMALL;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(v.name.as_ptr(), name, v.name.len());
        *name.add(v.name.len()) = 0;
        *guid = v.guid;
    }
    efi::Status::SUCCESS
}

pub extern "efiapi" fn set_variable(
    name: *mut efi::Char16,
    guid: *mut efi::Guid,
    attributes: u32,
    size: usize,
    data: *mut c_void,
) -> efi::Status {
    if name.is_null() || guid.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    let name = unsafe { wstr(name) };
    let guid = unsafe { *guid };
    if name.is_empty() || (size > 0 && data.is_null()) {
        return efi::Status::INVALID_PARAMETER;
    }
    let existing = find(name, &guid);
    if let Some(i) = existing {
        if VARS.get()[i].fixed {
            warn!("var", "built-in variable not changed"; name = W(name));
            return efi::Status::WRITE_PROTECTED;
        }
    }
    let bytes = unsafe { core::slice::from_raw_parts(data as *const u8, size) };
    if is_key(name, &guid) {
        return if attributes & efi::VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS != 0 {
            write_key(name, guid, attributes, bytes, true)
        } else {
            warn!("var", "write without a signature refused"; name = W(name));
            efi::Status::SECURITY_VIOLATION
        };
    }
    if attributes & AUTH != 0 {
        warn!("var", "authenticated variables cannot be written"; name = W(name));
        return efi::Status::WRITE_PROTECTED;
    }
    let delete = attributes & !APPEND == 0 || (size == 0 && attributes & APPEND == 0);
    if delete {
        return match existing {
            Some(i) => {
                VARS.get().remove(i);
                efi::Status::SUCCESS
            }
            None => efi::Status::NOT_FOUND,
        };
    }
    if attributes & BS == 0 || size as u64 > MAX_VARIABLE {
        return efi::Status::INVALID_PARAMETER;
    }
    let append = attributes & APPEND != 0;
    let attributes = attributes & !APPEND;
    match existing {
        Some(i) if append || VARS.get()[i].attributes == attributes => {
            let v = &mut VARS.get()[i];
            if !append {
                v.data.clear();
            }
            v.data.extend_from_slice(bytes);
        }
        Some(_) => return efi::Status::INVALID_PARAMETER,
        None => VARS.get().push(Var {
            name: name.to_vec(),
            guid,
            attributes,
            data: bytes.to_vec(),
            fixed: false,
            time: [0; 16],
            history: Vec::new(),
        }),
    }
    debug!("var", "variable set"; name = W(name), bytes = size);
    efi::Status::SUCCESS
}

/// The parts of an `EFI_VARIABLE_AUTHENTICATION_2` descriptor and what
/// follows it.
struct Auth<'a> {
    time: [u8; 16],
    /// The `WIN_CERTIFICATE_UEFI_GUID`: header, type and the PKCS #7.
    descriptor: &'a [u8],
    signature: &'a [u8],
    payload: &'a [u8],
}

/// `EFI_CERT_TYPE_PKCS7_GUID`.
const PKCS7: efi::Guid =
    efi::Guid::from_fields(0x4aafd29d, 0x68df, 0x49ee, 0x8a, 0xa9, &[0x34, 0x7d, 0x37, 0x56, 0x65, 0xa7]);

impl<'a> Auth<'a> {
    fn parse(buf: &'a [u8]) -> Option<Auth<'a>> {
        let time: [u8; 16] = buf.get(..16)?.try_into().ok()?;
        let length = u32::from_le_bytes(buf.get(16..20)?.try_into().ok()?) as usize;
        let revision = u16::from_le_bytes(buf.get(20..22)?.try_into().ok()?);
        let kind = u16::from_le_bytes(buf.get(22..24)?.try_into().ok()?);
        let end = 16usize.checked_add(length)?;
        if revision != 0x0200 || kind != 0x0ef1 || length < 24 || buf.get(24..40)? != PKCS7.as_bytes() {
            return None;
        }
        Some(Auth { time, descriptor: buf.get(16..end)?, signature: buf.get(40..end)?, payload: buf.get(end..)? })
    }
}

/// A timestamp as something that orders: year, month, day, hour, minute,
/// second.
fn when(t: &[u8; 16]) -> (u16, u8, u8, u8, u8, u8) {
    (u16::from_le_bytes([t[0], t[1]]), t[2], t[3], t[4], t[5], t[6])
}

fn clean(t: &[u8; 16]) -> bool {
    t[7] == 0 && t[8..].iter().all(|&b| b == 0)
}

/// Write `KEK`, `db` or `dbx`: `buf` is a descriptor and the new value,
/// signed over the name, GUID, attributes, timestamp and value.
fn write_key(name: &[u16], guid: efi::Guid, attributes: u32, buf: &[u8], persist: bool) -> efi::Status {
    let Some(i) = find(name, &guid) else { return efi::Status::NOT_FOUND };
    let Some(auth) = Auth::parse(buf) else { return efi::Status::INVALID_PARAMETER };
    let var = &VARS.get()[i];
    let append = attributes & APPEND != 0;
    if attributes & !APPEND != var.attributes || !clean(&auth.time) {
        return efi::Status::INVALID_PARAMETER;
    }
    if when(&auth.time) <= when(&var.time) {
        warn!("var", "write refused: timestamp not newer"; name = W(name));
        return efi::Status::SECURITY_VIOLATION;
    }
    let mut content = Vec::new();
    for c in name {
        content.extend_from_slice(&c.to_le_bytes());
    }
    content.extend_from_slice(guid.as_bytes());
    content.extend_from_slice(&attributes.to_le_bytes());
    content.extend_from_slice(&auth.time);
    content.extend_from_slice(auth.payload);
    let signed = match pkcs7::signed_content(auth.signature, &content) {
        Ok(signed) => signed,
        Err(why) => {
            warn!("var", "write refused: bad signature"; name = W(name), reason = why);
            return efi::Status::SECURITY_VIOLATION;
        }
    };
    let signer = signed.chain[0].whole;
    let kek = bytes("KEK", &GLOBAL).unwrap_or_default();
    let by_platform = signer == secure::platform_key();
    let by_kek = !is(name, "KEK") && secure::x509_entries(&kek).iter().any(|(_, der)| *der == signer);
    if !by_platform && !by_kek {
        warn!("var", "write refused: signer is not in PK or KEK"; name = W(name), signer = signed.chain[0].name());
        return efi::Status::SECURITY_VIOLATION;
    }
    let delete = auth.payload.is_empty() && !append;
    let mut data = if append { var.data.clone() } else { Vec::new() };
    data.extend_from_slice(auth.payload);
    if !secure::well_formed(&data) {
        return efi::Status::INVALID_PARAMETER;
    }
    let record = store::Record {
        kind: if delete { store::DELETE } else { store::SET },
        attributes,
        guid: *guid.as_bytes(),
        time: auth.time,
        name: name.to_vec(),
        data: auth.payload.to_vec(),
        auth: auth.descriptor.to_vec(),
    };
    let seq = *NEXT.get();
    let mut history = if append { var.history.clone() } else { Vec::new() };
    history.push((seq, record.clone()));
    if persist && !commit(i, &record, &history) {
        return efi::Status::DEVICE_ERROR;
    }
    *NEXT.get() += 1;
    let var = &mut VARS.get()[i];
    var.data = data;
    var.time = auth.time;
    var.history = history;
    info!("var", "key variable written"; name = W(name), bytes = var.data.len(), signer = signed.chain[0].name());
    if is(name, "db") || is(name, "dbx") {
        secure::refresh();
    }
    efi::Status::SUCCESS
}

/// Put `record` in the flash store, which on a full bank is given everything
/// the variables still need, in the order it was written.
fn commit(index: usize, record: &store::Record, history: &[(u64, store::Record)]) -> bool {
    if !store::available() {
        warn!("var", "no flash store, the change lasts until reset");
        return true;
    }
    store::append(record, || {
        let mut live: Vec<&(u64, store::Record)> = history.iter().collect();
        for (n, v) in VARS.get().iter().enumerate() {
            if n != index {
                live.extend(v.history.iter());
            }
        }
        live.sort_by_key(|(seq, _)| *seq);
        live.into_iter().map(|(_, r)| r.clone()).collect()
    })
}

/// Apply the writes the flash store holds to the built-in keys, each checked
/// as it was when it was made.
pub fn load_store() {
    for r in store::load() {
        let name = r.name.clone();
        let guid = efi::Guid::from_bytes(&r.guid);
        if !is_key(&name, &guid) {
            warn!("var", "stored record is for no key variable, ignored"; name = W(&name));
            continue;
        }
        let mut buf = r.time.to_vec();
        buf.extend_from_slice(&r.auth);
        buf.extend_from_slice(&r.data);
        let status = write_key(&name, guid, r.attributes, &buf, false);
        if status != efi::Status::SUCCESS {
            warn!("var", "stored write refused"; name = W(&name), status = status.as_usize());
        }
    }
}

pub extern "efiapi" fn query_variable_info(
    _attributes: u32,
    max_storage: *mut u64,
    remaining: *mut u64,
    max_size: *mut u64,
) -> efi::Status {
    if max_storage.is_null() || remaining.is_null() || max_size.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    let used: u64 = VARS.get().iter().map(|v| (v.name.len() * 2 + v.data.len()) as u64).sum();
    unsafe {
        *max_storage = STORE_BYTES;
        *remaining = STORE_BYTES.saturating_sub(used);
        *max_size = MAX_VARIABLE;
    }
    efi::Status::SUCCESS
}

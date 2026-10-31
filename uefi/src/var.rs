//! UEFI variables, kept in memory for the boot. `PK` and the Secure Boot state
//! are built in and cannot be written. `KEK`, `db` and `dbx` start as the
//! built-in keys and take authenticated writes: time-based, signed by the
//! platform key for `KEK` and by it or a `KEK` entry for the others. Each
//! accepted write goes to the variable store ([`crate::store`]) and is checked
//! again from the start at every boot, so what a change to the disk can do is
//! take writes away, never make one up.

use alloc::vec::Vec;
use core::ffi::c_void;

use r_efi::efi;

use crate::util::{Global, W, wstr};
use crate::{debug, error, esrt, info, pkcs7, secure, store, warn};

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

/// Whether what [`keep`] keeps survives a reset: the board has a device key
/// to seal it with, and the variable store answers.
pub fn keeps() -> bool {
    *DEVICE.get() && store::available()
}

/// A variable the firmware keeps across resets for itself: not visible to
/// the OS, and sealed in the variable store when the board has a device key.
pub fn keep(name: &str, guid: efi::Guid, data: &[u8]) -> efi::Status {
    let name: Vec<u16> = name.encode_utf16().collect();
    write_plain(&name, guid, NV | BS, data, None)
}

/// Drop what [`keep`] kept.
pub fn forget(name: &str, guid: efi::Guid) -> efi::Status {
    let name: Vec<u16> = name.encode_utf16().collect();
    write_plain(&name, guid, 0, &[], None)
}

/// What a variable holds, for the firmware's own use.
pub fn bytes(name: &str, guid: &efi::Guid) -> Option<Vec<u8>> {
    let name: Vec<u16> = name.encode_utf16().collect();
    find(&name, guid).map(|i| VARS.get()[i].data.clone())
}

/// Copy the variables the OS can read into the table its runtime services
/// answer from ([`crate::rtvar`]). Those it may also change are the
/// non-volatile ones no signature guards: a volatile variable is something the
/// boot chain made for the OS to read (shim's `MokListRT`, which a kernel
/// takes keys from), and is the boot chain's to write.
pub fn export_runtime() {
    crate::rtvar::clear();
    crate::rtvar::arm(*PLAIN_SEQ.get(), crate::diskstore::target());
    for v in VARS.get().iter().filter(|v| visible(v) && v.attributes & RT != 0) {
        let key = !v.fixed && is_key(&v.name, &v.guid);
        let writable = !v.fixed && !key && v.attributes & AUTH == 0 && v.attributes & NV != 0;
        if !crate::rtvar::add(&v.name, &v.guid, v.attributes, &v.data, writable, key) {
            warn!("var", "variable not kept for the OS: runtime table full"; name = W(&v.name));
        }
    }
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
    write_plain(name, guid, attributes, bytes, None)
}

/// Whether the VPU seals for UEFI: the board has a device key, and the OS has
/// not got the board yet. The store's records are sealed with it, and checked
/// against it.
static DEVICE: Global<bool> = Global::new(false);
/// Whether the VPU failed to answer when a stored record's seal was checked: what
/// the boot read is then not all the store holds.
static SEAL_CHECK_FAILED: Global<bool> = Global::new(false);
/// The sequence number the next sealed record gets: what stops an old record
/// being put back after a newer one.
static PLAIN_SEQ: Global<u64> = Global::new(0);
/// The most a sealed record holds.
const MAX_SEALED: usize = 16 * 1024;

/// Who made a sealed record: this firmware, before the OS had the board, or
/// the VPU, at the OS's request. The VPU signs what the OS asks, so what it
/// signs is the OS's word, and carries the OS's limits.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Origin {
    Firmware,
    Runtime,
}

const FIRMWARE_LABEL: &[u8] = b"nuboot variable store record v4";
const RUNTIME_LABEL: &[u8] = b"nuboot runtime variable record v2";
/// The device key's HMAC-SHA256 of a record's digest.
const SEAL: usize = 32;

/// What a record is sealed over: everything but the seal, each length before
/// what it measures.
fn digest(r: &store::Record, origin: Origin) -> [u8; 32] {
    let mut message = Vec::new();
    message.extend_from_slice(if origin == Origin::Firmware { FIRMWARE_LABEL } else { RUNTIME_LABEL });
    message.extend_from_slice(&r.kind.to_le_bytes());
    message.extend_from_slice(&r.attributes.to_le_bytes());
    message.extend_from_slice(&r.guid);
    message.extend_from_slice(&r.time);
    message.extend_from_slice(&(r.name.len() as u32).to_le_bytes());
    message.extend_from_slice(&(r.data.len() as u32).to_le_bytes());
    for c in &r.name {
        message.extend_from_slice(&c.to_le_bytes());
    }
    message.extend_from_slice(&r.data);
    crate::sha256::digest(&message)
}

/// Who the device key sealed `r` for, if it did: its `auth` is the seal.
fn sealed_by(r: &store::Record) -> Option<Origin> {
    if r.auth.len() != SEAL {
        return None;
    }
    [Origin::Firmware, Origin::Runtime].into_iter().find(|&origin| {
        let Some(seal) = crate::mailbox::device_hmac(&digest(r, origin)) else {
            *SEAL_CHECK_FAILED.get() = true;
            return false;
        };
        seal.iter().zip(&r.auth).fold(0, |different, (a, b)| different | (a ^ b)) == 0
    })
}

/// `SetVariable` for a variable no signature guards. `replayed` is the
/// record the variable store held, when this puts it back.
fn write_plain(
    name: &[u16],
    guid: efi::Guid,
    attributes: u32,
    bytes: &[u8],
    replayed: Option<store::Record>,
) -> efi::Status {
    let existing = find(name, &guid);
    if existing.is_some_and(|i| VARS.get()[i].fixed) {
        return efi::Status::WRITE_PROTECTED;
    }
    let delete = attributes & !APPEND == 0 || (bytes.is_empty() && attributes & APPEND == 0);
    if delete {
        let Some(i) = existing else { return efi::Status::NOT_FOUND };
        let v = &VARS.get()[i];
        if replayed.is_none() && v.attributes & NV != 0 && !v.history.is_empty() {
            let Some(record) = sealed(store::DELETE, v.attributes, &guid, name, &[]) else {
                return efi::Status::DEVICE_ERROR;
            };
            if !commit(i, &record, &[]) {
                return efi::Status::DEVICE_ERROR;
            }
        }
        VARS.get().remove(i);
        return efi::Status::SUCCESS;
    }
    if attributes & BS == 0 || bytes.len() as u64 > MAX_VARIABLE {
        return efi::Status::INVALID_PARAMETER;
    }
    let append = attributes & APPEND != 0;
    let attributes = attributes & !APPEND;
    let persistent = attributes & NV != 0 && *DEVICE.get();
    if let Some(i) = existing {
        if !append && VARS.get()[i].attributes != attributes {
            return efi::Status::INVALID_PARAMETER;
        }
    }
    if persistent && bytes.len() > MAX_SEALED {
        return efi::Status::OUT_OF_RESOURCES;
    }
    let mut history = match existing {
        Some(i) if append => VARS.get()[i].history.clone(),
        _ => Vec::new(),
    };
    if persistent {
        let order = *NEXT.get();
        let record = match replayed {
            Some(r) => r,
            None => {
                let kept = attributes | if append { APPEND } else { 0 };
                let Some(record) = sealed(store::SET, kept, &guid, name, bytes) else {
                    return efi::Status::DEVICE_ERROR;
                };
                let mut all = history.clone();
                all.push((order, record.clone()));
                if !commit(existing.unwrap_or(usize::MAX), &record, &all) {
                    return efi::Status::DEVICE_ERROR;
                }
                record
            }
        };
        history.push((order, record));
        *NEXT.get() += 1;
    } else if attributes & NV != 0 && !*DEVICE.get() {
        debug!("var", "no device key, a non-volatile variable lasts until reset"; name = W(name));
    }
    match existing {
        Some(i) => {
            let v = &mut VARS.get()[i];
            if !append {
                v.data.clear();
            }
            v.data.extend_from_slice(bytes);
            v.history = history;
        }
        None => VARS.get().push(Var {
            name: name.to_vec(),
            guid,
            attributes,
            data: bytes.to_vec(),
            fixed: false,
            time: [0; 16],
            history,
        }),
    }
    debug!("var", "variable set"; name = W(name), bytes = bytes.len());
    efi::Status::SUCCESS
}

/// A new record for the store, sealed by the device key: none when the VPU
/// does not seal it.
fn sealed(kind: u32, attributes: u32, guid: &efi::Guid, name: &[u16], data: &[u8]) -> Option<store::Record> {
    let seq = *PLAIN_SEQ.get();
    *PLAIN_SEQ.get() = seq.checked_add(1)?;
    let mut time = [0u8; 16];
    time[..8].copy_from_slice(&seq.to_le_bytes());
    let mut record = store::Record {
        kind,
        attributes,
        guid: *guid.as_bytes(),
        time,
        name: name.to_vec(),
        data: data.to_vec(),
        auth: Vec::new(),
    };
    if *DEVICE.get() {
        record.auth = crate::mailbox::device_hmac(&digest(&record, Origin::Firmware))?.to_vec();
    }
    Some(record)
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
    if VARS.get()[i].fixed {
        return efi::Status::WRITE_PROTECTED;
    }
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
    // What was written to `KEK` stays: a later write of `db` or `dbx` was
    // checked against the keys it held then, and is checked so again.
    let mut history = if append || is(name, "KEK") { var.history.clone() } else { Vec::new() };
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

/// Put `record` in the variable store, which on a full bank is given everything
/// the variables still need, in the order it was written.
fn commit(index: usize, record: &store::Record, history: &[(u64, store::Record)]) -> bool {
    if !store::available() {
        warn!("var", "no variable store, the change lasts until reset");
        return true;
    }
    store::append(record, || live_records(index, history))
}

/// Every record the variables still need, in the order they were written:
/// `history` stands in for the one the variable at `index` has.
fn live_records(index: usize, history: &[(u64, store::Record)]) -> Vec<store::Record> {
    let mut live: Vec<&(u64, store::Record)> = history.iter().collect();
    for (n, v) in VARS.get().iter().enumerate() {
        if n != index {
            live.extend(v.history.iter());
        }
    }
    live.sort_by_key(|(seq, _)| *seq);
    live.into_iter().map(|(_, r)| r.clone()).collect()
}

/// The OS has the board: nothing seals for it from here on.
fn lock() {
    *DEVICE.get() = false;
    if !crate::mailbox::lock_device_key() {
        error!("var", "the device key is not locked, the board is not handed to the OS");
        crate::util::halt()
    }
}

/// Apply what the variable store holds to the built-in keys and the variables:
/// each write to `KEK`, `db` and `dbx` checked as it was when it was made,
/// each of the others checked against its seal.
pub fn load_store() {
    *DEVICE.get() = crate::mailbox::device_hmac(&[0; 32]).is_some();
    crate::tables::on_exit_boot_services(lock);
    if !*DEVICE.get() {
        warn!("var", "no device key is fused: variables other than KEK, db and dbx stay in memory");
    }
    for r in store::load() {
        let name = r.name.clone();
        let guid = efi::Guid::from_bytes(&r.guid);
        if !is_key(&name, &guid) {
            replay_plain(r);
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
    store::start_if_empty();
    let plain_records_were_checked = *DEVICE.get() && !*SEAL_CHECK_FAILED.get();
    if *SEAL_CHECK_FAILED.get() {
        warn!("var", "the VPU did not answer for a stored record, the store is left as it is");
    }
    if plain_records_were_checked {
        store::compact_when_crowded(|| live_records(usize::MAX, &[]));
    }
}

fn replay_plain(r: store::Record) {
    if !*DEVICE.get() {
        warn!("var", "stored variable ignored: no device key is fused"; name = W(&r.name));
        return;
    }
    let seq = u64::from_le_bytes(r.time[..8].try_into().unwrap());
    let Some(origin) = sealed_by(&r) else {
        warn!("var", "stored variable ignored: the device key did not seal it"; name = W(&r.name));
        return;
    };
    if seq < *PLAIN_SEQ.get() || seq == u64::MAX {
        warn!("var", "stored variable ignored: older than one before it"; name = W(&r.name), seq = seq);
        return;
    }
    if origin == Origin::Runtime && !runtime_may_replay(&r) {
        warn!("var", "stored variable ignored: not the OS's to write"; name = W(&r.name));
        return;
    }
    *PLAIN_SEQ.get() = seq.saturating_add(1);
    let guid = efi::Guid::from_bytes(&r.guid);
    let (name, attributes, data) = (r.name.clone(), r.attributes, r.data.clone());
    let status = if r.kind == store::DELETE {
        write_plain(&name, guid, 0, &[], Some(r))
    } else {
        write_plain(&name, guid, attributes, &data, Some(r))
    };
    if status != efi::Status::SUCCESS {
        warn!("var", "stored variable not restored"; name = W(&name), status = status.as_usize());
    }
}

/// What the OS may write through the VPU: a variable that is theirs, that is,
/// one that has the attributes it was written with, or none yet. Never a
/// firmware variable, and never one the boot chain keeps hidden from the OS.
fn runtime_may_replay(r: &store::Record) -> bool {
    const NV_BS_RT: u32 = NV | BS | RT;
    if r.attributes != NV_BS_RT || !(r.kind == store::SET || r.kind == store::DELETE) {
        return false;
    }
    let guid = efi::Guid::from_bytes(&r.guid);
    if guid == esrt::FIRMWARE_CLASS {
        return false;
    }
    match find(&r.name, &guid) {
        Some(i) => {
            let v = &VARS.get()[i];
            !v.fixed && v.attributes == NV_BS_RT
        }
        None => r.kind == store::SET,
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

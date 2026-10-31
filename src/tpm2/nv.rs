//! NV indices: ordinary, counter, bit field and extend. They live in RAM, like
//! the PCRs; what makes them last is that the firmware asks for each change
//! sealed ([`export`]) and keeps it on the boot disk, and puts it back at the
//! next boot ([`import`]).
//!
//! An index is authorized by its own authorization value or its policy, or by
//! the owner or the platform hierarchy, as its attributes say. Locks
//! (`WRITELOCKED`, `READLOCKED` and their `*_STCLEAR`, `GLOBALLOCK`) and the
//! PIN types are not offered: an index that asks for them is not defined.

use super::session::Authorization;
use super::{In, RC_ATTRIBUTES, RC_COMMAND_SIZE, RC_HANDLE, RC_NV_DEFINED, RC_NV_SPACE, RC_P, RC_SIZE, RC_VALUE, RC_1, RC_2};
use crate::{aes, keystore, rng, sha256};

pub const CC_NV_UNDEFINE_SPACE: u32 = 0x122;
pub const CC_NV_DEFINE_SPACE: u32 = 0x12a;
pub const CC_NV_INCREMENT: u32 = 0x134;
pub const CC_NV_SET_BITS: u32 = 0x135;
pub const CC_NV_EXTEND: u32 = 0x136;
pub const CC_NV_WRITE: u32 = 0x137;
pub const CC_NV_READ: u32 = 0x14e;
pub const CC_NV_READ_PUBLIC: u32 = 0x169;

const RC_NV_UNINITIALIZED: u32 = 0x14a;
const RC_NV_RANGE: u32 = 0x146;
const RC_NV_AUTHORIZATION: u32 = 0x149;
const RC_NV_UNAVAILABLE: u32 = 0x923;
const RC_AUTH_UNAVAILABLE: u32 = 0x12f;

pub const SLOTS: usize = 8;
/// The most data an index holds.
pub const DATA_MAX: usize = 256;
const ALG_SHA256: u16 = 0x000b;
const RH_OWNER: u32 = 0x4000_0001;
const RH_PLATFORM: u32 = 0x4000_000c;

pub const PPWRITE: u32 = 1 << 0;
pub const OWNERWRITE: u32 = 1 << 1;
pub const AUTHWRITE: u32 = 1 << 2;
pub const POLICYWRITE: u32 = 1 << 3;
const NT_SHIFT: u32 = 4;
const NT_MASK: u32 = 0xf << NT_SHIFT;
pub const WRITEALL: u32 = 1 << 12;
pub const PPREAD: u32 = 1 << 16;
pub const OWNERREAD: u32 = 1 << 17;
pub const AUTHREAD: u32 = 1 << 18;
pub const POLICYREAD: u32 = 1 << 19;
const NO_DA: u32 = 1 << 25;
const ORDERLY: u32 = 1 << 26;
const CLEAR_STCLEAR: u32 = 1 << 27;
pub const WRITTEN: u32 = 1 << 29;
const PLATFORMCREATE: u32 = 1 << 30;

const NT_ORDINARY: u32 = 0;
const NT_COUNTER: u32 = 1;
const NT_BITS: u32 = 2;
const NT_EXTEND: u32 = 4;

/// What a definition may set: the rest is a lock, a type this does not do, or
/// reserved.
const ACCEPTED: u32 = PPWRITE | OWNERWRITE | AUTHWRITE | POLICYWRITE | NT_MASK | WRITEALL | PPREAD | OWNERREAD | AUTHREAD | POLICYREAD | NO_DA | ORDERLY | CLEAR_STCLEAR | PLATFORMCREATE;
const WRITE_METHODS: u32 = PPWRITE | OWNERWRITE | AUTHWRITE | POLICYWRITE;
const READ_METHODS: u32 = PPREAD | OWNERREAD | AUTHREAD | POLICYREAD;

#[derive(Clone, Copy)]
pub struct Index {
    pub used: bool,
    pub handle: u32,
    pub attributes: u32,
    pub policy: [u8; 32],
    pub policy_len: usize,
    pub auth: [u8; 32],
    pub auth_len: usize,
    pub size: usize,
    pub data: [u8; DATA_MAX],
    /// Changed since it was last exported or imported.
    pub dirty: bool,
}

const EMPTY: Index = Index {
    used: false,
    handle: 0,
    attributes: 0,
    policy: [0; 32],
    policy_len: 0,
    auth: [0; 32],
    auth_len: 0,
    size: 0,
    data: [0; DATA_MAX],
    dirty: false,
};

static mut INDICES: [Index; SLOTS] = [EMPTY; SLOTS];

pub fn table() -> &'static mut [Index; SLOTS] {
    unsafe { &mut *(&raw mut INDICES) }
}

pub fn index_of(handle: u32) -> Option<&'static mut Index> {
    (handle >> 24 == 0x01).then_some(())?;
    table().iter_mut().find(|i| i.used && i.handle == handle)
}

pub fn handles() -> impl Iterator<Item = u32> {
    table().iter().filter(|i| i.used).map(|i| i.handle)
}

pub fn counters() -> usize {
    table().iter().filter(|i| i.used && (i.attributes & NT_MASK) >> NT_SHIFT == NT_COUNTER).count()
}

fn kind(index: &Index) -> u32 {
    (index.attributes & NT_MASK) >> NT_SHIFT
}

/// `TPMS_NV_PUBLIC`.
fn public(index: &Index, out: &mut [u8; 80]) -> usize {
    let mut at = 0;
    let mut put = |bytes: &[u8]| {
        out[at..at + bytes.len()].copy_from_slice(bytes);
        at += bytes.len();
    };
    put(&index.handle.to_be_bytes());
    put(&ALG_SHA256.to_be_bytes());
    put(&index.attributes.to_be_bytes());
    put(&(index.policy_len as u16).to_be_bytes());
    put(&index.policy[..index.policy_len]);
    put(&(index.size as u16).to_be_bytes());
    at
}

/// The name: the hash algorithm, then the hash of the public area as it is
/// now, `TPMA_NV_WRITTEN` and all.
pub fn name(index: &Index) -> [u8; 34] {
    let mut area = [0u8; 80];
    let len = public(index, &mut area);
    let mut name = [0u8; 34];
    name[..2].copy_from_slice(&ALG_SHA256.to_be_bytes());
    name[2..].copy_from_slice(&sha256::digest(&area[..len]));
    name
}

/// What authorizing with an index's own authorization value or policy takes:
/// for `Entity::of`.
pub struct Authority {
    pub auth: [u8; 32],
    pub auth_len: usize,
    pub policy: [u8; 32],
    pub policy_len: usize,
    pub user_with_auth: bool,
    pub written: bool,
}

pub fn authority(handle: u32) -> Result<Authority, u32> {
    let index = index_of(handle).ok_or(RC_HANDLE)?;
    Ok(Authority {
        auth: index.auth,
        auth_len: index.auth_len,
        policy: index.policy,
        policy_len: if index.attributes & (POLICYWRITE | POLICYREAD) != 0 { index.policy_len } else { 0 },
        user_with_auth: index.attributes & (AUTHWRITE | AUTHREAD) != 0,
        written: index.attributes & WRITTEN != 0,
    })
}

fn is_hierarchy(handle: u32) -> bool {
    handle == RH_OWNER || handle == RH_PLATFORM
}

/// Whether `auth` (the first handle) may write, or read, the index: the
/// hierarchy or the index's own value or policy, by what the attributes allow.
fn allowed(auth: u32, index: &Index, a: &Authorization, write: bool) -> Result<(), u32> {
    let (pp, owner, own_auth, own_policy) = if write {
        (PPWRITE, OWNERWRITE, AUTHWRITE, POLICYWRITE)
    } else {
        (PPREAD, OWNERREAD, AUTHREAD, POLICYREAD)
    };
    let ok = match auth {
        RH_PLATFORM => index.attributes & pp != 0,
        RH_OWNER => index.attributes & owner != 0,
        handle if handle == index.handle => {
            if a.first_is_policy() {
                index.attributes & own_policy != 0
            } else {
                index.attributes & own_auth != 0
            }
        }
        _ => return Err(RC_HANDLE | RC_1),
    };
    if ok { Ok(()) } else { Err(RC_AUTH_UNAVAILABLE) }
}

fn out_buffer(a: &mut Authorization, data: &[u8]) {
    let mut response = [0u8; 2 + DATA_MAX];
    response[..2].copy_from_slice(&(data.len() as u16).to_be_bytes());
    response[2..2 + data.len()].copy_from_slice(data);
    a.response_params(&response[..2 + data.len()]);
}

/// `TPM2_NV_DefineSpace`.
pub fn define_space(handles: [u32; 2], params: &mut In, _a: &mut Authorization) -> Result<(), u32> {
    let auth_handle = handles[0];
    if !is_hierarchy(auth_handle) {
        return Err(RC_HANDLE | RC_1);
    }
    let auth = params.sized().ok_or(RC_COMMAND_SIZE)?;
    let info = params.sized().ok_or(RC_COMMAND_SIZE)?;
    if params.rest() != 0 {
        return Err(RC_COMMAND_SIZE);
    }
    if auth.len() > 32 {
        return Err(RC_SIZE | RC_P | RC_1);
    }
    let mut p = In { buf: info, at: 0 };
    let handle = p.u32().ok_or(RC_SIZE | RC_P | RC_2)?;
    let name_alg = p.u16().ok_or(RC_SIZE | RC_P | RC_2)?;
    let attributes = p.u32().ok_or(RC_SIZE | RC_P | RC_2)?;
    let policy = p.sized().ok_or(RC_SIZE | RC_P | RC_2)?;
    let size = p.u16().ok_or(RC_SIZE | RC_P | RC_2)? as usize;
    if p.rest() != 0 {
        return Err(RC_SIZE | RC_P | RC_2);
    }
    if handle >> 24 != 0x01 {
        return Err(RC_VALUE | RC_P | RC_2);
    }
    if name_alg != ALG_SHA256 {
        return Err(super::RC_HASH | RC_P | RC_2);
    }
    let platform = auth_handle == RH_PLATFORM;
    if (attributes & PLATFORMCREATE != 0) != platform {
        return Err(RC_ATTRIBUTES | RC_P | RC_2);
    }
    if attributes & !ACCEPTED != 0 || attributes & WRITTEN != 0 || attributes & WRITE_METHODS == 0 || attributes & READ_METHODS == 0 {
        return Err(RC_ATTRIBUTES | RC_P | RC_2);
    }
    let wants_policy = attributes & (POLICYWRITE | POLICYREAD) != 0;
    if (wants_policy && policy.len() != 32) || (!wants_policy && !policy.is_empty() && policy.len() != 32) {
        return Err(RC_SIZE | RC_P | RC_2);
    }
    let valid_size = match (attributes & NT_MASK) >> NT_SHIFT {
        NT_ORDINARY => (1..=DATA_MAX).contains(&size),
        NT_COUNTER | NT_BITS => size == 8,
        NT_EXTEND => size == 32,
        _ => return Err(RC_ATTRIBUTES | RC_P | RC_2),
    };
    if !valid_size {
        return Err(RC_SIZE | RC_P | RC_2);
    }
    if index_of(handle).is_some() {
        return Err(RC_NV_DEFINED);
    }
    let slot = table().iter_mut().find(|i| !i.used).ok_or(RC_NV_SPACE)?;
    *slot = EMPTY;
    slot.used = true;
    slot.handle = handle;
    slot.attributes = attributes;
    slot.policy[..policy.len()].copy_from_slice(policy);
    slot.policy_len = policy.len();
    slot.auth[..auth.len()].copy_from_slice(auth);
    slot.auth_len = auth.len();
    slot.size = size;
    slot.dirty = true;
    forget_removal(handle);
    Ok(())
}

/// `TPM2_NV_UndefineSpace`.
pub fn undefine_space(handles: [u32; 2]) -> Result<(), u32> {
    let index = index_of(handles[1]).ok_or(RC_HANDLE | RC_2)?;
    let created_by_platform = index.attributes & PLATFORMCREATE != 0;
    match handles[0] {
        RH_PLATFORM => {}
        RH_OWNER if !created_by_platform => {}
        RH_OWNER => return Err(RC_NV_AUTHORIZATION),
        _ => return Err(RC_HANDLE | RC_1),
    }
    keystore::zero(&mut index.data);
    keystore::zero(&mut index.auth);
    let handle = index.handle;
    *index = EMPTY;
    note_removal(handle);
    Ok(())
}

/// `TPM2_NV_ReadPublic`.
pub fn read_public(handle: u32, a: &mut Authorization) -> Result<(), u32> {
    let index = index_of(handle).ok_or(RC_HANDLE | RC_1)?;
    let mut area = [0u8; 80];
    let len = public(index, &mut area);
    let name = name(index);
    let mut response = [0u8; 2 + 80 + 2 + 34];
    response[..2].copy_from_slice(&(len as u16).to_be_bytes());
    response[2..2 + len].copy_from_slice(&area[..len]);
    response[2 + len..4 + len].copy_from_slice(&34u16.to_be_bytes());
    response[4 + len..4 + len + 34].copy_from_slice(&name);
    a.response_params(&response[..4 + len + 34]);
    Ok(())
}

/// `TPM2_NV_Read`.
pub fn read(handles: [u32; 2], params: &mut In, a: &mut Authorization) -> Result<(), u32> {
    let size = params.u16().ok_or(RC_COMMAND_SIZE)? as usize;
    let offset = params.u16().ok_or(RC_COMMAND_SIZE)? as usize;
    if params.rest() != 0 {
        return Err(RC_COMMAND_SIZE);
    }
    let index = index_of(handles[1]).ok_or(RC_HANDLE | RC_2)?;
    allowed(handles[0], index, a, false)?;
    if index.attributes & WRITTEN == 0 {
        return Err(RC_NV_UNINITIALIZED);
    }
    if size > DATA_MAX || offset > index.size || size > index.size - offset {
        return Err(RC_NV_RANGE);
    }
    let data = index.data;
    out_buffer(a, &data[offset..offset + size]);
    Ok(())
}

fn written(index: &mut Index) {
    index.attributes |= WRITTEN;
    index.dirty = true;
}

/// `TPM2_NV_Write`: an ordinary index.
pub fn write(handles: [u32; 2], params: &mut In, a: &mut Authorization) -> Result<(), u32> {
    let data = params.sized().ok_or(RC_COMMAND_SIZE)?;
    let offset = params.u16().ok_or(RC_COMMAND_SIZE)? as usize;
    if params.rest() != 0 {
        return Err(RC_COMMAND_SIZE);
    }
    let index = index_of(handles[1]).ok_or(RC_HANDLE | RC_2)?;
    allowed(handles[0], index, a, true)?;
    if kind(index) != NT_ORDINARY {
        return Err(RC_ATTRIBUTES | RC_2);
    }
    if offset > index.size || data.len() > index.size - offset {
        return Err(RC_NV_RANGE);
    }
    if index.attributes & WRITEALL != 0 && data.len() != index.size {
        return Err(RC_NV_RANGE);
    }
    index.data[offset..offset + data.len()].copy_from_slice(data);
    written(index);
    Ok(())
}

/// `TPM2_NV_Extend`: an extend index becomes the hash of what it held and the
/// data.
pub fn extend(handles: [u32; 2], params: &mut In, a: &mut Authorization) -> Result<(), u32> {
    let data = params.sized().ok_or(RC_COMMAND_SIZE)?;
    if params.rest() != 0 {
        return Err(RC_COMMAND_SIZE);
    }
    let index = index_of(handles[1]).ok_or(RC_HANDLE | RC_2)?;
    allowed(handles[0], index, a, true)?;
    if kind(index) != NT_EXTEND {
        return Err(RC_ATTRIBUTES | RC_2);
    }
    let mut hash = sha256::Sha256::new();
    hash.update(&index.data[..32]);
    hash.update(data);
    index.data[..32].copy_from_slice(&hash.finish());
    written(index);
    Ok(())
}

/// `TPM2_NV_Increment`: a counter.
pub fn increment(handles: [u32; 2], a: &mut Authorization) -> Result<(), u32> {
    let index = index_of(handles[1]).ok_or(RC_HANDLE | RC_2)?;
    allowed(handles[0], index, a, true)?;
    if kind(index) != NT_COUNTER {
        return Err(RC_ATTRIBUTES | RC_2);
    }
    let value = u64::from_be_bytes(index.data[..8].try_into().unwrap()).checked_add(1).ok_or(RC_NV_UNAVAILABLE)?;
    index.data[..8].copy_from_slice(&value.to_be_bytes());
    written(index);
    Ok(())
}

/// `TPM2_NV_SetBits`: a bit field.
pub fn set_bits(handles: [u32; 2], params: &mut In, a: &mut Authorization) -> Result<(), u32> {
    let bits = u64::from_be_bytes(params.take(8).ok_or(RC_COMMAND_SIZE)?.try_into().unwrap());
    if params.rest() != 0 {
        return Err(RC_COMMAND_SIZE);
    }
    let index = index_of(handles[1]).ok_or(RC_HANDLE | RC_2)?;
    allowed(handles[0], index, a, true)?;
    if kind(index) != NT_BITS {
        return Err(RC_ATTRIBUTES | RC_2);
    }
    let value = u64::from_be_bytes(index.data[..8].try_into().unwrap()) | bits;
    index.data[..8].copy_from_slice(&value.to_be_bytes());
    written(index);
    Ok(())
}

// The indices outlast a boot as records on the boot disk. Only the VPU can
// make or open one: a record is the index's state encrypted and authenticated
// under keys from the device key, so the disk, which the OS owns, can drop or
// replace records but not forge or read them.

const RECORD_LABEL: &[u8] = b"nuboot NV index record v1";
const ENCRYPTION_LABEL: &[u8] = b"nv index encryption";
const INTEGRITY_LABEL: &[u8] = b"nv index integrity";
const BODY_FIXED: usize = 4 + 1 + 32 + 1 + 32 + 2;
const RECORD_HEAD: usize = 8 + 4 + 16 + 2;
const MAC: usize = 32;
/// The most a record holds.
pub const RECORD_MAX: usize = RECORD_HEAD + BODY_FIXED + DATA_MAX + MAC;
/// What a stored index may have set: what a definition may, and whether it was
/// written.
const STORED: u32 = ACCEPTED | WRITTEN;

/// The handles undefined since the last export, oldest first, so that the
/// disk forgets them as well. When it is full, the oldest is lost.
static mut REMOVED: [u32; 2 * SLOTS] = [0; 2 * SLOTS];
/// The number of the last record exported or imported: what stops an older
/// record being put back after a newer one.
static mut LAST_SEQ: u64 = 0;

fn removed() -> &'static mut [u32; 2 * SLOTS] {
    unsafe { &mut *(&raw mut REMOVED) }
}

fn note_removal(handle: u32) {
    if !keystore::device_key_fused() {
        return;
    }
    let list = removed();
    if list.contains(&handle) {
        return;
    }
    match list.iter_mut().find(|h| **h == 0) {
        Some(free) => *free = handle,
        None => {
            list.copy_within(1.., 0);
            list[list.len() - 1] = handle;
        }
    }
}

fn forget_removal(handle: u32) {
    for h in removed().iter_mut().filter(|h| **h == handle) {
        *h = 0;
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ExportError {
    Nothing,
    NoDeviceKey,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ImportError {
    NoDeviceKey,
    Malformed,
    Stale,
    Busy,
    NoSpace,
}

fn keys() -> (aes::Aes128, [u8; 32]) {
    let mut encryption = keystore::tpm_secret(ENCRYPTION_LABEL, true);
    let mac = keystore::tpm_secret(INTEGRITY_LABEL, true);
    let key = aes::Aes128::new(encryption[..16].try_into().unwrap());
    keystore::zero(&mut encryption);
    (key, mac)
}

fn mac_of(key: &[u8; 32], head_and_body: &[u8]) -> [u8; 32] {
    let mut message = [0u8; RECORD_LABEL.len() + RECORD_MAX];
    message[..RECORD_LABEL.len()].copy_from_slice(RECORD_LABEL);
    message[RECORD_LABEL.len()..RECORD_LABEL.len() + head_and_body.len()].copy_from_slice(head_and_body);
    sha256::hmac(key, &message[..RECORD_LABEL.len() + head_and_body.len()])
}

/// The next change to an index, as a record for the disk: the number, the
/// handle, the IV, the length of the body, the body (the index's state,
/// encrypted; none for an index that was undefined) and the MAC. The change is
/// then the disk's to keep.
pub fn export(out: &mut [u8; RECORD_MAX]) -> Result<usize, ExportError> {
    if !keystore::device_key_fused() {
        return Err(ExportError::NoDeviceKey);
    }
    let (handle, body_len) = match table().iter_mut().find(|i| i.used && i.dirty) {
        Some(index) => (index.handle, BODY_FIXED + index.size),
        None => match removed().iter().copied().find(|h| *h != 0) {
            Some(handle) => (handle, 0),
            None => return Err(ExportError::Nothing),
        },
    };
    let mut iv = [0u8; 16];
    if !rng::fill(&mut iv) {
        return Err(ExportError::NoDeviceKey);
    }
    let seq = unsafe { LAST_SEQ }.checked_add(1).ok_or(ExportError::NoDeviceKey)?;
    out[..8].copy_from_slice(&seq.to_le_bytes());
    out[8..12].copy_from_slice(&handle.to_le_bytes());
    out[12..28].copy_from_slice(&iv);
    out[28..30].copy_from_slice(&(body_len as u16).to_le_bytes());
    let (cipher, mac_key) = keys();
    if body_len != 0 {
        let index = index_of(handle).unwrap();
        let body = &mut out[RECORD_HEAD..RECORD_HEAD + body_len];
        body[..4].copy_from_slice(&index.attributes.to_le_bytes());
        body[4] = index.policy_len as u8;
        body[5..37].copy_from_slice(&index.policy);
        body[37] = index.auth_len as u8;
        body[38..70].copy_from_slice(&index.auth);
        body[70..72].copy_from_slice(&(index.size as u16).to_le_bytes());
        body[72..].copy_from_slice(&index.data[..index.size]);
        cipher.cfb_encrypt(&iv, body);
        index.dirty = false;
    } else {
        forget_removal(handle);
    }
    let end = RECORD_HEAD + body_len;
    let mac = mac_of(&mac_key, &out[..end]);
    out[end..end + MAC].copy_from_slice(&mac);
    unsafe { LAST_SEQ = seq };
    Ok(end + MAC)
}

/// Put back what a record from the disk holds, if this firmware made it and
/// nothing newer has been taken. An index that clears at a restart
/// (`TPMA_NV_CLEAR_STCLEAR`) comes back empty, as the boot is one.
pub fn import(record: &[u8]) -> Result<(), ImportError> {
    if !keystore::device_key_fused() {
        return Err(ImportError::NoDeviceKey);
    }
    if record.len() < RECORD_HEAD + MAC || record.len() > RECORD_MAX {
        return Err(ImportError::Malformed);
    }
    let body_len = u16::from_le_bytes(record[28..30].try_into().unwrap()) as usize;
    let valid_body = body_len == 0 || (BODY_FIXED..=BODY_FIXED + DATA_MAX).contains(&body_len);
    if !valid_body || record.len() != RECORD_HEAD + body_len + MAC {
        return Err(ImportError::Malformed);
    }
    let (signed, mac) = record.split_at(RECORD_HEAD + body_len);
    let (cipher, mac_key) = keys();
    let expected = mac_of(&mac_key, signed);
    if expected.iter().zip(mac).fold(0, |different, (a, b)| different | (a ^ b)) != 0 {
        return Err(ImportError::Malformed);
    }
    let seq = u64::from_le_bytes(record[..8].try_into().unwrap());
    let handle = u32::from_le_bytes(record[8..12].try_into().unwrap());
    if seq <= unsafe { LAST_SEQ } {
        return Err(ImportError::Stale);
    }
    if handle >> 24 != 0x01 {
        return Err(ImportError::Malformed);
    }
    let existing = table().iter().position(|i| i.used && i.handle == handle);
    if existing.is_some_and(|n| table()[n].dirty) {
        return Err(ImportError::Busy);
    }
    if body_len == 0 {
        if let Some(n) = existing {
            table()[n] = EMPTY;
        }
        unsafe { LAST_SEQ = seq };
        return Ok(());
    }
    let slot = match existing.or_else(|| table().iter().position(|i| !i.used)) {
        Some(n) => n,
        None => return Err(ImportError::NoSpace),
    };
    let iv: [u8; 16] = record[12..28].try_into().unwrap();
    let mut body = [0u8; BODY_FIXED + DATA_MAX];
    let body = &mut body[..body_len];
    body.copy_from_slice(&record[RECORD_HEAD..RECORD_HEAD + body_len]);
    cipher.cfb_decrypt(&iv, body);
    let attributes = u32::from_le_bytes(body[..4].try_into().unwrap());
    let (policy_len, auth_len) = (body[4] as usize, body[37] as usize);
    let size = u16::from_le_bytes(body[70..72].try_into().unwrap()) as usize;
    if attributes & !STORED != 0 || policy_len > 32 || auth_len > 32 || size > DATA_MAX || BODY_FIXED + size != body_len {
        keystore::zero(body);
        return Err(ImportError::Malformed);
    }
    let mut index = EMPTY;
    index.used = true;
    index.handle = handle;
    index.attributes = attributes;
    index.policy = body[5..37].try_into().unwrap();
    index.policy_len = policy_len;
    index.auth = body[38..70].try_into().unwrap();
    index.auth_len = auth_len;
    index.size = size;
    index.data[..size].copy_from_slice(&body[72..]);
    keystore::zero(body);
    if attributes & CLEAR_STCLEAR != 0 {
        keystore::zero(&mut index.data);
        index.attributes &= !WRITTEN;
    }
    table()[slot] = index;
    unsafe { LAST_SEQ = seq };
    Ok(())
}

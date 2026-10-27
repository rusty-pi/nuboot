//! NV indices: ordinary, counter, bit field and extend. They live in RAM, like
//! the PCRs, and are gone when the TPM starts again.
//!
//! An index is authorized by its own authorization value or its policy, or by
//! the owner or the platform hierarchy, as its attributes say. Locks
//! (`WRITELOCKED`, `READLOCKED` and their `*_STCLEAR`, `GLOBALLOCK`) and the
//! PIN types are not offered: an index that asks for them is not defined.

use super::session::Authorization;
use super::{In, RC_ATTRIBUTES, RC_COMMAND_SIZE, RC_HANDLE, RC_NV_DEFINED, RC_NV_SPACE, RC_P, RC_SIZE, RC_VALUE, RC_1, RC_2};
use crate::{keystore, sha256};

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
    *index = EMPTY;
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

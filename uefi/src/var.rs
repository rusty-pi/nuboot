//! UEFI variables, kept in memory for the boot. The Secure Boot state and
//! keys are built in and cannot be written.

use alloc::vec::Vec;
use core::ffi::c_void;

use r_efi::efi;

use crate::util::{Global, W, wstr};
use crate::{debug, warn};

struct Var {
    name: Vec<u16>,
    guid: efi::Guid,
    attributes: u32,
    data: Vec<u8>,
    /// Built in: no `SetVariable` changes it.
    fixed: bool,
}

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
    let name: Vec<u16> = name.encode_utf16().collect();
    let vars = VARS.get();
    vars.retain(|v| !(v.guid == guid && v.name == name));
    vars.push(Var { name, guid, attributes, data, fixed: true });
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
    let Some(i) = find(name, unsafe { &*guid }) else { return efi::Status::NOT_FOUND };
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
    let Some(v) = vars.get(next) else { return efi::Status::NOT_FOUND };
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
    if attributes & AUTH != 0 {
        warn!("var", "authenticated variables cannot be written"; name = W(name));
        return efi::Status::WRITE_PROTECTED;
    }
    let bytes = unsafe { core::slice::from_raw_parts(data as *const u8, size) };
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
        None => VARS.get().push(Var { name: name.to_vec(), guid, attributes, data: bytes.to_vec(), fixed: false }),
    }
    debug!("var", "variable set"; name = W(name), bytes = size);
    efi::Status::SUCCESS
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

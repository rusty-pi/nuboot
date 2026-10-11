//! The EFI System Resource Table: the one resource a firmware update
//! capsule can replace, this firmware itself, with the version it is and the
//! result of the last capsule applied. fwupd's `uefi-capsule` plugin reads it
//! through `/sys/firmware/efi/esrt`.

use core::ffi::c_void;

use alloc::vec;
use r_efi::efi;

use crate::util::Global;
use crate::{mem, tables, var};

/// `EFI_SYSTEM_RESOURCE_TABLE_GUID`.
const ESRT_GUID: efi::Guid =
    efi::Guid::from_fields(0xb122a263, 0x3661, 0x4f68, 0x99, 0x29, &[0x78, 0xf8, 0xb0, 0xd6, 0x21, 0x80]);

/// What a capsule for this firmware names: `ESRT_FIRMWARE_CLASS`.
pub const FIRMWARE_CLASS: efi::Guid =
    efi::Guid::from_fields(0x7d1c0a4e, 0x5b83, 0x4f2a, 0x9c, 0x61, &[0xe2, 0x08, 0x4a, 0x3d, 0x95, 0xb7]);

const FIRMWARE_TYPE_SYSTEM: u32 = 1;
/// `ESRT` entry's version: 1.
const TABLE_VERSION: u64 = 1;
/// `LAST_ATTEMPT_STATUS_SUCCESS`.
const SUCCESS: u32 = 0;
pub const UNSUCCESSFUL: u32 = 1;
pub const INSUFFICIENT_RESOURCES: u32 = 2;
pub const INCORRECT_VERSION: u32 = 3;
pub const INVALID_FORMAT: u32 = 4;
pub const AUTH_ERROR: u32 = 5;

/// The commit's time, in seconds: what orders one build after another.
pub const VERSION: u32 = match u32::from_str_radix(env!("FIRMWARE_TIME"), 10) {
    Ok(time) => time,
    Err(_) => 0,
};

/// `EFI_OS_INDICATIONS_FILE_CAPSULE_DELIVERY_SUPPORTED`.
const FILE_CAPSULE_DELIVERY: u64 = 4;

#[repr(C)]
struct Entry {
    class: efi::Guid,
    kind: u32,
    version: u32,
    lowest_supported: u32,
    capsule_flags: u32,
    last_attempt_version: u32,
    last_attempt_status: u32,
}

#[repr(C)]
struct Table {
    count: u32,
    count_max: u32,
    version: u64,
    entry: Entry,
}

static TABLE: Global<*mut Table> = Global::new(core::ptr::null_mut());

/// Record the last capsule attempt for the OS: the version it carried and how
/// it went.
pub fn attempted(version: u32, status: u32) {
    let table = *TABLE.get();
    if !table.is_null() {
        unsafe {
            (*table).entry.last_attempt_version = version;
            (*table).entry.last_attempt_status = status;
        }
    }
}

pub fn init() {
    let at = mem::alloc_pages(efi::BOOT_SERVICES_DATA, 1).expect("ESRT page") as *mut Table;
    unsafe {
        at.write(Table {
            count: 1,
            count_max: 1,
            version: TABLE_VERSION,
            entry: Entry {
                class: FIRMWARE_CLASS,
                kind: FIRMWARE_TYPE_SYSTEM,
                version: VERSION,
                lowest_supported: 1,
                capsule_flags: 0,
                last_attempt_version: 0,
                last_attempt_status: SUCCESS,
            },
        })
    };
    *TABLE.get() = at;
    tables::install_table(ESRT_GUID, at as *mut c_void);
    var::fixed("OsIndicationsSupported", var::GLOBAL, var::BS | var::RT, FILE_CAPSULE_DELIVERY.to_le_bytes().to_vec());
    var::seed("OsIndications", var::GLOBAL, var::NV | var::BS | var::RT, vec![0; 8]);
}

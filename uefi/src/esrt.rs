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

/// What a capsule for the EEPROM bootloader names.
pub const EEPROM_CLASS: efi::Guid =
    efi::Guid::from_fields(0x3f8a0c5e, 0x91d2, 0x4b7a, 0xa6, 0xc3, &[0x5d, 0x1e, 0x08, 0xf2, 0xb9, 0x47]);

/// What a capsule for an update bundle names: the VPU firmware and this one,
/// signed by an update key instead of the board owner's.
pub const UPDATE_CLASS: efi::Guid =
    efi::Guid::from_fields(0xb4c1e7a2, 0x6d39, 0x4f58, 0x8e, 0x10, &[0x72, 0xa9, 0xc5, 0xd3, 0xf0, 0xb6]);

const FIRMWARE_TYPE_SYSTEM: u32 = 1;
const FIRMWARE_TYPE_DEVICE: u32 = 2;
/// `ESRT` entry's version: 1.
const TABLE_VERSION: u64 = 1;
/// `LAST_ATTEMPT_STATUS_SUCCESS`.
pub const SUCCESS: u32 = 0;
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

/// `EFI_OS_INDICATIONS_BOOT_TO_FW_UI`: the OS asks for the firmware's own
/// screen at the next boot.
pub const BOOT_TO_FW_UI: u64 = 1;
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
    entries: [Entry; 3],
}

static TABLE: Global<*mut Table> = Global::new(core::ptr::null_mut());

/// Record the last capsule attempt for the OS: the resource it was for, the
/// version it carried and how it went.
pub fn attempted(class: &efi::Guid, version: u32, status: u32) {
    let table = *TABLE.get();
    if table.is_null() {
        return;
    }
    for entry in unsafe { &mut (*table).entries } {
        if entry.class == *class {
            entry.last_attempt_version = version;
            entry.last_attempt_status = status;
        }
    }
}

pub fn init() {
    crate::info!("esrt", "resources"; firmware = VERSION, eeprom = crate::eeprom::version());
    let at = mem::alloc_pages(efi::BOOT_SERVICES_DATA, 1).expect("ESRT page") as *mut Table;
    unsafe {
        at.write(Table {
            count: 3,
            count_max: 3,
            version: TABLE_VERSION,
            entries: [
                Entry {
                    class: FIRMWARE_CLASS,
                    kind: FIRMWARE_TYPE_SYSTEM,
                    version: VERSION,
                    lowest_supported: 1,
                    capsule_flags: 0,
                    last_attempt_version: 0,
                    last_attempt_status: SUCCESS,
                },
                Entry {
                    class: UPDATE_CLASS,
                    kind: FIRMWARE_TYPE_SYSTEM,
                    version: VERSION,
                    lowest_supported: 1,
                    capsule_flags: 0,
                    last_attempt_version: 0,
                    last_attempt_status: SUCCESS,
                },
                Entry {
                    class: EEPROM_CLASS,
                    kind: FIRMWARE_TYPE_DEVICE,
                    version: crate::eeprom::version(),
                    lowest_supported: 1,
                    capsule_flags: 0,
                    last_attempt_version: 0,
                    last_attempt_status: SUCCESS,
                },
            ],
        })
    };
    *TABLE.get() = at;
    tables::install_table(ESRT_GUID, at as *mut c_void);
    var::fixed("OsIndicationsSupported", var::GLOBAL, var::BS | var::RT, (BOOT_TO_FW_UI | FILE_CAPSULE_DELIVERY).to_le_bytes().to_vec());
    var::seed("OsIndications", var::GLOBAL, var::NV | var::BS | var::RT, vec![0; 8]);
}

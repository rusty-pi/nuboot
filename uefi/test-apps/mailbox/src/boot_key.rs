//! Asks for the boot key bound to PCR 4, the images, then extends a PCR and
//! asks again: the key goes once.

#![no_std]
#![no_main]

use r_efi::efi::{Handle, Status, SystemTable};

#[path = "boot_key_common.rs"]
mod common;

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(_image: Handle, system_table: *mut SystemTable) -> Status {
    common::boot_key_test(system_table, 0x10)
}

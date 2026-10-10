//! Asks for the boot key bound to nothing: one stable key per board, whatever
//! was booted.

#![no_std]
#![no_main]

use r_efi::efi::{Handle, Status, SystemTable};

#[path = "boot_key_common.rs"]
mod common;

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(_image: Handle, system_table: *mut SystemTable) -> Status {
    common::boot_key_test(system_table, 0x0)
}

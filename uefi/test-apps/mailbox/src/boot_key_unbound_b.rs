//! The same as `boot_key_unbound`, a different image: the key it gets has to
//! be the same.

#![no_std]
#![no_main]

use r_efi::efi::{Handle, Status, SystemTable};

#[path = "boot_key_common.rs"]
mod common;

#[used]
static MARK: [u8; 16] = *b"another image..\0";

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(_image: Handle, system_table: *mut SystemTable) -> Status {
    common::boot_key_test(system_table, 0x0)
}

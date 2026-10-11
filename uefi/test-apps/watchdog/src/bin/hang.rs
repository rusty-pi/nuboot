//! Asks for a one-second watchdog, then hangs in boot services.

#![no_std]
#![no_main]

use r_efi::efi::{Handle, Status, SystemTable};
use watchdog_efi::{after_reset, hang, say};

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(_image: Handle, system_table: *mut SystemTable) -> Status {
    after_reset(system_table);
    unsafe {
        let bs = (*system_table).boot_services;
        ((*bs).set_watchdog_timer)(1, 0, 0, core::ptr::null_mut());
    }
    say(system_table, "watchdog test: hanging in boot services\r\n");
    hang()
}

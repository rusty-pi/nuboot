//! Asks for ten minutes of watchdog, then executes an undefined instruction: a
//! fault that stops the firmware, which has to let the watchdog reset the
//! board.

#![no_std]
#![no_main]

use r_efi::efi::{Handle, Status, SystemTable};
use watchdog_efi::say;

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(_image: Handle, system_table: *mut SystemTable) -> Status {
    unsafe {
        let bs = (*system_table).boot_services;
        ((*bs).set_watchdog_timer)(600, 0, 0, core::ptr::null_mut());
    }
    say(system_table, "watchdog test: faulting\r\n");
    unsafe { core::arch::asm!("udf #0") };
    Status::SUCCESS
}

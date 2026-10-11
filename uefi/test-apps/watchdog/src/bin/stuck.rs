//! Asks for ten minutes of watchdog, then masks interrupts and spins: an ARM
//! that is stuck without the timer interrupt that beats the dog.

#![no_std]
#![no_main]

use r_efi::efi::{Handle, Status, SystemTable};
use watchdog_efi::{after_reset, hang, say};

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(_image: Handle, system_table: *mut SystemTable) -> Status {
    after_reset(system_table);
    unsafe {
        let bs = (*system_table).boot_services;
        ((*bs).set_watchdog_timer)(600, 0, 0, core::ptr::null_mut());
    }
    say(system_table, "watchdog test: masking interrupts\r\n");
    unsafe { core::arch::asm!("msr daifset, #2") };
    hang()
}

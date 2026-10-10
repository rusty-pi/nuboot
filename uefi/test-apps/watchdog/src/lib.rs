//! EFI applications the watchdog scenarios boot: each says what it is about
//! to do, then does something the boot watchdog has to deal with.

#![no_std]

use r_efi::efi::{self, Char16, SystemTable};

/// Print `text` (ASCII) on the console.
pub fn say(system_table: *mut SystemTable, text: &str) {
    let mut buf = [0 as Char16; 128];
    for (i, b) in text.bytes().take(buf.len() - 1).enumerate() {
        buf[i] = b as Char16;
    }
    unsafe {
        let con_out = (*system_table).con_out;
        ((*con_out).output_string)(con_out, buf.as_mut_ptr());
    }
}

pub fn hang() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    hang()
}

pub type Status = efi::Status;

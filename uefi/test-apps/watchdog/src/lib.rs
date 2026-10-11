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

const MARKER_GUID: efi::Guid = efi::Guid::from_fields(0x7c1a4e2b, 0x5d3f, 0x4a96, 0x8b, 0x02, &[0x61, 0x9c, 0xe4, 0x37, 0xa8, 0x15]);
const NON_VOLATILE: u32 = 1;
const BOOT_SERVICES: u32 = 2;
const RUNTIME: u32 = 4;

/// Whether this board has run the application before: the first run leaves
/// a variable in the flash store, which the board's reset does not take.
pub fn booted_before(system_table: *mut SystemTable) -> bool {
    let mut name = [0 as Char16; 13];
    for (i, b) in b"WatchdogTest".iter().enumerate() {
        name[i] = *b as Char16;
    }
    let mut guid = MARKER_GUID;
    let mut size = 1usize;
    let mut value = [0u8; 1];
    unsafe {
        let rt = (*system_table).runtime_services;
        let status = ((*rt).get_variable)(name.as_mut_ptr(), &mut guid, core::ptr::null_mut(), &mut size, value.as_mut_ptr().cast());
        if status == efi::Status::SUCCESS {
            return true;
        }
        value[0] = 1;
        ((*rt).set_variable)(name.as_mut_ptr(), &mut guid, NON_VOLATILE | BOOT_SERVICES | RUNTIME, 1, value.as_mut_ptr().cast());
    }
    false
}

/// Say the board came back from its reset, which is what the scenarios wait
/// for, and stop.
pub fn after_reset(system_table: *mut SystemTable) {
    if booted_before(system_table) {
        say(system_table, "watchdog test: the board reset and booted again\r\n");
        hang()
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

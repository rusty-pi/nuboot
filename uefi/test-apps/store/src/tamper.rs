//! Says which of the variables the tamper scenario's flash store holds the
//! firmware restored.

#![no_std]
#![no_main]

use core::ffi::c_void;
use core::ptr::null_mut;

use r_efi::efi::{Char16, Guid, Handle, Status, SystemTable};

const GUID: Guid = Guid::from_fields(0x5d0f3a58, 0x1c0e, 0x4d1b, 0x9a, 0x44, &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab]);

fn say(system_table: *mut SystemTable, text: &str) {
    let mut buf = [0 as Char16; 80];
    for (i, b) in text.bytes().take(buf.len() - 1).enumerate() {
        buf[i] = b as Char16;
    }
    unsafe {
        let con_out = (*system_table).con_out;
        ((*con_out).output_string)(con_out, buf.as_mut_ptr());
    }
}

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(_image: Handle, system_table: *mut SystemTable) -> Status {
    let rt = unsafe { (*system_table).runtime_services };
    for name in ["Good", "Fresh", "Forged", "Stale", "Torn", "AfterTorn"] {
        let mut wide = [0u16; 16];
        for (i, b) in name.bytes().enumerate() {
            wide[i] = b as u16;
        }
        let mut value = [0u8; 16];
        let mut size = value.len();
        let status = unsafe {
            ((*rt).get_variable)(wide.as_mut_ptr(), &GUID as *const _ as *mut _, null_mut(), &mut size,
                value.as_mut_ptr() as *mut c_void)
        };
        say(system_table, "tamper test: ");
        say(system_table, name);
        say(system_table, if status.is_error() { " absent\r\n" } else { " present\r\n" });
    }
    say(system_table, "tamper test: done\r\n");
    Status::SUCCESS
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

//! Says which of the variables the tamper scenario's flash store holds the
//! firmware restored.

#![no_std]
#![no_main]

use core::ffi::c_void;
use core::ptr::null_mut;

use r_efi::efi::{Char16, Guid, Handle, Status, SystemTable};

const GUID: Guid = Guid::from_fields(0x5d0f3a58, 0x1c0e, 0x4d1b, 0x9a, 0x44, &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab]);
const GLOBAL: Guid = Guid::from_fields(0x8be4df61, 0x93ca, 0x11d2, 0xaa, 0x0d, &[0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c]);
const FIRMWARE_CLASS: Guid = Guid::from_fields(0x7d1c0a4e, 0x5b83, 0x4f2a, 0x9c, 0x61, &[0xe2, 0x08, 0x4a, 0x3d, 0x95, 0xb7]);

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
    for (name, guid) in [
        ("Good", &GUID),
        ("Fresh", &GUID),
        ("Forged", &GUID),
        ("Stale", &GUID),
        ("Torn", &GUID),
        ("AfterTorn", &GUID),
        ("Hidden", &GUID),
        ("RuntimeOk", &GUID),
        ("SecureBoot", &GLOBAL),
        ("FwUpdateResult", &FIRMWARE_CLASS),
    ] {
        let mut wide = [0u16; 16];
        for (i, b) in name.bytes().enumerate() {
            wide[i] = b as u16;
        }
        let mut value = [0u8; 16];
        let mut size = value.len();
        let status = unsafe {
            ((*rt).get_variable)(wide.as_mut_ptr(), guid as *const _ as *mut _, null_mut(), &mut size,
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

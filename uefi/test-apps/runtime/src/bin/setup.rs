//! An OS asks for the firmware's screen with `OsIndications`: the firmware
//! offers the bit, shows its screen at the next boot, and takes the request
//! back. The first boot sets the bit and resets; the second checks it is gone.

#![no_std]
#![no_main]

use core::ffi::c_void;

use r_efi::efi::{self, Guid, Handle, RuntimeServices, Status, SystemTable};
use runtime_efi::{check, name, say};

const NV_BS_RT: u32 = efi::VARIABLE_NON_VOLATILE | efi::VARIABLE_BOOTSERVICE_ACCESS | efi::VARIABLE_RUNTIME_ACCESS;
const GLOBAL: Guid = Guid::from_fields(0x8be4df61, 0x93ca, 0x11d2, 0xaa, 0x0d, &[0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c]);
const OURS: Guid = Guid::from_fields(0x6b1c0a52, 0x3a7e, 0x4d1f, 0x9a, 0x0b, &[0x11, 0x22, 0x33, 0x44, 0x55, 0x67]);
const BOOT_TO_FW_UI: u64 = 1;

fn set(rt: *mut RuntimeServices, var: &str, guid: &Guid, data: &[u8]) -> Status {
    let mut buf = [0u16; 32];
    let n = name(var, &mut buf);
    let mut guid = *guid;
    unsafe { ((*rt).set_variable)(n, &mut guid, NV_BS_RT, data.len(), data.as_ptr() as *mut c_void) }
}

fn get(rt: *mut RuntimeServices, var: &str, guid: &Guid, out: &mut [u8]) -> (Status, usize) {
    let mut buf = [0u16; 32];
    let n = name(var, &mut buf);
    let mut guid = *guid;
    let (mut size, mut attributes) = (out.len(), 0u32);
    let status = unsafe { ((*rt).get_variable)(n, &mut guid, &mut attributes, &mut size, out.as_mut_ptr() as *mut c_void) };
    (status, size)
}

fn word(rt: *mut RuntimeServices, var: &str) -> Option<u64> {
    let mut out = [0u8; 8];
    let (status, size) = get(rt, var, &GLOBAL, &mut out);
    (status == Status::SUCCESS && size == 8).then(|| u64::from_le_bytes(out))
}

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(_image: Handle, system_table: *mut SystemTable) -> Status {
    let rt = unsafe { (*system_table).runtime_services };
    let mut out = [0u8; 8];
    let (status, _) = get(rt, "SetupAsked", &OURS, &mut out);
    if status == Status::NOT_FOUND {
        say("setup test: first boot\r\n");
        check("OsIndicationsSupported offers boot to firmware setup", word(rt, "OsIndicationsSupported").is_some_and(|w| w & BOOT_TO_FW_UI != 0));
        check("OsIndicationsSupported still offers capsule delivery", word(rt, "OsIndicationsSupported").is_some_and(|w| w & 4 != 0));
        check("the request is written", set(rt, "OsIndications", &GLOBAL, &(BOOT_TO_FW_UI | 4).to_le_bytes()) == Status::SUCCESS);
        check("the mark is written", set(rt, "SetupAsked", &OURS, &[1]) == Status::SUCCESS);
        say("setup test: resetting\r\n");
        unsafe { ((*rt).reset_system)(efi::RESET_COLD, Status::SUCCESS, 0, core::ptr::null_mut()) };
        runtime_efi::hang()
    }
    say("setup test: second boot\r\n");
    let indications = word(rt, "OsIndications");
    check("the firmware took the request back", indications.is_some_and(|w| w & BOOT_TO_FW_UI == 0));
    check("and left the other indications alone", indications.is_some_and(|w| w & 4 != 0));
    say("setup test: done\r\n");
    runtime_efi::hang()
}

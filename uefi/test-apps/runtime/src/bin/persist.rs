//! What the OS writes through the runtime services outlasts a reset: a
//! non-volatile variable, its deletion, and an authenticated write of `db`,
//! which takes effect at the boot after. The first boot writes after
//! `ExitBootServices` and resets; the second checks.

#![no_std]
#![no_main]

use core::ffi::c_void;

use r_efi::efi::{self, Guid, Handle, RuntimeServices, Status, SystemTable};
use runtime_efi::{check, exit_boot_services, name, say, settle};

const NV_BS_RT: u32 = efi::VARIABLE_NON_VOLATILE | efi::VARIABLE_BOOTSERVICE_ACCESS | efi::VARIABLE_RUNTIME_ACCESS;
const TIME_BASED: u32 = efi::VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
const APPEND: u32 = efi::VARIABLE_APPEND_WRITE;
const SECURITY_DB: Guid = Guid::from_fields(0xd719b2cb, 0x3d3a, 0x4596, 0xa3, 0xbc, &[0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f]);
const OURS: Guid = Guid::from_fields(0x6b1c0a52, 0x3a7e, 0x4d1f, 0x9a, 0x0b, &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);

/// An update of `db` appending a certificate, signed by a key `KEK` holds.
static DB_UPDATE: &[u8] = include_bytes!("../../../../../out/db-x.auth");

fn set(rt: *mut RuntimeServices, var: &str, guid: &Guid, attributes: u32, data: &[u8]) -> Status {
    let mut buf = [0u16; 32];
    let n = name(var, &mut buf);
    let mut guid = *guid;
    unsafe { ((*rt).set_variable)(n, &mut guid, attributes, data.len(), data.as_ptr() as *mut c_void) }
}

fn get(rt: *mut RuntimeServices, var: &str, guid: &Guid, out: &mut [u8]) -> (Status, usize) {
    let mut buf = [0u16; 32];
    let n = name(var, &mut buf);
    let mut guid = *guid;
    let (mut size, mut attributes) = (out.len(), 0u32);
    let status = unsafe { ((*rt).get_variable)(n, &mut guid, &mut attributes, &mut size, out.as_mut_ptr() as *mut c_void) };
    (status, size)
}

fn reset() -> ! {
    const PM_RSTC: usize = 0xfe10_001c;
    const PM_WDOG: usize = 0xfe10_0024;
    const PASSWORD: u32 = 0x5a00_0000;
    unsafe {
        core::ptr::write_volatile(PM_WDOG as *mut u32, PASSWORD | 10);
        let rstc = core::ptr::read_volatile(PM_RSTC as *const u32);
        core::ptr::write_volatile(PM_RSTC as *mut u32, PASSWORD | (rstc & !0x30) | 0x20);
    }
    runtime_efi::hang()
}

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(image: Handle, system_table: *mut SystemTable) -> Status {
    let rt = unsafe { (*system_table).runtime_services };
    let mut out = [0u8; 8192];
    let (status, db_size) = get(rt, "db", &SECURITY_DB, &mut out);
    if status != Status::SUCCESS {
        say("persist test: db is not there\r\n");
        runtime_efi::hang()
    }

    let (status, _) = get(rt, "RtKept", &OURS, &mut out);
    if status == Status::NOT_FOUND {
        say("persist test: first boot\r\n");
        set(rt, "RtGone", &OURS, NV_BS_RT, &[1]);
        let rt = exit_boot_services(image, system_table);
        settle();
        check("a variable is written after ExitBootServices", set(rt, "RtKept", &OURS, NV_BS_RT, &[1, 2, 3]) == Status::SUCCESS);
        check("and appended to", set(rt, "RtKept", &OURS, NV_BS_RT | APPEND, &[4]) == Status::SUCCESS);
        check("db's old size is kept", set(rt, "RtDbSize", &OURS, NV_BS_RT, &(db_size as u32).to_le_bytes()) == Status::SUCCESS);
        check("another is deleted", set(rt, "RtGone", &OURS, 0, &[]) == Status::SUCCESS);
        check(
            "a signed update of db is accepted",
            set(rt, "db", &SECURITY_DB, NV_BS_RT | TIME_BASED | APPEND, DB_UPDATE) == Status::SUCCESS,
        );
        say("persist test: resetting\r\n");
        reset()
    }

    say("persist test: second boot\r\n");
    let (status, size) = get(rt, "RtKept", &OURS, &mut out);
    check("the variable is still there with what was appended", status == Status::SUCCESS && out[..size] == [1, 2, 3, 4]);
    let (status, _) = get(rt, "RtGone", &OURS, &mut out);
    check("the deleted variable is gone", status == Status::NOT_FOUND);
    let (status, size) = get(rt, "RtDbSize", &OURS, &mut out);
    let before = u32::from_le_bytes([out[0], out[1], out[2], out[3]]) as usize;
    check("db's old size was kept", status == Status::SUCCESS && size == 4);
    check("db holds the certificate the signed update added", db_size > before);
    say("persist test: done\r\n");
    runtime_efi::hang()
}

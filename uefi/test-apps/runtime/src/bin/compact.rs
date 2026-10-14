//! The flash store has room again at the next boot, and keeps what has to last.
//! What the OS writes through the runtime services is appended to the bank, and
//! the VPU cannot make room once it is full, so UEFI starts a fresh bank with
//! what the variables still need when it finds the bank more than half full.
//!
//! The first boot writes a variable, adds a certificate to `db` with a signed
//! update, then writes another variable over and over until the bank is mostly
//! what the writes replaced, and resets. The second boot finds all of it as it
//! was, writes as much again and resets, and the third finds that the bank the
//! second started over still holds what the first wrote.

#![no_std]
#![no_main]

use core::ffi::c_void;

use r_efi::efi::{self, Guid, Handle, RuntimeServices, Status, SystemTable};
use runtime_efi::{check, exit_boot_services, name, say, settle};

const NV_BS_RT: u32 = efi::VARIABLE_NON_VOLATILE | efi::VARIABLE_BOOTSERVICE_ACCESS | efi::VARIABLE_RUNTIME_ACCESS;
const TIME_BASED: u32 = efi::VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
const APPEND: u32 = efi::VARIABLE_APPEND_WRITE;
const OURS: Guid = Guid::from_fields(0x6b1c0a52, 0x3a7e, 0x4d1f, 0x9a, 0x0b, &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
const SECURITY_DB: Guid = Guid::from_fields(0xd719b2cb, 0x3d3a, 0x4596, 0xa3, 0xbc, &[0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f]);

/// An update of `db` appending a certificate, signed by a key `KEK` holds.
static DB_UPDATE: &[u8] = include_bytes!("../../../../../out/db-x.auth");

/// A write is a record of about 1.7 KiB in the flash: this many are most of a
/// bank of 20 KiB, and twice as many do not fit in one.
const WRITES: u8 = 8;
const SIZE: usize = 1500;

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

/// Write `RtChurn` `WRITES` times, each time with a value of its own: whether
/// every write was taken.
fn churn(rt: *mut RuntimeServices, first: u8) -> bool {
    let mut value = [0u8; SIZE];
    let mut all = true;
    for n in first..first + WRITES {
        value.fill(n);
        all &= set(rt, "RtChurn", &OURS, NV_BS_RT, &value) == Status::SUCCESS;
    }
    all
}

fn reset(rt: *mut RuntimeServices) -> ! {
    unsafe { ((*rt).reset_system)(efi::RESET_COLD, Status::SUCCESS, 0, core::ptr::null_mut()) };
    runtime_efi::hang()
}

/// What each check says, for the boot that makes it.
struct Names {
    keep: &'static str,
    churn: &'static str,
    db: &'static str,
}

const AFTER_THE_FIRST: Names = Names {
    keep: "the variable written once is still there",
    churn: "the other holds what was written last",
    db: "db still holds the certificate the signed update added",
};
const AFTER_THE_SECOND: Names = Names {
    keep: "the variable written once is there after the store started over",
    churn: "the other holds what was written last after the store started over",
    db: "db holds the certificate after the store started over",
};

/// What the variables hold after a reset: the one written once, the one written
/// over and over as of its `last` write, and `db` with the certificate.
fn check_what_lasted(rt: *mut RuntimeServices, last: u8, names: &Names) {
    let mut out = [0u8; 8192];
    let (status, size) = get(rt, "RtKeep", &OURS, &mut out);
    check(names.keep, status == Status::SUCCESS && out[..size] == [1, 2, 3]);
    let (status, size) = get(rt, "RtChurn", &OURS, &mut out);
    check(names.churn, status == Status::SUCCESS && size == SIZE && out[..size].iter().all(|b| *b == last));
    let (status, size) = get(rt, "RtDbSize", &OURS, &mut out);
    let before = u32::from_le_bytes([out[0], out[1], out[2], out[3]]) as usize;
    let valid = status == Status::SUCCESS && size == 4;
    let (status, now) = get(rt, "db", &SECURITY_DB, &mut out);
    check(names.db, valid && status == Status::SUCCESS && now > before);
}

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(image: Handle, system_table: *mut SystemTable) -> Status {
    let rt = unsafe { (*system_table).runtime_services };
    let mut out = [0u8; 8192];

    let (status, size) = get(rt, "RtBoot", &OURS, &mut out);
    if status == Status::NOT_FOUND {
        say("compact test: first boot\r\n");
        let (_, db_size) = get(rt, "db", &SECURITY_DB, &mut out);
        let rt = exit_boot_services(image, system_table);
        settle();
        check("a variable is written once", set(rt, "RtKeep", &OURS, NV_BS_RT, &[1, 2, 3]) == Status::SUCCESS);
        check("db's size is kept", set(rt, "RtDbSize", &OURS, NV_BS_RT, &(db_size as u32).to_le_bytes()) == Status::SUCCESS);
        check(
            "a signed update of db is accepted",
            set(rt, "db", &SECURITY_DB, NV_BS_RT | TIME_BASED | APPEND, DB_UPDATE) == Status::SUCCESS,
        );
        check("another is written again and again, filling the bank", churn(rt, 0));
        set(rt, "RtBoot", &OURS, NV_BS_RT, &[1]);
        say("compact test: resetting\r\n");
        reset(rt)
    }

    if out[..size] == [1] {
        say("compact test: second boot\r\n");
        check_what_lasted(rt, WRITES - 1, &AFTER_THE_FIRST);
        let rt = exit_boot_services(image, system_table);
        settle();
        check("as much again is written", churn(rt, WRITES));
        set(rt, "RtBoot", &OURS, NV_BS_RT, &[2]);
        say("compact test: resetting\r\n");
        reset(rt)
    }

    say("compact test: third boot\r\n");
    check_what_lasted(rt, 2 * WRITES - 1, &AFTER_THE_SECOND);
    say("compact test: done\r\n");
    runtime_efi::hang()
}

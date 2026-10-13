//! The flash store has room again at the next boot. What the OS writes through
//! the runtime services is appended to the bank, and the VPU cannot make room
//! once it is full, so UEFI starts a fresh bank with what the variables still
//! need when it finds the bank more than half full. The first boot writes one
//! variable, then another over and over until the bank is mostly what the
//! writes replaced, and resets; the second finds both as they were and writes
//! as much again.

#![no_std]
#![no_main]

use core::ffi::c_void;

use r_efi::efi::{self, Guid, Handle, RuntimeServices, Status, SystemTable};
use runtime_efi::{check, exit_boot_services, name, say, settle};

const NV_BS_RT: u32 = efi::VARIABLE_NON_VOLATILE | efi::VARIABLE_BOOTSERVICE_ACCESS | efi::VARIABLE_RUNTIME_ACCESS;
const OURS: Guid = Guid::from_fields(0x6b1c0a52, 0x3a7e, 0x4d1f, 0x9a, 0x0b, &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);

/// A write is a record of about 1.7 KiB in the flash: this many are most of a
/// bank of 20 KiB, and twice as many do not fit in one.
const WRITES: u8 = 10;
const SIZE: usize = 1500;

fn set(rt: *mut RuntimeServices, var: &str, data: &[u8]) -> Status {
    let mut buf = [0u16; 32];
    let n = name(var, &mut buf);
    let mut guid = OURS;
    unsafe { ((*rt).set_variable)(n, &mut guid, NV_BS_RT, data.len(), data.as_ptr() as *mut c_void) }
}

fn get(rt: *mut RuntimeServices, var: &str, out: &mut [u8]) -> (Status, usize) {
    let mut buf = [0u16; 32];
    let n = name(var, &mut buf);
    let mut guid = OURS;
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
        all &= set(rt, "RtChurn", &value) == Status::SUCCESS;
    }
    all
}

fn reset(rt: *mut RuntimeServices) -> ! {
    unsafe { ((*rt).reset_system)(efi::RESET_COLD, Status::SUCCESS, 0, core::ptr::null_mut()) };
    runtime_efi::hang()
}

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(image: Handle, system_table: *mut SystemTable) -> Status {
    let rt = unsafe { (*system_table).runtime_services };
    let mut out = [0u8; SIZE];

    let (status, _) = get(rt, "RtKeep", &mut out);
    if status == Status::NOT_FOUND {
        say("compact test: first boot\r\n");
        let rt = exit_boot_services(image, system_table);
        settle();
        check("a variable is written once", set(rt, "RtKeep", &[1, 2, 3]) == Status::SUCCESS);
        check("another is written again and again, filling the bank", churn(rt, 0));
        say("compact test: resetting\r\n");
        reset(rt)
    }

    say("compact test: second boot\r\n");
    let (status, size) = get(rt, "RtKeep", &mut out);
    check("the variable written once is still there", status == Status::SUCCESS && out[..size] == [1, 2, 3]);
    let (status, size) = get(rt, "RtChurn", &mut out);
    check("the other holds what was written last", status == Status::SUCCESS && size == SIZE && out.iter().all(|b| *b == WRITES - 1));
    let rt = exit_boot_services(image, system_table);
    settle();
    check("as much again is written", churn(rt, WRITES));
    say("compact test: done\r\n");
    runtime_efi::hang()
}

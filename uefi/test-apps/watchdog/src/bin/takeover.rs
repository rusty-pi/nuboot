//! Exits boot services as an operating system loader does, waits for the
//! watchdog to be carried for the operating system, then arms it with a
//! timeout of its own, five seconds, the way a driver that has found it
//! running does, and stops beating it.

#![no_std]
#![no_main]

use core::mem::size_of;
use core::ptr::write_volatile;

use r_efi::efi::{Handle, MemoryDescriptor, Status, SystemTable};
use watchdog_efi::{after_reset, hang, say};

static mut MAP: [u8; 16384] = [0; 16384];

const PM_RSTC: usize = 0xFE10_001C;
const PM_WDOG: usize = 0xFE10_0024;
const PM_PASSWORD: u32 = 0x5A00_0000;
const PM_RSTC_FULL_RESET: u32 = 0x20;

fn counter() -> u64 {
    let count: u64;
    unsafe { core::arch::asm!("isb", "mrs {0}, CNTPCT_EL0", out(reg) count) };
    count
}

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(image: Handle, system_table: *mut SystemTable) -> Status {
    after_reset(system_table);
    say(system_table, "watchdog test: taking the watchdog over\r\n");
    let bs = unsafe { (*system_table).boot_services };
    for _ in 0..4 {
        let mut size = core::mem::size_of_val(unsafe { &*(&raw const MAP) });
        let (mut key, mut desc_size, mut version) = (0usize, size_of::<MemoryDescriptor>(), 0u32);
        let status = unsafe {
            ((*bs).get_memory_map)(&mut size, (&raw mut MAP).cast(), &mut key, &mut desc_size, &mut version)
        };
        if status.is_error() {
            continue;
        }
        if !unsafe { ((*bs).exit_boot_services)(image, key) }.is_error() {
            let freq: u64;
            unsafe { core::arch::asm!("mrs {0}, CNTFRQ_EL0", out(reg) freq) };
            let until = counter() + 3 * freq;
            while counter() < until {}
            unsafe {
                write_volatile(PM_WDOG as *mut u32, PM_PASSWORD | 5 * 65536);
                write_volatile(PM_RSTC as *mut u32, PM_PASSWORD | PM_RSTC_FULL_RESET);
            }
            hang()
        }
    }
    say(system_table, "watchdog test: ExitBootServices failed\r\n");
    hang()
}

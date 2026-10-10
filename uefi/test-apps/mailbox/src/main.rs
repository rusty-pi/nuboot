//! Asks the firmware over the property mailbox to reload the VL805's
//! firmware, as Linux does once it has reset the PCIe link, and says whether
//! the request was answered.

#![no_std]
#![no_main]

use core::ptr::{read_volatile, write_volatile};

use r_efi::efi::{self, Char16, Handle, Status, SystemTable};

/// The ARM's view of the mailboxes: it writes mailbox 1 and reads mailbox 0.
const MAIL0_READ: usize = 0xfe00_b880;
const MAIL0_STATUS: usize = 0xfe00_b898;
const MAIL1_WRITE: usize = 0xfe00_b8a0;
const MAIL1_STATUS: usize = 0xfe00_b8b8;
const FULL: u32 = 1 << 31;
const EMPTY: u32 = 1 << 30;
const CHANNEL_PROPERTY: u32 = 8;
const RESPONSE: u32 = 0x8000_0000;
const TAG_NOTIFY_XHCI_RESET: u32 = 0x0003_0058;
/// Bus 1, device 0, function 0, as Linux names the VL805.
const VL805: u32 = 1 << 20;

fn say(system_table: *mut SystemTable, text: &str) {
    let mut buf = [0 as Char16; 128];
    for (i, b) in text.bytes().take(buf.len() - 1).enumerate() {
        buf[i] = b as Char16;
    }
    unsafe {
        let con_out = (*system_table).con_out;
        ((*con_out).output_string)(con_out, buf.as_mut_ptr());
    }
}

/// Write the buffer's lines out to memory and drop them from the cache.
fn flush(at: usize, len: usize) {
    for line in (at & !63..at + len).step_by(64) {
        unsafe { core::arch::asm!("dc civac, {}", in(reg) line) };
    }
    unsafe { core::arch::asm!("dsb sy") };
}

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(_image: Handle, system_table: *mut SystemTable) -> Status {
    say(system_table, "mailbox test: NOTIFY_XHCI_RESET\r\n");
    // The mailbox carries a 32-bit bus address, which reaches the first GiB.
    let mut page: efi::PhysicalAddress = 0x3fff_ffff;
    let status = unsafe {
        let bs = (*system_table).boot_services;
        ((*bs).allocate_pages)(efi::ALLOCATE_MAX_ADDRESS, efi::LOADER_DATA, 1, &mut page)
    };
    if status.is_error() {
        say(system_table, "mailbox test: no page below 1 GiB\r\n");
        return status;
    }
    let buf = page as usize;
    let words = [7 * 4, 0, TAG_NOTIFY_XHCI_RESET, 4, 4, VL805, 0];
    for (i, w) in words.iter().enumerate() {
        unsafe { write_volatile((buf as *mut u32).add(i), *w) };
    }
    flush(buf, 64);
    let message = (0xc000_0000 | buf as u32) | CHANNEL_PROPERTY;
    unsafe {
        while read_volatile(MAIL1_STATUS as *const u32) & FULL != 0 {}
        write_volatile(MAIL1_WRITE as *mut u32, message);
        loop {
            while read_volatile(MAIL0_STATUS as *const u32) & EMPTY != 0 {}
            if read_volatile(MAIL0_READ as *const u32) == message {
                break;
            }
        }
    }
    flush(buf, 64);
    let code = unsafe { read_volatile((buf as *const u32).add(1)) };
    let tag = unsafe { read_volatile((buf as *const u32).add(4)) };
    if code == RESPONSE && tag == RESPONSE | 4 {
        say(system_table, "mailbox test: NOTIFY_XHCI_RESET answered\r\n");
        Status::SUCCESS
    } else {
        say(system_table, "mailbox test: NOTIFY_XHCI_RESET not answered\r\n");
        Status::DEVICE_ERROR
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

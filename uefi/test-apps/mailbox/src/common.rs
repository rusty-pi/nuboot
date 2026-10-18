use core::ptr::{read_volatile, write_volatile};

use r_efi::efi::{Char16, SystemTable};

const MAIL0_READ: usize = 0xfe00_b880;
const MAIL0_STATUS: usize = 0xfe00_b898;
const MAIL1_WRITE: usize = 0xfe00_b8a0;
const MAIL1_STATUS: usize = 0xfe00_b8b8;
const FULL: u32 = 1 << 31;
const EMPTY: u32 = 1 << 30;
const CHANNEL_PROPERTY: u32 = 8;
const RESPONSE: u32 = 0x8000_0000;

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

fn flush(at: usize, len: usize) {
    for line in (at & !63..at + len).step_by(64) {
        unsafe { core::arch::asm!("dc civac, {}", in(reg) line) };
    }
    unsafe { core::arch::asm!("dsb sy") };
}

/// Post one tag whose value is `words` (at least 8 words of room) and give
/// the words it answered with, or `None` if the tag was not answered.
pub fn call(buf: usize, tag: u32, words: &[u32]) -> Option<[u32; 8]> {
    let room = words.len().max(8);
    let mut message = [0u32; 16];
    message[0] = (5 + room as u32 + 1) * 4;
    message[2] = tag;
    message[3] = room as u32 * 4;
    message[5..5 + words.len()].copy_from_slice(words);
    for (i, w) in message[..6 + room].iter().enumerate() {
        unsafe { write_volatile((buf as *mut u32).add(i), *w) };
    }
    flush(buf, 64);
    let reply = (0xc000_0000 | buf as u32) | CHANNEL_PROPERTY;
    unsafe {
        while read_volatile(MAIL1_STATUS as *const u32) & FULL != 0 {}
        write_volatile(MAIL1_WRITE as *mut u32, reply);
        loop {
            while read_volatile(MAIL0_STATUS as *const u32) & EMPTY != 0 {}
            if read_volatile(MAIL0_READ as *const u32) == reply {
                break;
            }
        }
    }
    flush(buf, 64);
    if unsafe { read_volatile((buf as *const u32).add(4)) } & RESPONSE == 0 {
        return None;
    }
    let mut out = [0u32; 8];
    for (i, o) in out.iter_mut().enumerate() {
        *o = unsafe { read_volatile((buf as *const u32).add(5 + i)) };
    }
    Some(out)
}

pub fn page_below_1gib(system_table: *mut SystemTable) -> Option<usize> {
    use r_efi::efi;
    let mut page: efi::PhysicalAddress = 0x3fff_ffff;
    let status = unsafe {
        let bs = (*system_table).boot_services;
        ((*bs).allocate_pages)(efi::ALLOCATE_MAX_ADDRESS, efi::LOADER_DATA, 1, &mut page)
    };
    (!status.is_error()).then_some(page as usize)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

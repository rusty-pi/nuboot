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

pub const TAG_GET_BOOT_KEY: u32 = 0x0003_00a0;
pub const TAG_EXTEND_BOOT_MEASUREMENT: u32 = 0x0003_00a1;

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

/// Post one tag whose value is `words` (8 words of room) and give the words
/// it answered with, or `None` if the tag was not answered.
pub fn call(buf: usize, tag: u32, words: &[u32; 8]) -> Option<[u32; 8]> {
    let message_words = [14 * 4, 0, tag, 32, 0, words[0], words[1], words[2], words[3], words[4], words[5], words[6], words[7], 0];
    for (i, w) in message_words.iter().enumerate() {
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
    if unsafe { read_volatile((buf as *const u32).add(4)) } != RESPONSE | 32 {
        return None;
    }
    let mut out = [0u32; 8];
    for (i, o) in out.iter_mut().enumerate() {
        *o = unsafe { read_volatile((buf as *const u32).add(5 + i)) };
    }
    Some(out)
}

pub fn hex(system_table: *mut SystemTable, key: &[u32; 8]) {
    let mut out = [0u8; 64];
    for (i, word) in key.iter().enumerate() {
        for (j, byte) in word.to_le_bytes().iter().enumerate() {
            out[i * 8 + j * 2] = b"0123456789abcdef"[(byte >> 4) as usize];
            out[i * 8 + j * 2 + 1] = b"0123456789abcdef"[(byte & 15) as usize];
        }
    }
    say(system_table, unsafe { core::str::from_utf8_unchecked(&out) });
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

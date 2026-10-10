//! The VPU firmware's property mailbox, for the boot measurement: every image
//! this firmware loads is folded into it, and it is closed as boot services
//! exit.

use core::cell::UnsafeCell;
use core::ptr::{read_volatile, write_volatile};

use crate::util::{self, cache_flush};
use crate::warn;

const MAIL0_READ: u64 = 0xfe00_b880;
const MAIL0_STATUS: u64 = 0xfe00_b898;
const MAIL1_WRITE: u64 = 0xfe00_b8a0;
const MAIL1_STATUS: u64 = 0xfe00_b8b8;
const FULL: u32 = 1 << 31;
const EMPTY: u32 = 1 << 30;
const CHANNEL_PROPERTY: u32 = 8;
const RESPONSE: u32 = 0x8000_0000;
/// How long the VPU is given to answer.
const ANSWER_US: u64 = 200_000;

const TAG_EXTEND_BOOT_MEASUREMENT: u32 = 0x0003_00a1;
const TAG_LOCK_BOOT_MEASUREMENT: u32 = 0x0003_00a2;

#[repr(C, align(16))]
struct Buffer(UnsafeCell<[u32; 16]>);

unsafe impl Sync for Buffer {}

/// The bus address is 32 bits, so this has to sit in the first gigabyte,
/// which this image does.
static BUFFER: Buffer = Buffer(UnsafeCell::new([0; 16]));

/// Post one tag with `value` words and wait for the VPU to answer it. Whether
/// it did.
fn call(tag: u32, value: &[u32]) -> bool {
    let buf = BUFFER.0.get() as *mut u32;
    let words = 5 + value.len();
    unsafe {
        write_volatile(buf, 4 * (words as u32 + 1));
        write_volatile(buf.add(1), 0);
        write_volatile(buf.add(2), tag);
        write_volatile(buf.add(3), 4 * value.len() as u32);
        write_volatile(buf.add(4), 0);
        for (i, w) in value.iter().enumerate() {
            write_volatile(buf.add(5 + i), *w);
        }
        write_volatile(buf.add(words), 0);
    }
    let at = buf as u64;
    cache_flush(at, 64);
    let message = (0xc000_0000 | at as u32) | CHANNEL_PROPERTY;
    if !util::wait_for(ANSWER_US, || util::read32(MAIL1_STATUS) & FULL == 0) {
        return false;
    }
    util::write32(MAIL1_WRITE, message);
    let replied = util::wait_for(ANSWER_US, || {
        util::read32(MAIL0_STATUS) & EMPTY == 0 && util::read32(MAIL0_READ) == message
    });
    if !replied {
        return false;
    }
    cache_flush(at, 64);
    let status = unsafe { read_volatile(buf.add(4)) };
    status & RESPONSE != 0
}

/// Extend a PCR on the VPU.
pub fn extend(pcr: u32, digest: &[u8; 32]) {
    let mut words = [0u32; 9];
    words[0] = pcr;
    for (w, bytes) in words[1..].iter_mut().zip(digest.chunks_exact(4)) {
        *w = u32::from_le_bytes(bytes.try_into().unwrap());
    }
    if !call(TAG_EXTEND_BOOT_MEASUREMENT, &words) {
        warn!("measure", "the VPU did not take a measurement"; pcr = pcr);
    }
}

/// Close the measurement before the OS has the board.
pub fn lock() {
    if !call(TAG_LOCK_BOOT_MEASUREMENT, &[]) {
        warn!("measure", "the VPU did not close the boot measurement");
    }
}

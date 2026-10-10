//! The boot key: a secret the VPU derives from the device private key and
//! what was booted, and hands to the ARM once.
//!
//! The UEFI firmware measures every image it loads and extends the boot
//! measurement ([`extend`]): `SHA-256(measurement || digest)`, from zero.
//! The OS (or whatever runs last) asks for the boot key ([`take`]), which is
//! `HMAC-SHA256(private key, LABEL || measurement)` over OTP rows 56-63. A
//! different payload, or the same one booted through a different chain,
//! measures differently and gets a different key.
//!
//! The private key is read when the key is asked for and never leaves this
//! module: the ARM cannot reach the OTP block, and this firmware answers no
//! mailbox tag that returns a fuse. Everything the derivation touched is
//! overwritten ([`scrub`]) before it returns, since anything left in SDRAM or
//! the L2 is readable from an ARM that has raw memory access.
//!
//! Measurements close at [`lock`] (UEFI calls it as it exits boot services)
//! and once the key has been taken, and the key goes out once.
//!
//! None of this holds against a payload that can write the VPU's memory: it
//! can change the measurement, or the code that checks it.

use core::ptr::{read_volatile, write_volatile};

use crate::{cache, critical, otp, sha256};

const FIRST_ROW: u32 = 56;
const ROWS: usize = 8;
const LABEL: &[u8] = b"pi4-server-firmware boot key v1";

static mut MEASUREMENT: [u8; 32] = [0; 32];
static mut OPEN: bool = true;
static mut COUNT: u32 = 0;
static mut TAKEN: bool = false;

pub enum Refused {
    Closed,
}

/// Fold `digest` into the boot measurement. How many images that makes.
pub fn extend(digest: &[u8; 32]) -> Result<u32, Refused> {
    if !unsafe { read_volatile(&raw const OPEN) } {
        return Err(Refused::Closed);
    }
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(unsafe { &*(&raw const MEASUREMENT) });
    data[32..].copy_from_slice(digest);
    unsafe { *(&raw mut MEASUREMENT) = sha256::digest(&data) };
    let count = unsafe { read_volatile(&raw const COUNT) } + 1;
    unsafe { write_volatile(&raw mut COUNT, count) };
    Ok(count)
}

/// Close the measurement.
pub fn lock() {
    unsafe { write_volatile(&raw mut OPEN, false) };
}

pub fn count() -> u32 {
    unsafe { read_volatile(&raw const COUNT) }
}

pub fn measurement() -> [u8; 32] {
    unsafe { *(&raw const MEASUREMENT) }
}

/// The boot key, once, if the board's private key is fused.
pub fn take() -> Option<[u8; 32]> {
    if unsafe { read_volatile(&raw const TAKEN) } {
        return None;
    }
    lock();
    unsafe { write_volatile(&raw mut TAKEN, true) };
    let _section = critical::enter();
    let key = derive();
    scrub();
    key
}

#[inline(never)]
fn derive() -> Option<[u8; 32]> {
    let mut private = [0u8; ROWS * 4];
    let mut fused = 0;
    for (i, chunk) in private.chunks_exact_mut(4).enumerate() {
        let row = otp::read(FIRST_ROW + i as u32);
        fused |= row;
        chunk.copy_from_slice(&row.to_le_bytes());
    }
    if fused == 0 {
        return None;
    }
    let mut message = [0u8; 64];
    message[..LABEL.len()].copy_from_slice(LABEL);
    message[LABEL.len()..LABEL.len() + 32].copy_from_slice(&measurement());
    let key = sha256::hmac(&private, &message[..LABEL.len() + 32]);
    zero(&mut private);
    Some(key)
}

/// Overwrite the stack below the caller, where the frames of the calls that
/// held the key and its hash have been, and push the zeros out of the caches.
#[inline(never)]
fn scrub() {
    const WORDS: usize = 1024;
    let mut below = [0u32; WORDS];
    for word in below.iter_mut() {
        unsafe { write_volatile(word, 0) };
    }
    cache::write_back_with_l2(below.as_ptr() as u32, below.as_ptr() as u32 + WORDS as u32 * 4 - 1);
}

pub fn zero(bytes: &mut [u8]) {
    for byte in bytes {
        unsafe { write_volatile(byte, 0) };
    }
}

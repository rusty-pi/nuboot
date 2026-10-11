//! The boot measurement and the boot key: a secret the VPU derives from the
//! device private key and what was booted, and hands to the ARM once.
//!
//! The VPU keeps a bank of [`PCRS`] SHA-256 registers, as a TPM does. UEFI
//! extends them as it boots (`EFI_TCG2_PROTOCOL`, which shim, GRUB and the
//! Linux EFI stub measure into): `PCR = SHA-256(PCR || digest)`, from zero.
//! The OS (or whatever runs last) asks for the boot key ([`take`]) with a
//! mask of the registers it wants it bound to. The key is
//! `HMAC-SHA256(private key, LABEL || mask || the selected registers)` over
//! OTP rows 56-63. An empty mask binds it to nothing: one stable key per
//! board. Binding to PCR 7 (Secure Boot policy and the certificates that
//! verified each stage) or PCR 4 (the images) makes it change when those do.
//!
//! The private key is read when the key is asked for and never leaves this
//! module: the ARM cannot reach the OTP block, and this firmware answers no
//! mailbox tag that returns a fuse. Everything the derivation touched is
//! overwritten ([`scrub`]) before it returns, since anything left in SDRAM or
//! the L2 is readable from an ARM that has raw memory access.
//!
//! The key goes out once. The registers themselves are the TPM's
//! ([`crate::tpm2`]): they can be extended at any time, never set, so a late
//! extend can only move a register away from the value a key was bound to.
//!
//! None of this holds against a payload that can write the VPU's memory: it
//! can change the registers, or the code that checks them.

use core::ptr::{read_volatile, write_volatile};

use crate::{cache, critical, otp, sha256};

const FIRST_ROW: u32 = 56;
const ROWS: usize = 8;
const LABEL: &[u8] = b"pi4-server-firmware boot key v1";
const STORE_LABEL: &[u8] = b"pi4-server-firmware variable store key v1";
pub const PCRS: usize = 24;

static mut PCR: [[u8; 32]; PCRS] = [[0; 32]; PCRS];
static mut COUNT: u32 = 0;
static mut TAKEN: bool = false;
static mut STORE_TAKEN: bool = false;

pub enum Refused {
    NoSuchRegister,
}

/// Fold `digest` into register `pcr`. How many extends that makes.
pub fn extend(pcr: usize, digest: &[u8; 32]) -> Result<u32, Refused> {
    if pcr >= PCRS {
        return Err(Refused::NoSuchRegister);
    }
    let register = unsafe { &mut (*(&raw mut PCR))[pcr] };
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(register);
    data[32..].copy_from_slice(digest);
    *register = sha256::digest(&data);
    let count = unsafe { read_volatile(&raw const COUNT) } + 1;
    unsafe { write_volatile(&raw mut COUNT, count) };
    Ok(count)
}

/// Register `pcr`.
pub fn pcr(pcr: usize) -> Option<[u8; 32]> {
    (pcr < PCRS).then(|| unsafe { (*(&raw const PCR))[pcr] })
}

/// Set register `pcr` back to zero. How many changes that makes.
pub fn reset(pcr: usize) -> Result<u32, Refused> {
    if pcr >= PCRS {
        return Err(Refused::NoSuchRegister);
    }
    unsafe { (*(&raw mut PCR))[pcr] = [0; 32] };
    let count = unsafe { read_volatile(&raw const COUNT) } + 1;
    unsafe { write_volatile(&raw mut COUNT, count) };
    Ok(count)
}

/// How many times the registers have changed: the TPM's `pcrUpdateCounter`.
pub fn count() -> u32 {
    unsafe { read_volatile(&raw const COUNT) }
}

/// The boot key bound to the registers `mask` selects, once, if the board's
/// private key is fused. An empty mask binds it to nothing.
pub fn take(mask: u32) -> Option<[u8; 32]> {
    if unsafe { read_volatile(&raw const TAKEN) } || mask >> PCRS != 0 {
        return None;
    }
    unsafe { write_volatile(&raw mut TAKEN, true) };
    let _section = critical::enter();
    let key = derive(mask);
    scrub();
    key
}

/// The key UEFI seals its variable store with, once, if the board's private
/// key is fused: it depends on nothing else, so it is the same at every boot.
/// UEFI takes it before the OS runs and the OS is never given it.
pub fn take_store_key() -> Option<[u8; 32]> {
    if unsafe { read_volatile(&raw const STORE_TAKEN) } {
        return None;
    }
    unsafe { write_volatile(&raw mut STORE_TAKEN, true) };
    let _section = critical::enter();
    let key = derive_store();
    scrub();
    key
}

#[inline(never)]
fn derive_store() -> Option<[u8; 32]> {
    let mut private = private_key()?;
    let key = sha256::hmac(&private, STORE_LABEL);
    zero(&mut private);
    Some(key)
}

fn private_key() -> Option<[u8; ROWS * 4]> {
    let mut private = [0u8; ROWS * 4];
    let mut fused = 0;
    for (i, chunk) in private.chunks_exact_mut(4).enumerate() {
        let row = otp::read(FIRST_ROW + i as u32);
        fused |= row;
        chunk.copy_from_slice(&row.to_le_bytes());
    }
    (fused != 0).then_some(private)
}

#[inline(never)]
fn derive(mask: u32) -> Option<[u8; 32]> {
    let mut private = private_key()?;
    let mut message = [0u8; LABEL.len() + 4 + 32 * PCRS];
    message[..LABEL.len()].copy_from_slice(LABEL);
    message[LABEL.len()..LABEL.len() + 4].copy_from_slice(&mask.to_le_bytes());
    let mut len = LABEL.len() + 4;
    for (i, register) in unsafe { &*(&raw const PCR) }.iter().enumerate() {
        if mask >> i & 1 != 0 {
            message[len..len + 32].copy_from_slice(register);
            len += 32;
        }
    }
    let key = sha256::hmac(&private, &message[..len]);
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

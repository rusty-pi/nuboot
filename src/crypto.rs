//! The firmware cryptography service, as Raspberry Pi's firmware offers it to
//! `rpi-fw-crypto`: an ECDSA P-256 signature, an HMAC-SHA256 and the public key
//! of the device private key, by key id, without the key itself. Key id 1 is
//! the device private key in OTP rows 56-63.
//!
//! A key's status says what it may no longer be asked, and locks are only
//! ever added, until the next boot. This firmware never reads the key out,
//! never generates one and never sets its usage, so those three are locked
//! from the start. UEFI locks signing and HMAC when it hands over to the OS:
//! it signs the records of its variable store with the key, and an OS that
//! could sign any digest could forge them.

use crate::keystore::{self, Fault};
use crate::p256;

pub const DEVICE_KEY: u32 = 1;

pub const TYPE_DEVICE_PRIVATE_KEY: u32 = 1 << 0;
pub const READ_LOCKED: u32 = 1 << 8;
pub const GEN_LOCKED: u32 = 1 << 9;
pub const SIGN_LOCKED: u32 = 1 << 10;
pub const HMAC_LOCKED: u32 = 1 << 11;
pub const USAGE_LOCKED: u32 = 1 << 12;
const LOCKS: u32 = READ_LOCKED | GEN_LOCKED | SIGN_LOCKED | HMAC_LOCKED | USAGE_LOCKED;

/// `RPI_FW_CRYPTO_STATUS`.
pub const ERR_KEY_NOT_FOUND: u32 = 3;
pub const ERR_KEY_LOCKED: u32 = 4;
pub const ERR_KEY_NOT_SET: u32 = 6;
pub const ERR_KEY_INVALID: u32 = 7;
pub const ERR_NOT_SUPPORTED: u32 = 8;
pub const ERR_OPERATION_FAILED: u32 = 9;
pub const ERR_EINVAL: u32 = 2;

/// The error flag in the first word of an answer.
pub const ERROR: u32 = 0x8000_0000;

pub const HMAC_MESSAGE_MAX: usize = 2048;

static mut STATUS: u32 = TYPE_DEVICE_PRIVATE_KEY | READ_LOCKED | GEN_LOCKED | USAGE_LOCKED;
static mut LAST_ERROR: u32 = 0;

pub fn last_error() -> u32 {
    unsafe { core::ptr::read_volatile(&raw const LAST_ERROR) }
}

fn fail(code: u32) -> u32 {
    unsafe { core::ptr::write_volatile(&raw mut LAST_ERROR, code) };
    code
}

fn fault(f: Fault) -> u32 {
    fail(match f {
        Fault::NotSet => ERR_KEY_NOT_SET,
        Fault::Invalid => ERR_KEY_INVALID,
        Fault::NoRandom => ERR_OPERATION_FAILED,
    })
}

/// How many keys there are to ask about.
pub fn keys() -> u32 {
    1
}

/// The status of key `id`.
pub fn status(id: u32) -> Result<u32, u32> {
    if id != DEVICE_KEY {
        return Err(fail(ERR_KEY_NOT_FOUND));
    }
    Ok(unsafe { core::ptr::read_volatile(&raw const STATUS) })
}

/// Add the locks in `bits` to key `id`.
pub fn lock(id: u32, bits: u32) -> Result<(), u32> {
    let now = status(id)?;
    unsafe { core::ptr::write_volatile(&raw mut STATUS, now | (bits & LOCKS)) };
    Ok(())
}

fn allowed(id: u32, lock: u32) -> Result<(), u32> {
    if status(id)? & lock != 0 {
        return Err(fail(ERR_KEY_LOCKED));
    }
    Ok(())
}

/// Whether the key may still sign: UEFI does not hand the board over while
/// it can.
pub fn may_sign() -> bool {
    allowed(DEVICE_KEY, SIGN_LOCKED).is_ok()
}

fn der_integer(out: &mut [u8], at: &mut usize, value: &[u8; 32]) {
    let skip = value.iter().take_while(|&&b| b == 0).count().min(31);
    let body = &value[skip..];
    let pad = body[0] & 0x80 != 0;
    out[*at] = 0x02;
    out[*at + 1] = (body.len() + pad as usize) as u8;
    *at += 2;
    if pad {
        out[*at] = 0;
        *at += 1;
    }
    out[*at..*at + body.len()].copy_from_slice(body);
    *at += body.len();
}

/// An ECDSA signature of `hash` by key `id`, as a DER `SEQUENCE` of `r` and
/// `s`, in `out`: its length.
pub fn sign(id: u32, hash: &[u8], out: &mut [u8; 72]) -> Result<usize, u32> {
    allowed(id, SIGN_LOCKED)?;
    let hash: &[u8; 32] = hash.try_into().map_err(|_| fail(ERR_EINVAL))?;
    let (r, s) = keystore::device_sign(hash).map_err(fault)?;
    let mut at = 2;
    der_integer(out, &mut at, &r);
    der_integer(out, &mut at, &s);
    out[0] = 0x30;
    out[1] = (at - 2) as u8;
    Ok(at)
}

/// `HMAC-SHA256(key, message)`.
pub fn hmac(id: u32, message: &[u8]) -> Result<[u8; 32], u32> {
    allowed(id, HMAC_LOCKED)?;
    keystore::device_hmac(message).map_err(fault)
}

/// `SubjectPublicKeyInfo` for an ECDSA P-256 key.
const SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// The public key of key `id` in DER: its length.
pub fn public_key(id: u32, out: &mut [u8; 91]) -> Result<usize, u32> {
    status(id)?;
    let p: p256::Point = keystore::device_public().map_err(fault)?;
    out[..26].copy_from_slice(&SPKI_PREFIX);
    out[26] = 4;
    out[27..59].copy_from_slice(&p.x);
    out[59..91].copy_from_slice(&p.y);
    Ok(91)
}

/// Asking for the private key itself, or to make a key or set its usage, is
/// refused.
pub fn refused() -> u32 {
    fail(ERR_KEY_LOCKED)
}

pub fn unsupported() -> u32 {
    fail(ERR_NOT_SUPPORTED)
}

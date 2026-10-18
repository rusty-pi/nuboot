//! The boot measurement and the secrets the VPU derives from the device
//! private key: the TPM's seeds and the key's signatures and MACs.
//!
//! The VPU keeps a bank of [`PCRS`] SHA-256 registers, as a TPM does. UEFI
//! extends them as it boots (`EFI_TCG2_PROTOCOL`, which shim, GRUB and the
//! Linux EFI stub measure into): `PCR = SHA-256(PCR || digest)`, from zero.
//! The registers are the TPM's ([`crate::tpm2`]): they can be extended at any
//! time, never set.
//!
//! The private key is read when it is needed and never leaves this module: no
//! mailbox tag returns a fuse. Privileged ARM code can still read the OTP block
//! itself. Everything a computation with the key
//! touched is overwritten ([`scrub`]) before it returns, since anything left in
//! SDRAM or the L2 is readable from an ARM that has raw memory access.
//!
//! None of this holds against a payload that can write the VPU's memory: it
//! can change the registers, or the code that checks them.

use core::ptr::{read_volatile, write_volatile};

use crate::{cache, critical, otp, p256, rng, sha256};

const FIRST_ROW: u32 = 56;
const ROWS: usize = 8;
const TPM_LABEL: &[u8] = b"nuboot TPM secret v1";
pub const PCRS: usize = 24;
/// The PCRs of dynamic root of trust measurements, which nothing here does and
/// which no caller of the mailbox or the TPM may extend.
const DRTM_PCRS: core::ops::RangeInclusive<usize> = 17..=22;

static mut PCR: [[u8; 32]; PCRS] = [[0; 32]; PCRS];
static mut COUNT: u32 = 0;
static mut BOOT_SECRET: [u8; 32] = [0; 32];
static mut BOOT_SECRET_SET: bool = false;

pub enum Refused {
    NoSuchRegister,
}

/// Fold `digest` into register `pcr`. How many extends that makes.
pub fn extend(pcr: usize, digest: &[u8; 32]) -> Result<u32, Refused> {
    if pcr >= PCRS || DRTM_PCRS.contains(&pcr) {
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

/// A secret of the TPM called `label`: with `stable`, the same at every boot on
/// a board whose private key is fused, and random for this boot on one whose is
/// not; without, random for this boot. The TPM's seeds and proofs come from
/// here when they are used, and are not kept.
pub fn tpm_secret(label: &[u8], stable: bool) -> [u8; 32] {
    let _section = critical::enter();
    let mut message = [0u8; TPM_LABEL.len() + 32];
    message[..TPM_LABEL.len()].copy_from_slice(TPM_LABEL);
    message[TPM_LABEL.len()..TPM_LABEL.len() + label.len()].copy_from_slice(label);
    let message = &message[..TPM_LABEL.len() + label.len()];
    match private_key().filter(|_| stable) {
        Some(mut private) => {
            let secret = sha256::hmac(&private, message);
            zero(&mut private);
            secret
        }
        None => {
            if !unsafe { read_volatile(&raw const BOOT_SECRET_SET) } {
                seed();
            }
            sha256::hmac(unsafe { &*(&raw const BOOT_SECRET) }, message)
        }
    }
}

/// Draw the secret that stands in for the device key where there is none, and
/// for the null hierarchy. The firmware does it at its start, while a generator
/// that has run dry is the board's fault and not the OS's doing; a board with no
/// random numbers does not boot with a seed of zeros.
pub fn seed() {
    let mut fresh = [0u8; 32];
    assert!(rng::fill(&mut fresh), "no random numbers for the TPM's seed");
    unsafe {
        write_volatile(&raw mut BOOT_SECRET, fresh);
        write_volatile(&raw mut BOOT_SECRET_SET, true);
    }
}

/// Why the device key could not do what it was asked.
pub enum Fault {
    /// No private key is fused.
    NotSet,
    /// The fused value is not a P-256 private key.
    Invalid,
    /// The random number generator ran dry.
    NoRandom,
}

/// The device key as a P-256 private key: the 32 bytes of rows 56-63, most
/// significant first.
fn device_scalar() -> Result<[u8; 32], Fault> {
    let mut d = private_key().ok_or(Fault::NotSet)?;
    if !p256::valid_scalar(&d) {
        zero(&mut d);
        return Err(Fault::Invalid);
    }
    Ok(d)
}

/// The device key's public key.
pub fn device_public() -> Result<p256::Point, Fault> {
    let mut d = device_scalar()?;
    let public = p256::public_key(&d);
    zero(&mut d);
    scrub();
    public.ok_or(Fault::Invalid)
}

/// An ECDSA signature `(r, s)` of `digest` by the device key. The
/// per-signature secret mixes the key and the digest with fresh random bytes,
/// so a weak draw does not give the key away.
pub fn device_sign(digest: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), Fault> {
    let mut d = device_scalar()?;
    let mut result = Err(Fault::NoRandom);
    for attempt in 0..8u8 {
        let mut message = [0u8; 32 + 32 + 1];
        message[32..64].copy_from_slice(digest);
        message[64] = attempt;
        if !rng::fill(&mut message[..32]) {
            break;
        }
        let mut k = sha256::hmac(&d, &message);
        zero(&mut message);
        let signature = p256::sign(&d, digest, &k);
        zero(&mut k);
        if let Some(signature) = signature {
            result = Ok(signature);
            break;
        }
    }
    zero(&mut d);
    scrub();
    result
}

/// `HMAC-SHA256(device key, message)`, the key as its 32 raw bytes.
pub fn device_hmac(message: &[u8]) -> Result<[u8; 32], Fault> {
    let mut key = private_key().ok_or(Fault::NotSet)?;
    let mac = sha256::hmac(&key, message);
    zero(&mut key);
    scrub();
    Ok(mac)
}

/// Whether the board's private key is fused, so the TPM's keys outlast a boot.
pub fn device_key_fused() -> bool {
    match private_key() {
        Some(mut private) => {
            zero(&mut private);
            true
        }
        None => false,
    }
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

/// Overwrite the stack below the caller, where the frames of the calls that
/// held the key and its hash have been, and push the zeros out of the caches.
#[inline(never)]
pub fn scrub() {
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

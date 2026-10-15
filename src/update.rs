//! Updates that need no signature by the board's owner. The owner's key in
//! the OTP signs the `start4.elf` the bootloader loads, once; that image
//! carries the update keys, and the UEFI firmware it starts leaves a bundle
//! in RAM for the next boot: a whole firmware image linked for the update
//! slot, signed by an update key. [`staged`] checks one, and [`chain`] runs it
//! in place of the firmware the bootloader loaded.
//!
//! The bundle sits at [`BUNDLE_ADDR`], in the ARM's memory, which survives the
//! reset that follows it:
//!
//! | at | what |
//! |---|---|
//! | 0 | `P4UB` |
//! | 4 | format, 1 |
//! | 8 | version: the build's commit time |
//! | 12 | the address the image is linked at, [`SLOT_BASE`] |
//! | 16 | length of the image |
//! | 20 | zero |
//! | 24 | ECDSA P-256 signature, `r` then `s` |
//! | 88 | the image |
//!
//! The signature is over the SHA-256 of [`LABEL`], the first 24 bytes and
//! the image.

use crate::{cache, mmio, p256, sha256};

/// Where the UEFI firmware leaves the bundle: ARM physical memory below the
/// VPU's own, which the device tree gives the ARM and nothing else uses.
pub const BUNDLE_ADDR: u32 = 0x3e00_0000;
/// Where the update slot's image is linked, and entered.
pub const SLOT_BASE: u32 = 0x3ee0_0200;
/// The biggest image a bundle can carry.
pub const MAX_IMAGE: usize = 2 << 20;

const MAGIC: [u8; 4] = *b"P4UB";
const FORMAT: u32 = 1;
const HEADER: usize = 24;
const SIGNATURE: usize = 64;
const LABEL: &[u8] = b"pi4-server-firmware update\0";

/// What replaces the bundle's header once it runs: `P4UH`, the version of the
/// firmware that started it, the length of its commit and the commit.
const LOADER: [u8; 4] = *b"P4UH";
const LOADER_VERSION: u32 = 4;
const LOADER_COMMIT_LEN: u32 = 8;
const LOADER_COMMIT: u32 = 9;
const COMMIT_MAX: usize = 40;

/// The uncached alias of SDRAM, so what the ARM side wrote is read from memory.
const UNCACHED: u32 = 0xc000_0000;

/// The commit's time, in seconds: what orders one build after another, and
/// what a bundle has to beat.
pub const VERSION: u32 = match u32::from_str_radix(env!("FIRMWARE_TIME"), 10) {
    Ok(time) => time,
    Err(_) => 0,
};

/// The update keys, each the 64 bytes of a P-256 point's coordinates.
static KEYS: &[u8] = include_bytes!(env!("UPDATE_KEYS"));

pub struct Staged {
    pub version: u32,
    image: &'static [u8],
}

impl Staged {
    pub fn image_bytes(&self) -> usize {
        self.image.len()
    }
}

/// Whether the code running is the update slot's image, not what the
/// bootloader loaded.
pub fn in_slot() -> bool {
    let here = KEYS.as_ptr() as u32 & !UNCACHED;
    (SLOT_BASE..SLOT_BASE + MAX_IMAGE as u32).contains(&here)
}

fn bundle_memory(len: usize) -> &'static [u8] {
    unsafe { core::slice::from_raw_parts((UNCACHED | BUNDLE_ADDR) as usize as *const u8, len) }
}

fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

fn signed_by_an_update_key(header: &[u8], image: &[u8], signature: &[u8]) -> bool {
    let mut hash = sha256::Sha256::new();
    hash.update(LABEL);
    hash.update(header);
    hash.update(image);
    let digest = hash.finish();
    let (mut r, mut s) = ([0u8; 32], [0u8; 32]);
    r.copy_from_slice(&signature[..32]);
    s.copy_from_slice(&signature[32..]);
    KEYS.chunks_exact(64).any(|key| {
        let (mut x, mut y) = ([0u8; 32], [0u8; 32]);
        x.copy_from_slice(&key[..32]);
        y.copy_from_slice(&key[32..]);
        p256::verify(&p256::Point { x, y }, &digest, &r, &s)
    })
}

/// The bundle the UEFI firmware left, if there is one: `Ok(None)` when no
/// bundle is staged, and why not when something that claims to be one is
/// refused.
pub fn staged() -> Result<Option<Staged>, &'static str> {
    let header = bundle_memory(HEADER + SIGNATURE);
    if header[..4] != MAGIC {
        return Ok(None);
    }
    if word(header, 4) != FORMAT {
        return Err("the bundle's format is not one this firmware knows");
    }
    if word(header, 12) != SLOT_BASE {
        return Err("the bundle's image is not linked for the update slot");
    }
    let len = word(header, 16) as usize;
    if len == 0 || len > MAX_IMAGE {
        return Err("the bundle's image is empty or too large");
    }
    let all = bundle_memory(HEADER + SIGNATURE + len);
    let image = &all[HEADER + SIGNATURE..];
    if !signed_by_an_update_key(&header[..HEADER], image, &header[HEADER..HEADER + SIGNATURE]) {
        return Err("no update key signed the bundle");
    }
    Ok(Some(Staged { version: word(header, 8), image }))
}

/// Run the bundle's image, in the update slot, as the bootloader would have
/// started it. The bundle is gone first, so a reset does not run it again; in
/// its place the image finds who started it, which it measures.
pub fn chain(staged: &Staged, commit: &str) -> ! {
    let slot = (UNCACHED | SLOT_BASE) as usize as *mut u8;
    unsafe { core::ptr::copy_nonoverlapping(staged.image.as_ptr(), slot, staged.image.len()) };
    let at = UNCACHED | BUNDLE_ADDR;
    let commit = &commit.as_bytes()[..commit.len().min(COMMIT_MAX)];
    for (i, &b) in commit.iter().enumerate() {
        mmio::write8(at + LOADER_COMMIT + i as u32, b);
    }
    mmio::write8(at + LOADER_COMMIT_LEN, commit.len() as u8);
    mmio::write(at + LOADER_VERSION, VERSION);
    mmio::write(at, u32::from_le_bytes(LOADER));
    cache::enter(SLOT_BASE)
}

/// The firmware that started this one as an update: its version and its
/// commit. Once, before anything else uses the memory.
pub fn take_loader() -> Option<Loader> {
    let at = UNCACHED | BUNDLE_ADDR;
    if mmio::read(at) != u32::from_le_bytes(LOADER) {
        return None;
    }
    let len = (mmio::read8(at + LOADER_COMMIT_LEN) as usize).min(COMMIT_MAX);
    let mut loader = Loader { version: mmio::read(at + LOADER_VERSION), commit: [0; COMMIT_MAX], len };
    for (i, byte) in loader.commit[..len].iter_mut().enumerate() {
        *byte = mmio::read8(at + LOADER_COMMIT + i as u32);
    }
    mmio::write(at, 0);
    Some(loader)
}

pub struct Loader {
    pub version: u32,
    commit: [u8; COMMIT_MAX],
    len: usize,
}

impl Loader {
    pub fn commit(&self) -> &str {
        core::str::from_utf8(&self.commit[..self.len]).unwrap_or("?")
    }
}

/// Drop what is staged without running it.
pub fn discard() {
    mmio::write(UNCACHED | BUNDLE_ADDR, 0);
}

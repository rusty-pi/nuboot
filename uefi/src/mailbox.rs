//! The VPU firmware's property mailbox, for the TPM on the VPU: PCR extends
//! and the commands `EFI_TCG2_PROTOCOL.SubmitCommand` carries.

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
/// How long it is given for a TPM command, which can be a key's worth of
/// arithmetic.
const TPM_ANSWER_US: u64 = 5_000_000;

const TAG_EXTEND_BOOT_MEASUREMENT: u32 = 0x0003_00a1;
const TAG_CRYPTO_KEY_STATUS: u32 = 0x0003_0090;
const TAG_CRYPTO_SET_KEY_STATUS: u32 = 0x0003_8090;
const TAG_CRYPTO_HMAC_SHA256: u32 = 0x0003_0092;
/// The device private key's id in the firmware cryptography service.
const DEVICE_KEY: u32 = 1;
const SIGN_LOCKED: u32 = 1 << 10;
const HMAC_LOCKED: u32 = 1 << 11;
const TAG_TPM2_COMMAND: u32 = 0x0003_00a3;
const TAG_GET_EARLY_EVENT: u32 = 0x0003_00a4;
const TAG_GET_OWNER_DB: u32 = 0x0003_00a8;
/// The largest `owner-db.der` (`src/ramdisk.rs`).
const OWNER_DB_MAX: usize = 4096;
/// The largest TPM command or response (`src/tpm2.rs`).
const TPM_MAX: usize = 2048;

#[repr(C, align(16))]
struct Buffer(UnsafeCell<[u32; 16]>);

unsafe impl Sync for Buffer {}

/// The bus address is 32 bits, so this has to sit in the first gigabyte,
/// which this image does.
static BUFFER: Buffer = Buffer(UnsafeCell::new([0; 16]));

#[repr(C, align(16))]
struct Big(UnsafeCell<[u32; 6 + TPM_MAX / 4 + 1]>);

unsafe impl Sync for Big {}

static BIG: Big = Big(UnsafeCell::new([0; 6 + TPM_MAX / 4 + 1]));

/// Post `message` (a whole property buffer at `at`, `len` bytes) and wait for
/// the VPU to answer it. Whether it did.
fn post(at: u64, len: usize, answer_us: u64) -> bool {
    cache_flush(at, len);
    let message = (0xc000_0000 | at as u32) | CHANNEL_PROPERTY;
    if !util::wait_for(ANSWER_US, || util::read32(MAIL1_STATUS) & FULL == 0) {
        return false;
    }
    util::write32(MAIL1_WRITE, message);
    let replied = util::wait_for(answer_us, || {
        util::read32(MAIL0_STATUS) & EMPTY == 0 && util::read32(MAIL0_READ) == message
    });
    if replied {
        cache_flush(at, len);
    }
    replied
}

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
    if !post(buf as u64, 4 * (words + 1), ANSWER_US) {
        return false;
    }
    let status = unsafe { read_volatile(buf.add(4)) };
    status & RESPONSE != 0
}

/// Run a TPM 2.0 command on the VPU: the length of its response, put in
/// `response`, or `None` if the VPU did not answer or it does not fit.
pub fn tpm2_command(command: &[u8], response: &mut [u8]) -> Option<usize> {
    if command.len() > TPM_MAX {
        return None;
    }
    let buf = BIG.0.get() as *mut u32;
    let bytes = buf as *mut u8;
    unsafe {
        write_volatile(buf, (4 * (6 + TPM_MAX / 4 + 1)) as u32);
        write_volatile(buf.add(1), 0);
        write_volatile(buf.add(2), TAG_TPM2_COMMAND);
        write_volatile(buf.add(3), TPM_MAX as u32);
        write_volatile(buf.add(4), command.len() as u32);
        for (i, b) in command.iter().enumerate() {
            write_volatile(bytes.add(20 + i), *b);
        }
        write_volatile(buf.add(5 + TPM_MAX / 4), 0);
    }
    if !post(buf as u64, 4 * (6 + TPM_MAX / 4 + 1), TPM_ANSWER_US) {
        return None;
    }
    let status = unsafe { read_volatile(buf.add(4)) };
    if status & RESPONSE == 0 {
        return None;
    }
    let length = (status & !RESPONSE) as usize;
    if length > response.len() || length > TPM_MAX {
        return None;
    }
    for (i, b) in response[..length].iter_mut().enumerate() {
        *b = unsafe { read_volatile(bytes.add(20 + i)) };
    }
    Some(length)
}

/// An event the VPU measured before the ARM started: the PCR it went into, its
/// type, its digest and its data.
pub struct EarlyEvent {
    pub pcr: u32,
    pub kind: u32,
    pub digest: [u8; 32],
    pub data: alloc::vec::Vec<u8>,
}

/// Event `index` of what the VPU measured before the ARM started, if there is
/// one.
pub fn early_event(index: u32) -> Option<EarlyEvent> {
    const WORDS: usize = 31;
    let buf = BIG.0.get() as *mut u32;
    unsafe {
        write_volatile(buf, (4 * (6 + WORDS + 1)) as u32);
        write_volatile(buf.add(1), 0);
        write_volatile(buf.add(2), TAG_GET_EARLY_EVENT);
        write_volatile(buf.add(3), 4 * WORDS as u32);
        write_volatile(buf.add(4), 4);
        write_volatile(buf.add(5), index);
        for i in 1..WORDS {
            write_volatile(buf.add(5 + i), 0);
        }
        write_volatile(buf.add(5 + WORDS), 0);
    }
    if !post(buf as u64, 4 * (6 + WORDS + 1), ANSWER_US) {
        return None;
    }
    let word = |i: usize| unsafe { read_volatile(buf.add(5 + i)) };
    if unsafe { read_volatile(buf.add(4)) } & RESPONSE == 0 {
        return None;
    }
    let mut digest = [0u8; 32];
    for (n, chunk) in digest.chunks_exact_mut(4).enumerate() {
        chunk.copy_from_slice(&word(2 + n).to_le_bytes());
    }
    let len = (word(10) as usize).min(80);
    let mut data = alloc::vec::Vec::with_capacity(len);
    for n in 0..len {
        data.push((word(11 + n / 4) >> (8 * (n % 4))) as u8);
    }
    Some(EarlyEvent { pcr: word(0), kind: word(1), digest, data })
}

#[repr(C, align(16))]
struct OwnerDbBuffer(UnsafeCell<[u32; 6 + 2 + OWNER_DB_MAX / 4]>);

unsafe impl Sync for OwnerDbBuffer {}

static OWNER_DB_BUFFER: OwnerDbBuffer = OwnerDbBuffer(UnsafeCell::new([0; 6 + 2 + OWNER_DB_MAX / 4]));

/// What the `boot.img` the bootloader checked says about the certificate that
/// signs images.
pub enum OwnerDb {
    /// It says nothing: the built-in `db` stays.
    None,
    /// The DER certificate in its `owner-db.der`.
    Certificate(alloc::vec::Vec<u8>),
    /// It has an `owner-db.der` the VPU could not read, or the VPU did not
    /// answer a firmware that asks.
    Unusable,
}

/// Ask the VPU for the owner's `db`. A VPU that does not know the tag leaves
/// the answer unmarked, which reads as none.
pub fn owner_db() -> OwnerDb {
    const WORDS: usize = 2 + OWNER_DB_MAX / 4;
    let buf = OWNER_DB_BUFFER.0.get() as *mut u32;
    unsafe {
        write_volatile(buf, (4 * (6 + WORDS)) as u32);
        write_volatile(buf.add(1), 0);
        write_volatile(buf.add(2), TAG_GET_OWNER_DB);
        write_volatile(buf.add(3), 4 * WORDS as u32);
        write_volatile(buf.add(4), 0);
        for i in 0..WORDS {
            write_volatile(buf.add(5 + i), 0);
        }
        write_volatile(buf.add(5 + WORDS), 0);
    }
    if !post(buf as u64, 4 * (6 + WORDS), ANSWER_US) {
        return OwnerDb::Unusable;
    }
    if unsafe { read_volatile(buf.add(4)) } & RESPONSE == 0 {
        return OwnerDb::None;
    }
    let word = |i: usize| unsafe { read_volatile(buf.add(5 + i)) };
    let length = word(1) as usize;
    match word(0) {
        1 if length <= OWNER_DB_MAX => {
            let bytes = buf as *const u8;
            OwnerDb::Certificate((0..length).map(|n| unsafe { read_volatile(bytes.add(28 + n)) }).collect())
        }
        0 => OwnerDb::None,
        _ => OwnerDb::Unusable,
    }
}

/// One tag of the firmware cryptography service, with `request` as the first
/// words of its value and `room` bytes of value: the words it answered with,
/// if the VPU answered.
fn crypto_call(tag: u32, request: &[u32], room: usize) -> Option<alloc::vec::Vec<u32>> {
    let buf = BIG.0.get() as *mut u32;
    let words = room / 4;
    if words + 6 > 6 + TPM_MAX / 4 {
        return None;
    }
    unsafe {
        write_volatile(buf, (4 * (words + 6)) as u32);
        write_volatile(buf.add(1), 0);
        write_volatile(buf.add(2), tag);
        write_volatile(buf.add(3), room as u32);
        write_volatile(buf.add(4), 4 * request.len() as u32);
        for i in 0..words {
            write_volatile(buf.add(5 + i), request.get(i).copied().unwrap_or(0));
        }
        write_volatile(buf.add(5 + words), 0);
    }
    if !post(buf as u64, 4 * (words + 6), TPM_ANSWER_US) || unsafe { read_volatile(buf.add(4)) } & RESPONSE == 0 {
        return None;
    }
    Some((0..words).map(|i| unsafe { read_volatile(buf.add(5 + i)) }).collect())
}

fn word_bytes(words: &[u32], len: usize) -> alloc::vec::Vec<u8> {
    words.iter().flat_map(|w| w.to_le_bytes()).take(len).collect()
}

/// `HMAC-SHA256(device key, message)`, the key as its 32 raw bytes, if a key is
/// fused and the VPU answers.
pub fn device_hmac(message: &[u8; 32]) -> Option<[u8; 32]> {
    let mut request = [0u32; 11];
    request[1] = DEVICE_KEY;
    request[2] = 32;
    for (w, bytes) in request[3..].iter_mut().zip(message.chunks_exact(4)) {
        *w = u32::from_le_bytes(bytes.try_into().unwrap());
    }
    let answer = crypto_call(TAG_CRYPTO_HMAC_SHA256, &request, 12 + 32)?;
    if answer[0] != 0 || answer[1] != 32 {
        return None;
    }
    word_bytes(&answer[2..], 32).try_into().ok()
}

/// Forbid the device key to sign and to HMAC until the next boot: the OS has
/// the board. Whether the VPU says the key is locked.
pub fn lock_device_key() -> bool {
    for _ in 0..3 {
        crypto_call(TAG_CRYPTO_SET_KEY_STATUS, &[DEVICE_KEY, SIGN_LOCKED | HMAC_LOCKED], 8);
        let locked = crypto_call(TAG_CRYPTO_KEY_STATUS, &[DEVICE_KEY], 4)
            .is_some_and(|answer| answer[0] & (SIGN_LOCKED | HMAC_LOCKED) == SIGN_LOCKED | HMAC_LOCKED);
        if locked {
            return true;
        }
    }
    false
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

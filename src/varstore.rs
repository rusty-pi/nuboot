//! The UEFI variable store in the EEPROM's free tail, as the VPU adds to it
//! once the OS has the board and UEFI is gone: the writes the OS makes through
//! the runtime services. The records are the ones `uefi/src/store.rs` reads
//! and writes. The VPU only appends; a bank that is full is compacted by UEFI
//! at its next boot.
//!
//! Two kinds of record come in. A variable no signature guards, which the VPU
//! seals with the device key as UEFI does, so the seal says the write went
//! through this firmware. And a record the OS made out of a write signed by PK
//! or a KEK key, which the VPU appends as it is: UEFI checks that signature
//! again at every boot, and what does not verify is ignored.

use crate::sha256::{self, Sha256};
use crate::{keystore, spi_flash};

pub const BASE: u32 = 0x74000;
pub const BANK: u32 = 0x5000;
const BANKS: [u32; 2] = [BASE, BASE + BANK];

const BANK_MAGIC: u32 = 0x5634_4950;
const RECORD_MAGIC: u32 = 0x5245_4331;
const BANK_HEADER: u32 = 8;
const RECORD_HEADER: usize = 60;
const DIGEST: usize = 32;
/// The device key's HMAC-SHA256 of a record's digest.
const SEAL: usize = 32;

pub const SET: u32 = 1;
pub const DELETE: u32 = 2;

/// The most a record is: UEFI keeps variables of up to 16 KiB.
pub const MAX_RECORD: usize = 20 * 1024;
const MAX_NAME_UNITS: usize = 256;
/// The most data the VPU seals for the OS.
pub const MAX_SEALED_DATA: usize = 16 * 1024;

const NV: u32 = 1;
const BS: u32 = 2;
const RT: u32 = 4;
/// `EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS` and the time-based one.
const AUTH: u32 = 0x10 | 0x20;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// The record is not one: its framing, size or digest is wrong.
    Malformed,
    /// A variable no signature guards is for the OS to write only if it is
    /// kept across resets and readable at runtime.
    Refused,
    /// The board has no device key to seal with.
    NoDeviceKey,
    /// The bank has no room: UEFI compacts it at the next boot.
    Full,
    /// The flash did not take the write.
    Flash,
}

/// Where the log ends: the bank, its sequence number and the next free byte.
struct Tail {
    bank: usize,
    seq: u32,
    at: u32,
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn bank_header(bank: usize) -> Option<u32> {
    let mut head = [0u8; 8];
    spi_flash::read(BANKS[bank], &mut head);
    (u32_at(&head, 0) == BANK_MAGIC).then(|| u32_at(&head, 4))
}

/// The first page at or after `from` that is erased.
fn first_erased(from: u32, end: u32) -> u32 {
    let mut at = from.next_multiple_of(4);
    let mut page = [0u8; spi_flash::PAGE];
    while at + spi_flash::PAGE as u32 <= end {
        spi_flash::read(at, &mut page);
        if page.iter().all(|&b| b == 0xff) {
            return at;
        }
        at += spi_flash::PAGE as u32;
    }
    end
}

/// The length of the intact record at `at`, in a bank that ends at `end`: its
/// framing, sizes and SHA-256 are the ones UEFI checks.
fn record_len(at: u32, end: u32) -> Option<u32> {
    let mut head = [0u8; RECORD_HEADER];
    if at.checked_add(RECORD_HEADER as u32)? > end {
        return None;
    }
    spi_flash::read(at, &mut head);
    let total = u32_at(&head, 4) as usize;
    if u32_at(&head, 0) != RECORD_MAGIC
        || total < RECORD_HEADER + DIGEST
        || total > MAX_RECORD
        || total % 4 != 0
        || at as usize + total > end as usize
    {
        return None;
    }
    let content = RECORD_HEADER as u64 + 2 * u32_at(&head, 48) as u64 + u32_at(&head, 52) as u64 + u32_at(&head, 56) as u64;
    if content > (total - DIGEST) as u64 {
        return None;
    }
    let mut hash = Sha256::new();
    let mut chunk = [0u8; 128];
    let mut done = 0;
    while done < total - DIGEST {
        let n = (total - DIGEST - done).min(chunk.len());
        spi_flash::read(at + done as u32, &mut chunk[..n]);
        hash.update(&chunk[..n]);
        done += n;
    }
    let mut stored = [0u8; DIGEST];
    spi_flash::read(at + (total - DIGEST) as u32, &mut stored);
    (hash.finish() == stored).then_some(total as u32)
}

/// The first intact record at or after `from`: what comes after a record that
/// is not, such as one cut short by a power loss.
fn find_record(from: u32, end: u32) -> Option<u32> {
    let mut at = from.next_multiple_of(4);
    let mut chunk = [0u8; 256];
    while at + 8 <= end {
        let n = (end - at).min(chunk.len() as u32) as usize;
        spi_flash::read(at, &mut chunk[..n]);
        let mut i = 0;
        while i + 8 <= n {
            if u32_at(&chunk, i) == RECORD_MAGIC && record_len(at + i as u32, end).is_some() {
                return Some(at + i as u32);
            }
            i += 4;
        }
        if n < 12 {
            break;
        }
        at += (n as u32 - 4) & !3;
    }
    None
}

/// Each intact record of the active bank: its start and its header, in order,
/// and the end of the log. A record that is not intact is stepped over to the
/// next one that is, as UEFI does when it reads the bank.
fn walk(mut each: impl FnMut(u32, &[u8; RECORD_HEADER])) -> Option<Tail> {
    let seqs = [bank_header(0), bank_header(1)];
    let bank = match (seqs[0], seqs[1]) {
        (Some(a), Some(b)) => usize::from(b.wrapping_sub(a) as i32 > 0),
        (Some(_), None) => 0,
        (None, Some(_)) => 1,
        (None, None) => return None,
    };
    let end = BANKS[bank] + BANK;
    let mut at = BANKS[bank] + BANK_HEADER;
    let mut head = [0u8; RECORD_HEADER];
    while at + 8 <= end {
        spi_flash::read(at, &mut head[..8]);
        if u32_at(&head, 0) == 0xffff_ffff {
            break;
        }
        match record_len(at, end) {
            Some(total) => {
                spi_flash::read(at, &mut head);
                each(at, &head);
                at += total;
            }
            None => match find_record(at + 4, end) {
                Some(next) => at = next,
                None => {
                    at = first_erased(at + 4, end);
                    break;
                }
            },
        }
    }
    Some(Tail { bank, seq: seqs[bank].unwrap_or(0), at })
}

/// The sequence number the next record of a variable no signature guards
/// gets: one past the highest among those the bank holds.
fn next_sequence() -> u64 {
    let mut next = 0u64;
    walk(|_, head| {
        let sealed = u32_at(head, 56) as usize == SEAL && u32_at(head, 12) & AUTH == 0;
        if sealed {
            let seq = u64::from_le_bytes(head[32..40].try_into().unwrap());
            next = next.max(seq.saturating_add(1));
        }
    });
    next
}

/// Start a bank: erased, and valid once its header is written.
fn start_bank(bank: usize, seq: u32) -> bool {
    for sector in (0..BANK).step_by(spi_flash::SECTOR) {
        if !spi_flash::erase_sector(BANKS[bank] + sector) {
            return false;
        }
    }
    let mut head = [0u8; 8];
    head[..4].copy_from_slice(&BANK_MAGIC.to_le_bytes());
    head[4..].copy_from_slice(&seq.to_le_bytes());
    spi_flash::program(BANKS[bank], &head)
}

/// Check a whole record's framing and digest.
fn check(record: &[u8]) -> Result<(), Error> {
    if record.len() < RECORD_HEADER + DIGEST
        || record.len() > MAX_RECORD
        || record.len() % 4 != 0
        || u32_at(record, 0) != RECORD_MAGIC
        || u32_at(record, 4) as usize != record.len()
    {
        return Err(Error::Malformed);
    }
    let (body, digest) = record.split_at(record.len() - DIGEST);
    let (name, data, auth) = (u32_at(record, 48) as usize, u32_at(record, 52) as usize, u32_at(record, 56) as usize);
    let content = RECORD_HEADER as u64 + 2 * name as u64 + data as u64 + auth as u64;
    if content > body.len() as u64 || sha256::digest(body) != *digest {
        return Err(Error::Malformed);
    }
    Ok(())
}

/// Append a whole record, as UEFI wrote it: framing and digest checked, and
/// the flash read back. Only the record of an authenticated write (`KEK`, `db`,
/// `dbx`) comes in this way: one without would claim a seal it has not got.
pub fn append(record: &[u8]) -> Result<(), Error> {
    check(record)?;
    if u32_at(record, 12) & AUTH == 0 || !matches!(u32_at(record, 8), SET | DELETE) {
        return Err(Error::Refused);
    }
    spi_flash::with_pins(|| append_with_pins(record))
}

/// [`append`], with the flash's pins already the SPI's.
fn append_with_pins(record: &[u8]) -> Result<(), Error> {
    let tail = match walk(|_, _| {}) {
        Some(tail) => tail,
        None => {
            if !start_bank(0, 1) {
                return Err(Error::Flash);
            }
            Tail { bank: 0, seq: 1, at: BANKS[0] + BANK_HEADER }
        }
    };
    let _ = tail.seq;
    if tail.at as usize + record.len() > (BANKS[tail.bank] + BANK) as usize {
        return Err(Error::Full);
    }
    if !spi_flash::program(tail.at, record) {
        return Err(Error::Flash);
    }
    let mut back = [0u8; 64];
    for (n, chunk) in record.chunks(back.len()).enumerate() {
        let back = &mut back[..chunk.len()];
        spi_flash::read(tail.at + (n * 64) as u32, back);
        if back != chunk {
            return Err(Error::Flash);
        }
    }
    Ok(())
}

static mut RECORD: [u8; MAX_RECORD] = [0; MAX_RECORD];

/// Seal and append a write of a variable no signature guards: a non-volatile
/// variable the OS can read, or the deletion of one. `name` is UCS-2, as
/// bytes. The seal is of the runtime domain, which UEFI accepts for these
/// attributes and no others: what the OS asks the VPU to seal is the OS's own
/// say, never a firmware variable's.
pub fn persist(kind: u32, attributes: u32, guid: &[u8; 16], name: &[u8], data: &[u8]) -> Result<(), Error> {
    let units = name.len() / 2;
    if !(kind == SET || kind == DELETE)
        || name.len() % 2 != 0
        || units == 0
        || units > MAX_NAME_UNITS
        || name.chunks_exact(2).any(|unit| unit == [0, 0])
        || attributes != NV | BS | RT
        || (kind == DELETE && !data.is_empty())
        || data.len() > MAX_SEALED_DATA
    {
        return Err(Error::Refused);
    }
    let body = RECORD_HEADER + name.len() + data.len() + SEAL;
    let total = body.next_multiple_of(4) + DIGEST;
    if total > MAX_RECORD {
        return Err(Error::Refused);
    }
    let record = unsafe { &mut *(&raw mut RECORD) };
    record[..total].fill(0);
    let seq = spi_flash::with_pins(next_sequence);
    let mut time = [0u8; 16];
    time[..8].copy_from_slice(&seq.to_le_bytes());
    record[0..4].copy_from_slice(&RECORD_MAGIC.to_le_bytes());
    record[4..8].copy_from_slice(&(total as u32).to_le_bytes());
    record[8..12].copy_from_slice(&kind.to_le_bytes());
    record[12..16].copy_from_slice(&attributes.to_le_bytes());
    record[16..32].copy_from_slice(guid);
    record[32..48].copy_from_slice(&time);
    record[48..52].copy_from_slice(&(units as u32).to_le_bytes());
    record[52..56].copy_from_slice(&(data.len() as u32).to_le_bytes());
    record[56..60].copy_from_slice(&(SEAL as u32).to_le_bytes());
    let name_at = RECORD_HEADER;
    record[name_at..name_at + name.len()].copy_from_slice(name);
    let data_at = name_at + name.len();
    record[data_at..data_at + data.len()].copy_from_slice(data);

    let mut digest = Sha256::new();
    digest.update(b"nuboot runtime variable record v2");
    digest.update(&kind.to_le_bytes());
    digest.update(&attributes.to_le_bytes());
    digest.update(guid);
    digest.update(&time);
    digest.update(&(units as u32).to_le_bytes());
    digest.update(&(data.len() as u32).to_le_bytes());
    digest.update(name);
    digest.update(data);
    let seal = keystore::device_hmac(&digest.finish()).map_err(|_| Error::NoDeviceKey)?;
    let seal_at = data_at + data.len();
    record[seal_at..seal_at + SEAL].copy_from_slice(&seal);

    let tail = body.next_multiple_of(4);
    let digest = sha256::digest(&record[..tail]);
    record[tail..tail + DIGEST].copy_from_slice(&digest);
    spi_flash::with_pins(|| append_with_pins(&record[..total]))
}

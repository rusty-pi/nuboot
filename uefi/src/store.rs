//! The variable store: a log of records in two banks in the free tail of the
//! stock EEPROM image's flash, after its last section. Records are only appended; a full bank is replaced by a
//! fresh one holding what is still live, which becomes valid once its header
//! is written. A record carries its own SHA-256, so one cut short by a power
//! loss ends the log instead of being read.

use alloc::vec::Vec;

use crate::sha256;
use crate::spiflash::{self, PAGE, SECTOR};
use crate::util::Global;
use crate::{debug, info, warn};

pub const BASE: u32 = 0x74000;
pub const BANK: u32 = 0x5000;
const BANKS: [u32; 2] = [BASE, BASE + BANK];

const BANK_MAGIC: u32 = 0x5634_4950;
const RECORD_MAGIC: u32 = 0x5245_4331;
const BANK_HEADER: u32 = 8;
const RECORD_HEADER: usize = 60;
const DIGEST: usize = 32;
const MAX_RECORD: usize = 80 * 1024;

pub const SET: u32 = 1;
pub const DELETE: u32 = 2;

/// One change to a variable.
#[derive(Clone)]
pub struct Record {
    pub kind: u32,
    pub attributes: u32,
    pub guid: [u8; 16],
    pub time: [u8; 16],
    pub name: Vec<u16>,
    pub data: Vec<u8>,
    pub auth: Vec<u8>,
}

struct State {
    ready: bool,
    bank: usize,
    seq: u32,
    tail: u32,
}

static STATE: Global<State> = Global::new(State { ready: false, bank: 0, seq: 0, tail: 0 });

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

impl Record {
    fn encode(&self) -> Vec<u8> {
        let body = RECORD_HEADER + self.name.len() * 2 + self.data.len() + self.auth.len();
        let total = body.next_multiple_of(4) + DIGEST;
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&RECORD_MAGIC.to_le_bytes());
        out.extend_from_slice(&(total as u32).to_le_bytes());
        out.extend_from_slice(&self.kind.to_le_bytes());
        out.extend_from_slice(&self.attributes.to_le_bytes());
        out.extend_from_slice(&self.guid);
        out.extend_from_slice(&self.time);
        out.extend_from_slice(&(self.name.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.auth.len() as u32).to_le_bytes());
        for c in &self.name {
            out.extend_from_slice(&c.to_le_bytes());
        }
        out.extend_from_slice(&self.data);
        out.extend_from_slice(&self.auth);
        out.resize(body.next_multiple_of(4), 0);
        let digest = sha256::digest(&out);
        out.extend_from_slice(&digest);
        out
    }

    fn decode(b: &[u8]) -> Option<Record> {
        if b.len() < RECORD_HEADER + DIGEST || u32_at(b, 0) != RECORD_MAGIC || u32_at(b, 4) as usize != b.len() {
            return None;
        }
        let (body, digest) = b.split_at(b.len() - DIGEST);
        if sha256::digest(body) != *digest {
            return None;
        }
        let (name_chars, data_len, auth_len) = (u32_at(b, 48) as usize, u32_at(b, 52) as usize, u32_at(b, 56) as usize);
        let name_end = RECORD_HEADER + name_chars.checked_mul(2)?;
        let data_end = name_end.checked_add(data_len)?;
        let auth_end = data_end.checked_add(auth_len)?;
        if auth_end > body.len() {
            return None;
        }
        Some(Record {
            kind: u32_at(b, 8),
            attributes: u32_at(b, 12),
            guid: b[16..32].try_into().unwrap(),
            time: b[32..48].try_into().unwrap(),
            name: b[RECORD_HEADER..name_end].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect(),
            data: b[name_end..data_end].to_vec(),
            auth: b[data_end..auth_end].to_vec(),
        })
    }
}

fn bank_header(bank: usize) -> Option<u32> {
    let mut head = [0u8; 8];
    spiflash::read(BANKS[bank], &mut head);
    (u32_at(&head, 0) == BANK_MAGIC).then(|| u32_at(&head, 4))
}

/// Whether the store reaches a flash that answers.
pub fn available() -> bool {
    STATE.get().ready
}

/// Read the active bank's records, oldest first.
pub fn load() -> Vec<Record> {
    let state = STATE.get();
    let mut out;
    if !spiflash::present() {
        warn!("store", "no flash answers, variables stay in memory");
        return Vec::new();
    }
    let seqs = [bank_header(0), bank_header(1)];
    let bank = match (seqs[0], seqs[1]) {
        (Some(a), Some(b)) => usize::from(b.wrapping_sub(a) as i32 > 0),
        (Some(_), None) => 0,
        (None, Some(_)) => 1,
        (None, None) => {
            state.ready = true;
            state.bank = 1;
            state.seq = 0;
            state.tail = 0;
            info!("store", "flash store is empty");
            return Vec::new();
        }
    };
    let mut image = alloc::vec![0xffu8; BANK as usize];
    spiflash::read(BANKS[bank], &mut image);
    let (records, tail, damaged) = parse(&image);
    out = records;
    let used = tail as u32 - BANK_HEADER;
    state.ready = true;
    state.bank = bank;
    state.seq = seqs[bank].unwrap_or(0);
    state.tail = BANKS[bank] + tail as u32;
    info!("store", "flash store loaded"; records = out.len(), bank = bank, used = used, damaged = damaged);
    if damaged {
        warn!("store", "a record was unreadable, the store moves to the other bank without it");
        let other = 1 - bank;
        let seq = state.seq.wrapping_add(1).max(1);
        match write_bank(other, seq, &out) {
            Some(tail) => *state = State { ready: true, bank: other, seq, tail },
            None => warn!("store", "the store did not move, what is after the damage is read again at the next boot"),
        }
    }
    out
}

/// The records of a bank's image in order, where the log ends in it, and
/// whether a record in it was unreadable. A record that is not intact is
/// stepped over to the next one that is: what the VPU appended after a write
/// cut short by a power loss is still there.
fn parse(image: &[u8]) -> (Vec<Record>, usize, bool) {
    let mut out = Vec::new();
    let mut damaged = false;
    let mut at = BANK_HEADER as usize;
    while at + 8 <= image.len() {
        if u32_at(image, at) == 0xffff_ffff {
            break;
        }
        match record_at(image, at) {
            Some((record, total)) => {
                at += total;
                out.push(record);
            }
            None => {
                damaged = true;
                warn!("store", "record unreadable"; at = at);
                match (at + 4..image.len().saturating_sub(8)).step_by(4).find(|&p| record_at(image, p).is_some()) {
                    Some(next) => at = next,
                    None => {
                        at = first_erased_in(image, at + 4);
                        break;
                    }
                }
            }
        }
    }
    (out, at, damaged)
}

fn record_at(image: &[u8], at: usize) -> Option<(Record, usize)> {
    if u32_at(image, at) != RECORD_MAGIC {
        return None;
    }
    let total = u32_at(image, at + 4) as usize;
    if total % 4 != 0 || total > MAX_RECORD || at.checked_add(total)? > image.len() {
        return None;
    }
    Some((Record::decode(&image[at..at + total])?, total))
}

/// The first page at or after `from` of `image` that is erased.
fn first_erased_in(image: &[u8], from: usize) -> usize {
    let mut at = from.next_multiple_of(4);
    while at + PAGE <= image.len() {
        if image[at..at + PAGE].iter().all(|&b| b == 0xff) {
            return at;
        }
        at += PAGE;
    }
    image.len()
}

fn write_bank(bank: usize, seq: u32, records: &[Record]) -> Option<u32> {
    let base = BANKS[bank];
    for sector in (0..BANK).step_by(SECTOR) {
        if !spiflash::erase_sector(base + sector) {
            return None;
        }
    }
    let mut at = base + BANK_HEADER;
    for r in records {
        let bytes = r.encode();
        if at as usize + bytes.len() > (base + BANK) as usize || !spiflash::program(at, &bytes) {
            return None;
        }
        at += bytes.len() as u32;
    }
    let mut head = [0u8; 8];
    head[..4].copy_from_slice(&BANK_MAGIC.to_le_bytes());
    head[4..].copy_from_slice(&seq.to_le_bytes());
    spiflash::program(base, &head).then_some(at)
}

/// Start the other bank with `live`, every record the variables still need,
/// when this one is more than half full and that leaves it room. Once UEFI is
/// gone the VPU only appends, and the OS's writes fail when the bank is full:
/// the boot is where room is made.
pub fn compact_when_crowded(live: impl FnOnce() -> Vec<Record>) {
    let state = STATE.get();
    if !state.ready || state.seq == 0 || !spiflash::present() {
        return;
    }
    let used = (state.tail - BANKS[state.bank] - BANK_HEADER) as usize;
    if used <= (BANK - BANK_HEADER) as usize / 2 {
        return;
    }
    let records = live();
    let needed: usize = records.iter().map(|r| r.encode().len()).sum();
    if needed >= used {
        return;
    }
    let other = 1 - state.bank;
    let seq = state.seq.wrapping_add(1).max(1);
    match write_bank(other, seq, &records) {
        Some(tail) => {
            *state = State { ready: true, bank: other, seq, tail };
            info!("store", "bank more than half full, the other started with what is still needed"; bank = other, records = records.len(), bytes = used, bytes_needed = needed);
        }
        None => warn!("store", "bank more than half full and the other did not take what is needed"; bytes = used, bytes_needed = needed),
    }
}

/// Add `record` to the log. When the bank is full, `live` (every record
/// still needed, `record` included) starts the other bank.
pub fn append(record: &Record, live: impl FnOnce() -> Vec<Record>) -> bool {
    let state = STATE.get();
    if !state.ready || !spiflash::present() {
        return false;
    }
    let bytes = record.encode();
    let end = BANKS[state.bank] + BANK;
    if state.seq != 0 && state.tail as usize + bytes.len() <= end as usize {
        debug!("store", "appending"; at = state.tail, len = bytes.len());
        if spiflash::program(state.tail, &bytes) {
            let mut back = alloc::vec![0u8; bytes.len()];
            spiflash::read(state.tail, &mut back);
            if back != bytes {
                warn!("store", "record read back differs"; at = state.tail);
            }
            state.tail += bytes.len() as u32;
            return true;
        }
        warn!("store", "record not written");
        return false;
    }
    let other = 1 - state.bank;
    let seq = state.seq.wrapping_add(1).max(1);
    let records = live();
    debug!("store", "compacting"; bank = other, records = records.len(), bytes = records.iter().map(|r| r.encode().len()).sum::<usize>());
    match write_bank(other, seq, &records) {
        Some(tail) => {
            debug!("store", "store moved to the other bank"; bank = other, seq = seq);
            *state = State { ready: true, bank: other, seq, tail };
            true
        }
        None => {
            warn!("store", "store does not fit the flash");
            false
        }
    }
}

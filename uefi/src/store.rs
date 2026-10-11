//! The variable store: a log of records in two banks at the end of the
//! EEPROM's flash. Records are only appended; a full bank is replaced by a
//! fresh one holding what is still live, which becomes valid once its header
//! is written. A record carries its own SHA-256, so one cut short by a power
//! loss ends the log instead of being read.

use alloc::vec::Vec;

use crate::sha256;
use crate::spiflash::{self, PAGE, SECTOR};
use crate::util::Global;
use crate::{debug, info, warn};

const BASE: u32 = 0x62000;
const BANK: u32 = 0xF000;
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

/// The first page at or after `from` that is erased, so a record cut short
/// by a power loss is stepped over.
fn first_erased(from: u32, end: u32) -> u32 {
    let mut at = from.next_multiple_of(4);
    let mut page = [0u8; PAGE];
    while at + PAGE as u32 <= end {
        spiflash::read(at, &mut page);
        if page.iter().all(|&b| b == 0xff) {
            return at;
        }
        at += PAGE as u32;
    }
    end
}

/// Whether the store reaches a flash that answers.
pub fn available() -> bool {
    STATE.get().ready
}

/// Read the active bank's records, oldest first.
pub fn load() -> Vec<Record> {
    let state = STATE.get();
    let mut out = Vec::new();
    if !spiflash::present() {
        warn!("store", "no flash answers, variables stay in memory");
        return out;
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
            return out;
        }
    };
    let start = BANKS[bank] + BANK_HEADER;
    let end = BANKS[bank] + BANK;
    let mut at = start;
    let mut head = [0u8; 8];
    while at + 8 <= end {
        spiflash::read(at, &mut head);
        if u32_at(&head, 0) == 0xffff_ffff {
            break;
        }
        let total = u32_at(&head, 4) as usize;
        let record = (u32_at(&head, 0) == RECORD_MAGIC && total <= MAX_RECORD && at as usize + total <= end as usize && total % 4 == 0)
            .then(|| {
                let mut b = alloc::vec![0u8; total];
                spiflash::read(at, &mut b);
                Record::decode(&b)
            })
            .flatten();
        match record {
            Some(r) => {
                at += total as u32;
                out.push(r);
            }
            None => {
                warn!("store", "record unreadable, log ends here"; at = at);
                at = first_erased(at + 4, end);
                break;
            }
        }
    }
    state.ready = true;
    state.bank = bank;
    state.seq = seqs[bank].unwrap_or(0);
    state.tail = at;
    info!("store", "flash store loaded"; records = out.len(), bank = bank, used = at - start);
    out
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
        if spiflash::program(state.tail, &bytes) {
            state.tail += bytes.len() as u32;
            return true;
        }
        warn!("store", "record not written");
        return false;
    }
    let other = 1 - state.bank;
    let seq = state.seq.wrapping_add(1).max(1);
    match write_bank(other, seq, &live()) {
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

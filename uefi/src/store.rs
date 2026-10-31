//! The variable store: a log of records in two banks of a medium (the window
//! on the boot disk, [`crate::diskstore`]). Records are only appended; a full
//! bank is replaced by a fresh one holding what is still live, which becomes
//! valid once its header is written. A record carries its own SHA-256, so one
//! cut short by a power loss ends the log instead of being read.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::sha256;
use crate::util::Global;
use crate::{debug, info, warn};

/// Where the banks are kept: `len` bytes, read and written at any offset.
/// What `write` returns true for is on the medium.
pub trait Medium {
    fn len(&self) -> u32;
    fn read(&mut self, at: u32, buf: &mut [u8]) -> bool;
    fn write(&mut self, at: u32, data: &[u8]) -> bool;
}

static MEDIUM: Global<Option<Box<dyn Medium>>> = Global::new(None);

/// Keep the store on `medium`.
pub fn attach(medium: Box<dyn Medium>) {
    *MEDIUM.get() = Some(medium);
}

fn medium() -> Option<&'static mut dyn Medium> {
    MEDIUM.get().as_deref_mut()
}

/// The size of one bank, and where a bank starts.
fn bank_len() -> u32 {
    medium().map_or(0, |m| m.len() / 2)
}

fn bank_base(bank: usize) -> u32 {
    bank as u32 * bank_len()
}

/// How much of a bank is read or erased at a time.
const CHUNK: usize = 16 * 1024;

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
    if !medium()?.read(bank_base(bank), &mut head) {
        return None;
    }
    (u32_at(&head, 0) == BANK_MAGIC).then(|| u32_at(&head, 4))
}

/// Whether the store reaches a medium that answers.
pub fn available() -> bool {
    STATE.get().ready
}

/// Read `buf` from `at` in the medium.
pub fn read_raw(at: u32, buf: &mut [u8]) -> bool {
    medium().is_some_and(|m| m.read(at, buf))
}

/// Start the first bank when the store has none, so that the log has a header
/// to append to once UEFI is gone.
pub fn start_if_empty() {
    let state = STATE.get();
    if !state.ready || state.seq != 0 {
        return;
    }
    match write_bank(0, 1, &[]) {
        Some(tail) => *state = State { ready: true, bank: 0, seq: 1, tail },
        None => warn!("store", "the first bank could not be started"),
    }
}

/// Where the log of the active bank ends, as an offset in the medium, and the
/// bank's last byte.
pub fn tail() -> (u32, u32) {
    let state = STATE.get();
    (state.tail, bank_base(state.bank) + bank_len())
}

/// A bank's bytes. All of it is read: a record can hold a chunk of erased
/// bytes, so no chunk says where the log ends.
fn read_bank(bank: usize) -> Option<Vec<u8>> {
    let m = medium()?;
    let mut image = alloc::vec![0xffu8; bank_len() as usize];
    for (n, chunk) in image.chunks_mut(CHUNK).enumerate() {
        if !m.read(bank_base(bank) + (n * CHUNK) as u32, chunk) {
            return None;
        }
    }
    Some(image)
}

/// Erase a bank: every chunk of it that is not erased already is overwritten.
fn erase_bank(bank: usize) -> bool {
    let Some(m) = medium() else { return false };
    let erased = alloc::vec![0xffu8; CHUNK];
    let mut at = 0;
    while at < bank_len() {
        let n = CHUNK.min((bank_len() - at) as usize);
        let mut got = alloc::vec![0u8; n];
        let base = bank_base(bank) + at;
        if !m.read(base, &mut got) || (got.iter().any(|&b| b != 0xff) && !m.write(base, &erased[..n])) {
            return false;
        }
        at += n as u32;
    }
    true
}

/// Read the active bank's records, oldest first.
pub fn load() -> Vec<Record> {
    let state = STATE.get();
    let out;
    if medium().is_none() {
        warn!("store", "no disk holds the store, variables stay in memory");
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
            info!("store", "variable store is empty");
            return Vec::new();
        }
    };
    let Some(image) = read_bank(bank) else {
        warn!("store", "the store could not be read, variables stay in memory");
        return Vec::new();
    };
    let (records, tail, damaged) = parse(&image);
    out = records;
    let used = tail as u32 - BANK_HEADER;
    state.ready = true;
    state.bank = bank;
    state.seq = seqs[bank].unwrap_or(0);
    state.tail = bank_base(bank) + tail as u32;
    info!("store", "variable store loaded"; records = out.len(), bank = bank, used = used, damaged = damaged);
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

/// The first block of 256 bytes at or after `from` of `image` that is erased.
fn first_erased_in(image: &[u8], from: usize) -> usize {
    const BLOCK: usize = 256;
    let mut at = from.next_multiple_of(4);
    while at + BLOCK <= image.len() {
        if image[at..at + BLOCK].iter().all(|&b| b == 0xff) {
            return at;
        }
        at += BLOCK;
    }
    image.len()
}

/// Write `bytes` at `at`, and whether they read back as they were written.
fn write_verified(at: u32, bytes: &[u8]) -> bool {
    let Some(m) = medium() else { return false };
    if !m.write(at, bytes) {
        return false;
    }
    let mut back = alloc::vec![0u8; bytes.len()];
    m.read(at, &mut back) && back == bytes
}

fn write_bank(bank: usize, seq: u32, records: &[Record]) -> Option<u32> {
    let base = bank_base(bank);
    if !erase_bank(bank) {
        return None;
    }
    let mut log = Vec::new();
    for r in records {
        log.extend_from_slice(&r.encode());
    }
    if BANK_HEADER as usize + log.len() > bank_len() as usize || !(log.is_empty() || write_verified(base + BANK_HEADER, &log)) {
        return None;
    }
    let mut head = [0u8; 8];
    head[..4].copy_from_slice(&BANK_MAGIC.to_le_bytes());
    head[4..].copy_from_slice(&seq.to_le_bytes());
    write_verified(base, &head).then_some(base + BANK_HEADER + log.len() as u32)
}

/// Start the other bank with `live`, every record the variables still need,
/// when this one is more than half full and that leaves it room. Once UEFI is
/// gone the VPU only appends, and the OS's writes fail when the bank is full:
/// the boot is where room is made.
pub fn compact_when_crowded(live: impl FnOnce() -> Vec<Record>) {
    let state = STATE.get();
    if !state.ready || state.seq == 0 || medium().is_none() {
        return;
    }
    let used = (state.tail - bank_base(state.bank) - BANK_HEADER) as usize;
    if used <= (bank_len() - BANK_HEADER) as usize / 2 {
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
    if !state.ready || medium().is_none() {
        return false;
    }
    let bytes = record.encode();
    let end = bank_base(state.bank) + bank_len();
    if state.seq != 0 && state.tail as usize + bytes.len() <= end as usize {
        debug!("store", "appending"; at = state.tail, len = bytes.len());
        let at = state.tail;
        state.tail += bytes.len() as u32;
        if !write_verified(at, &bytes) {
            warn!("store", "record not written or read back differently, not taken"; at = at);
            return false;
        }
        return true;
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
            warn!("store", "store does not fit the disk window");
            false
        }
    }
}

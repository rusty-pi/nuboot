//! The variable services after `ExitBootServices`. The OS calls them through
//! its own mapping of the regions typed as runtime services, which it places
//! where they are (`EFI_RT_PROPERTIES_TABLE` does not offer
//! `SetVirtualAddressMap`), so they run from the image's own code and touch
//! nothing but the table below: no allocation, no logging, no registers of
//! the board but one page, the mailbox's. The variables that are readable at
//! runtime are copied into it at `ExitBootServices`.
//!
//! A write the OS makes to a non-volatile variable no signature guards is
//! sealed by the VPU with the device key, and kept with the records of the
//! other writes until `ResetSystem`, which appends them to the variable store
//! on the SD card (the OS owns the card until then). A write to `KEK`, `db` or
//! `dbx` is made of a signature and is kept as it is, for UEFI to check at
//! the next boot against `PK` and the `KEK`s, and takes effect then; the table
//! keeps the old value until then. The VPU's answer comes in the message's own
//! buffer: its channel is not the one the OS's mailbox driver listens on, and
//! nothing is posted back.
//!
//! Writes the board loses power or resets without `ResetSystem` for are lost.
//! A store that is not on the SD card is not reached from here: the writes
//! last until reset.

use core::ffi::c_void;

use r_efi::efi;

use crate::util::{Global, wstr};

const CAPACITY: usize = 128 * 1024;
const MAX_VARIABLE: usize = 32 * 1024;

const BS: u32 = efi::VARIABLE_BOOTSERVICE_ACCESS;
const RT: u32 = efi::VARIABLE_RUNTIME_ACCESS;
const AUTH: u32 = efi::VARIABLE_AUTHENTICATED_WRITE_ACCESS | efi::VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
const APPEND: u32 = efi::VARIABLE_APPEND_WRITE;

/// An entry is a header, the name in UCS-2 and the data, padded to 4 bytes:
/// `total: u32, attributes: u32, data length: u32, name length: u16, flags:
/// u16, GUID: 16 bytes`.
const HEADER: usize = 32;
const DELETED: u16 = 1;
/// The OS may change it: not `PK`, `KEK`, `db`, `dbx` or the Secure Boot state.
const WRITABLE: u16 = 2;
/// `KEK`, `db` or `dbx`: an authenticated write may change it.
const KEY: u16 = 4;

/// The mailbox registers' page, which the OS has to map for these services.
pub const MAILBOX_PAGE: u64 = 0xfe00_b000;
const MAIL1_WRITE: u64 = 0xfe00_b8a0;
const MAIL1_STATUS: u64 = 0xfe00_b8b8;
const MAIL_FULL: u32 = 1 << 31;
const CHANNEL_RUNTIME: u32 = 7;
const RESPONSE: u32 = 0x8000_0000;
const TAG_STORE_SEAL: u32 = 0x0003_00a9;
const TAG_STORE_PREPARE_CARD: u32 = 0x0003_00aa;
/// The most the VPU takes of a variable.
const PERSIST_MAX: usize = 16 * 1024;
const PERSIST_NAME_MAX: usize = 512;
const TIME_BASED: u32 = efi::VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
const NV: u32 = efi::VARIABLE_NON_VOLATILE;
const SET: u32 = 1;
const DELETE: u32 = 2;
const RECORD_MAGIC: u32 = 0x5245_4331;
/// The device key's seal on a record.
const SEAL: usize = 32;

const MESSAGE_WORDS: usize = 6 + 8 + (PERSIST_MAX + PERSIST_NAME_MAX + 4096) / 4;

/// The message to the VPU: where the first word of its value is, and the rest.
#[repr(C, align(64))]
struct Message([u32; MESSAGE_WORDS]);

static MESSAGE: Global<Message> = Global::new(Message([0; MESSAGE_WORDS]));

/// The block size of the SD card, which the flush writes in.
const BLOCK: usize = 512;
/// The most records written since boot that are kept for `ResetSystem`.
const QUEUE_MAX: usize = 64 * 1024;

/// The records to append to the store: the block the log ends in as it was, up
/// to where the log ends, then the records.
#[repr(C, align(8))]
struct Queue([u8; BLOCK + QUEUE_MAX + BLOCK]);

static QUEUE: Global<Queue> = Global::new(Queue([0; BLOCK + QUEUE_MAX + BLOCK]));

/// Where the queue goes and how much of it is used.
struct Pending {
    /// Whether the store is on the SD card, and the OS may write to it.
    armed: bool,
    /// The card's block the log ends in, and where in it.
    lba: u64,
    skip: usize,
    /// How much of the queue the records take, and how much more fits.
    len: usize,
    room: usize,
    /// The number of the next write the VPU seals.
    seq: u64,
}

static PENDING: Global<Pending> = Global::new(Pending { armed: false, lba: 0, skip: 0, len: 0, room: 0, seq: 0 });

/// Where the log of the store ends, for the writes of the OS to be added to.
pub struct Target {
    pub lba: u64,
    /// The bytes of that block before the end of the log.
    pub head: [u8; BLOCK],
    pub skip: usize,
    /// How much room the bank has left.
    pub room: usize,
}

/// Keep the writes the OS makes for `ResetSystem`, numbered from `seq`, when
/// the store is where the flush reaches.
pub fn arm(seq: u64, target: Option<Target>) {
    let p = PENDING.get();
    *p = Pending { armed: false, lba: 0, skip: 0, len: 0, room: 0, seq };
    if let Some(t) = target {
        QUEUE.get().0[..BLOCK].copy_from_slice(&t.head);
        *p = Pending { armed: true, lba: t.lba, skip: t.skip, len: 0, room: t.room.min(QUEUE_MAX), seq };
    }
}

#[repr(C, align(8))]
struct Table([u8; CAPACITY]);

static TABLE: Global<Table> = Global::new(Table([0; CAPACITY]));
static USED: Global<usize> = Global::new(0);

fn base() -> *mut u8 {
    TABLE.get().0.as_mut_ptr()
}

fn read<const N: usize>(at: usize) -> [u8; N] {
    let mut out = [0u8; N];
    if at + N <= CAPACITY {
        unsafe { core::ptr::copy_nonoverlapping(base().add(at), out.as_mut_ptr(), N) };
    }
    out
}

fn put(at: usize, bytes: &[u8]) {
    if at + bytes.len() <= CAPACITY {
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), base().add(at), bytes.len()) };
    }
}

fn rd32(at: usize) -> u32 {
    u32::from_le_bytes(read(at))
}

fn rd16(at: usize) -> u16 {
    u16::from_le_bytes(read(at))
}

struct Entry {
    at: usize,
    total: usize,
    attributes: u32,
    data_len: usize,
    name_len: usize,
    flags: u16,
}

impl Entry {
    fn name_at(&self) -> usize {
        self.at + HEADER
    }

    fn data_at(&self) -> usize {
        self.at + HEADER + self.name_len * 2
    }

    fn live(&self) -> bool {
        self.flags & DELETED == 0
    }

    fn named(&self, name: &[u16], guid: &efi::Guid) -> bool {
        self.live()
            && self.name_len == name.len()
            && read::<16>(self.at + 16) == *guid.as_bytes()
            && name.iter().enumerate().all(|(i, &c)| rd16(self.name_at() + 2 * i) == c)
    }
}

fn entry_at(at: usize) -> Option<Entry> {
    let used = *USED.get();
    if at + HEADER > used {
        return None;
    }
    let e = Entry {
        at,
        total: rd32(at) as usize,
        attributes: rd32(at + 4),
        data_len: rd32(at + 8) as usize,
        name_len: rd16(at + 12) as usize,
        flags: rd16(at + 14),
    };
    let fits = e.total % 4 == 0 && at + e.total <= used && HEADER + e.name_len * 2 + e.data_len <= e.total;
    fits.then_some(e)
}

fn entries() -> impl Iterator<Item = Entry> {
    let mut at = 0;
    core::iter::from_fn(move || {
        let e = entry_at(at)?;
        at += e.total;
        Some(e)
    })
}

fn find(name: &[u16], guid: &efi::Guid) -> Option<Entry> {
    entries().find(|e| e.named(name, guid))
}

fn entry_size(name_len: usize, data_len: usize) -> usize {
    (HEADER + name_len * 2 + data_len).next_multiple_of(4)
}

fn live_bytes() -> usize {
    entries().filter(Entry::live).map(|e| e.total).sum()
}

/// Drop the deleted entries, moving the rest down.
fn compact() {
    let (mut from, mut to) = (0, 0);
    while let Some(e) = entry_at(from) {
        let next = from + e.total;
        if e.live() {
            if to != from {
                unsafe { core::ptr::copy(base().add(from), base().add(to), e.total) };
            }
            to += e.total;
        }
        from = next;
    }
    *USED.get() = to;
}

/// Room for an entry of `size` bytes at the end, compacting if it takes it.
fn reserve(size: usize) -> bool {
    if *USED.get() + size > CAPACITY {
        compact();
    }
    *USED.get() + size <= CAPACITY
}

/// Add an entry at the end. `data` may point into the table.
fn push(name: &[u16], guid: &efi::Guid, attributes: u32, flags: u16, parts: &[(*const u8, usize)]) -> bool {
    let data_len: usize = parts.iter().map(|p| p.1).sum();
    let total = entry_size(name.len(), data_len);
    if !reserve(total) {
        return false;
    }
    let at = *USED.get();
    put(at, &(total as u32).to_le_bytes());
    put(at + 4, &attributes.to_le_bytes());
    put(at + 8, &(data_len as u32).to_le_bytes());
    put(at + 12, &(name.len() as u16).to_le_bytes());
    put(at + 14, &flags.to_le_bytes());
    put(at + 16, guid.as_bytes());
    for (i, c) in name.iter().enumerate() {
        put(at + HEADER + 2 * i, &c.to_le_bytes());
    }
    let mut to = at + HEADER + name.len() * 2;
    for &(from, len) in parts {
        if to + len <= CAPACITY {
            unsafe { core::ptr::copy_nonoverlapping(from, base().add(to), len) };
        }
        to += len;
    }
    for pad in to..at + total {
        put(pad, &[0]);
    }
    *USED.get() = at + total;
    true
}

/// Start the table afresh, for the boot's variables to be added to.
pub fn clear() {
    *USED.get() = 0;
}

/// Add a variable the OS may read, and change when `writable`. Whether it fit.
pub fn add(name: &[u16], guid: &efi::Guid, attributes: u32, data: &[u8], writable: bool, key: bool) -> bool {
    let flags = if writable { WRITABLE } else { 0 } | if key { KEY } else { 0 };
    push(name, guid, attributes, flags, &[(data.as_ptr(), data.len())])
}

fn counter() -> u64 {
    let now: u64;
    unsafe { core::arch::asm!("isb", "mrs {0}, cntpct_el0", out(reg) now) };
    now
}

fn frequency() -> u64 {
    let hz: u64;
    unsafe { core::arch::asm!("mrs {0}, cntfrq_el0", out(reg) hz) };
    hz
}

fn flush(at: usize, len: usize) {
    for line in (at & !63..at + len).step_by(64) {
        unsafe { core::arch::asm!("dc civac, {}", in(reg) line) };
    }
    unsafe { core::arch::asm!("dsb sy") };
}

/// The message's value, which the VPU reads and answers in.
fn value() -> &'static mut [u8] {
    let m = MESSAGE.get().0.as_mut_ptr() as *mut u8;
    unsafe { core::slice::from_raw_parts_mut(m.add(20), 4 * (MESSAGE_WORDS - 6)) }
}

/// Post `tag` with the first `len` bytes of [`value`] as its value, and wait
/// for the VPU's status word, which it writes over the value's first. `None`
/// if it did not answer.
fn post(tag: u32, len: usize) -> Option<u32> {
    let words = len.div_ceil(4);
    if words + 7 > MESSAGE_WORDS {
        return None;
    }
    let m = MESSAGE.get().0.as_mut_ptr();
    unsafe {
        core::ptr::write_bytes((m.add(5) as *mut u8).add(len), 0, 4 * words - len);
        core::ptr::write_volatile(m, (4 * (words + 6)) as u32);
        core::ptr::write_volatile(m.add(1), 0);
        core::ptr::write_volatile(m.add(2), tag);
        core::ptr::write_volatile(m.add(3), (4 * words) as u32);
        core::ptr::write_volatile(m.add(4), len as u32);
        core::ptr::write_volatile(m.add(5 + words), 0);
    }
    flush(m as usize, 4 * (words + 6));
    let bus = 0xc000_0000 | m as u32;
    let deadline = counter() + 5 * frequency();
    unsafe {
        while core::ptr::read_volatile(MAIL1_STATUS as *const u32) & MAIL_FULL != 0 {
            if counter() > deadline {
                return None;
            }
        }
        core::ptr::write_volatile(MAIL1_WRITE as *mut u32, bus | CHANNEL_RUNTIME);
        loop {
            flush(m as usize, 4 * (words + 6));
            if core::ptr::read_volatile(m.add(1)) == RESPONSE {
                return Some(core::ptr::read_volatile(m.add(5)));
            }
            if counter() > deadline {
                return None;
            }
        }
    }
}

/// Add a record to the queue. Whether it fitted.
fn queue_record(kind: u32, attributes: u32, guid: &[u8; 16], time: &[u8], name: &[u16], data: &[u8], auth: &[u8]) -> bool {
    let body = 60 + name.len() * 2 + data.len() + auth.len();
    let total = body.next_multiple_of(4) + 32;
    let p = PENDING.get();
    if total > p.room - p.len.min(p.room) {
        return false;
    }
    let at = p.skip + p.len;
    let out = &mut QUEUE.get().0[at..at + total];
    out.fill(0);
    out[0..4].copy_from_slice(&RECORD_MAGIC.to_le_bytes());
    out[4..8].copy_from_slice(&(total as u32).to_le_bytes());
    out[8..12].copy_from_slice(&kind.to_le_bytes());
    out[12..16].copy_from_slice(&attributes.to_le_bytes());
    out[16..32].copy_from_slice(guid);
    out[32..48].copy_from_slice(time);
    out[48..52].copy_from_slice(&(name.len() as u32).to_le_bytes());
    out[52..56].copy_from_slice(&(data.len() as u32).to_le_bytes());
    out[56..60].copy_from_slice(&(auth.len() as u32).to_le_bytes());
    for (i, c) in name.iter().enumerate() {
        out[60 + 2 * i..62 + 2 * i].copy_from_slice(&c.to_le_bytes());
    }
    let data_at = 60 + name.len() * 2;
    out[data_at..data_at + data.len()].copy_from_slice(data);
    out[data_at + data.len()..body].copy_from_slice(auth);
    let digest = crate::sha256::digest(&out[..body.next_multiple_of(4)]);
    out[body.next_multiple_of(4)..total].copy_from_slice(&digest);
    p.len += total;
    true
}

/// Whether a record of a name of `units` characters, `data` bytes of value and
/// `auth` bytes of seal or signature still fits the queue.
fn queue_fits(units: usize, data: usize, auth: usize) -> bool {
    let p = PENDING.get();
    let total = (60 + units * 2 + data + auth).next_multiple_of(4) + 32;
    total <= p.room - p.len.min(p.room)
}

/// Have the VPU seal a change of a non-volatile variable no signature guards,
/// and keep the record for `ResetSystem`: `data` is what it holds now, none
/// for a deletion. The variable stays in the table whatever the answer.
fn persist(kind: u32, attributes: u32, guid: &efi::Guid, name: &[u16], data: *const u8, len: usize) -> efi::Status {
    if attributes & NV == 0 || !PENDING.get().armed {
        return efi::Status::SUCCESS;
    }
    if !queue_fits(name.len(), len, SEAL) {
        return efi::Status::OUT_OF_RESOURCES;
    }
    let seq = PENDING.get().seq;
    if seq == u64::MAX {
        return efi::Status::OUT_OF_RESOURCES;
    }
    let out = value();
    out[0..4].copy_from_slice(&kind.to_le_bytes());
    out[4..8].copy_from_slice(&attributes.to_le_bytes());
    out[8..12].copy_from_slice(&((name.len() * 2) as u32).to_le_bytes());
    out[12..16].copy_from_slice(&(len as u32).to_le_bytes());
    out[16..32].copy_from_slice(guid.as_bytes());
    out[32..40].copy_from_slice(&seq.to_le_bytes());
    for (i, c) in name.iter().enumerate() {
        out[40 + 2 * i..42 + 2 * i].copy_from_slice(&c.to_le_bytes());
    }
    let at = 40 + (name.len() * 2).next_multiple_of(4);
    out[40 + name.len() * 2..at].fill(0);
    unsafe { core::ptr::copy_nonoverlapping(data, out.as_mut_ptr().add(at), len) };
    match post(TAG_STORE_SEAL, at + len) {
        Some(0) => {
            let mut seal = [0u8; SEAL];
            seal.copy_from_slice(&value()[4..4 + SEAL]);
            let mut time = [0u8; 16];
            time[..8].copy_from_slice(&seq.to_le_bytes());
            let data = if len == 0 { &[][..] } else { unsafe { core::slice::from_raw_parts(data, len) } };
            if !queue_record(kind, attributes, guid.as_bytes(), &time, name, data, &seal) {
                return efi::Status::OUT_OF_RESOURCES;
            }
            PENDING.get().seq = seq + 1;
            efi::Status::SUCCESS
        }
        // No device key to seal with: the variable lasts until reset.
        Some(3) => efi::Status::SUCCESS,
        Some(1) | Some(2) => efi::Status::INVALID_PARAMETER,
        _ => efi::Status::DEVICE_ERROR,
    }
}

/// A write of `KEK`, `db` or `dbx`, the value `bytes` that `SetVariable` was
/// given: a time, a certificate holding a signature, and the new value. The
/// record UEFI makes of such a write when it takes one is kept for
/// `ResetSystem`.
fn write_key(name: &[u16], guid: &efi::Guid, attributes: u32, bytes: &[u8], append: bool) -> efi::Status {
    let length = u32::from_le_bytes([bytes.get(16).copied().unwrap_or(0), bytes.get(17).copied().unwrap_or(0), bytes.get(18).copied().unwrap_or(0), bytes.get(19).copied().unwrap_or(0)]) as usize;
    let end = 16usize.saturating_add(length);
    if bytes.len() < 40 || length < 24 || end > bytes.len() || name.len() * 2 > PERSIST_NAME_MAX || bytes.len() > PERSIST_MAX {
        return efi::Status::INVALID_PARAMETER;
    }
    if !PENDING.get().armed {
        return efi::Status::DEVICE_ERROR;
    }
    let (time, descriptor, payload) = (&bytes[..16], &bytes[16..end], &bytes[end..]);
    let kind = if payload.is_empty() && !append { DELETE } else { SET };
    if queue_record(kind, attributes, guid.as_bytes(), time, name, payload, descriptor) { efi::Status::SUCCESS } else { efi::Status::OUT_OF_RESOURCES }
}

/// `ResetSystem`: append what the OS wrote since boot to the store on the SD
/// card. The OS has quiesced its driver for the card; the VPU gives the card
/// and its host back to this firmware as they were at the start, and this
/// writes the records after the end of the log. What cannot be written is lost
/// with the reset, which nothing can report.
pub fn flush_store() {
    let p = PENDING.get();
    if !p.armed || p.len == 0 {
        return;
    }
    value()[..4].fill(0);
    if post(TAG_STORE_PREPARE_CARD, 4) != Some(0) {
        return;
    }
    let end = (p.skip + p.len).next_multiple_of(BLOCK);
    QUEUE.get().0[p.skip + p.len..end].fill(0xff);
    if let Some(mut card) = crate::sd::Runtime::open() {
        card.write(p.lba, &QUEUE.get().0[..end]);
    }
}

pub extern "efiapi" fn get_variable(
    name: *mut efi::Char16,
    guid: *mut efi::Guid,
    attributes: *mut u32,
    size: *mut usize,
    data: *mut c_void,
) -> efi::Status {
    if name.is_null() || guid.is_null() || size.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    let Some(e) = find(unsafe { wstr(name) }, unsafe { &*guid }) else { return efi::Status::NOT_FOUND };
    if !attributes.is_null() {
        unsafe { *attributes = e.attributes };
    }
    let room = unsafe { *size };
    unsafe { *size = e.data_len };
    if room < e.data_len {
        return efi::Status::BUFFER_TOO_SMALL;
    }
    if data.is_null() && e.data_len > 0 {
        return efi::Status::INVALID_PARAMETER;
    }
    unsafe { core::ptr::copy_nonoverlapping(base().add(e.data_at()), data as *mut u8, e.data_len) };
    efi::Status::SUCCESS
}

pub extern "efiapi" fn get_next_variable_name(size: *mut usize, name: *mut efi::Char16, guid: *mut efi::Guid) -> efi::Status {
    if size.is_null() || name.is_null() || guid.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    let current = unsafe { wstr(name) };
    let skip = if current.is_empty() {
        0
    } else {
        match find(current, unsafe { &*guid }) {
            Some(e) => e.at + e.total,
            None => return efi::Status::INVALID_PARAMETER,
        }
    };
    let Some(next) = entries().find(|e| e.at >= skip && e.live()) else { return efi::Status::NOT_FOUND };
    let need = (next.name_len + 1) * 2;
    let room = unsafe { *size };
    unsafe { *size = need };
    if room < need {
        return efi::Status::BUFFER_TOO_SMALL;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(base().add(next.name_at()), name as *mut u8, next.name_len * 2);
        *name.add(next.name_len) = 0;
        core::ptr::copy_nonoverlapping(base().add(next.at + 16), guid as *mut u8, 16);
    }
    efi::Status::SUCCESS
}

pub extern "efiapi" fn set_variable(
    name: *mut efi::Char16,
    guid: *mut efi::Guid,
    attributes: u32,
    size: usize,
    data: *mut c_void,
) -> efi::Status {
    if name.is_null() || guid.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    let name = unsafe { wstr(name) };
    let guid = unsafe { *guid };
    if name.is_empty() || (size > 0 && data.is_null()) {
        return efi::Status::INVALID_PARAMETER;
    }
    if guid == crate::esrt::FIRMWARE_CLASS {
        return efi::Status::WRITE_PROTECTED;
    }
    let append = attributes & APPEND != 0;
    let given = attributes;
    let attributes = attributes & !APPEND;
    let delete = attributes == 0 || (size == 0 && !append);
    let existing = find(name, &guid);
    if let Some(e) = &existing {
        if e.flags & KEY != 0 {
            if attributes != e.attributes || attributes & TIME_BASED == 0 {
                return efi::Status::INVALID_PARAMETER;
            }
            let bytes = if size == 0 { &[][..] } else { unsafe { core::slice::from_raw_parts(data as *const u8, size) } };
            return write_key(name, &guid, given, bytes, append);
        }
        if e.flags & WRITABLE == 0 {
            return efi::Status::WRITE_PROTECTED;
        }
    }
    if delete {
        let Some(e) = existing else { return efi::Status::NOT_FOUND };
        put(e.at + 14, &(e.flags | DELETED).to_le_bytes());
        return persist(DELETE, e.attributes, &guid, name, [].as_ptr(), 0);
    }
    if attributes & AUTH != 0 {
        return efi::Status::WRITE_PROTECTED;
    }
    if attributes & NV == 0 || attributes & BS == 0 || attributes & RT == 0 || size > MAX_VARIABLE {
        return efi::Status::INVALID_PARAMETER;
    }
    let kept = if append { existing.as_ref().map_or(0, |e| e.data_len) } else { 0 };
    if attributes & NV != 0 && (attributes != NV | BS | RT || kept + size > PERSIST_MAX || name.len() * 2 > PERSIST_NAME_MAX) {
        return efi::Status::INVALID_PARAMETER;
    }
    if let Some(e) = &existing {
        if !append && e.attributes != attributes {
            return efi::Status::INVALID_PARAMETER;
        }
    }
    if !reserve(entry_size(name.len(), kept + size)) {
        return efi::Status::OUT_OF_RESOURCES;
    }
    let old = find(name, &guid);
    let new = (data as *const u8, size);
    let pushed = match (&old, append) {
        (Some(e), true) => push(name, &guid, attributes, WRITABLE, &[(unsafe { base().add(e.data_at()) } as *const u8, e.data_len), new]),
        _ => push(name, &guid, attributes, WRITABLE, &[new]),
    };
    if !pushed {
        return efi::Status::OUT_OF_RESOURCES;
    }
    if let Some(e) = old {
        put(e.at + 14, &(e.flags | DELETED).to_le_bytes());
    }
    match find(name, &guid) {
        Some(e) => persist(SET, attributes, &guid, name, unsafe { base().add(e.data_at()) }, e.data_len),
        None => efi::Status::SUCCESS,
    }
}

pub extern "efiapi" fn query_variable_info(
    _attributes: u32,
    max_storage: *mut u64,
    remaining: *mut u64,
    max_size: *mut u64,
) -> efi::Status {
    if max_storage.is_null() || remaining.is_null() || max_size.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    unsafe {
        *max_storage = CAPACITY as u64;
        *remaining = (CAPACITY - live_bytes()) as u64;
        *max_size = MAX_VARIABLE as u64;
    }
    efi::Status::SUCCESS
}

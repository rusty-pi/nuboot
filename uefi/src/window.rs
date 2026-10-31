//! Where the variable store sits on a disk: a window of 512 KiB from byte
//! 512 KiB, in the gap that partitioning tools leave in front of the first
//! partition. The firmware lists the window in the disk's partition table as a
//! partition of its own, so that tools which rewrite the gap (`systemd-repart`
//! discards it) leave it alone, and an operating system sees a partition of a
//! type it has no use for.
//!
//! Only a GPT can list it. This module only decides: it reads a disk through [`Blocks`] and says
//! whether the window is there, may be listed, or has to be left alone, and
//! with what writes the listing is made.

use alloc::vec;
use alloc::vec::Vec;

use crate::util::crc32;

/// Where the window starts and how long it is, in bytes.
pub const START: u64 = 512 * 1024;
pub const LEN: u64 = 512 * 1024;

/// The GPT partition type of the window, as the entry holds it.
pub const GPT_TYPE: [u8; 16] = [0xc0, 0xcd, 0xa9, 0x0c, 0x28, 0x6c, 0xa6, 0x49, 0xa0, 0x41, 0xee, 0xec, 0x61, 0x23, 0xdf, 0x3a];
const NAME: &str = "nuboot store";

/// A disk, read by block.
pub trait Blocks {
    fn block_size(&self) -> u32;
    fn blocks(&self) -> u64;
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> bool;
}

/// A run of blocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Range {
    pub first: u64,
    pub blocks: u64,
}

/// Blocks to write, from `lba` on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Write {
    pub lba: u64,
    pub data: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Plan {
    /// The partition table lists the window already.
    Found(Range),
    /// The window is free: write these, in order, to list it.
    List(Range, Vec<Write>),
    /// The disk has no room for the store, and why.
    Refuse(&'static str),
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

/// The window on a disk of blocks of `block_size`, or none when the block size
/// does not divide it.
pub fn range(block_size: u32) -> Option<Range> {
    let bs = block_size as u64;
    (bs >= 512 && bs <= 4096 && START % bs == 0).then(|| Range { first: START / bs, blocks: LEN / bs })
}

/// Whether the window is blank: every byte of it 0x00, or every byte 0xFF.
fn blank(disk: &mut impl Blocks, window: Range) -> bool {
    let bs = disk.block_size() as usize;
    let step = (64 * 1024 / bs) as u64;
    let mut buf = vec![0u8; 64 * 1024];
    let mut fill = None;
    let mut at = 0;
    while at < window.blocks {
        let n = step.min(window.blocks - at);
        let chunk = &mut buf[..n as usize * bs];
        if !disk.read(window.first + at, chunk) {
            return false;
        }
        let want = *fill.get_or_insert(chunk[0]);
        if (want != 0 && want != 0xff) || chunk.iter().any(|&b| b != want) {
            return false;
        }
        at += n;
    }
    true
}

/// Look at a disk's partition table. `unique` is the GUID a new entry gets.
pub fn plan(disk: &mut impl Blocks, unique: [u8; 16]) -> Plan {
    let Some(window) = range(disk.block_size()) else { return Plan::Refuse("block size") };
    if disk.blocks() <= window.first + window.blocks {
        return Plan::Refuse("disk too small");
    }
    plan_gpt(disk, window, unique)
}

/// A GPT header and the table it describes, checked.
struct Gpt {
    header: Vec<u8>,
    lba: u64,
    table: Vec<u8>,
    table_lba: u64,
    count: usize,
    size: usize,
}

fn read_gpt(disk: &mut impl Blocks, lba: u64) -> Option<Gpt> {
    let bs = disk.block_size() as usize;
    let mut header = vec![0u8; bs];
    if lba >= disk.blocks() || !disk.read(lba, &mut header) || &header[0..8] != b"EFI PART" {
        return None;
    }
    let header_size = le32(&header, 12) as usize;
    if !(92..=bs).contains(&header_size) {
        return None;
    }
    let mut copy = header[..header_size].to_vec();
    copy[16..20].fill(0);
    if crc32(&copy) != le32(&header, 16) || le64(&header, 24) != lba {
        return None;
    }
    let (table_lba, count, size) = (le64(&header, 72), le32(&header, 80) as usize, le32(&header, 84) as usize);
    if !(128..=4096).contains(&size) || size % 8 != 0 || count == 0 || count > 1024 {
        return None;
    }
    let mut table = vec![0u8; (count * size).next_multiple_of(bs)];
    if table_lba.checked_add((table.len() / bs) as u64)? > disk.blocks() || !disk.read(table_lba, &mut table) {
        return None;
    }
    (crc32(&table[..count * size]) == le32(&header, 88)).then_some(Gpt { header, lba, table, table_lba, count, size })
}

/// The blocks to write to put `table` in place of `gpt`'s, whose entry at
/// `slot` changed: the blocks of the table the entry is in, then the header,
/// whose checksums follow. Where the first block partitions may use is after
/// the window, the header says it starts at `usable` instead.
fn with_entry(disk: &impl Blocks, gpt: &Gpt, slot: usize, table: &[u8], usable: u64) -> Vec<Write> {
    let bs = disk.block_size() as usize;
    let (first, last) = (slot * gpt.size / bs, ((slot + 1) * gpt.size - 1) / bs);
    let mut header = gpt.header.clone();
    let header_size = le32(&header, 12) as usize;
    header[88..92].copy_from_slice(&crc32(&table[..gpt.count * gpt.size]).to_le_bytes());
    let usable = usable.min(le64(&header, 40));
    header[40..48].copy_from_slice(&usable.to_le_bytes());
    header[16..20].fill(0);
    let crc = crc32(&header[..header_size]);
    header[16..20].copy_from_slice(&crc.to_le_bytes());
    let mut writes: Vec<Write> =
        (first..=last).map(|b| Write { lba: gpt.table_lba + b as u64, data: table[b * bs..(b + 1) * bs].to_vec() }).collect();
    writes.push(Write { lba: gpt.lba, data: header });
    writes
}

fn plan_gpt(disk: &mut impl Blocks, window: Range, unique: [u8; 16]) -> Plan {
    let bs = disk.block_size() as usize;
    let end = window.first + window.blocks;
    let Some(primary) = read_gpt(disk, 1) else { return Plan::Refuse("the GPT is not intact") };
    let Some(backup) = read_gpt(disk, le64(&primary.header, 32)) else { return Plan::Refuse("the backup GPT is not intact") };
    if backup.count != primary.count || backup.size != primary.size || backup.table[..backup.count * backup.size] != primary.table[..primary.count * primary.size] {
        return Plan::Refuse("the backup GPT differs");
    }
    if primary.table_lba + (primary.table.len() / bs) as u64 > window.first {
        return Plan::Refuse("the partition entries reach the window");
    }
    if le64(&primary.header, 48) + 1 < end {
        return Plan::Refuse("the window is not usable space");
    }
    let mut free = None;
    for i in 0..primary.count {
        let e = &primary.table[i * primary.size..(i + 1) * primary.size];
        let (first, last) = (le64(e, 32), le64(e, 40));
        if e[0..16].iter().all(|&b| b == 0) {
            free.get_or_insert(i);
        } else if e[0..16] == GPT_TYPE {
            return if first == window.first && last + 1 == end { Plan::Found(window) } else { Plan::Refuse("a store entry elsewhere") };
        } else if first < end && last >= window.first {
            return Plan::Refuse("a partition reaches into the window");
        }
    }
    let Some(slot) = free else { return Plan::Refuse("no free partition entry") };
    if !blank(disk, window) {
        return Plan::Refuse("the window holds data");
    }

    let mut entry = vec![0u8; primary.size];
    entry[0..16].copy_from_slice(&GPT_TYPE);
    entry[16..32].copy_from_slice(&unique);
    entry[32..40].copy_from_slice(&window.first.to_le_bytes());
    entry[40..48].copy_from_slice(&(end - 1).to_le_bytes());
    for (i, c) in NAME.encode_utf16().enumerate().take((primary.size - 56) / 2) {
        entry[56 + 2 * i..58 + 2 * i].copy_from_slice(&c.to_le_bytes());
    }
    let mut table = primary.table.clone();
    table[slot * primary.size..(slot + 1) * primary.size].copy_from_slice(&entry);
    let mut writes = with_entry(disk, &primary, slot, &table, window.first);
    writes.extend(with_entry(disk, &backup, slot, &table, window.first));
    Plan::List(window, writes)
}

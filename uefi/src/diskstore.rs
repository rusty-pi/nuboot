//! The variable store's place on the boot disk: the window [`crate::window`]
//! decides on, listed in the disk's partition table, read and written through
//! the disk's driver. The store partition is not published as a block device:
//! nothing but the store reads it.

use alloc::boxed::Box;
use alloc::vec;

use crate::block::{Disk, Volume};
use crate::store::{self, Medium};
use crate::util::Global;
use crate::window::{self, Blocks, Plan};
use crate::{info, warn};

/// Where the store is, for the runtime services that write it at `ResetSystem`.
#[derive(Clone, Copy)]
pub struct Placement {
    /// Whether the disk is the SD card, which is all the runtime flush can reach.
    pub sd: bool,
    /// The window's first block on the disk, and the disk's block size.
    pub first: u64,
    pub block_size: u32,
}

static PLACED: Global<Option<Placement>> = Global::new(None);

/// Where the store is, once a disk holds it.
pub fn placement() -> Option<Placement> {
    *PLACED.get()
}

/// Whether a disk holds the store already.
pub fn taken() -> bool {
    PLACED.get().is_some()
}

struct Window {
    disk: *mut dyn Disk,
    first: u64,
    block_size: u32,
}

impl Window {
    fn disk(&self) -> &'static mut dyn Disk {
        unsafe { &mut *self.disk }
    }

    /// The blocks that hold `len` bytes from `at`, as the first of them and
    /// how many, and where in the first one `at` is.
    fn span(&self, at: u32, len: usize) -> (u64, usize, usize) {
        let bs = self.block_size as u64;
        let first = at as u64 / bs;
        let skip = (at as u64 % bs) as usize;
        (self.first + first, (skip + len).div_ceil(bs as usize), skip)
    }
}

impl Medium for Window {
    fn len(&self) -> u32 {
        window::LEN as u32
    }

    fn read(&mut self, at: u32, buf: &mut [u8]) -> bool {
        let (lba, blocks, skip) = self.span(at, buf.len());
        let mut raw = vec![0u8; blocks * self.block_size as usize];
        if self.disk().read(lba, &mut raw).is_err() {
            return false;
        }
        buf.copy_from_slice(&raw[skip..skip + buf.len()]);
        true
    }

    fn write(&mut self, at: u32, data: &[u8]) -> bool {
        let (lba, blocks, skip) = self.span(at, data.len());
        let bs = self.block_size as usize;
        let mut raw = vec![0u8; blocks * bs];
        let partial_tail = (skip + data.len()) % bs != 0;
        if (skip != 0 || (partial_tail && blocks == 1)) && self.disk().read(lba, &mut raw[..bs]).is_err() {
            return false;
        }
        if partial_tail && blocks > 1 && self.disk().read(lba + (blocks - 1) as u64, &mut raw[(blocks - 1) * bs..]).is_err() {
            return false;
        }
        raw[skip..skip + data.len()].copy_from_slice(data);
        self.disk().write(lba, &raw).is_ok()
    }
}

/// The disk as the window planner reads it.
struct Whole<'a>(&'a Volume);

impl Blocks for Whole<'_> {
    fn block_size(&self) -> u32 {
        self.0.block_size()
    }

    fn blocks(&self) -> u64 {
        self.0.blocks()
    }

    fn read(&mut self, lba: u64, buf: &mut [u8]) -> bool {
        self.0.read_blocks(lba, buf).is_ok()
    }
}

/// Make the window a partition of `disk`, if its partition table leaves room
/// and the window is free. Nothing else on the disk is changed.
pub fn list(disk: &Volume, name: &'static str) {
    let mut unique = [0u8; 16];
    if !crate::rng::fill(&mut unique) {
        warn!("store", "no random number for the store partition"; disk = name);
        return;
    }
    unique[7] = unique[7] & 0x0f | 0x40;
    unique[8] = unique[8] & 0x3f | 0x80;
    match window::plan(&mut Whole(disk), unique) {
        Plan::Found(_) => {}
        Plan::Refuse(why) => info!("store", "this disk cannot hold the store"; disk = name, why = why),
        Plan::List(range, writes) => {
            if writes.iter().all(|w| disk.write_blocks(w.lba, &w.data).is_ok()) {
                info!("store", "store partition listed in the partition table"; disk = name, first = range.first, blocks = range.blocks);
            } else {
                warn!("store", "the partition table could not be written"; disk = name);
            }
        }
    }
}

/// Keep the store in the partition of `disk` at `first`, `blocks` long, when
/// it is the window and no disk has the store yet.
pub fn adopt(disk: *mut dyn Disk, first: u64, blocks: u64, name: &'static str) -> bool {
    let block_size = unsafe { (*disk).block_size() };
    if taken() || window::range(block_size).is_none_or(|w| w.first != first || w.blocks != blocks) {
        return false;
    }
    *PLACED.get() = Some(Placement { sd: name == "sd", first, block_size });
    store::attach(Box::new(Window { disk, first, block_size }));
    info!("store", "the store is on the disk"; disk = name, first = first, blocks = blocks);
    true
}

/// Where the OS's writes go once the firmware is gone, if the store is on the
/// SD card, which is all the flush at `ResetSystem` reaches.
pub fn target() -> Option<crate::rtvar::Target> {
    let placed = placement().filter(|p| p.sd && p.block_size == 512)?;
    let (tail, end) = store::tail();
    let skip = tail as usize % 512;
    let mut head = [0u8; 512];
    if !store::read_raw(tail - skip as u32, &mut head) {
        return None;
    }
    Some(crate::rtvar::Target { lba: placed.first + (tail / 512) as u64, head, skip, room: (end - tail) as usize })
}

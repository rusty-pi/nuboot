//! The variable store's place on the boot disk: the window [`crate::window`]
//! decides on, listed in the disk's partition table, read and written through
//! the disk's driver. The store partition is not published as a block device:
//! nothing but the store reads it.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use r_efi::protocols::{device_path, simple_file_system};

use crate::block::{self, Disk, Volume};
use crate::{devpath, fat, proto};
use crate::store::{self, Medium};
use crate::util::Global;
use crate::window::{self, Blocks, Plan};
use crate::{info, warn};

/// Where the store is, for the runtime services that write it at `ResetSystem`.
#[derive(Clone, Copy)]
pub struct Placement {
    /// What kind of disk it is, which decides how the runtime services reach it.
    pub kind: Kind,
    /// The window's first block on the disk, and the disk's block size.
    pub first: u64,
    pub block_size: u32,
}

/// What sort of disk holds the store.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Sd,
    Usb,
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

/// The file system of one of `disk`'s partitions that holds `name` of length
/// `len` (any length when `len` is none).
fn holds(disk: &block::Found, name: &str, len: Option<u64>) -> bool {
    let wide: Vec<u16> = name.encode_utf16().collect();
    let prefix = &disk.whole.path[..disk.whole.path.len() - 4];
    proto::with(Some(&simple_file_system::PROTOCOL_GUID)).into_iter().any(|fs| {
        let Some(dp) = proto::get(fs, &device_path::PROTOCOL_GUID) else { return false };
        devpath::bytes(dp as *const u8).starts_with(prefix) && fat::file_size(fs, &wide).is_some_and(|size| len.is_none_or(|l| l == size))
    })
}

/// Keep the store on the disk the firmware came from, the one that holds
/// `start4.elf` or the `boot.img` the bootloader started it out of. The
/// bootloader says which medium: a `boot.img` in RAM says nothing of the disk
/// under it, so that one is the disk that holds a `boot.img` of its length.
/// A board that came off the network, or that the VPU does not say, keeps its
/// variables in memory.
pub fn choose() {
    let Some(medium) = crate::mailbox::boot_medium() else {
        info!("store", "the VPU does not say where the firmware came from, the variables stay in memory");
        return;
    };
    let disks = block::found();
    let picked = match medium.code {
        0 => disks.iter().find(|d| d.name == "sd"),
        2 => disks.iter().filter(|d| d.name == "usb").find(|d| holds(d, "start4.elf", None)).or_else(|| disks.iter().find(|d| d.name == "usb")),
        5 => medium.ramdisk_len.and_then(|len| disks.iter().find(|d| holds(d, "boot.img", Some(len)))),
        _ => None,
    };
    let Some(disk) = picked else {
        info!("store", "no disk to keep the store on, the variables stay in memory"; medium = medium.code);
        return;
    };
    list(disk.whole, disk.name);
    match block::store_partition(disk.whole) {
        Some((first, blocks)) => {
            adopt(disk.disk, first, blocks, disk.name);
        }
        None => info!("store", "the disk the firmware came from does not hold the store, the variables stay in memory"; disk = disk.name),
    }
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
    let kind = if name == "sd" { Kind::Sd } else { Kind::Usb };
    *PLACED.get() = Some(Placement { kind, first, block_size });
    store::attach(Box::new(Window { disk, first, block_size }));
    info!("store", "the store is on the disk"; disk = name, first = first, blocks = blocks);
    true
}

static SNAPSHOT: Global<Option<crate::rtvar::Target>> = Global::new(None);

/// Read where the log ends while the disk can still be read: the controllers
/// stop at `ExitBootServices`, and the last write of boot services is made.
pub fn snapshot() {
    *SNAPSHOT.get() = target();
}

/// What [`snapshot`] read.
pub fn snapshot_taken() -> Option<crate::rtvar::Target> {
    SNAPSHOT.get().take()
}

/// Where the OS's writes go once the firmware is gone, if the store is on a
/// disk the runtime services reach: the SD card, with 512-byte blocks, or a
/// drive on the VL805.
fn target() -> Option<crate::rtvar::Target> {
    let placed = placement().filter(|p| p.kind == Kind::Usb || p.block_size == 512)?;
    let bs = placed.block_size as usize;
    let (tail, end) = store::tail();
    let bank = end - (window::LEN / 2) as u32;
    let skip = tail as usize % bs;
    let mut head = [0u8; 4096];
    let mut expect = [0u8; 8];
    if !store::read_raw(tail - skip as u32, &mut head[..bs]) || !store::read_raw(bank, &mut expect) {
        return None;
    }
    Some(crate::rtvar::Target {
        kind: placed.kind,
        block: bs,
        lba: placed.first + (tail as usize / bs) as u64,
        head,
        skip,
        room: (end - tail) as usize,
        bank_lba: placed.first + (bank as usize / bs) as u64,
        expect,
    })
}

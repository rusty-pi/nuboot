//! The `boot.img` the bootloader checked and started this firmware out of: a
//! FAT volume the bootloader left in memory ([`handover::ramdisk`]). The
//! signature on it covers every file in it, so what is read from it here is
//! what the owner's key signed.
//!
//! One file is read, `owner-db.der` in the root directory: the certificate the
//! UEFI firmware trusts for images in place of its built-in `db`
//! ([`owner_db`], docs/uefi.md).

use crate::{arm, handover};

/// The largest `owner-db.der`: one certificate, a CA's included.
pub const MAX_OWNER_DB: usize = 4096;

/// `owner-db.der` as a directory entry has its name: eight characters, then
/// the extension, in capitals and padded with spaces.
const OWNER_DB_NAME: &[u8; 11] = b"OWNER-DBDER";

/// What the `boot.img` said about the owner's `db`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum OwnerDb {
    /// The firmware did not start out of a `boot.img`, so nothing in the
    /// medium is signed and nothing is read.
    NotSigned,
    /// The `boot.img` is not a FAT volume this reads, so it cannot say.
    Unreadable(&'static str),
    /// The `boot.img` has no `owner-db.der`.
    Absent,
    /// The file is in [`owner_db`].
    Present,
    /// The `boot.img` has an `owner-db.der` that cannot be read, which leaves
    /// the owner with no trust at all and not with the built-in one.
    Invalid(&'static str),
}

static mut CONTENT: [u8; MAX_OWNER_DB] = [0; MAX_OWNER_DB];
static mut LENGTH: usize = 0;
static mut STATE: OwnerDb = OwnerDb::NotSigned;

/// What [`load_owner_db`] found.
pub fn state() -> OwnerDb {
    unsafe { core::ptr::read_volatile(&raw const STATE) }
}

/// The bytes of `owner-db.der`, when [`state`] is [`OwnerDb::Present`].
pub fn owner_db() -> &'static [u8] {
    if state() != OwnerDb::Present {
        return &[];
    }
    unsafe { core::slice::from_raw_parts((&raw const CONTENT).cast::<u8>(), core::ptr::read_volatile(&raw const LENGTH)) }
}

/// Look for `owner-db.der` in the `boot.img` and keep it. Once, before the ARM
/// starts and the memory is the ARM's.
pub fn load_owner_db() -> OwnerDb {
    let state = match handover::ramdisk() {
        None => OwnerDb::NotSigned,
        Some((base, len)) => match Volume::open(base, len) {
            Err(why) => OwnerDb::Unreadable(why),
            Ok(volume) => match volume.read_root_file(OWNER_DB_NAME) {
                Ok(None) => OwnerDb::Absent,
                Ok(Some(length)) => {
                    unsafe { core::ptr::write_volatile(&raw mut LENGTH, length) };
                    OwnerDb::Present
                }
                Err(why) => OwnerDb::Invalid(why),
            },
        },
    };
    unsafe { core::ptr::write_volatile(&raw mut STATE, state) };
    state
}

/// A FAT12, FAT16 or FAT32 volume with no partition table in front of it, in
/// memory the VPU reads through its uncached alias.
struct Volume {
    base: u32,
    len: u32,
    cluster_bytes: u32,
    fat_bits: u8,
    fat_at: u32,
    root_at: u32,
    root_entries: u32,
    root_cluster: u32,
    data_at: u32,
    clusters: u32,
}

impl Volume {
    fn open(base: u32, len: u32) -> Result<Volume, &'static str> {
        if base % 4 != 0 || len < 512 || u64::from(base) + u64::from(len) > u64::from(arm::VPU_BASE) {
            return Err("the boot.img is not in the ARM's memory");
        }
        let mut volume = Volume {
            base,
            len,
            cluster_bytes: 0,
            fat_bits: 0,
            fat_at: 0,
            root_at: 0,
            root_entries: 0,
            root_cluster: 0,
            data_at: 0,
            clusters: 0,
        };
        let mut sector = [0u8; 512];
        volume.read(0, &mut sector).ok_or("the boot.img has no boot sector")?;
        let half = |at: usize| u32::from(u16::from_le_bytes([sector[at], sector[at + 1]]));
        let word = |at: usize| u32::from_le_bytes([sector[at], sector[at + 1], sector[at + 2], sector[at + 3]]);
        let (bytes_per_sector, per_cluster, reserved, fats, root_entries) = (half(0x0b), u32::from(sector[0x0d]), half(0x0e), u32::from(sector[0x10]), half(0x11));
        let total = if half(0x13) != 0 { half(0x13) } else { word(0x20) };
        let fat_sectors = if half(0x16) != 0 { half(0x16) } else { word(0x24) };
        if sector[510] != 0x55 || sector[511] != 0xaa || !matches!(sector[0], 0xeb | 0xe9) {
            return Err("the boot.img is not a FAT volume");
        }
        if !matches!(bytes_per_sector, 512 | 1024 | 2048 | 4096)
            || !per_cluster.is_power_of_two()
            || per_cluster > 128
            || reserved == 0
            || fats == 0
            || fat_sectors == 0
        {
            return Err("the boot.img's FAT volume is not one this reads");
        }
        let root_sectors = (root_entries * 32).div_ceil(bytes_per_sector);
        let fixed = u64::from(reserved) + u64::from(fats) * u64::from(fat_sectors) + u64::from(root_sectors);
        if u64::from(total) * u64::from(bytes_per_sector) > u64::from(len) || u64::from(total) <= fixed {
            return Err("the boot.img's FAT volume is larger than the image");
        }
        let clusters = (u64::from(total) - fixed) as u32 / per_cluster;
        volume.fat_bits = match clusters {
            0..=4084 => 12,
            4085..=65524 => 16,
            _ => 32,
        };
        volume.cluster_bytes = per_cluster * bytes_per_sector;
        volume.fat_at = reserved * bytes_per_sector;
        volume.root_at = volume.fat_at + fats * fat_sectors * bytes_per_sector;
        volume.root_entries = root_entries;
        volume.root_cluster = word(0x2c);
        volume.data_at = volume.root_at + root_sectors * bytes_per_sector;
        volume.clusters = clusters;
        if (volume.fat_bits == 32) == (root_entries != 0) {
            return Err("the boot.img's FAT volume is not one this reads");
        }
        Ok(volume)
    }

    fn read(&self, at: u32, out: &mut [u8]) -> Option<()> {
        let end = at.checked_add(out.len() as u32)?;
        if end > self.len {
            return None;
        }
        for (n, byte) in out.iter_mut().enumerate() {
            *byte = unsafe { core::ptr::read_volatile((0xc000_0000 | (self.base + at + n as u32)) as usize as *const u8) };
        }
        Some(())
    }

    /// The cluster after `cluster` in its chain, `None` at the chain's end.
    fn next(&self, cluster: u32) -> Result<Option<u32>, &'static str> {
        let mut raw = [0u8; 4];
        let (at, size) = match self.fat_bits {
            12 => (cluster + cluster / 2, 2),
            16 => (cluster * 2, 2),
            _ => (cluster * 4, 4),
        };
        self.read(self.fat_at + at, &mut raw[..size]).ok_or("the FAT runs past the boot.img")?;
        let entry = u32::from_le_bytes(raw);
        let (next, end) = match self.fat_bits {
            12 => (if cluster % 2 == 0 { entry & 0xfff } else { entry >> 4 }, 0xff8),
            16 => (entry, 0xfff8),
            _ => (entry & 0x0fff_ffff, 0x0fff_fff8),
        };
        if next >= end {
            Ok(None)
        } else if next < 2 || next >= self.clusters + 2 {
            Err("the file's cluster chain leaves the volume")
        } else {
            Ok(Some(next))
        }
    }

    fn cluster_at(&self, cluster: u32) -> u32 {
        self.data_at + (cluster - 2) * self.cluster_bytes
    }

    /// The root directory's entry for `name`: its first cluster, its size and
    /// its attributes.
    fn find_root(&self, name: &[u8; 11]) -> Result<Option<(u32, u32, u8)>, &'static str> {
        let mut entry = [0u8; 32];
        let mut cluster = self.root_cluster;
        let mut walked = 0;
        loop {
            let (at, entries) = if self.fat_bits == 32 {
                if cluster < 2 || cluster >= self.clusters + 2 {
                    return Err("the root directory leaves the volume");
                }
                (self.cluster_at(cluster), self.cluster_bytes / 32)
            } else {
                (self.root_at, self.root_entries)
            };
            for n in 0..entries {
                self.read(at + 32 * n, &mut entry).ok_or("the root directory runs past the boot.img")?;
                match entry[0] {
                    0 => return Ok(None),
                    0xe5 => continue,
                    _ => {}
                }
                let attributes = entry[11];
                if attributes & 0x3f == 0x0f || attributes & 0x08 != 0 || entry[..11] != name[..] {
                    continue;
                }
                let high = if self.fat_bits == 32 { u32::from(u16::from_le_bytes([entry[20], entry[21]])) } else { 0 };
                let low = u32::from(u16::from_le_bytes([entry[26], entry[27]]));
                let size = u32::from_le_bytes([entry[28], entry[29], entry[30], entry[31]]);
                return Ok(Some((high << 16 | low, size, attributes)));
            }
            if self.fat_bits != 32 {
                return Ok(None);
            }
            walked += 1;
            if walked > self.clusters {
                return Err("the root directory's cluster chain loops");
            }
            match self.next(cluster)? {
                Some(next) => cluster = next,
                None => return Ok(None),
            }
        }
    }

    /// Copy the file `name` in the root directory into [`CONTENT`]: its
    /// length, or `None` when there is none.
    fn read_root_file(&self, name: &[u8; 11]) -> Result<Option<usize>, &'static str> {
        let Some((first, size, attributes)) = self.find_root(name)? else { return Ok(None) };
        if attributes & 0x10 != 0 {
            return Err("owner-db.der is a directory");
        }
        if size == 0 || size as usize > MAX_OWNER_DB {
            return Err("owner-db.der is empty or longer than 4096 bytes");
        }
        let content = unsafe { &mut *(&raw mut CONTENT) };
        let mut cluster = first;
        let mut done = 0usize;
        while done < size as usize {
            if cluster < 2 || cluster >= self.clusters + 2 {
                return Err("owner-db.der's cluster chain leaves the volume");
            }
            let take = (size as usize - done).min(self.cluster_bytes as usize);
            self.read(self.cluster_at(cluster), &mut content[done..done + take]).ok_or("owner-db.der runs past the boot.img")?;
            done += take;
            if done < size as usize {
                cluster = self.next(cluster)?.ok_or("owner-db.der's cluster chain ends before its size")?;
            }
        }
        Ok(Some(size as usize))
    }
}

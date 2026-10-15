//! Block devices: each disk a driver finds gets a handle with
//! `EFI_BLOCK_IO_PROTOCOL`, `EFI_DISK_IO_PROTOCOL` and its device path, and so
//! does each partition on it (MBR or GPT). Every FAT volume among them gets
//! `EFI_SIMPLE_FILE_SYSTEM_PROTOCOL` as well.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::ffi::c_void;

use r_efi::efi;
use r_efi::protocols::{block_io, device_path, disk_io};

use crate::devpath::{self, Builder};
use crate::util::Global;
use crate::{info, proto, warn};

/// What a storage driver gives the firmware.
pub trait Disk {
    /// Read whole blocks from `lba` into `buf`, whose length is a multiple of
    /// the block size.
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), ()>;
    /// Write whole blocks to `lba`, and have them on the medium when it
    /// returns. For the firmware's own files: nothing an EFI application calls
    /// reaches it.
    fn write(&mut self, lba: u64, buf: &[u8]) -> Result<(), ()>;
    fn block_size(&self) -> u32;
    fn blocks(&self) -> u64;
}

/// A disk or one partition of one, as the protocols see it. The protocols
/// come first so the `this` they are called with is this.
#[repr(C)]
pub struct Volume {
    block_io: block_io::Protocol,
    disk_io: disk_io::Protocol,
    media: block_io::Media,
    disk: *mut dyn Disk,
    /// Where the volume starts on the disk, in blocks.
    first: u64,
    pub handle: efi::Handle,
    pub path: Vec<u8>,
}

impl Volume {
    fn disk(&self) -> &'static mut dyn Disk {
        unsafe { &mut *self.disk }
    }

    pub fn block_size(&self) -> u32 {
        self.media.block_size
    }

    pub fn blocks(&self) -> u64 {
        self.media.last_block + 1
    }

    /// Read whole blocks of the volume.
    pub fn read_blocks(&self, lba: u64, buf: &mut [u8]) -> Result<(), ()> {
        let bs = self.block_size() as u64;
        if buf.len() as u64 % bs != 0 || lba.checked_add(buf.len() as u64 / bs).is_none_or(|end| end > self.blocks()) {
            return Err(());
        }
        if buf.is_empty() {
            return Ok(());
        }
        self.disk().read(self.first + lba, buf)
    }

    /// Write whole blocks of the volume.
    pub fn write_blocks(&self, lba: u64, buf: &[u8]) -> Result<(), ()> {
        let bs = self.block_size() as u64;
        if buf.len() as u64 % bs != 0 || lba.checked_add(buf.len() as u64 / bs).is_none_or(|end| end > self.blocks()) {
            return Err(());
        }
        if buf.is_empty() {
            return Ok(());
        }
        self.disk().write(self.first + lba, buf)
    }

    /// Write any bytes of the volume: the blocks they share with other bytes
    /// are read, changed and written back.
    pub fn write_bytes(&self, offset: u64, data: &[u8]) -> Result<(), ()> {
        let bs = self.block_size() as u64;
        let mut done = 0usize;
        while done < data.len() {
            let at = offset + done as u64;
            let lba = at / bs;
            let skip = (at % bs) as usize;
            let left = data.len() - done;
            if skip == 0 && left as u64 >= bs {
                let whole = left - left % bs as usize;
                self.write_blocks(lba, &data[done..done + whole])?;
                done += whole;
            } else {
                let mut block = vec![0u8; bs as usize];
                self.read_blocks(lba, &mut block)?;
                let n = (bs as usize - skip).min(left);
                block[skip..skip + n].copy_from_slice(&data[done..done + n]);
                self.write_blocks(lba, &block)?;
                done += n;
            }
        }
        Ok(())
    }

    /// Read any bytes of the volume.
    pub fn read_bytes(&self, offset: u64, buf: &mut [u8]) -> Result<(), ()> {
        let bs = self.block_size() as u64;
        let mut done = 0usize;
        while done < buf.len() {
            let at = offset + done as u64;
            let lba = at / bs;
            let skip = (at % bs) as usize;
            let left = buf.len() - done;
            if skip == 0 && left as u64 >= bs {
                let whole = left - left % bs as usize;
                self.read_blocks(lba, &mut buf[done..done + whole])?;
                done += whole;
            } else {
                let mut block = vec![0u8; bs as usize];
                self.read_blocks(lba, &mut block)?;
                let n = (bs as usize - skip).min(left);
                buf[done..done + n].copy_from_slice(&block[skip..skip + n]);
                done += n;
            }
        }
        Ok(())
    }
}

extern "efiapi" fn reset(_this: *mut block_io::Protocol, _verify: efi::Boolean) -> efi::Status {
    efi::Status::SUCCESS
}

extern "efiapi" fn read_blocks(
    this: *mut block_io::Protocol,
    media_id: u32,
    lba: efi::Lba,
    size: usize,
    buf: *mut c_void,
) -> efi::Status {
    let v = unsafe { &*(this as *const Volume) };
    if media_id != v.media.media_id {
        return efi::Status::MEDIA_CHANGED;
    }
    if buf.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    if size % v.block_size() as usize != 0 {
        return efi::Status::BAD_BUFFER_SIZE;
    }
    if lba > v.media.last_block || lba + (size / v.block_size() as usize) as u64 > v.blocks() {
        return efi::Status::INVALID_PARAMETER;
    }
    let out = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, size) };
    match v.read_blocks(lba, out) {
        Ok(()) => efi::Status::SUCCESS,
        Err(()) => efi::Status::DEVICE_ERROR,
    }
}

extern "efiapi" fn write_blocks(
    _this: *mut block_io::Protocol,
    _media_id: u32,
    _lba: efi::Lba,
    _size: usize,
    _buf: *mut c_void,
) -> efi::Status {
    efi::Status::WRITE_PROTECTED
}

extern "efiapi" fn flush_blocks(_this: *mut block_io::Protocol) -> efi::Status {
    efi::Status::SUCCESS
}

fn from_disk_io(this: *mut disk_io::Protocol) -> &'static Volume {
    let offset = core::mem::offset_of!(Volume, disk_io);
    unsafe { &*((this as *mut u8).sub(offset) as *const Volume) }
}

extern "efiapi" fn disk_read(
    this: *mut disk_io::Protocol,
    media_id: u32,
    offset: u64,
    size: usize,
    buf: *mut c_void,
) -> efi::Status {
    let v = from_disk_io(this);
    if media_id != v.media.media_id {
        return efi::Status::MEDIA_CHANGED;
    }
    if offset.saturating_add(size as u64) > v.blocks() * v.block_size() as u64 {
        return efi::Status::INVALID_PARAMETER;
    }
    let out = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, size) };
    match v.read_bytes(offset, out) {
        Ok(()) => efi::Status::SUCCESS,
        Err(()) => efi::Status::DEVICE_ERROR,
    }
}

extern "efiapi" fn disk_write(
    _this: *mut disk_io::Protocol,
    _media_id: u32,
    _offset: u64,
    _size: usize,
    _buf: *mut c_void,
) -> efi::Status {
    efi::Status::WRITE_PROTECTED
}

fn publish(disk: *mut dyn Disk, first: u64, blocks: u64, partition: bool, path: Vec<u8>) -> &'static mut Volume {
    let d = unsafe { &*disk };
    let v = Box::leak(Box::new(Volume {
        block_io: block_io::Protocol {
            revision: block_io::REVISION,
            media: core::ptr::null_mut(),
            reset,
            read_blocks,
            write_blocks,
            flush_blocks,
        },
        disk_io: disk_io::Protocol { revision: disk_io::REVISION, read_disk: disk_read, write_disk: disk_write },
        media: block_io::Media {
            media_id: 0,
            removable_media: true,
            media_present: true,
            logical_partition: partition,
            read_only: true,
            write_caching: false,
            block_size: d.block_size(),
            io_align: 0,
            last_block: blocks - 1,
            lowest_aligned_lba: 0,
            logical_blocks_per_physical_block: 1,
            optimal_transfer_length_granularity: 1,
        },
        disk,
        first,
        handle: core::ptr::null_mut(),
        path,
    }));
    v.block_io.media = &mut v.media;
    let mut h = core::ptr::null_mut();
    for (guid, iface) in [
        (block_io::PROTOCOL_GUID, &mut v.block_io as *mut _ as *mut c_void),
        (disk_io::PROTOCOL_GUID, &mut v.disk_io as *mut _ as *mut c_void),
        (device_path::PROTOCOL_GUID, v.path.as_mut_ptr() as *mut c_void),
    ] {
        h = proto::install(h, &guid, iface).unwrap();
    }
    v.handle = h;
    v
}

/// A partition: where it starts and how long it is, in blocks, and its
/// `HD()` node's data.
struct Partition {
    first: u64,
    blocks: u64,
    node: [u8; 38],
}

fn hd_node(number: u32, first: u64, blocks: u64, signature: &[u8], gpt: bool) -> [u8; 38] {
    let mut n = [0u8; 38];
    n[0..4].copy_from_slice(&number.to_le_bytes());
    n[4..12].copy_from_slice(&first.to_le_bytes());
    n[12..20].copy_from_slice(&blocks.to_le_bytes());
    n[20..20 + signature.len()].copy_from_slice(signature);
    n[36] = if gpt { 2 } else { 1 };
    n[37] = if gpt { 2 } else { 1 };
    n
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

fn partitions(disk: &Volume) -> Vec<Partition> {
    let bs = disk.block_size() as usize;
    let mut mbr = vec![0u8; bs];
    if disk.read_blocks(0, &mut mbr).is_err() || mbr[510] != 0x55 || mbr[511] != 0xaa {
        return Vec::new();
    }
    let entry = |i: usize| &mbr[446 + 16 * i..446 + 16 * (i + 1)];
    if (0..4).any(|i| entry(i)[4] == 0xee) {
        return gpt(disk);
    }
    // A FAT boot sector carries the signature too, and has no partitions.
    if fat_signature(&mbr) {
        return Vec::new();
    }
    let signature = &mbr[440..444];
    (0..4)
        .filter_map(|i| {
            let e = entry(i);
            let (ty, first, blocks) = (e[4], le32(e, 8) as u64, le32(e, 12) as u64);
            let usable = ty != 0 && ty != 0x05 && ty != 0x0f && ty != 0x85 && blocks > 0;
            (usable && first + blocks <= disk.blocks())
                .then(|| Partition { first, blocks, node: hd_node(i as u32 + 1, first, blocks, signature, false) })
        })
        .collect()
}

/// Each GPT disk's path and its `UEFI_GPT_DATA`: the header, the number of
/// partitions in use and their entries.
static GPT_DATA: Global<Vec<(Vec<u8>, Vec<u8>)>> = Global::new(Vec::new());

/// The `UEFI_GPT_DATA` of the disk the partition at `path` is on.
pub fn gpt_data(path: &[u8]) -> Option<&'static [u8]> {
    GPT_DATA.get().iter().find(|(disk, _)| path.starts_with(&disk[..disk.len() - 4])).map(|(_, data)| data.as_slice())
}

fn remember_gpt(disk: &Volume, header: &[u8], table: &[u8], count: usize, size: usize) {
    let used: Vec<&[u8]> = (0..count).map(|i| &table[i * size..(i + 1) * size]).filter(|e| e[0..16].iter().any(|&b| b != 0)).collect();
    let mut data = header[..(le32(header, 12) as usize).clamp(92, header.len())].to_vec();
    data.extend_from_slice(&(used.len() as u64).to_le_bytes());
    used.iter().for_each(|e| data.extend_from_slice(e));
    GPT_DATA.get().push((disk.path.clone(), data));
}

fn gpt(disk: &Volume) -> Vec<Partition> {
    let bs = disk.block_size() as usize;
    let mut header = vec![0u8; bs];
    if disk.read_blocks(1, &mut header).is_err() || &header[0..8] != b"EFI PART" {
        warn!("disk", "protective MBR without a GPT header"; path = devpath::Text(&disk.path));
        return Vec::new();
    }
    let (entries_lba, count, size) = (le64(&header, 72), le32(&header, 80) as usize, le32(&header, 84) as usize);
    if !(128..=4096).contains(&size) || count > 1024 {
        return Vec::new();
    }
    let mut table = vec![0u8; (count * size).next_multiple_of(bs)];
    if disk.read_blocks(entries_lba, &mut table).is_err() {
        return Vec::new();
    }
    remember_gpt(disk, &header, &table, count, size);
    (0..count)
        .filter_map(|i| {
            let e = &table[i * size..(i + 1) * size];
            let (first, last) = (le64(e, 32), le64(e, 40));
            let used = e[0..16].iter().any(|&b| b != 0) && last >= first && last < disk.blocks();
            used.then(|| Partition {
                first,
                blocks: last - first + 1,
                node: hd_node(i as u32 + 1, first, last - first + 1, &e[16..32], true),
            })
        })
        .collect()
}

pub fn fat_signature(boot: &[u8]) -> bool {
    boot[510] == 0x55 && boot[511] == 0xaa && (&boot[54..57] == b"FAT" || &boot[82..87] == b"FAT32")
}

/// Publish a disk a driver found, its partitions, and the file systems on
/// them. `path` is the disk's device path.
pub fn add_disk(disk: Box<dyn Disk>, path: Vec<u8>, name: &'static str) {
    let disk: *mut dyn Disk = Box::into_raw(disk);
    let blocks = unsafe { (*disk).blocks() };
    let whole = publish(disk, 0, blocks, false, path);
    let parts = partitions(whole);
    info!("disk", "disk found"; name = name, mib = blocks * whole.block_size() as u64 >> 20,
        partitions = parts.len(), path = devpath::Text(&whole.path));
    if parts.is_empty() {
        crate::fat::mount(whole);
    }
    for p in parts {
        let path = Builder::from(&whole.path).node(devpath::MEDIA, devpath::MEDIA_HD, &p.node).done();
        let v = publish(disk, p.first, p.blocks, true, path);
        crate::fat::mount(v);
    }
}

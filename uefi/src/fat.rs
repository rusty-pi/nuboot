//! FAT12, FAT16 and FAT32, with long names: what an EFI system partition is.
//! Each volume gets `EFI_SIMPLE_FILE_SYSTEM_PROTOCOL`, and each open file or
//! directory an `EFI_FILE_PROTOCOL`, both read-only to an EFI application. The
//! firmware itself writes the files an update needs ([`write_file`],
//! [`remove_file`], [`adopt`]).

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::ffi::c_void;

use r_efi::efi;
use r_efi::protocols::{file, simple_file_system};

use crate::block::{self, Volume};
use crate::util::{eq_ignore_case, wstr};
use crate::{debug, proto};

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Fat12,
    Fat16,
    Fat32,
}

#[repr(C)]
pub struct Fs {
    sfs: simple_file_system::Protocol,
    vol: &'static Volume,
    kind: Kind,
    cluster_size: u64,
    /// Byte offsets into the volume.
    fat: u64,
    root_dir: u64,
    root_dir_size: u64,
    data: u64,
    root_cluster: u32,
    clusters: u32,
    fats: u64,
    /// The size of one FAT, in bytes.
    fat_size: u64,
    /// FAT32's FSInfo sector, or 0.
    fsinfo: u64,
    label: [u8; 11],
    /// The 4 KiB of the FAT read last: its offset and its bytes.
    cache: (u64, Vec<u8>),
    /// Where a read of a chain stopped: the chain's first cluster, the index
    /// of the cluster it stopped in and that cluster. The next read of the
    /// chain from there on goes on from it, not from the start.
    walk: (u32, u64, u32),
}

/// A directory entry, or the root directory.
#[derive(Clone)]
struct Entry {
    name: Vec<u16>,
    attr: u8,
    cluster: u32,
    size: u32,
    /// The FAT date and time words: created, accessed (date only), written.
    times: [u16; 5],
}

/// An entry found in a directory's bytes: where its slots are.
struct Found {
    entry: Entry,
    /// The slot of the first long-name entry, or its own when it has none.
    first: usize,
    /// The slot of its short entry.
    slot: usize,
}

const ATTR_DIR: u8 = 0x10;
const ATTR_VOLUME: u8 = 0x08;
const ATTR_LFN: u8 = 0x0f;
const CHUNK: u64 = 4096;

impl Fs {
    fn fat_byte(&mut self, at: u64) -> Option<u8> {
        let base = at & !(CHUNK - 1);
        if self.cache.1.is_empty() || self.cache.0 != base {
            let mut buf = vec![0u8; CHUNK as usize];
            self.vol.read_bytes(self.fat + base, &mut buf).ok()?;
            self.cache = (base, buf);
        }
        Some(self.cache.1[(at - base) as usize])
    }

    /// The cluster after `c`, or None at the end of the chain.
    fn next(&mut self, c: u32) -> Option<u32> {
        let n = match self.kind {
            Kind::Fat12 => {
                let at = c as u64 * 3 / 2;
                let v = self.fat_byte(at)? as u16 | (self.fat_byte(at + 1)? as u16) << 8;
                (if c & 1 == 1 { v >> 4 } else { v & 0xfff }) as u32
            }
            Kind::Fat16 => {
                let at = c as u64 * 2;
                self.fat_byte(at)? as u32 | (self.fat_byte(at + 1)? as u32) << 8
            }
            Kind::Fat32 => {
                let at = c as u64 * 4;
                let b = [self.fat_byte(at)?, self.fat_byte(at + 1)?, self.fat_byte(at + 2)?, self.fat_byte(at + 3)?];
                u32::from_le_bytes(b) & 0x0fff_ffff
            }
        };
        (n >= 2 && n < self.clusters + 2).then_some(n)
    }

    fn cluster_offset(&self, c: u32) -> u64 {
        self.data + (c as u64 - 2) * self.cluster_size
    }

    /// Read `buf.len()` bytes from `pos` of the chain starting at `first`.
    fn read_chain(&mut self, first: u32, pos: u64, buf: &mut [u8]) -> Result<(), ()> {
        let target = pos / self.cluster_size;
        let (mut c, mut index) = if self.walk.0 == first && self.walk.1 <= target { (self.walk.2, self.walk.1) } else { (first, 0) };
        while index < target {
            c = self.next(c).ok_or(())?;
            index += 1;
        }
        let mut skip = pos % self.cluster_size;
        let mut done = 0usize;
        while done < buf.len() {
            // A run of consecutive clusters is one read.
            let start = c;
            let mut len = self.cluster_size - skip;
            while (done as u64 + len) < buf.len() as u64 {
                match self.next(c) {
                    Some(n) if n == c + 1 => {
                        c = n;
                        index += 1;
                        len += self.cluster_size;
                    }
                    _ => break,
                }
            }
            let n = (len as usize).min(buf.len() - done);
            self.vol.read_bytes(self.cluster_offset(start) + skip, &mut buf[done..done + n])?;
            done += n;
            skip = 0;
            if done < buf.len() {
                c = self.next(c).ok_or(())?;
                index += 1;
            }
        }
        self.walk = (first, index, c);
        Ok(())
    }

    fn chain_len(&mut self, first: u32) -> u64 {
        let mut n = 0;
        let mut c = Some(first);
        while let Some(x) = c {
            n += 1;
            if n > self.clusters as u64 {
                break;
            }
            c = self.next(x);
        }
        n * self.cluster_size
    }

    /// The bytes of a directory: the fixed root of FAT12/16, or a chain.
    fn dir_bytes(&mut self, dir: &Entry) -> Vec<u8> {
        let (len, root_fixed) = if dir.cluster == 0 && self.kind != Kind::Fat32 {
            (self.root_dir_size, true)
        } else {
            let first = if dir.cluster == 0 { self.root_cluster } else { dir.cluster };
            (self.chain_len(first), false)
        };
        let mut buf = vec![0u8; len.min(1 << 20) as usize];
        let ok = if root_fixed {
            self.vol.read_bytes(self.root_dir, &mut buf).is_ok()
        } else {
            let first = if dir.cluster == 0 { self.root_cluster } else { dir.cluster };
            self.read_chain(first, 0, &mut buf).is_ok()
        };
        if !ok {
            buf.clear();
        }
        buf
    }

    fn entries(&mut self, dir: &Entry) -> Vec<Entry> {
        let bytes = self.dir_bytes(dir);
        self.parse(&bytes).into_iter().map(|f| f.entry).collect()
    }

    /// The entries of a directory's bytes, each with where its slots are: the
    /// first of its long name's, and its own.
    fn parse(&self, bytes: &[u8]) -> Vec<Found> {
        let mut out = Vec::new();
        let mut lfn = [0u16; 260];
        let mut lfn_len = 0usize;
        let mut first = 0usize;
        for (index, e) in bytes.chunks_exact(32).enumerate() {
            match e[0] {
                0 => break,
                0xe5 => {
                    lfn_len = 0;
                    continue;
                }
                _ => {}
            }
            let attr = e[11];
            if attr & 0x3f == ATTR_LFN {
                let ord = (e[0] & 0x3f) as usize;
                if ord == 0 || ord > 20 {
                    lfn_len = 0;
                    continue;
                }
                if e[0] & 0x40 != 0 {
                    lfn_len = 0;
                    first = index;
                }
                let at = (ord - 1) * 13;
                for (i, off) in [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30].into_iter().enumerate() {
                    let c = u16::from_le_bytes([e[off], e[off + 1]]);
                    if c == 0 || c == 0xffff {
                        break;
                    }
                    lfn[at + i] = c;
                    lfn_len = lfn_len.max(at + i + 1);
                }
                continue;
            }
            if attr & ATTR_VOLUME != 0 {
                lfn_len = 0;
                continue;
            }
            let first = if lfn_len > 0 { first } else { index };
            let name = if lfn_len > 0 { lfn[..lfn_len].to_vec() } else { short_name(e) };
            lfn_len = 0;
            let w = |at: usize| u16::from_le_bytes([e[at], e[at + 1]]);
            let cluster = if self.kind == Kind::Fat32 { (w(20) as u32) << 16 } else { 0 } | w(26) as u32;
            out.push(Found {
                entry: Entry {
                    name,
                    attr,
                    cluster,
                    size: u32::from_le_bytes(e[28..32].try_into().unwrap()),
                    times: [w(16), w(14), w(18), w(24), w(22)],
                },
                first,
                slot: index,
            });
        }
        out
    }

    fn root(&self) -> Entry {
        Entry { name: Vec::new(), attr: ATTR_DIR, cluster: 0, size: 0, times: [0; 5] }
    }
}

fn short_name(e: &[u8]) -> Vec<u16> {
    let lower_base = e[12] & 0x08 != 0;
    let lower_ext = e[12] & 0x10 != 0;
    let conv = |b: u8, lower: bool| (if lower { b.to_ascii_lowercase() } else { b }) as u16;
    let mut name: Vec<u16> = e[0..8].iter().take_while(|&&b| b != b' ').map(|&b| conv(b, lower_base)).collect();
    if name.first() == Some(&0x05) {
        name[0] = 0xe5;
    }
    let ext: Vec<u16> = e[8..11].iter().take_while(|&&b| b != b' ').map(|&b| conv(b, lower_ext)).collect();
    if !ext.is_empty() {
        name.push(b'.' as u16);
        name.extend(ext);
    }
    name
}

/// Mount the FAT file system on `vol`, if it holds one.
pub fn mount(vol: &'static Volume) {
    let mut boot = vec![0u8; vol.block_size() as usize];
    if vol.read_blocks(0, &mut boot).is_err() || boot.len() < 512 || !block::fat_signature(&boot) {
        return;
    }
    let w = |at: usize| u16::from_le_bytes([boot[at], boot[at + 1]]) as u64;
    let d = |at: usize| u32::from_le_bytes(boot[at..at + 4].try_into().unwrap()) as u64;
    let bps = w(11);
    let spc = boot[13] as u64;
    let reserved = w(14);
    let fats = boot[16] as u64;
    let root_entries = w(17);
    let total = if w(19) != 0 { w(19) } else { d(32) };
    let fat_size = if w(22) != 0 { w(22) } else { d(36) };
    if !matches!(bps, 512 | 1024 | 2048 | 4096) || spc == 0 || fats == 0 || fat_size == 0 {
        return;
    }
    let root_dir_sectors = (root_entries * 32).div_ceil(bps);
    let data_sector = reserved + fats * fat_size + root_dir_sectors;
    if total <= data_sector {
        return;
    }
    let clusters = ((total - data_sector) / spc) as u32;
    let kind = if clusters < 4085 {
        Kind::Fat12
    } else if clusters < 65525 {
        Kind::Fat16
    } else {
        Kind::Fat32
    };
    let mut label = [0u8; 11];
    label.copy_from_slice(if kind == Kind::Fat32 { &boot[71..82] } else { &boot[43..54] });
    let fs = Box::leak(Box::new(Fs {
        sfs: simple_file_system::Protocol { revision: simple_file_system::REVISION, open_volume },
        vol,
        kind,
        cluster_size: spc * bps,
        fat: reserved * bps,
        root_dir: (reserved + fats * fat_size) * bps,
        root_dir_size: root_entries * 32,
        data: data_sector * bps,
        root_cluster: if kind == Kind::Fat32 { d(44) as u32 } else { 0 },
        clusters,
        fats,
        fat_size: fat_size * bps,
        fsinfo: if kind == Kind::Fat32 { w(48) } else { 0 },
        label,
        cache: (0, Vec::new()),
        walk: (0, 0, 0),
    }));
    debug!("fat", "file system found"; clusters = clusters, cluster_size = fs.cluster_size,
        path = crate::devpath::Text(&vol.path));
    let _ = proto::install(vol.handle, &simple_file_system::PROTOCOL_GUID, &mut fs.sfs as *mut _ as *mut c_void);
}

/// An open file or directory.
#[repr(C)]
struct File {
    proto: file::Protocol,
    fs: *mut Fs,
    entry: Entry,
    /// The directories from the root down to this one's, for `..`.
    parents: Vec<Entry>,
    pos: u64,
}

fn new_file(fs: *mut Fs, entry: Entry, parents: Vec<Entry>) -> *mut file::Protocol {
    let f = Box::into_raw(Box::new(File {
        proto: file::Protocol {
            revision: file::REVISION,
            open,
            close,
            delete,
            read,
            write,
            get_position,
            set_position,
            get_info,
            set_info,
            flush,
            open_ex,
            read_ex,
            write_ex,
            flush_ex,
        },
        fs,
        entry,
        parents,
        pos: 0,
    }));
    f as *mut file::Protocol
}

fn this<'a>(p: *mut file::Protocol) -> &'a mut File {
    unsafe { &mut *(p as *mut File) }
}

extern "efiapi" fn open_volume(this: *mut simple_file_system::Protocol, root: *mut *mut file::Protocol) -> efi::Status {
    if root.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    let fs = this as *mut Fs;
    let entry = unsafe { (*fs).root() };
    unsafe { *root = new_file(fs, entry, Vec::new()) };
    efi::Status::SUCCESS
}

extern "efiapi" fn open(
    this_: *mut file::Protocol,
    new: *mut *mut file::Protocol,
    name: *mut efi::Char16,
    mode: u64,
    _attributes: u64,
) -> efi::Status {
    if new.is_null() || name.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    let f = this(this_);
    let fs = unsafe { &mut *f.fs };
    let name = unsafe { wstr(name) };
    // The directories from the root down to where the path has got to.
    let mut stack: Vec<Entry> = if name.first() == Some(&(b'\\' as u16)) {
        Vec::new()
    } else if f.entry.attr & ATTR_DIR != 0 {
        let mut s = f.parents.clone();
        if f.entry.cluster != 0 {
            s.push(f.entry.clone());
        }
        s
    } else {
        return efi::Status::NOT_FOUND;
    };
    let mut parts = name.split(|&c| c == b'\\' as u16).filter(|p| !p.is_empty()).peekable();
    let mut file: Option<Entry> = None;
    while let Some(part) = parts.next() {
        if part == [b'.' as u16] {
            continue;
        }
        if part == [b'.' as u16, b'.' as u16] {
            stack.pop();
            continue;
        }
        let dir = stack.last().cloned().unwrap_or_else(|| fs.root());
        let Some(e) = fs.entries(&dir).into_iter().find(|e| eq_ignore_case(&e.name, part)) else {
            return efi::Status::NOT_FOUND;
        };
        if e.attr & ATTR_DIR != 0 {
            stack.push(e);
        } else if parts.peek().is_none() {
            file = Some(e);
        } else {
            return efi::Status::NOT_FOUND;
        }
    }
    if mode & (file::MODE_WRITE | file::MODE_CREATE) != 0 {
        return efi::Status::WRITE_PROTECTED;
    }
    let (entry, parents) = match file {
        Some(e) => (e, stack),
        None => match stack.pop() {
            Some(d) => (d, stack),
            None => (fs.root(), Vec::new()),
        },
    };
    unsafe { *new = new_file(f.fs, entry, parents) };
    efi::Status::SUCCESS
}

extern "efiapi" fn close(this_: *mut file::Protocol) -> efi::Status {
    drop(unsafe { Box::from_raw(this_ as *mut File) });
    efi::Status::SUCCESS
}

extern "efiapi" fn delete(this_: *mut file::Protocol) -> efi::Status {
    close(this_);
    efi::Status::WARN_DELETE_FAILURE
}

/// FAT's date and time words as an `EFI_TIME`.
fn time(date: u16, time: u16) -> efi::Time {
    efi::Time {
        year: 1980 + (date >> 9),
        month: ((date >> 5) & 0xf) as u8,
        day: (date & 0x1f) as u8,
        hour: (time >> 11) as u8,
        minute: ((time >> 5) & 0x3f) as u8,
        second: ((time & 0x1f) * 2) as u8,
        pad1: 0,
        nanosecond: 0,
        timezone: efi::UNSPECIFIED_TIMEZONE,
        daylight: 0,
        pad2: 0,
    }
}

/// `EFI_FILE_INFO` for `e`, into `buf` if it fits; its size either way.
fn file_info(fs: &mut Fs, e: &Entry, buf: *mut u8, room: usize) -> usize {
    let header = core::mem::size_of::<file::Info>();
    let size = header + (e.name.len() + 1) * 2;
    if room < size || buf.is_null() {
        return size;
    }
    let physical = if e.attr & ATTR_DIR != 0 || e.size == 0 {
        if e.cluster >= 2 { fs.chain_len(e.cluster) } else { 0 }
    } else {
        (e.size as u64).next_multiple_of(fs.cluster_size)
    };
    let info = file::Info {
        size: size as u64,
        file_size: if e.attr & ATTR_DIR != 0 { physical } else { e.size as u64 },
        physical_size: physical,
        create_time: time(e.times[0], e.times[1]),
        last_access_time: time(e.times[2], 0),
        modification_time: time(e.times[3], e.times[4]),
        attribute: (e.attr & 0x37) as u64,
        file_name: [],
    };
    unsafe {
        core::ptr::write_unaligned(buf as *mut file::Info, info);
        let name = buf.add(header) as *mut u16;
        for (i, &c) in e.name.iter().chain(&[0]).enumerate() {
            name.add(i).write_unaligned(c);
        }
    }
    size
}

extern "efiapi" fn read(this_: *mut file::Protocol, size: *mut usize, buf: *mut c_void) -> efi::Status {
    if size.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    let f = this(this_);
    let fs = unsafe { &mut *f.fs };
    if f.entry.attr & ATTR_DIR != 0 {
        let entries = fs.entries(&f.entry);
        let entries: Vec<&Entry> = entries.iter().collect();
        let Some(e) = entries.get(f.pos as usize) else {
            unsafe { *size = 0 };
            return efi::Status::SUCCESS;
        };
        let need = file_info(fs, e, buf as *mut u8, unsafe { *size });
        if need > unsafe { *size } {
            unsafe { *size = need };
            return efi::Status::BUFFER_TOO_SMALL;
        }
        unsafe { *size = need };
        f.pos += 1;
        return efi::Status::SUCCESS;
    }
    let left = (f.entry.size as u64).saturating_sub(f.pos);
    let n = (unsafe { *size } as u64).min(left) as usize;
    if n > 0 {
        if buf.is_null() {
            return efi::Status::INVALID_PARAMETER;
        }
        let out = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, n) };
        if fs.read_chain(f.entry.cluster, f.pos, out).is_err() {
            return efi::Status::DEVICE_ERROR;
        }
    }
    f.pos += n as u64;
    unsafe { *size = n };
    efi::Status::SUCCESS
}

extern "efiapi" fn write(_this: *mut file::Protocol, _size: *mut usize, _buf: *mut c_void) -> efi::Status {
    efi::Status::WRITE_PROTECTED
}

extern "efiapi" fn get_position(this_: *mut file::Protocol, pos: *mut u64) -> efi::Status {
    let f = this(this_);
    if f.entry.attr & ATTR_DIR != 0 {
        return efi::Status::UNSUPPORTED;
    }
    unsafe { *pos = f.pos };
    efi::Status::SUCCESS
}

extern "efiapi" fn set_position(this_: *mut file::Protocol, pos: u64) -> efi::Status {
    let f = this(this_);
    if f.entry.attr & ATTR_DIR != 0 {
        if pos != 0 {
            return efi::Status::UNSUPPORTED;
        }
        f.pos = 0;
    } else {
        f.pos = if pos == u64::MAX { f.entry.size as u64 } else { pos };
    }
    efi::Status::SUCCESS
}

extern "efiapi" fn get_info(this_: *mut file::Protocol, ty: *mut efi::Guid, size: *mut usize, buf: *mut c_void) -> efi::Status {
    if ty.is_null() || size.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    let f = this(this_);
    let fs = unsafe { &mut *f.fs };
    let ty = unsafe { &*ty };
    let room = unsafe { *size };
    let label: Vec<u16> = {
        let end = fs.label.iter().rposition(|&b| b != b' ').map_or(0, |i| i + 1);
        let l = &fs.label[..end];
        if l == b"NO NAME" { Vec::new() } else { l.iter().map(|&b| b as u16).collect() }
    };
    let need = if *ty == file::INFO_ID {
        let e = f.entry.clone();
        file_info(fs, &e, buf as *mut u8, room)
    } else if *ty == file::SYSTEM_INFO_ID {
        let header = core::mem::size_of::<file::SystemInfo>();
        let need = header + (label.len() + 1) * 2;
        if room >= need && !buf.is_null() {
            let info = file::SystemInfo {
                size: need as u64,
                read_only: true.into(),
                volume_size: fs.clusters as u64 * fs.cluster_size,
                free_space: 0,
                block_size: fs.cluster_size as u32,
                volume_label: [],
            };
            unsafe {
                core::ptr::write_unaligned(buf as *mut file::SystemInfo, info);
                let name = (buf as *mut u8).add(header) as *mut u16;
                for (i, &c) in label.iter().chain(&[0]).enumerate() {
                    name.add(i).write_unaligned(c);
                }
            }
        }
        need
    } else if *ty == file::SYSTEM_VOLUME_LABEL_ID {
        let need = (label.len() + 1) * 2;
        if room >= need && !buf.is_null() {
            let name = buf as *mut u16;
            for (i, &c) in label.iter().chain(&[0]).enumerate() {
                unsafe { name.add(i).write_unaligned(c) };
            }
        }
        need
    } else {
        return efi::Status::UNSUPPORTED;
    };
    unsafe { *size = need };
    if need > room { efi::Status::BUFFER_TOO_SMALL } else { efi::Status::SUCCESS }
}

extern "efiapi" fn set_info(_this: *mut file::Protocol, _ty: *mut efi::Guid, _size: usize, _buf: *mut c_void) -> efi::Status {
    efi::Status::WRITE_PROTECTED
}

extern "efiapi" fn flush(_this: *mut file::Protocol) -> efi::Status {
    efi::Status::SUCCESS
}

extern "efiapi" fn open_ex(
    _this: *mut file::Protocol,
    _new: *mut *mut file::Protocol,
    _name: *mut efi::Char16,
    _mode: u64,
    _attributes: u64,
    _token: *mut file::IoToken,
) -> efi::Status {
    efi::Status::UNSUPPORTED
}

extern "efiapi" fn read_ex(_this: *mut file::Protocol, _token: *mut file::IoToken) -> efi::Status {
    efi::Status::UNSUPPORTED
}

extern "efiapi" fn write_ex(_this: *mut file::Protocol, _token: *mut file::IoToken) -> efi::Status {
    efi::Status::UNSUPPORTED
}

extern "efiapi" fn flush_ex(_this: *mut file::Protocol, _token: *mut file::IoToken) -> efi::Status {
    efi::Status::UNSUPPORTED
}

/// Read a whole file from the file system on `handle`, for the boot manager
/// and `LoadImage`.
pub fn read_file(handle: efi::Handle, path: &[u16]) -> Result<Vec<u8>, efi::Status> {
    let sfs = proto::get(handle, &simple_file_system::PROTOCOL_GUID).ok_or(efi::Status::NOT_FOUND)?
        as *mut simple_file_system::Protocol;
    let mut root = core::ptr::null_mut();
    let s = unsafe { ((*sfs).open_volume)(sfs, &mut root) };
    if s.is_error() {
        return Err(s);
    }
    let mut name: Vec<u16> = path.to_vec();
    name.push(0);
    let mut f = core::ptr::null_mut();
    let s = open(root, &mut f, name.as_mut_ptr(), file::MODE_READ, 0);
    close(root);
    if s.is_error() {
        return Err(s);
    }
    let file = this(f);
    if file.entry.attr & ATTR_DIR != 0 {
        close(f);
        return Err(efi::Status::NOT_FOUND);
    }
    let mut data = vec![0u8; file.entry.size as usize];
    let mut n = data.len();
    let s = read(f, &mut n, data.as_mut_ptr() as *mut c_void);
    close(f);
    if s.is_error() {
        return Err(s);
    }
    Ok(data)
}

/// The names of the files (not directories) in the directory at `path` on
/// the file system on `handle`.
pub fn list_files(handle: efi::Handle, path: &[u16]) -> Result<Vec<Vec<u16>>, efi::Status> {
    let sfs = proto::get(handle, &simple_file_system::PROTOCOL_GUID).ok_or(efi::Status::NOT_FOUND)?
        as *mut simple_file_system::Protocol;
    let mut root = core::ptr::null_mut();
    let s = unsafe { ((*sfs).open_volume)(sfs, &mut root) };
    if s.is_error() {
        return Err(s);
    }
    let mut name: Vec<u16> = path.to_vec();
    name.push(0);
    let mut dir = core::ptr::null_mut();
    let s = open(root, &mut dir, name.as_mut_ptr(), file::MODE_READ, 0);
    close(root);
    if s.is_error() {
        return Err(s);
    }
    if this(dir).entry.attr & ATTR_DIR == 0 {
        close(dir);
        return Err(efi::Status::NOT_FOUND);
    }
    let mut names = Vec::new();
    loop {
        let mut buf = [0u8; 512];
        let mut n = buf.len();
        if read(dir, &mut n, buf.as_mut_ptr() as *mut c_void).is_error() || n == 0 {
            break;
        }
        let header = core::mem::size_of::<file::Info>();
        let info = unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const file::Info) };
        if info.attribute & ATTR_DIR as u64 == 0 {
            let units = (n.saturating_sub(header)) / 2;
            let name: Vec<u16> = (0..units)
                .map(|i| u16::from_le_bytes([buf[header + 2 * i], buf[header + 2 * i + 1]]))
                .take_while(|&c| c != 0)
                .collect();
            names.push(name);
        }
    }
    close(dir);
    Ok(names)
}

// --- writing, for the firmware's own files ---

impl Fs {
    fn end_of_chain(&self) -> u32 {
        match self.kind {
            Kind::Fat12 => 0xfff,
            Kind::Fat16 => 0xffff,
            Kind::Fat32 => 0x0fff_ffff,
        }
    }

    fn get(&self, fat: &[u8], c: u32) -> u32 {
        match self.kind {
            Kind::Fat12 => {
                let at = c as usize * 3 / 2;
                let v = fat[at] as u32 | (fat[at + 1] as u32) << 8;
                if c & 1 == 1 { v >> 4 } else { v & 0xfff }
            }
            Kind::Fat16 => u16::from_le_bytes([fat[c as usize * 2], fat[c as usize * 2 + 1]]) as u32,
            Kind::Fat32 => u32::from_le_bytes(fat[c as usize * 4..c as usize * 4 + 4].try_into().unwrap()) & 0x0fff_ffff,
        }
    }

    fn put(&self, fat: &mut [u8], c: u32, value: u32) {
        match self.kind {
            Kind::Fat12 => {
                let at = c as usize * 3 / 2;
                let old = fat[at] as u32 | (fat[at + 1] as u32) << 8;
                let new = if c & 1 == 1 { (old & 0x000f) | value << 4 } else { (old & 0xf000) | (value & 0xfff) };
                fat[at] = new as u8;
                fat[at + 1] = (new >> 8) as u8;
            }
            Kind::Fat16 => fat[c as usize * 2..c as usize * 2 + 2].copy_from_slice(&(value as u16).to_le_bytes()),
            Kind::Fat32 => {
                let old = u32::from_le_bytes(fat[c as usize * 4..c as usize * 4 + 4].try_into().unwrap());
                fat[c as usize * 4..c as usize * 4 + 4].copy_from_slice(&((old & 0xf000_0000) | (value & 0x0fff_ffff)).to_le_bytes());
            }
        }
    }

    fn load_fat(&mut self) -> Result<Vec<u8>, efi::Status> {
        if self.fat_size > 32 << 20 {
            return Err(efi::Status::OUT_OF_RESOURCES);
        }
        let mut fat = vec![0u8; self.fat_size as usize];
        self.vol.read_bytes(self.fat, &mut fat).map_err(|_| efi::Status::DEVICE_ERROR)?;
        Ok(fat)
    }

    /// Write back what differs between `old` and `new` in every copy of the
    /// FAT, and forget what was cached of it.
    fn store_fat(&mut self, old: &[u8], new: &[u8]) -> Result<(), efi::Status> {
        const PIECE: usize = 512;
        self.cache = (0, Vec::new());
        self.walk = (0, 0, 0);
        let mut at = 0;
        while at < new.len() {
            let end = (at + PIECE).min(new.len());
            if old[at..end] != new[at..end] {
                let mut stop = end;
                while stop < new.len() && old[stop..(stop + PIECE).min(new.len())] != new[stop..(stop + PIECE).min(new.len())] {
                    stop = (stop + PIECE).min(new.len());
                }
                for copy in 0..self.fats {
                    let at_bytes = self.fat + copy * self.fat_size + at as u64;
                    self.vol.write_bytes(at_bytes, &new[at..stop]).map_err(|_| efi::Status::DEVICE_ERROR)?;
                }
                at = stop;
            } else {
                at = end;
            }
        }
        Ok(())
    }

    /// Link `n` free clusters into a chain, and give them.
    fn allocate(&self, fat: &mut [u8], n: usize) -> Result<Vec<u32>, efi::Status> {
        let mut out = Vec::with_capacity(n);
        let mut c = 2;
        while out.len() < n && c < self.clusters + 2 {
            if self.get(fat, c) == 0 {
                out.push(c);
            }
            c += 1;
        }
        if out.len() < n {
            return Err(efi::Status::VOLUME_FULL);
        }
        for (i, &c) in out.iter().enumerate() {
            let next = out.get(i + 1).copied().unwrap_or(self.end_of_chain());
            self.put(fat, c, next);
        }
        Ok(out)
    }

    fn release(&self, fat: &mut [u8], first: u32) {
        let mut c = first;
        for _ in 0..self.clusters {
            if c < 2 || c >= self.clusters + 2 {
                break;
            }
            let next = self.get(fat, c);
            self.put(fat, c, 0);
            if next == 0 || next >= self.end_of_chain() - 7 {
                break;
            }
            c = next;
        }
    }

    /// Write `data` into `clusters`, a run of consecutive ones at a time.
    fn write_clusters(&self, clusters: &[u32], data: &[u8]) -> Result<(), efi::Status> {
        let size = self.cluster_size as usize;
        let mut i = 0;
        while i < clusters.len() {
            let mut run = 1;
            while i + run < clusters.len() && clusters[i + run] == clusters[i] + run as u32 {
                run += 1;
            }
            let from = i * size;
            let to = ((i + run) * size).min(data.len());
            let mut buf = data[from..to].to_vec();
            buf.resize(run * size, 0);
            self.vol.write_bytes(self.cluster_offset(clusters[i]), &buf).map_err(|_| efi::Status::DEVICE_ERROR)?;
            i += run;
        }
        Ok(())
    }

    /// The directory at `path`, from the root.
    fn resolve(&mut self, path: &[u16]) -> Option<Entry> {
        let mut dir = self.root();
        for part in path.split(|&c| c == b'\\' as u16).filter(|p| !p.is_empty()) {
            let next = self.entries(&dir).into_iter().find(|e| e.attr & ATTR_DIR != 0 && eq_ignore_case(&e.name, part))?;
            dir = next;
        }
        Some(dir)
    }

    fn dir_first(&self, dir: &Entry) -> u32 {
        if dir.cluster == 0 { self.root_cluster } else { dir.cluster }
    }

    /// Write the slots of a directory's bytes that differ from `old`.
    fn store_dir(&mut self, dir: &Entry, old: &[u8], new: &[u8]) -> Result<(), efi::Status> {
        let fixed_root = dir.cluster == 0 && self.kind != Kind::Fat32;
        let first = self.dir_first(dir);
        let mut at = 0;
        while at < new.len() {
            let end = (at + 512).min(new.len());
            if old.get(at..end) != Some(&new[at..end]) {
                if fixed_root {
                    self.vol.write_bytes(self.root_dir + at as u64, &new[at..end]).map_err(|_| efi::Status::DEVICE_ERROR)?;
                } else {
                    self.write_chain(first, at as u64, &new[at..end])?;
                }
            }
            at = end;
        }
        self.cache = (0, Vec::new());
        self.walk = (0, 0, 0);
        Ok(())
    }

    fn write_chain(&mut self, first: u32, pos: u64, data: &[u8]) -> Result<(), efi::Status> {
        let mut c = first;
        for _ in 0..pos / self.cluster_size {
            c = self.next(c).ok_or(efi::Status::DEVICE_ERROR)?;
        }
        let mut skip = pos % self.cluster_size;
        let mut done = 0;
        while done < data.len() {
            let n = ((self.cluster_size - skip) as usize).min(data.len() - done);
            self.vol.write_bytes(self.cluster_offset(c) + skip, &data[done..done + n]).map_err(|_| efi::Status::DEVICE_ERROR)?;
            done += n;
            skip = 0;
            if done < data.len() {
                c = self.next(c).ok_or(efi::Status::DEVICE_ERROR)?;
            }
        }
        Ok(())
    }

    /// FSInfo's free count and next free cluster are no longer known.
    fn forget_free_count(&mut self) {
        if self.fsinfo != 0 {
            let at = self.fsinfo * self.vol.block_size() as u64;
            let _ = self.vol.write_bytes(at + 488, &[0xff; 8]);
        }
    }
}

/// `name` as 8.3 in a directory slot, if it fits.
fn short_slot(name: &[u16]) -> Option<[u8; 11]> {
    let text: Vec<u8> = name.iter().map(|&c| u8::try_from(c).ok()).collect::<Option<_>>()?;
    let upper = text.to_ascii_uppercase();
    let (base, ext) = match upper.iter().rposition(|&b| b == b'.') {
        Some(dot) => (&upper[..dot], &upper[dot + 1..]),
        None => (&upper[..], &[][..]),
    };
    let ok = |part: &[u8]| part.iter().all(|&b| b.is_ascii_uppercase() || b.is_ascii_digit() || b"_-$~!#%&'(){}@^`".contains(&b));
    if base.is_empty() || base.len() > 8 || ext.len() > 3 || !ok(base) || !ok(ext) {
        return None;
    }
    let mut slot = [b' '; 11];
    slot[..base.len()].copy_from_slice(base);
    slot[8..8 + ext.len()].copy_from_slice(ext);
    Some(slot)
}

fn fs_of(handle: efi::Handle) -> Result<&'static mut Fs, efi::Status> {
    let p = proto::get(handle, &simple_file_system::PROTOCOL_GUID).ok_or(efi::Status::NOT_FOUND)?;
    Ok(unsafe { &mut *(p as *mut Fs) })
}

fn set_cluster(slot: &mut [u8], kind: Kind, cluster: u32, size: u32) {
    if kind == Kind::Fat32 {
        slot[20..22].copy_from_slice(&((cluster >> 16) as u16).to_le_bytes());
    }
    slot[26..28].copy_from_slice(&(cluster as u16).to_le_bytes());
    slot[28..32].copy_from_slice(&size.to_le_bytes());
}

/// Make the file `name` in the directory `dir` of the file system on `handle`
/// hold `data`: the new data goes into free clusters and the FAT first, and
/// the directory entry is written last, so a write that stops short leaves the
/// file as it was.
pub fn write_file(handle: efi::Handle, dir: &[u16], name: &[u16], data: &[u8]) -> Result<(), efi::Status> {
    let fs = fs_of(handle)?;
    let dir = fs.resolve(dir).ok_or(efi::Status::NOT_FOUND)?;
    let mut bytes = fs.dir_bytes(&dir);
    if bytes.is_empty() {
        return Err(efi::Status::DEVICE_ERROR);
    }
    let found = fs.parse(&bytes).into_iter().find(|f| eq_ignore_case(&f.entry.name, name));
    if found.as_ref().is_some_and(|f| f.entry.attr & ATTR_DIR != 0) {
        return Err(efi::Status::ACCESS_DENIED);
    }
    let short = short_slot(name);
    if found.is_none() && short.is_none() {
        return Err(efi::Status::UNSUPPORTED);
    }
    let old_dir = bytes.clone();
    let mut fat = fs.load_fat()?;
    let before = fat.clone();
    let needed = data.len().div_ceil(fs.cluster_size as usize);
    let clusters = fs.allocate(&mut fat, needed)?;
    let mut grown = None;
    let at = match &found {
        Some(f) => f.slot,
        None => {
            let free = bytes.chunks_exact(32).position(|e| e[0] == 0 || e[0] == 0xe5);
            match free {
                Some(i) => i,
                None => {
                    if dir.cluster == 0 && fs.kind != Kind::Fat32 {
                        return Err(efi::Status::OUT_OF_RESOURCES);
                    }
                    let extra = fs.allocate(&mut fat, 1)?[0];
                    let mut last = fs.dir_first(&dir);
                    while let Some(n) = fs.next(last) {
                        last = n;
                    }
                    fs.put(&mut fat, last, extra);
                    grown = Some(extra);
                    let at = bytes.len() / 32;
                    bytes.resize(bytes.len() + fs.cluster_size as usize, 0);
                    at
                }
            }
        }
    };
    fs.write_clusters(&clusters, data)?;
    if let Some(extra) = grown {
        fs.write_clusters(&[extra], &[])?;
    }
    fs.store_fat(&before, &fat)?;
    let first = clusters.first().copied().unwrap_or(0);
    let slot = &mut bytes[at * 32..at * 32 + 32];
    if found.is_none() {
        slot.fill(0);
        slot[..11].copy_from_slice(&short.unwrap_or([b' '; 11]));
        slot[11] = 0x20;
        slot[16..18].copy_from_slice(&0x0021u16.to_le_bytes());
        slot[18..20].copy_from_slice(&0x0021u16.to_le_bytes());
        slot[24..26].copy_from_slice(&0x0021u16.to_le_bytes());
    }
    set_cluster(slot, fs.kind, first, data.len() as u32);
    // A directory that grew has its new cluster zeroed and then written from
    // the start; the slots that differ are all that goes to the old part.
    let old_for_diff = if grown.is_some() {
        let mut o = old_dir.clone();
        o.resize(bytes.len(), 0xaa);
        o
    } else {
        old_dir
    };
    fs.store_dir(&dir, &old_for_diff, &bytes)?;
    if let Some(f) = &found {
        if f.entry.cluster >= 2 {
            let mut after = fat.clone();
            fs.release(&mut after, f.entry.cluster);
            fs.store_fat(&fat, &after)?;
        }
    }
    fs.forget_free_count();
    Ok(())
}

/// Remove the file `name` from the directory `dir`.
pub fn remove_file(handle: efi::Handle, dir: &[u16], name: &[u16]) -> Result<(), efi::Status> {
    let fs = fs_of(handle)?;
    let dir = fs.resolve(dir).ok_or(efi::Status::NOT_FOUND)?;
    let mut bytes = fs.dir_bytes(&dir);
    let old = bytes.clone();
    let f = fs.parse(&bytes).into_iter().find(|f| eq_ignore_case(&f.entry.name, name)).ok_or(efi::Status::NOT_FOUND)?;
    if f.entry.attr & ATTR_DIR != 0 {
        return Err(efi::Status::ACCESS_DENIED);
    }
    for i in f.first..=f.slot {
        bytes[i * 32] = 0xe5;
    }
    fs.store_dir(&dir, &old, &bytes)?;
    if f.entry.cluster >= 2 {
        let fat = fs.load_fat()?;
        let mut after = fat.clone();
        fs.release(&mut after, f.entry.cluster);
        fs.store_fat(&fat, &after)?;
    }
    fs.forget_free_count();
    Ok(())
}

/// Make each `to` in `dir` the file `from` is, and remove `from`: the entries
/// change in memory and go to the disk together, so with the slots in one
/// sector the swap is one write.
pub fn adopt(handle: efi::Handle, dir: &[u16], pairs: &[(&[u16], &[u16])]) -> Result<(), efi::Status> {
    let fs = fs_of(handle)?;
    let dir = fs.resolve(dir).ok_or(efi::Status::NOT_FOUND)?;
    let mut bytes = fs.dir_bytes(&dir);
    let old = bytes.clone();
    let mut released = Vec::new();
    for (from, to) in pairs {
        let all = fs.parse(&bytes);
        let source = all.iter().find(|f| eq_ignore_case(&f.entry.name, from)).ok_or(efi::Status::NOT_FOUND)?;
        let target = all.iter().find(|f| eq_ignore_case(&f.entry.name, to)).ok_or(efi::Status::NOT_FOUND)?;
        if source.entry.attr & ATTR_DIR != 0 || target.entry.attr & ATTR_DIR != 0 {
            return Err(efi::Status::ACCESS_DENIED);
        }
        if target.entry.cluster >= 2 {
            released.push(target.entry.cluster);
        }
        let (cluster, size) = (source.entry.cluster, source.entry.size);
        let (first, slot, target_slot) = (source.first, source.slot, target.slot);
        set_cluster(&mut bytes[target_slot * 32..target_slot * 32 + 32], fs.kind, cluster, size);
        for i in first..=slot {
            bytes[i * 32] = 0xe5;
        }
    }
    fs.store_dir(&dir, &old, &bytes)?;
    if !released.is_empty() {
        let fat = fs.load_fat()?;
        let mut after = fat.clone();
        for first in released {
            fs.release(&mut after, first);
        }
        fs.store_fat(&fat, &after)?;
    }
    fs.forget_free_count();
    Ok(())
}

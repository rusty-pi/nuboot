//! EFI images: PE32+ for AArch64, loaded, relocated and started, and
//! `Exit` back to whoever started them.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::arch::global_asm;
use core::ffi::c_void;
use core::fmt;

use r_efi::efi;
use r_efi::protocols::{device_path, loaded_image, loaded_image_device_path, simple_file_system};

use crate::devpath::{self, Text};
use crate::mem::{self, PAGE};
use crate::util::Global;
use crate::{debug, info, proto, warn};

/// The most of a file `LoadImage` reads to run it.
const MAX_LOADED: usize = 256 * 1024 * 1024;

const SUBSYSTEM_APPLICATION: u16 = 10;
const SUBSYSTEM_BOOT_DRIVER: u16 = 11;
const SUBSYSTEM_RUNTIME_DRIVER: u16 = 12;

/// What `image_call` saves and `image_exit` restores: x19..x28, d8..d15 and
/// the stack pointer.
type JumpBuffer = [u64; 19];

global_asm!(
    r#"
.text
// x0 = entry point, x1 = image handle, x2 = system table, x3 = jump buffer.
.global image_call
image_call:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    stp x19, x20, [x3, #0]
    stp x21, x22, [x3, #16]
    stp x23, x24, [x3, #32]
    stp x25, x26, [x3, #48]
    stp x27, x28, [x3, #64]
    stp d8, d9, [x3, #80]
    stp d10, d11, [x3, #96]
    stp d12, d13, [x3, #112]
    stp d14, d15, [x3, #128]
    mov x9, sp
    str x9, [x3, #144]
    mov x9, x0
    mov x0, x1
    mov x1, x2
    blr x9
    ldp x29, x30, [sp], #16
    ret

// x0 = jump buffer, x1 = status: return from that buffer's image_call.
.global image_exit
image_exit:
    ldp x19, x20, [x0, #0]
    ldp x21, x22, [x0, #16]
    ldp x23, x24, [x0, #32]
    ldp x25, x26, [x0, #48]
    ldp x27, x28, [x0, #64]
    ldp d8, d9, [x0, #80]
    ldp d10, d11, [x0, #96]
    ldp d12, d13, [x0, #112]
    ldp d14, d15, [x0, #128]
    ldr x9, [x0, #144]
    mov sp, x9
    mov x0, x1
    ldp x29, x30, [sp], #16
    ret
"#
);

unsafe extern "C" {
    fn image_call(entry: u64, handle: efi::Handle, st: *mut efi::SystemTable, jump: *mut JumpBuffer) -> efi::Status;
    fn image_exit(jump: *const JumpBuffer, status: efi::Status) -> !;
}

pub struct Image {
    handle: efi::Handle,
    base: u64,
    pages: u64,
    entry: u64,
    subsystem: u16,
    loaded: Box<loaded_image::Protocol>,
    /// The file part of the path the image came from, and the whole path.
    file_path: Vec<u8>,
    full_path: Vec<u8>,
    jump: JumpBuffer,
    running: bool,
    exit_data: (usize, *mut u16),
}

static IMAGES: Global<Vec<Box<Image>>> = Global::new(Vec::new());

fn find(handle: efi::Handle) -> Option<&'static mut Image> {
    IMAGES.get().iter_mut().find(|i| i.handle == handle).map(|b| &mut **b)
}

/// A PE32+ image laid out in memory.
struct Loaded {
    /// The pages allocated, and where in them the image starts.
    alloc: u64,
    base: u64,
    pages: u64,
    size: u64,
    entry: u64,
    subsystem: u16,
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

/// Why an image would not load.
#[derive(Debug, Clone, Copy)]
pub enum PeError {
    NotPe,
    NotAarch64,
    Subsystem,
    Layout,
    Memory,
}

fn layout(file: &[u8]) -> Result<Loaded, PeError> {
    if file.get(0..2) != Some(b"MZ") {
        return Err(PeError::NotPe);
    }
    let pe = u32_at(file, 0x3c).ok_or(PeError::NotPe)? as usize;
    if file.get(pe..pe + 4) != Some(b"PE\0\0") {
        return Err(PeError::NotPe);
    }
    if u16_at(file, pe + 4) != Some(0xaa64) {
        return Err(PeError::NotAarch64);
    }
    let sections = u16_at(file, pe + 6).ok_or(PeError::Layout)? as usize;
    let opt_size = u16_at(file, pe + 20).ok_or(PeError::Layout)? as usize;
    let opt = pe + 24;
    if u16_at(file, opt) != Some(0x20b) {
        return Err(PeError::NotPe);
    }
    let entry_rva = u32_at(file, opt + 16).ok_or(PeError::Layout)? as u64;
    let image_base = u64_at(file, opt + 24).ok_or(PeError::Layout)?;
    let align = (u32_at(file, opt + 32).ok_or(PeError::Layout)? as u64).max(PAGE);
    let size = u32_at(file, opt + 56).ok_or(PeError::Layout)? as u64;
    let headers = u32_at(file, opt + 60).ok_or(PeError::Layout)? as usize;
    let subsystem = u16_at(file, opt + 68).ok_or(PeError::Layout)?;
    let dirs = u32_at(file, opt + 108).ok_or(PeError::Layout)? as usize;
    if !matches!(subsystem, SUBSYSTEM_APPLICATION | SUBSYSTEM_BOOT_DRIVER | SUBSYSTEM_RUNTIME_DRIVER) {
        return Err(PeError::Subsystem);
    }
    if !align.is_power_of_two() || size == 0 || headers > file.len() || headers as u64 > size || entry_rva >= size {
        return Err(PeError::Layout);
    }
    // The optional header's fields and the data directories read below, and the
    // section table, lie inside the headers, which the signature's hash covers.
    let table_end = (opt + opt_size).saturating_add(40 * sections);
    if opt_size < 112 || opt + 112 + 8 * dirs > opt + opt_size || table_end > headers {
        return Err(PeError::Layout);
    }
    let ty = code_type(subsystem);
    let pages = (size + align - PAGE).div_ceil(PAGE);
    let at = mem::map().allocate(efi::ALLOCATE_ANY_PAGES, ty, pages, 0, PAGE).map_err(|_| PeError::Memory)?;
    let base = at.next_multiple_of(align);
    let image = unsafe { core::slice::from_raw_parts_mut(base as *mut u8, size as usize) };
    image.fill(0);
    image[..headers].copy_from_slice(&file[..headers]);

    let fail = |e| {
        let _ = mem::map().free(at, pages);
        Err(e)
    };
    let table = opt + opt_size;
    for i in 0..sections {
        let s = table + 40 * i;
        let (Some(vsize), Some(va), Some(raw_size), Some(raw)) =
            (u32_at(file, s + 8), u32_at(file, s + 12), u32_at(file, s + 16), u32_at(file, s + 20))
        else {
            return fail(PeError::Layout);
        };
        let (va, raw) = (va as usize, raw as usize);
        let n = (raw_size.min(vsize) as usize).min(file.len().saturating_sub(raw));
        if va + n > size as usize || va + vsize as usize > size as usize {
            return fail(PeError::Layout);
        }
        let Some(data) = file.get(raw..raw + n) else { return fail(PeError::Layout) };
        image[va..va + n].copy_from_slice(data);
    }

    // Base relocations: data directory 5.
    let delta = base.wrapping_sub(image_base);
    if dirs > 5 && delta != 0 {
        let (Some(rva), Some(len)) = (u32_at(file, opt + 112 + 40), u32_at(file, opt + 112 + 44)) else {
            return fail(PeError::Layout);
        };
        let (mut at, end) = (rva as usize, rva as usize + len as usize);
        if end > size as usize {
            return fail(PeError::Layout);
        }
        while at + 8 <= end {
            let (Some(page), Some(block)) = (u32_at(image, at), u32_at(image, at + 4)) else { return fail(PeError::Layout) };
            let (page, block) = (page as usize, block as usize);
            if block < 8 || at + block > end {
                break;
            }
            for e in (at + 8..at + block).step_by(2) {
                let Some(v) = u16_at(image, e) else { return fail(PeError::Layout) };
                let off = page + (v & 0xfff) as usize;
                match v >> 12 {
                    0 => {}
                    10 if off + 8 <= size as usize => {
                        let Some(x) = u64_at(image, off) else { return fail(PeError::Layout) };
                        image[off..off + 8].copy_from_slice(&x.wrapping_add(delta).to_le_bytes());
                    }
                    3 if off + 4 <= size as usize => {
                        let Some(x) = u32_at(image, off) else { return fail(PeError::Layout) };
                        image[off..off + 4].copy_from_slice(&x.wrapping_add(delta as u32).to_le_bytes());
                    }
                    _ => return fail(PeError::Layout),
                }
            }
            at += block;
        }
    }
    crate::util::sync_icache(base, size as usize);
    Ok(Loaded { alloc: at, base, pages, size, entry: base + entry_rva, subsystem })
}

fn code_type(subsystem: u16) -> u32 {
    match subsystem {
        SUBSYSTEM_BOOT_DRIVER => efi::BOOT_SERVICES_CODE,
        SUBSYSTEM_RUNTIME_DRIVER => efi::RUNTIME_SERVICES_CODE,
        _ => efi::LOADER_CODE,
    }
}

fn data_type(subsystem: u16) -> u32 {
    match subsystem {
        SUBSYSTEM_BOOT_DRIVER => efi::BOOT_SERVICES_DATA,
        SUBSYSTEM_RUNTIME_DRIVER => efi::RUNTIME_SERVICES_DATA,
        _ => efi::LOADER_DATA,
    }
}

/// The handle with `EFI_SIMPLE_FILE_SYSTEM_PROTOCOL` whose device path the
/// longest prefix of `path` is, and how much of `path` that covers. A path
/// that starts at a partition's `HD()` node matches that partition wherever
/// it is.
pub fn locate(guid: &efi::Guid, path: *const u8) -> Option<(efi::Handle, usize)> {
    let mut best: Option<(efi::Handle, usize)> = None;
    for h in proto::with(Some(guid)) {
        let Some(dp) = proto::get(h, &device_path::PROTOCOL_GUID) else { continue };
        let have = devpath::bytes(dp as *const u8);
        let matched = devpath::prefix_len(have, path).or_else(|| {
            // A short-form path: just the HD() node, then the file.
            let first = devpath::nodes(path).next()?;
            if first.ty != devpath::MEDIA || first.sub != devpath::MEDIA_HD {
                return None;
            }
            let last = devpath::nodes(have.as_ptr()).last()?;
            (last.ty == first.ty && last.sub == first.sub && last.data == first.data).then_some(first.data.len() + 4)
        });
        if let Some(n) = matched {
            if best.is_none_or(|(_, m)| n > m) {
                best = Some((h, n));
            }
        }
    }
    best
}

/// `LoadImage`: from `source` if given, else from the file `path` names.
pub fn load(parent: efi::Handle, path: *const u8, source: Option<&[u8]>) -> Result<efi::Handle, efi::Status> {
    let path_bytes = devpath::bytes(path).to_vec();
    let (device, file_path, owned);
    match source {
        Some(_) => {
            let found = if path.is_null() { None } else { locate(&simple_file_system::PROTOCOL_GUID, path) };
            device = found.map_or(core::ptr::null_mut(), |(h, _)| h);
            file_path = match found {
                Some((_, n)) => path_bytes[n..].to_vec(),
                None => path_bytes.clone(),
            };
            owned = None;
        }
        None => {
            if path.is_null() {
                return Err(efi::Status::INVALID_PARAMETER);
            }
            let (h, n) = locate(&simple_file_system::PROTOCOL_GUID, path).ok_or(efi::Status::NOT_FOUND)?;
            let rest = &path_bytes[n..];
            let name = devpath::file_name(rest.as_ptr());
            if name.is_empty() {
                return Err(efi::Status::NOT_FOUND);
            }
            owned = Some(crate::fat::read_file(h, &name, MAX_LOADED)?);
            device = h;
            file_path = rest.to_vec();
        }
    }
    let file: &[u8] = match (&owned, source) {
        (Some(v), _) => v,
        (None, Some(s)) => s,
        (None, None) => unreachable!(),
    };

    match crate::secure::check(file, &Text(&path_bytes)) {
        Ok((hash, authority)) => crate::tcg2::measure_image(&hash, &authority, &path_bytes, file.len()),
        Err(why) => {
            warn!("secboot", "image refused"; reason = why, path = Text(&path_bytes));
            return Err(efi::Status::SECURITY_VIOLATION);
        }
    }

    let l = layout(file).map_err(|e| {
        warn!("image", "not an image this firmware can run"; reason = crate::log::dbg(&e), path = Text(&path_bytes));
        match e {
            PeError::Memory => efi::Status::OUT_OF_RESOURCES,
            _ => efi::Status::LOAD_ERROR,
        }
    })?;
    let mut img = Box::new(Image {
        handle: core::ptr::null_mut(),
        base: l.alloc,
        pages: l.pages,
        entry: l.entry,
        subsystem: l.subsystem,
        loaded: Box::new(loaded_image::Protocol {
            revision: loaded_image::REVISION,
            parent_handle: parent,
            system_table: crate::tables::system_table(),
            device_handle: device,
            file_path: core::ptr::null_mut(),
            reserved: core::ptr::null_mut(),
            load_options_size: 0,
            load_options: core::ptr::null_mut(),
            image_base: l.base as *mut c_void,
            image_size: l.size,
            image_code_type: code_type(l.subsystem),
            image_data_type: data_type(l.subsystem),
            unload: None,
        }),
        file_path: if file_path.is_empty() { Vec::new() } else { file_path },
        full_path: path_bytes,
        jump: [0; 19],
        running: false,
        exit_data: (0, core::ptr::null_mut()),
    });
    if !img.file_path.is_empty() {
        img.loaded.file_path = img.file_path.as_mut_ptr() as *mut device_path::Protocol;
    }
    let mut h = proto::install(core::ptr::null_mut(), &loaded_image::PROTOCOL_GUID, &mut *img.loaded as *mut _ as *mut c_void)?;
    if !img.full_path.is_empty() {
        h = proto::install(h, &loaded_image_device_path::PROTOCOL_GUID, img.full_path.as_mut_ptr() as *mut c_void)?;
    }
    img.handle = h;
    debug!("image", "image loaded"; base = crate::util::Hex(img.loaded.image_base as u64), bytes = l.size,
        path = Text(&img.full_path));
    IMAGES.get().push(img);
    Ok(h)
}

pub fn start(handle: efi::Handle, exit_size: *mut usize, exit_data: *mut *mut u16) -> efi::Status {
    let Some(img) = find(handle) else { return efi::Status::INVALID_PARAMETER };
    if img.running {
        return efi::Status::INVALID_PARAMETER;
    }
    img.running = true;
    let entry = img.entry;
    let jump: *mut JumpBuffer = &mut img.jump;
    info!("image", "starting image"; path = Text(&img.full_path));
    let status = unsafe { image_call(entry, handle, crate::tables::system_table(), jump) };
    let Some(img) = find(handle) else { return status };
    img.running = false;
    if !exit_size.is_null() {
        unsafe { *exit_size = img.exit_data.0 };
    }
    if !exit_data.is_null() {
        unsafe { *exit_data = img.exit_data.1 };
    }
    if status.is_error() {
        warn!("image", "image returned an error"; status = crate::util::Hex(status.as_usize()), path = Text(&img.full_path));
    } else {
        debug!("image", "image returned"; path = Text(&img.full_path));
    }
    if img.subsystem == SUBSYSTEM_APPLICATION || status.is_error() {
        unload(handle);
    }
    status
}

pub fn exit(handle: efi::Handle, status: efi::Status, size: usize, data: *mut u16) -> efi::Status {
    let Some(img) = find(handle) else { return efi::Status::INVALID_PARAMETER };
    if !img.running {
        return unload(handle);
    }
    img.exit_data = (size, data);
    let jump: *const JumpBuffer = &img.jump;
    unsafe { image_exit(jump, status) }
}

pub fn unload(handle: efi::Handle) -> efi::Status {
    let images = IMAGES.get();
    let Some(i) = images.iter().position(|img| img.handle == handle) else { return efi::Status::INVALID_PARAMETER };
    if images[i].running {
        return efi::Status::UNSUPPORTED;
    }
    let mut img = images.remove(i);
    proto::uninstall(handle, &loaded_image::PROTOCOL_GUID, &mut *img.loaded as *mut _ as *mut c_void);
    if !img.full_path.is_empty() {
        proto::uninstall(handle, &loaded_image_device_path::PROTOCOL_GUID, img.full_path.as_mut_ptr() as *mut c_void);
    }
    let _ = mem::map().free(img.base, img.pages);
    efi::Status::SUCCESS
}

/// Where an address is, for a crash report: in this firmware, or in which
/// image and how far in.
pub struct Where(u64);

pub fn describe(addr: u64) -> Where {
    Where(addr)
}

impl fmt::Display for Where {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unsafe extern "C" {
            static _image_start: u8;
            static _end: u8;
        }
        let (start, end) = (&raw const _image_start as u64, &raw const _end as u64);
        if (start..end).contains(&self.0) {
            return write!(f, "firmware+{:#x}", self.0 - start);
        }
        for img in IMAGES.get().iter() {
            let base = img.loaded.image_base as u64;
            if (base..base + img.loaded.image_size).contains(&self.0) {
                return write!(f, "{}+{:#x}", Text(&img.full_path), self.0 - base);
            }
        }
        f.write_str("unknown")
    }
}

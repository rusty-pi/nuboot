//! Memory: the UEFI memory map, pages out of it, and pools out of pages.
//!
//! The map starts as the RAM the device tree describes, less what the tree
//! reserves, and every allocation is a range of it changing type. Pools are
//! first-fit free lists, one per memory type, each growing by whole pages of
//! its type; the firmware's own heap is the boot services data pool.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::null_mut;

use r_efi::efi;

use crate::util::Global;

pub const PAGE: u64 = 4096;
const MAX_DESCRIPTORS: usize = 512;

/// The size of a descriptor as `GetMemoryMap` hands them out: `EFI_MEMORY_DESCRIPTOR`
/// padded to 48 bytes, as most firmware does.
pub const DESCRIPTOR_SIZE: usize = 48;

#[derive(Clone, Copy)]
struct Desc {
    start: u64,
    pages: u64,
    ty: u32,
}

impl Desc {
    fn end(&self) -> u64 {
        self.start + self.pages * PAGE
    }
}

pub struct Map {
    d: [Desc; MAX_DESCRIPTORS],
    n: usize,
    /// Changes with every change to the map: `ExitBootServices` wants the key
    /// of the map the caller last saw.
    pub key: usize,
}

static MAP: Global<Map> =
    Global::new(Map { d: [Desc { start: 0, pages: 0, ty: 0 }; MAX_DESCRIPTORS], n: 0, key: 1 });

pub fn map() -> &'static mut Map {
    MAP.get()
}

fn is_free(ty: u32) -> bool {
    ty == efi::CONVENTIONAL_MEMORY
}

impl Map {
    /// Give `[start, end)` type `ty`, whatever it was. Only RAM the map
    /// already holds changes; with `add`, the range is added where the map has
    /// nothing.
    fn set(&mut self, start: u64, end: u64, ty: u32, add: bool) {
        let mut out = [Desc { start: 0, pages: 0, ty: 0 }; MAX_DESCRIPTORS];
        let mut m = 0;
        let push = |d: Desc, out: &mut [Desc; MAX_DESCRIPTORS], m: &mut usize| {
            if d.pages == 0 {
                return;
            }
            if *m > 0 && out[*m - 1].ty == d.ty && out[*m - 1].end() == d.start {
                out[*m - 1].pages += d.pages;
            } else if *m < MAX_DESCRIPTORS {
                out[*m] = d;
                *m += 1;
            }
        };
        let mut cursor = start;
        for i in 0..self.n {
            let d = self.d[i];
            if d.end() <= start || d.start >= end {
                if add && d.start >= end && cursor < end {
                    push(Desc { start: cursor, pages: (end - cursor) / PAGE, ty }, &mut out, &mut m);
                    cursor = end;
                }
                push(d, &mut out, &mut m);
                continue;
            }
            if add && cursor < d.start {
                push(Desc { start: cursor, pages: (d.start - cursor) / PAGE, ty }, &mut out, &mut m);
            }
            if d.start < start {
                push(Desc { start: d.start, pages: (start - d.start) / PAGE, ty: d.ty }, &mut out, &mut m);
            }
            let s = d.start.max(start);
            let e = d.end().min(end);
            push(Desc { start: s, pages: (e - s) / PAGE, ty }, &mut out, &mut m);
            cursor = e;
            if d.end() > end {
                push(Desc { start: end, pages: (d.end() - end) / PAGE, ty: d.ty }, &mut out, &mut m);
            }
        }
        if add && cursor < end {
            push(Desc { start: cursor, pages: (end - cursor) / PAGE, ty }, &mut out, &mut m);
        }
        self.d = out;
        self.n = m;
        self.key += 1;
    }

    /// Add RAM to the map, free.
    pub fn add_ram(&mut self, start: u64, end: u64) {
        let start = start.next_multiple_of(PAGE);
        let end = end & !(PAGE - 1);
        if end > start {
            self.set(start, end, efi::CONVENTIONAL_MEMORY, true);
        }
    }

    /// Add device registers the OS's runtime services need to the map.
    pub fn add_mmio(&mut self, start: u64, end: u64) {
        self.set(start & !(PAGE - 1), end.next_multiple_of(PAGE), efi::MEMORY_MAPPED_IO, true);
    }

    /// Mark RAM in `[start, end)` as `ty`, rounding out to pages.
    pub fn mark(&mut self, start: u64, end: u64, ty: u32) {
        let start = start & !(PAGE - 1);
        let end = end.next_multiple_of(PAGE);
        if end > start {
            self.set(start, end, ty, false);
        }
    }

    /// Whether all of `[start, end)` is in the map and of type `ty`.
    fn all(&self, start: u64, end: u64, ty: impl Fn(u32) -> bool) -> bool {
        let mut at = start;
        for d in &self.d[..self.n] {
            if d.end() <= at || d.start > at {
                continue;
            }
            if !ty(d.ty) {
                return false;
            }
            at = d.end();
            if at >= end {
                return true;
            }
        }
        at >= end
    }

    /// The highest free run of `pages` pages aligned to `align` that ends at
    /// or below `max` (inclusive).
    fn find(&self, pages: u64, max: u64, align: u64) -> Option<u64> {
        let size = pages * PAGE;
        self.d[..self.n]
            .iter()
            .rev()
            .filter(|d| is_free(d.ty))
            .find_map(|d| {
                let end = d.end().min(max.saturating_add(1));
                let start = end.checked_sub(size)? & !(align - 1);
                (start >= d.start).then_some(start)
            })
    }

    pub fn allocate(&mut self, kind: efi::AllocateType, ty: u32, pages: u64, addr: u64, align: u64) -> Result<u64, efi::Status> {
        if pages == 0 {
            return Err(efi::Status::INVALID_PARAMETER);
        }
        let len = pages.checked_mul(PAGE).ok_or(efi::Status::INVALID_PARAMETER)?;
        let start = match kind {
            efi::ALLOCATE_ADDRESS => {
                if addr % PAGE != 0 {
                    return Err(efi::Status::INVALID_PARAMETER);
                }
                let end = addr.checked_add(len).ok_or(efi::Status::INVALID_PARAMETER)?;
                if !self.all(addr, end, is_free) {
                    return Err(efi::Status::NOT_FOUND);
                }
                addr
            }
            efi::ALLOCATE_MAX_ADDRESS => self.find(pages, addr, align).ok_or(efi::Status::OUT_OF_RESOURCES)?,
            efi::ALLOCATE_ANY_PAGES => self
                .find(pages, LOW_PREFERRED, align)
                .or_else(|| self.find(pages, u64::MAX, align))
                .ok_or(efi::Status::OUT_OF_RESOURCES)?,
            _ => return Err(efi::Status::INVALID_PARAMETER),
        };
        self.set(start, start + len, ty, false);
        Ok(start)
    }

    pub fn free(&mut self, addr: u64, pages: u64) -> Result<(), efi::Status> {
        if addr % PAGE != 0 {
            return Err(efi::Status::INVALID_PARAMETER);
        }
        let end = pages.checked_mul(PAGE).and_then(|len| addr.checked_add(len)).ok_or(efi::Status::INVALID_PARAMETER)?;
        if !self.all(addr, end, |t| !is_free(t) && t != efi::RESERVED_MEMORY_TYPE) {
            return Err(efi::Status::NOT_FOUND);
        }
        self.set(addr, end, efi::CONVENTIONAL_MEMORY, false);
        Ok(())
    }

    /// The map as `GetMemoryMap` returns it.
    pub fn write(&self, out: *mut u8) {
        for (i, d) in self.d[..self.n].iter().enumerate() {
            let runtime = matches!(d.ty, efi::RUNTIME_SERVICES_CODE | efi::RUNTIME_SERVICES_DATA);
            let attribute = if d.ty == efi::MEMORY_MAPPED_IO {
                efi::MEMORY_UC | efi::MEMORY_RUNTIME
            } else {
                efi::MEMORY_UC
                    | efi::MEMORY_WC
                    | efi::MEMORY_WT
                    | efi::MEMORY_WB
                    | if runtime { efi::MEMORY_RUNTIME } else { 0 }
            };
            let desc = efi::MemoryDescriptor {
                r#type: d.ty,
                physical_start: d.start,
                virtual_start: 0,
                number_of_pages: d.pages,
                attribute,
            };
            unsafe {
                let at = out.add(i * DESCRIPTOR_SIZE);
                core::ptr::write_bytes(at, 0, DESCRIPTOR_SIZE);
                core::ptr::write_unaligned(at as *mut efi::MemoryDescriptor, desc);
            }
        }
    }

    pub fn len(&self) -> usize {
        self.n
    }

    pub fn total_free_mib(&self) -> u64 {
        self.d[..self.n].iter().filter(|d| is_free(d.ty)).map(|d| d.pages).sum::<u64>() * PAGE >> 20
    }

    pub fn total_mib(&self) -> u64 {
        self.d[..self.n].iter().map(|d| d.pages).sum::<u64>() * PAGE >> 20
    }
}

/// `AllocateAnyPages` takes the highest free run below 4 GiB first, where
/// every DMA engine on the board can reach and 32-bit pointers still work.
const LOW_PREFERRED: u64 = 0xFFFF_FFFF;

/// Pages of type `ty` anywhere below 4 GiB.
pub fn alloc_pages(ty: u32, pages: u64) -> Option<u64> {
    map().allocate(efi::ALLOCATE_ANY_PAGES, ty, pages, 0, PAGE).ok()
}

// --- pools ---

#[repr(C)]
struct FreeBlock {
    size: u64,
    next: *mut FreeBlock,
}

const GRAIN: u64 = 16;
/// The least a pool grows by.
const CHUNK: u64 = 256 * 1024;

pub struct Heap {
    ty: u32,
    free: *mut FreeBlock,
}

impl Heap {
    const fn new(ty: u32) -> Self {
        Heap { ty, free: null_mut() }
    }

    fn insert(&mut self, addr: u64, size: u64) {
        let block = addr as *mut FreeBlock;
        let mut prev: *mut FreeBlock = null_mut();
        let mut cur = self.free;
        unsafe {
            while !cur.is_null() && (cur as u64) < addr {
                prev = cur;
                cur = (*cur).next;
            }
            (*block).size = size;
            (*block).next = cur;
            if !cur.is_null() && addr + size == cur as u64 {
                (*block).size += (*cur).size;
                (*block).next = (*cur).next;
            }
            if prev.is_null() {
                self.free = block;
            } else if prev as u64 + (*prev).size == addr {
                (*prev).size += (*block).size;
                (*prev).next = (*block).next;
            } else {
                (*prev).next = block;
            }
        }
    }

    fn take(&mut self, size: u64, align: u64) -> *mut u8 {
        let mut prev: *mut FreeBlock = null_mut();
        let mut cur = self.free;
        unsafe {
            while !cur.is_null() {
                let start = cur as u64;
                let end = start + (*cur).size;
                let at = start.next_multiple_of(align);
                if at + size <= end {
                    let next = (*cur).next;
                    if prev.is_null() {
                        self.free = next;
                    } else {
                        (*prev).next = next;
                    }
                    if at > start {
                        self.insert(start, at - start);
                    }
                    if at + size < end {
                        self.insert(at + size, end - at - size);
                    }
                    return at as *mut u8;
                }
                prev = cur;
                cur = (*cur).next;
            }
        }
        null_mut()
    }

    pub fn alloc(&mut self, size: u64, align: u64) -> *mut u8 {
        if size > MAX_ALLOCATION {
            return null_mut();
        }
        let size = size.max(1).next_multiple_of(GRAIN);
        let align = align.max(GRAIN);
        let p = self.take(size, align);
        if !p.is_null() {
            return p;
        }
        let grow = (size + align).max(CHUNK).next_multiple_of(PAGE);
        match alloc_pages(self.ty, grow / PAGE) {
            Some(at) => {
                self.insert(at, grow);
                self.take(size, align)
            }
            None => null_mut(),
        }
    }

    pub fn free(&mut self, p: *mut u8, size: u64) {
        self.insert(p as u64, size.max(1).next_multiple_of(GRAIN));
    }
}

/// The pools, by memory type: loader code and data, boot services code and
/// data, runtime services code and data, and what the Linux EFI stub keeps for
/// the kernel (the TPM event log, the RNG seed, the memory map): ACPI reclaim
/// and ACPI NVS.
static HEAPS: Global<[Heap; 8]> = Global::new([
    Heap::new(efi::LOADER_CODE),
    Heap::new(efi::LOADER_DATA),
    Heap::new(efi::BOOT_SERVICES_CODE),
    Heap::new(efi::BOOT_SERVICES_DATA),
    Heap::new(efi::RUNTIME_SERVICES_CODE),
    Heap::new(efi::RUNTIME_SERVICES_DATA),
    Heap::new(efi::ACPI_RECLAIM_MEMORY),
    Heap::new(efi::ACPI_MEMORY_NVS),
]);

fn heap(ty: u32) -> Option<&'static mut Heap> {
    HEAPS.get().iter_mut().find(|h| h.ty == ty)
}

/// What sits before every pool allocation.
#[repr(C)]
struct PoolHeader {
    size: u64,
    ty: u32,
    magic: u32,
}

const POOL_MAGIC: u32 = 0x6c6f_6f70;

/// More than any memory this firmware runs on has: a request for more is
/// refused before its size is added to anything.
const MAX_ALLOCATION: u64 = 1 << 40;

pub fn pool_alloc(ty: u32, size: usize) -> Result<*mut u8, efi::Status> {
    let heap = heap(ty).ok_or(efi::Status::INVALID_PARAMETER)?;
    let total = (size as u64).checked_add(16).filter(|&n| n <= MAX_ALLOCATION).ok_or(efi::Status::OUT_OF_RESOURCES)?;
    let p = heap.alloc(total, 16);
    if p.is_null() {
        return Err(efi::Status::OUT_OF_RESOURCES);
    }
    unsafe {
        (p as *mut PoolHeader).write(PoolHeader { size: total, ty, magic: POOL_MAGIC });
        Ok(p.add(16))
    }
}

pub fn pool_free(p: *mut u8) -> efi::Status {
    if p.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    unsafe {
        let h = p.sub(16) as *mut PoolHeader;
        if (*h).magic != POOL_MAGIC {
            return efi::Status::INVALID_PARAMETER;
        }
        (*h).magic = 0;
        match heap((*h).ty) {
            Some(heap) => heap.free(h as *mut u8, (*h).size),
            None => return efi::Status::INVALID_PARAMETER,
        }
    }
    efi::Status::SUCCESS
}

/// The firmware's own heap: boot services data.
pub struct FirmwareHeap;

unsafe impl GlobalAlloc for FirmwareHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        heap(efi::BOOT_SERVICES_DATA).unwrap().alloc(layout.size() as u64, layout.align() as u64)
    }

    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        heap(efi::BOOT_SERVICES_DATA).unwrap().free(p, layout.size() as u64)
    }
}

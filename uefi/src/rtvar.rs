//! The variable services after `ExitBootServices`. The OS calls them through
//! its own mapping of the regions typed as runtime services, which it places
//! where they are (`EFI_RT_PROPERTIES_TABLE` does not offer
//! `SetVirtualAddressMap`), so they run from the image's own code and touch
//! nothing but the table below: no allocation, no logging, no registers of
//! the board. The variables that are readable at runtime are copied into it
//! at `ExitBootServices`; a write the OS makes lasts until reset.

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
pub fn add(name: &[u16], guid: &efi::Guid, attributes: u32, data: &[u8], writable: bool) -> bool {
    push(name, guid, attributes, if writable { WRITABLE } else { 0 }, &[(data.as_ptr(), data.len())])
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
    let append = attributes & APPEND != 0;
    let attributes = attributes & !APPEND;
    let delete = attributes == 0 || (size == 0 && !append);
    let existing = find(name, &guid);
    if let Some(e) = &existing {
        if e.flags & WRITABLE == 0 {
            return efi::Status::WRITE_PROTECTED;
        }
    }
    if delete {
        let Some(e) = existing else { return efi::Status::NOT_FOUND };
        put(e.at + 14, &(e.flags | DELETED).to_le_bytes());
        return efi::Status::SUCCESS;
    }
    if attributes & AUTH != 0 {
        return efi::Status::WRITE_PROTECTED;
    }
    if attributes & BS == 0 || attributes & RT == 0 || size > MAX_VARIABLE {
        return efi::Status::INVALID_PARAMETER;
    }
    if let Some(e) = &existing {
        if !append && e.attributes != attributes {
            return efi::Status::INVALID_PARAMETER;
        }
    }
    let kept = if append { existing.as_ref().map_or(0, |e| e.data_len) } else { 0 };
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
    efi::Status::SUCCESS
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

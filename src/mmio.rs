//! Peripheral register access.

use core::ptr::{read_volatile, write_volatile};

/// Clock-manager and power-manager registers ignore a write without this in
/// the top byte.
pub const PASSWD: u32 = 0x5a00_0000;

#[inline(always)]
pub fn read(addr: u32) -> u32 {
    unsafe { read_volatile(addr as usize as *const u32) }
}

#[inline(always)]
pub fn write(addr: u32, value: u32) {
    unsafe { write_volatile(addr as usize as *mut u32, value) }
}

#[inline(always)]
pub fn read8(addr: u32) -> u8 {
    unsafe { read_volatile(addr as usize as *const u8) }
}

#[inline(always)]
pub fn write8(addr: u32, value: u8) {
    unsafe { write_volatile(addr as usize as *mut u8, value) }
}

#[inline(always)]
pub fn read16(addr: u32) -> u16 {
    unsafe { read_volatile(addr as usize as *const u16) }
}

#[inline(always)]
pub fn write16(addr: u32, value: u16) {
    unsafe { write_volatile(addr as usize as *mut u16, value) }
}

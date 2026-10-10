//! Memory devices read and write by DMA: the 2 MiB `entry.rs` maps
//! non-cacheable, so neither side needs cache maintenance. Allocations last
//! for the whole boot; the controllers that use them stop at
//! `ExitBootServices`.

use crate::DMA_ARENA;
use crate::util::Global;

static NEXT: Global<u64> = Global::new(DMA_ARENA.0);

/// `size` zeroed bytes aligned to `align`, or None when the arena is used up.
pub fn alloc(size: usize, align: usize) -> Option<u64> {
    let next = NEXT.get();
    let at = next.next_multiple_of(align as u64);
    if at + size as u64 > DMA_ARENA.1 {
        return None;
    }
    *next = at + size as u64;
    unsafe { core::ptr::write_bytes(at as *mut u8, 0, size) };
    Some(at)
}

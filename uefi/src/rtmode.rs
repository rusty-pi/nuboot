//! What the runtime services need to use a driver written for boot services,
//! at `ResetSystem` in an OS's context: a heap of their own in place of the
//! boot services' pool, which the OS has taken back, the DMA arena handed out
//! again, no log, and a stack of their own.
//!
//! Nothing a driver allocated at boot is read again: the controller and its
//! drives are brought up from scratch, and what the boot left in the statics
//! is dropped without being freed.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::alloc::Layout;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::block::Disk;
use crate::util::Global;

static ACTIVE: AtomicBool = AtomicBool::new(false);

/// Whether the runtime services are using a driver.
pub fn active() -> bool {
    ACTIVE.load(Ordering::Relaxed)
}

const HEAP_BYTES: usize = 512 * 1024;
const STACK_BYTES: usize = 64 * 1024;

#[repr(C, align(4096))]
struct Heap([u8; HEAP_BYTES]);

#[repr(C, align(16))]
struct Stack([u8; STACK_BYTES]);

static HEAP: Global<Heap> = Global::new(Heap([0; HEAP_BYTES]));
static STACK: Global<Stack> = Global::new(Stack([0; STACK_BYTES]));
static USED: Global<usize> = Global::new(0);

/// A drive a driver found while the runtime services use it.
pub struct Offered {
    pub disk: Box<dyn Disk>,
    pub name: &'static str,
}

static OFFERED: Global<Vec<Offered>> = Global::new(Vec::new());

/// Start using the drivers: the heap and the DMA arena empty, nothing logged.
pub fn enter() {
    *USED.get() = 0;
    core::mem::forget(core::mem::take(OFFERED.get()));
    crate::dma::reset();
    crate::log::mute(true);
    ACTIVE.store(true, Ordering::Relaxed);
}

pub fn leave() {
    ACTIVE.store(false, Ordering::Relaxed);
    crate::log::mute(false);
}

/// Memory for the global allocator while the runtime services use a driver:
/// bumped, and never freed. Null when the heap is used up.
pub fn alloc(layout: Layout) -> *mut u8 {
    let used = USED.get();
    let base = HEAP.get().0.as_mut_ptr() as usize;
    let at = (base + *used).next_multiple_of(layout.align());
    let end = at + layout.size();
    if end > base + HEAP_BYTES {
        return core::ptr::null_mut();
    }
    *used = end - base;
    at as *mut u8
}

/// `block::add_disk` while the runtime services use a driver: keep the drive
/// for them instead of publishing it.
pub fn offer(disk: Box<dyn Disk>, name: &'static str) {
    OFFERED.get().push(Offered { disk, name });
}

pub fn offered() -> &'static mut Vec<Offered> {
    OFFERED.get()
}

/// Run `f` on a stack of the firmware's own: the OS gives its runtime services
/// a small one.
pub fn on_stack(f: extern "C" fn()) {
    let top = (STACK.get().0.as_mut_ptr() as usize + STACK_BYTES) & !15;
    unsafe {
        core::arch::asm!(
            "mov x20, sp",
            "mov sp, {top}",
            "blr {f}",
            "mov sp, x20",
            top = in(reg) top,
            f = in(reg) f,
            out("x20") _,
            clobber_abi("C"),
        );
    }
}

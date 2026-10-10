//! Critical sections: stretches of code no interrupt may land in, and so, once
//! a tick switches threads, no other thread either.
//!
//! A section is a [`Section`] guard: [`enter`] masks interrupts and dropping
//! the guard closes it, on every path out of the scope that holds it. Sections
//! nest by count, so only the outermost one's close puts back what its open
//! found, and an inner one never enables interrupts under an outer one.
//!
//! SR bit 30 is the interrupt enable. The core clears it on the way into a
//! handler and `rti` restores it, so a handler runs as a section of its own
//! and may open and close more inside it. `sleep` takes its interrupt whatever
//! the bit says, so a sleep inside a section still wakes; see
//! [`crate::idle::sleep_us`].

use core::marker::PhantomData;
use core::sync::atomic::{AtomicU32, Ordering};

const SR_IE: u32 = 1 << 30;
const DEPTH: u32 = 0xffff;

/// How deep the running code is in sections, and whether the outermost one
/// found interrupts enabled: the depth in the low half, [`SR_IE`] where the
/// status register keeps it. Zero outside every section.
static NESTING: AtomicU32 = AtomicU32::new(0);

/// An open section: interrupts stay masked until it and every section around
/// it are dropped. Tied to the thread that opened it.
pub struct Section {
    _thread: PhantomData<*mut ()>,
}

/// What [`nesting`] reads and [`restore`] puts back: the part of a thread's
/// state a switch has to carry, since it is not in any register.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct Nesting(u32);

#[inline(always)]
fn interrupts_enabled() -> bool {
    let sr: u32;
    unsafe { core::arch::asm!("mov.m {}, sr", out(reg) sr, options(nostack)) };
    sr & SR_IE != 0
}

/// Open a section.
pub fn enter() -> Section {
    let enabled = interrupts_enabled();
    unsafe { core::arch::asm!("di", options(nostack)) };
    let nesting = NESTING.load(Ordering::Relaxed);
    let opened = if nesting == 0 { 1 | if enabled { SR_IE } else { 0 } } else { nesting + 1 };
    NESTING.store(opened, Ordering::Relaxed);
    Section { _thread: PhantomData }
}

impl Drop for Section {
    fn drop(&mut self) {
        let nesting = NESTING.load(Ordering::Relaxed);
        if nesting & DEPTH != 1 {
            NESTING.store(nesting - 1, Ordering::Relaxed);
            return;
        }
        NESTING.store(0, Ordering::Relaxed);
        if nesting & SR_IE != 0 {
            unsafe { core::arch::asm!("ei", options(nostack)) };
        }
    }
}

impl Section {
    /// The guard for a section the caller is already in without having opened
    /// it: a thread's first run, which starts inside the one its spawner's
    /// switch opened.
    ///
    /// # Safety
    ///
    /// The running code must be inside a section no other guard closes.
    pub unsafe fn adopt() -> Section {
        Section { _thread: PhantomData }
    }
}

/// Enable interrupts outside every section: at once when none is open,
/// otherwise when the outermost one closes.
pub fn enable() {
    let nesting = NESTING.load(Ordering::Relaxed);
    if nesting == 0 {
        unsafe { core::arch::asm!("ei", options(nostack)) };
    } else {
        NESTING.store(nesting | SR_IE, Ordering::Relaxed);
    }
}

/// Disable interrupts outside every section, and keep them disabled when the
/// outermost open one closes.
pub fn disable() {
    unsafe { core::arch::asm!("di", options(nostack)) };
    let nesting = NESTING.load(Ordering::Relaxed);
    NESTING.store(nesting & !SR_IE, Ordering::Relaxed);
}

/// The running thread's nesting, for a switch to carry.
pub fn nesting() -> Nesting {
    Nesting(NESTING.load(Ordering::Relaxed))
}

/// Take up the nesting [`nesting`] read from the thread a switch is about to
/// resume.
///
/// # Safety
///
/// Interrupts must be masked, and stay masked until that thread runs: what
/// the running code opens or closes in between is counted as that thread's.
pub unsafe fn restore(nesting: Nesting) {
    NESTING.store(nesting.0, Ordering::Relaxed);
}

impl Nesting {
    /// Outside every section.
    pub const OUTSIDE: Nesting = Nesting(0);

    /// How many sections are open.
    pub fn depth(self) -> u32 {
        self.0 & DEPTH
    }
}

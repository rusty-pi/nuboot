//! Thread stacks: a pattern to measure how deep each one has gone, a guard
//! word to notice when one has gone too deep, and a stop that says so over the
//! UART instead of carrying on over whatever lies below.
//!
//! A stack is painted with [`FILL`] before anything runs on it, and its lowest
//! word holds [`GUARD`]. How much of it was ever used is then the distance
//! from the top to the lowest word that no longer reads [`FILL`], interrupt
//! frames included: an interrupt lands on whichever stack is current.

use core::ptr;

pub const FILL: u32 = 0xefef_efef;
pub const GUARD: u32 = 0x5555_aaaa;

/// A stack's bounds: the guard word at `bottom`, the first word past it at
/// `top`.
#[derive(Clone, Copy)]
pub struct Stack {
    bottom: u32,
    top: u32,
}

impl Stack {
    pub const NONE: Stack = Stack { bottom: 0, top: 0 };

    /// Paint all of `words` and take it as a stack.
    pub fn paint(words: &mut [u32]) -> Stack {
        words.fill(FILL);
        words[0] = GUARD;
        let bottom = words.as_mut_ptr();
        Stack { bottom: bottom as u32, top: bottom.wrapping_add(words.len()) as u32 }
    }

    /// Take the stack the caller is running on, painting what lies below its
    /// own frame.
    ///
    /// # Safety
    ///
    /// `bottom..top` must be the running stack, and nothing below the stack
    /// pointer may be live.
    #[inline(never)]
    pub unsafe fn paint_running(bottom: *mut u32, top: *const u32) -> Stack {
        let limit = (current_sp() as *mut u32).wrapping_sub(16);
        let mut at = bottom.wrapping_add(1);
        while at < limit {
            unsafe { at.write_volatile(FILL) };
            at = at.wrapping_add(1);
        }
        unsafe { bottom.write_volatile(GUARD) };
        Stack { bottom: bottom as u32, top: top as u32 }
    }

    #[inline(always)]
    pub fn intact(&self) -> bool {
        unsafe { ptr::read_volatile(self.bottom as *const u32) == GUARD }
    }

    /// Whether a stack pointer at `sp` is inside this stack and can still
    /// push `words` without reaching the guard.
    #[inline(always)]
    pub fn has_room(&self, sp: u32, words: u32) -> bool {
        sp <= self.top && sp.wrapping_sub(self.bottom) > 4 * words
    }

    /// Whether `words` pushed at `sp` lie inside this stack, above the guard.
    #[inline(always)]
    pub fn holds(&self, sp: u32, words: u32) -> bool {
        sp > self.bottom && sp <= self.top - 4 * words
    }

    pub fn size(&self) -> u32 {
        self.top - self.bottom
    }

    /// The most of this stack that has ever been used, in bytes.
    pub fn used(&self) -> u32 {
        let mut at = self.bottom + 4;
        while at < self.top && unsafe { ptr::read_volatile(at as *const u32) } == FILL {
            at += 4;
        }
        self.top - at
    }
}

#[inline(always)]
pub fn current_sp() -> u32 {
    let sp: u32;
    unsafe { core::arch::asm!("mov {}, sp", out(reg) sp, options(nomem, nostack)) };
    sp
}

/// What [`fault`] stops for.
#[derive(Clone, Copy)]
#[repr(u32)]
pub enum Fault {
    Overflow,
    StackPointer,
    NotRunnable,
    SectionOpen,
}

impl Fault {
    fn says(self) -> &'static str {
        match self {
            Fault::Overflow => "stack overflow",
            Fault::StackPointer => "stack pointer outside its stack",
            Fault::NotRunnable => "switch to a thread that is not runnable",
            Fault::SectionOpen => "critical section left open",
        }
    }
}

const FAULT_STACK_WORDS: usize = 512;
static mut FAULT_STACK: [u32; FAULT_STACK_WORDS] = [0; FAULT_STACK_WORDS];

core::arch::global_asm!(
    ".pushsection .text.stack_fault, \"ax\"",
    // r0-r2: what stack_fault_report takes. r3: the stack to run it on.
    "stack_fault_on:",
    "    mov sp, r3",
    "    b stack_fault_report",
    ".popsection",
);

unsafe extern "C" {
    fn stack_fault_on(fault: Fault, thread: u32, at: u32, stack: u32) -> !;
}

/// Stop the core for good, saying why over the UART first. Nothing of the
/// faulting thread's stack is trusted from here on: the report runs on a
/// stack of its own, with every interrupt off.
///
/// The caller must have stopped the threads switching, since the console's
/// wait yields.
pub fn fault(fault: Fault, thread: usize, at: u32) -> ! {
    crate::critical::disable();
    crate::idle::disable_all();
    let top = (&raw const FAULT_STACK).cast::<u32>().wrapping_add(FAULT_STACK_WORDS) as u32;
    unsafe { stack_fault_on(fault, thread as u32, at, top) }
}

#[unsafe(no_mangle)]
extern "C" fn stack_fault_report(fault: Fault, thread: u32, at: u32) -> ! {
    crate::log::emergency("sched", format_args!("{} (thread {}, {:#010x})", fault.says(), thread, at));
    crate::console::drain();
    loop {
        unsafe { core::arch::asm!("sleep", options(nostack)) };
    }
}

//! The VPU's caches, as the stock bootloader keeps them in step with memory it
//! has written: a range flush through the bootbox block at `0x7EE00000`, and
//! the stub both of its stages leave through.
//!
//! What sits behind the block is not documented. Two registers take a command
//! bit each for flag bits 0 and 1 of the stock flush routine, a third takes
//! two for flag bits 2 and 3, and `L2_CTRL` takes one for bit 4; each has a
//! first and last address before it. Bit 0 of each is only ever tested (the
//! stub skips a cache whose bit 0 is set), so nothing here sets it. bootmain
//! and start4 both run in the cached alias, so memory another master reads
//! or writes is either reached through the uncached alias (`0xC0000000`),
//! which bypasses the caches, or flushed around the transfer.

use core::ptr::addr_of;

use crate::{mmio, timer};

const CORE_A: u32 = 0x7ee0_2000;
const CORE_B: u32 = 0x7ee0_2080;
const SHARED: u32 = 0x7ee0_2100;
const SHARED_FIRST: u32 = 0x7ee0_2104;
const SHARED_LAST: u32 = 0x7ee0_2108;
const L2_CTRL: u32 = 0x7ee0_1000;
const L2_FIRST: u32 = 0x7ee0_1004;
const L2_LAST: u32 = 0x7ee0_1008;

/// The command bit `CORE_A` and `CORE_B` take, and the two `SHARED` takes.
const CORE_FLUSH: u32 = 1 << 1;
const SHARED_FLUSH: u32 = 0b11 << 1;
/// `L2_CTRL`: the flush command, and the two bits the stock routine clears
/// with it (the stub's own command sets the upper one, `0x14`).
const L2_FLUSH: u32 = 1 << 2;
const L2_FLUSH_CLEARS: u32 = 0b11 << 3;
/// Set by the stock bootmain once, as it sets up its heap (`0x8B3E0`); start4
/// keeps it in all its later commands.
pub const L2_CTRL_BOOTMAIN: u32 = 1 << 6;

/// How long any command is given to finish; the stock stages wait forever.
const COMMAND_US: u32 = 100_000;

/// The alias bits of a VPU bus address.
const ALIAS: u32 = 0xc000_0000;

/// Set `bits` in `L2_CTRL`.
pub fn set_l2_ctrl(bits: u32) {
    mmio::write(L2_CTRL, mmio::read(L2_CTRL) | bits);
}

/// Flush `len` bytes from `addr` out of every cache, as the stock bootmain
/// does with all flags set (`0x87DD4` through `0xA77FC`). The range goes out
/// as the physical address, the way the stock stage's cached buffers put it.
pub fn flush(addr: u32, len: u32) {
    let first = addr & !ALIAS;
    flush_range(first, first.wrapping_add(len).wrapping_sub(1));
}

/// [`flush`] over the whole address space, the stock bootmain's last flush
/// before it leaves (`0x866FA`).
pub fn flush_all() {
    flush_range(0, u32::MAX - 1);
}

/// Whether `addr` goes through the caches, which only the uncached alias
/// does not.
pub fn is_cached(addr: u32) -> bool {
    addr & ALIAS != ALIAS
}

/// Whether `addr..addr + len` can be handed to a DMA engine without a cache
/// line of it also holding something else: the uncached alias, or whole
/// lines.
pub fn owns_lines(addr: u32, len: u32) -> bool {
    !is_cached(addr) || (addr | len) & (LINE - 1) == 0
}

/// The bootbox flush's line.
const LINE: u32 = 32;

/// The same bytes through the alias that goes through the VPU's L1 data
/// cache, which is roughly ten times faster to read than the uncached one.
/// Whatever is written through it stays in the cache until
/// [`write_back`] or [`write_back_with_l2`], so it has to sit in cache lines of
/// its own.
pub fn cached_mut<T: ?Sized>(p: *mut T) -> *mut T {
    p.map_addr(|addr| addr & !(ALIAS as usize))
}

/// [`cached_mut`] for data that is never written, which needs no write-back.
pub fn cached<T: ?Sized>(data: &'static T) -> &'static T {
    unsafe { &*cached_mut((data as *const T).cast_mut()) }
}

/// Write `first..=last` back out of the data cache, as the stock start4 does
/// over a buffer it is about to read through a cached alias and over its own
/// heap (flags `0xC`).
pub fn write_back(first: u32, last: u32) {
    set_range(first, last);
    flush_shared();
}

/// [`write_back`] and the L2 as well, as the stock start4 does over the ARM's
/// memory just before the ARM starts (flags `0x1C`).
pub fn write_back_with_l2(first: u32, last: u32) {
    set_range(first, last);
    flush_shared();
    flush_l2();
}

fn set_range(first: u32, last: u32) {
    mmio::write(SHARED_FIRST, first);
    mmio::write(SHARED_LAST, last);
    mmio::write(L2_FIRST, first);
    mmio::write(L2_LAST, last);
}

fn flush_range(first: u32, last: u32) {
    set_range(first, last);
    let (a, b) = (mmio::read(CORE_A), mmio::read(CORE_B));
    mmio::write(CORE_A, a | CORE_FLUSH);
    mmio::write(CORE_B, b | CORE_FLUSH);
    let _ = (mmio::read(CORE_A), mmio::read(CORE_B));
    flush_shared();
    flush_l2();
}

fn flush_shared() {
    mmio::write(SHARED, mmio::read(SHARED) | SHARED_FLUSH);
    timer::wait(COMMAND_US, || mmio::read(SHARED) & SHARED_FLUSH == 0);
}

fn flush_l2() {
    mmio::write(L2_CTRL, mmio::read(L2_CTRL) & !L2_FLUSH_CLEARS | L2_FLUSH);
    timer::wait(COMMAND_US, || mmio::read(L2_CTRL) & L2_FLUSH == 0);
}

/// Where the stub runs: outside the L2, as the bootcode itself lives in it.
const STUB: u32 = 0x6001_0000;
/// A page both stock stages clear before they leave (`0x80009570`,
/// `0xA9784`).
const CLEARED: u32 = 0xc002_0000;
const CLEARED_LEN: usize = 1024;

// Flushes every cache whose bit 0 is clear over the low memory, `SHARED` and
// the core caches over 1 GiB and the L2 over its first 256 MiB, then enters
// the next stage at r0. The stock stages copy it out byte for byte
// (`0x800004CC`, `0x802CC`). Position-independent.
core::arch::global_asm!(
    ".pushsection .text.cache_stub, \"ax\"",
    ".balign 4",
    ".globl __cache_stub_start",
    ".globl __cache_stub_end",
    "__cache_stub_start:",
    "    mov r2, #0x7ee02100",
    "    ld r1, (r2)",
    "    btest r1, #0",
    "    bne 4f",
    "    mov r2, #0x7ee02104",
    "    mov r1, #0",
    "    st r1, (r2)",
    "    mov r2, #0x7ee02108",
    "    mov r1, #0x3fffffe0",
    "    st r1, (r2)",
    "    mov r2, #0x7ee02100",
    "    mov r1, #6",
    "    st r1, (r2)",
    "2:  ld r1, (r2)",
    "    btest r1, #2",
    "    bne 2b",
    "3:  ld r1, (r2)",
    "    btest r1, #1",
    "    bne 3b",
    "4:  mov r2, #0x7ee01000",
    "    ld r1, (r2)",
    "    btest r1, #0",
    "    bne 6f",
    "    mov r2, #0x7ee01004",
    "    mov r1, #0",
    "    st r1, (r2)",
    "    mov r2, #0x7ee01008",
    "    mov r1, #0x0fffffe0",
    "    st r1, (r2)",
    "    mov r2, #0x7ee01000",
    "    mov r1, #0x14",
    "    st r1, (r2)",
    "5:  ld r1, (r2)",
    "    btest r1, #2",
    "    bne 5b",
    "6:  mov r2, #0x7ee02000",
    "    ld r1, (r2)",
    "    btest r1, #0",
    "    bne 8f",
    "    mov r2, #0x7ee02008",
    "    mov r1, #0",
    "    st r1, (r2)",
    "    mov r2, #0x7ee0200c",
    "    mov r1, #0x3fffffe0",
    "    st r1, (r2)",
    "    mov r2, #0x7ee02000",
    "    mov r1, #2",
    "    st r1, (r2)",
    "7:  ld r1, (r2)",
    "    btest r1, #1",
    "    bne 7b",
    "8:  b r0",
    "__cache_stub_end:",
    ".popsection",
);

unsafe extern "C" {
    static __cache_stub_start: u8;
    static __cache_stub_end: u8;
}

/// Leave for the next stage at `entry` the way the stock stages do: the stub
/// copied out, the cleared page, `CORE_A` flushed on its own, then through
/// the stub.
pub fn enter(entry: u32) -> ! {
    // The vectors point into this stage, which the next one is about to
    // overwrite, so the watchdog's heartbeat and every other interrupt stop
    // here; the next stage arms its own. Nothing in the interrupt controller
    // is written, so the handoff looks the way the stock stage's does.
    crate::idle::heartbeat_off();
    unsafe {
        let start = addr_of!(__cache_stub_start);
        let len = addr_of!(__cache_stub_end) as usize - start as usize;
        core::ptr::copy_nonoverlapping(start, STUB as usize as *mut u8, len);
        core::ptr::write_bytes(CLEARED as usize as *mut u8, 0, CLEARED_LEN);
    }
    mmio::write(CORE_A, mmio::read(CORE_A) | CORE_FLUSH);
    timer::wait(COMMAND_US, || mmio::read(CORE_A) & CORE_FLUSH == 0);
    // A call puts `entry` in r0, where the stub wants it.
    let stub: extern "C" fn(u32) -> ! = unsafe { core::mem::transmute(STUB as usize) };
    stub(entry)
}

//! Idling the VPU the way the stock firmware's scheduler does once the ARM
//! runs: asleep until an interrupt comes. The only ones this firmware takes
//! are the system timer's first compare, so the core wakes when it asks to,
//! and the ARM's mailbox, so it wakes as soon as the ARM asks for something.
//!
//! The core vectors an interrupt through a table of 128 addresses whose base
//! it reads from its interrupt controller: 0-31 exceptions, 32-63 software
//! interrupts, 64 up the external sources, the system timer's first compare
//! at 64 and the ARM's mailbox at 94. `sleep` takes its interrupt whether or
//! not they are enabled, and the stock scheduler disables them again as soon
//! as it wakes; so does this, inside a [`crate::critical`] section so the
//! caller gets back the state it slept in.
//!
//! The system timer's third compare beats the boot watchdog while a boot is
//! under way; see [`crate::watchdog`].

use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

use crate::mmio;
use crate::sync::Semaphore;

/// The VPU core 0's interrupt controller: one 4-bit priority per source,
/// eight to a word from `+0x10` (zero disables the source), and the vector
/// base.
const IC: u32 = 0x7e00_2000;
const IC_PRIO: u32 = IC + 0x10;
const IC_PRIO_WORDS: u32 = 8;
const IC_VBASE: u32 = IC + 0x30;
/// The system timer: match flags (write 1 to clear) and the first compare.
const STC_CS: u32 = 0x7e00_3000;
const STC_CLO: u32 = 0x7e00_3004;
const STC_C0: u32 = 0x7e00_300c;
const STC_C2: u32 = 0x7e00_3014;
const MATCH0: u32 = 1 << 0;
const MATCH2: u32 = 1 << 2;
/// The VPU's side of the ARM's mailbox: the interrupt enable for "the ARM
/// has posted something". The line stays up while it is set and a request
/// waits, so the handler clears it and [`listen_mailbox`] or the next sleep
/// sets it again.
const MBOX_CONFIG1: u32 = 0x7e00_b9bc;
const MBOX_EN_HAVE_DATA: u32 = 1 << 0;
/// The sources this firmware enables, at the priority the stock firmware
/// gives them: the first compare (64) and the mailbox (94), word by word.
const IC_PRIO_ENABLED: [u32; IC_PRIO_WORDS as usize] = [
    prio_bit(TIMER0_IRQ) | prio_bit(HEARTBEAT_IRQ),
    0,
    0,
    prio_bit(MBOX_IRQ),
    0,
    0,
    0,
    0,
];
const TIMER0_IRQ: u32 = 64;
/// The third compare, which [`heartbeat_on`] keeps for the boot watchdog: the
/// kernel's `bcm2835-system-timer` claims the second and the fourth and leaves
/// this one and the first to the firmware.
const HEARTBEAT_IRQ: u32 = 66;
const MBOX_IRQ: u32 = 94;
/// Core 1's copies of the priority words.
const IC1_PRIO: u32 = IC_PRIO + 0x800;
const PRIO: u32 = 1;

const fn prio_bit(irq: u32) -> u32 {
    PRIO << ((irq & 7) * 4)
}

/// The table is indexed by the interrupt number itself: 0..31 exceptions,
/// 32..63 `swi`, 64..127 the external sources.
const _: () = assert!(MBOX_IRQ - TIMER0_IRQ - 1 == 29);
const _: () = assert!(TIMER0_IRQ >> 3 & 7 == 0 && MBOX_IRQ >> 3 & 7 == 3);
const _: () = assert!(IC_PRIO_ENABLED[0] == 0x101 && IC_PRIO_ENABLED[3] == 0x0100_0000);

core::arch::global_asm!(
    ".pushsection .text.vpu_idle, \"ax\"",
    // The timer interrupt: clear the match and return to after the `sleep`,
    // or, once the threads run, go on to the tick with the interrupted
    // thread's `r0`-`r5` and `lr` saved above the frame the core pushed.
    "vpu_timer0_irq:",
    "    stm r0-r5,lr,(--sp)",
    "    bl vpu_timer0_tick",
    "    cmp r0, #0",
    "    beq vpu_timer0_return",
    "    b r0",
    // Shared with the mailbox's handler, which goes on to the tick's entry
    // too when the thread it woke should run before the interrupted one.
    "vpu_timer0_return:",
    "    ldm r0-r5,(sp++)",
    "    ld lr, (sp)",
    "    add sp, sp, #4",
    "    rti",
    // The third compare: the boot watchdog's heartbeat, which runs in the
    // middle of a stage's work rather than after it, so the same frame as the
    // first compare's.
    "vpu_heartbeat_irq:",
    "    stm r0-r5,lr,(--sp)",
    "    bl vpu_heartbeat_tick",
    "    ldm r0-r5,(sp++)",
    "    ld lr, (sp)",
    "    add sp, sp, #4",
    "    rti",
    // The mailbox interrupt: drop its enable, which lowers the line; the idle
    // loop answers the request and enables it again. If that wakes a thread
    // that outranks the interrupted one, switch to it on the way out.
    "vpu_mbox_irq:",
    "    stm r0-r5,lr,(--sp)",
    "    bl vpu_mbox_tick",
    "    cmp r0, #0",
    "    beq vpu_timer0_return",
    "    b r0",
    // Any other source was left enabled by an earlier stage: put the enables
    // back to the timer's and the mailbox's, which lowers it here, and carry
    // on.
    "vpu_stray_irq:",
    "    stm r0-r1,(--sp)",
    "    mov r0, #0x7e002010",
    "    mov r1, #1",
    "    st r1, (r0)",
    "    mov r1, #0",
    "    mov r0, #0x7e002014",
    "    st r1, (r0)",
    "    mov r0, #0x7e002018",
    "    st r1, (r0)",
    "    mov r0, #0x7e002020",
    "    st r1, (r0)",
    "    mov r0, #0x7e002024",
    "    st r1, (r0)",
    "    mov r0, #0x7e002028",
    "    st r1, (r0)",
    "    mov r0, #0x7e00202c",
    "    st r1, (r0)",
    "    mov r0, #0x7e00201c",
    "    mov r1, #0x01000000",
    "    st r1, (r0)",
    "    ldm r0-r1,(sp++)",
    "    rti",
    // An exception or a software interrupt: nothing here raises one, so stop.
    "vpu_unexpected:",
    "    b vpu_unexpected",
    ".popsection",
    ".pushsection .rodata.vpu_vectors, \"a\"",
    // `IC0_VADDR` keeps only bits 31:9 of what is written (Broadcom's
    // `IC0_VADDR_MASK` is `0xFFFFFE00`), so a table that is not 512-byte
    // aligned is fetched from the address below it and no handler ever runs.
    ".balign 512",
    ".globl vpu_vectors",
    "vpu_vectors:",
    // 0..31 the processor exceptions, 32..63 the `swi` range, 64 up the
    // external sources, indexed by the interrupt number itself: the first
    // compare is 64, the third 66, the mailbox 94.
    ".rept 64",
    "    .long vpu_unexpected",
    ".endr",
    // The low bit of a hardware entry asks for the handler to run with the
    // supervisor bit set; lk-overlay stores `fleh_irq | 1` for 64..127 and
    // leaves it clear for the exception and `swi` entries.
    "    .long vpu_timer0_irq + 1",
    ".rept 1",
    "    .long vpu_stray_irq + 1",
    ".endr",
    "    .long vpu_heartbeat_irq + 1",
    ".rept 27",
    "    .long vpu_stray_irq + 1",
    ".endr",
    "    .long vpu_mbox_irq + 1",
    ".rept 33",
    "    .long vpu_stray_irq + 1",
    ".endr",
    ".popsection",
);

unsafe extern "C" {
    static vpu_vectors: [u32; 128];
}

/// The tick [`tick_every`] set: where the first compare's handler goes on to,
/// and how far ahead it asks for the next match. Null and 0 until then.
static TICK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
static TICK_US: AtomicU32 = AtomicU32::new(0);

/// The first compare's handler: clear the match so the line drops. Once a
/// tick is set, ask for the next match and return where the handler goes on
/// to; 0 returns from the interrupt.
#[unsafe(no_mangle)]
extern "C" fn vpu_timer0_tick() -> u32 {
    mmio::write(STC_CS, MATCH0);
    let tick = TICK.load(Ordering::Relaxed);
    if !tick.is_null() {
        arm_compare(TICK_US.load(Ordering::Relaxed));
    }
    tick as u32
}

/// Take the first compare every `us` from now on, and go on from its handler
/// to `entry` each time, with the interrupted code's frame on the stack as
/// far as `r0`-`r5` and `lr`. [`sleep_us`] still sets the compare for its
/// own wake, which the next tick follows.
pub fn tick_every(us: u32, entry: unsafe extern "C" fn() -> !) {
    TICK_US.store(us, Ordering::Relaxed);
    TICK.store(entry as *mut (), Ordering::Relaxed);
    arm_compare(us);
}

/// The heartbeat's period while it runs, 0 while it does not: what
/// [`vpu_heartbeat_tick`] rearms the third compare with, and what tells it
/// apart from a match left over from a stage that has handed the dog back.
static HEARTBEAT_US: AtomicU32 = AtomicU32::new(0);

/// The third compare's handler: the match cleared, and while the heartbeat
/// runs the next one asked for and the boot watchdog beaten.
#[unsafe(no_mangle)]
extern "C" fn vpu_heartbeat_tick() {
    mmio::write(STC_CS, MATCH2);
    let us = HEARTBEAT_US.load(Ordering::Relaxed);
    if us != 0 {
        arm_heartbeat(us);
        crate::watchdog::beat();
    }
}

/// Whether the heartbeat is the one beating the boot watchdog.
pub fn heartbeat_running() -> bool {
    HEARTBEAT_US.load(Ordering::Relaxed) != 0
}

/// Ask the third compare for a match `us` from now, and clear any that stands.
fn arm_heartbeat(us: u32) {
    mmio::write(STC_C2, mmio::read(STC_CLO).wrapping_add(us));
    mmio::write(STC_CS, MATCH2);
}

/// Beat the boot watchdog off the third compare every `period_us`, which is
/// what the stock firmware's one-second timer thread does: the reload rides an
/// interrupt, so no decompressor, digest or driver has to carry the dog.
///
/// Interrupts stay enabled from here until [`heartbeat_off`] — that is the
/// point of it — so the vectors go in here as well as in [`init`], for the
/// stages that have no idle loop.
pub fn heartbeat_on(period_us: u32) {
    mmio::write(IC_VBASE, (&raw const vpu_vectors) as usize as u32);
    let word = IC_PRIO + 4 * (HEARTBEAT_IRQ >> 3 & 7);
    mmio::write(word, mmio::read(word) | prio_bit(HEARTBEAT_IRQ));
    HEARTBEAT_US.store(period_us, Ordering::Relaxed);
    arm_heartbeat(period_us);
    crate::critical::enable();
}

/// Stop the beat, and with it every interrupt this firmware takes. The
/// interrupt controller is left as it stands, so a stage hands on the
/// registers the stock stage's hands on; with interrupts off and no match
/// armed the handler cannot run anyway.
pub fn heartbeat_off() {
    crate::critical::disable();
    HEARTBEAT_US.store(0, Ordering::Relaxed);
    mmio::write(STC_CS, MATCH2);
}

/// The mailbox's handler: drop the enable, which lowers the line, and signal
/// [`MAIL`]. The thread waiting on it answers the request and puts the enable
/// back.
///
/// Source 94 is the whole ARMC block's line, not the mailbox's alone: a
/// doorbell the ARM rings holds it up as well until the doorbell is read. No
/// doorbell is enabled here.
#[unsafe(no_mangle)]
extern "C" fn vpu_mbox_tick() -> u32 {
    mmio::write(MBOX_CONFIG1, 0);
    MAIL.signal();
    let to = PREEMPT.load(Ordering::Relaxed);
    PREEMPT.store(core::ptr::null_mut(), Ordering::Relaxed);
    to as u32
}

/// Where the mailbox's handler goes on to instead of returning: the tick's
/// entry once a wake has asked for [`preempt`], null otherwise.
static PREEMPT: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Have the mailbox's handler go on to the tick's entry rather than return
/// to the thread it interrupted.
pub fn preempt() {
    PREEMPT.store(TICK.load(Ordering::Relaxed), Ordering::Relaxed);
}

/// Take back a [`preempt`] a switch has already served.
pub fn preempted() {
    PREEMPT.store(core::ptr::null_mut(), Ordering::Relaxed);
}

/// Signalled each time the ARM's mailbox interrupt is taken.
pub static MAIL: Semaphore = Semaphore::new(0);

/// Have the next request the ARM posts raise the mailbox interrupt again,
/// after its handler has dropped the enable.
pub fn listen_mailbox() {
    mmio::write(MBOX_CONFIG1, MBOX_EN_HAVE_DATA);
}

/// Ask the first compare for a match `us` from now, and clear any that stands.
fn arm_compare(us: u32) {
    mmio::write(STC_C0, mmio::read(STC_CLO).wrapping_add(us));
    mmio::write(STC_CS, MATCH0);
}

/// Point the core at this firmware's vectors and enable the timer's first
/// compare and the mailbox, nothing else. Interrupts stay disabled until
/// [`sleep_us`] or [`crate::sched::start`].
pub fn init() {
    let base = (&raw const vpu_vectors) as usize as u32;
    mmio::write(IC_VBASE, base);
    for (i, word) in IC_PRIO_ENABLED.iter().enumerate() {
        mmio::write(IC_PRIO + 4 * i as u32, *word);
    }
}

/// Sleep for up to `us` microseconds, or until the ARM posts a request: the
/// first compare is set that far ahead and any earlier match cleared, the
/// mailbox's interrupt enabled, then the core waits for either. Once a tick
/// is set it follows from the wake, whatever woke the core.
pub fn sleep_us(us: u32) {
    arm_compare(us);
    mmio::write(MBOX_CONFIG1, MBOX_EN_HAVE_DATA);
    // `sleep` takes the interrupt it waits for whether or not the enable bit is
    // set, so the loop parks the way the stock scheduler's does. Measured on a
    // 4B rev 1.5: with the bit clear throughout, this handler still runs 1979
    // times in two seconds and the mailbox keeps being answered. The `ei` that
    // used to bracket this was put here while the vector table was misaligned,
    // when no handler ran at all.
    sleep();
    let tick_us = TICK_US.load(Ordering::Relaxed);
    if tick_us != 0 {
        arm_compare(tick_us);
    }
}

/// Wait for an interrupt and take it, and come back with interrupts as they
/// were: `sleep` wakes whatever SR says, and stock disables them straight
/// after, which is what the section's close puts right.
fn sleep() {
    let _section = crate::critical::enter();
    unsafe { core::arch::asm!("sleep", "di") };
}

/// Disable every interrupt source on both cores, and the vectors.
pub fn disable_all() {
    for i in 0..IC_PRIO_WORDS {
        mmio::write(IC_PRIO + 4 * i, 0);
    }
    for i in 0..IC_PRIO_WORDS {
        mmio::write(IC1_PRIO + 4 * i, 0);
    }
    mmio::write(IC_VBASE, 0);
}

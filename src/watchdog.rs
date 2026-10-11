//! The boot watchdog: the hardware countdown the first stage arms over the
//! whole boot (a stock bootloader only when `bootconf.txt` carries
//! `BOOT_WATCHDOG_TIMEOUT`), so a board that hangs anywhere between the
//! bootcode and the operating system's own watchdog driver resets instead of
//! sitting there. [`hand_over`] gives it to the ARM, which beats it from UEFI;
//! [`carry_poll`] takes it back for the operating system to start its driver.
//!
//! Only the bootcode arms it, and it arms it once: `PM_RSTC`'s
//! `WRCFG` asks for a full reset, and everything after that is a bare
//! `PM_WDOG` write, because `PM_WDOG` *is* the counter — writing it reloads a
//! countdown already running. So the whole budget lives in software, as a
//! deadline on the 1 MHz system timer that every stage reads out of the
//! `BPWR` block of the handover ([`crate::handover`]), and the hardware dog is only ever told how much of
//! it is left, up to the 16 s its 20 bits reach.
//!
//! The dog counts at 65536 Hz, so a tick is 15.26 µs; stock divides the
//! microseconds it has left by 16 rather than by 15.26, so the dog always
//! expires a little early rather than late.
//!
//! Twenty bits at that rate is 16 s, and that is the ceiling however large
//! `BOOT_WATCHDOG_TIMEOUT` is: a budget of ten minutes still resets the board
//! after sixteen seconds with no beat. So the beat cannot ride the code that
//! happens to look at the clock: decompressing a Raspberry Pi OS kernel is
//! twenty seconds of arithmetic that reads no register at all, and a stage
//! doing that would reset the board with three quarters of its budget
//! unspent. Stock beats from a one-second timer thread instead, and
//! [`set_deadline`] does the same with the hardware under it: the system
//! timer's third compare, every [`FEED_INTERVAL_US`], through
//! [`crate::idle::heartbeat_on`]. Nothing that does the work — no
//! decompressor, digest, ELF loader or driver — knows the dog exists.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::{mmio, stc};

const PM_RSTC: u32 = 0x7e10_001c;
const PM_WDOG: u32 = 0x7e10_0024;
const PASSWD: u32 = 0x5a00_0000;

/// `PM_WDOG` counts in 20 bits: `0xFFFFF` ticks is 16 s.
pub const WDOG_MAX: u32 = 0x000f_ffff;
/// `PM_RSTC.WRCFG`, and the code that resets the SoC when the dog expires.
pub const RSTC_WRCFG: u32 = 0x30;
pub const RSTC_WRCFG_FULL_RESET: u32 = 0x20;

/// The ticks stock asks the dog for to cover `us` microseconds.
fn ticks(us: u64) -> u32 {
    (us >> 4).min(WDOG_MAX as u64) as u32
}

/// Whether the dog is set to reset the SoC when it expires.
pub fn armed() -> bool {
    mmio::read(PM_RSTC) & RSTC_WRCFG != 0
}

/// What is left of the countdown, in microseconds, in the units the
/// `remaining` log lines print.
pub fn remaining_us() -> u32 {
    (mmio::read(PM_WDOG) & WDOG_MAX) << 4
}

/// Load the counter without touching `PM_RSTC`: the heartbeat every stage
/// beats, from the deadline the bootcode wrote into the handoff block. Once
/// the deadline has passed the dog is left to expire, which is how the reset
/// happens at all.
pub fn kick(end_at: u64) {
    if end_at == 0 {
        return;
    }
    let now = stc::now();
    if now >= end_at {
        return;
    }
    mmio::write(PM_WDOG, PASSWD | ticks(end_at - now));
}

/// The deadline the heartbeat beats against, in two halves because the core
/// has no 64-bit load. 0 — every stage's state until it takes the dog on —
/// means there is nothing to beat.
static DEADLINE_LO: AtomicU32 = AtomicU32::new(0);
static DEADLINE_HI: AtomicU32 = AtomicU32::new(0);

/// How often the heartbeat beats: the period of stock's own timer thread, and
/// a sixteenth of the longest the register can count.
pub const FEED_INTERVAL_US: u32 = 1_000_000;

/// Take the dog on for this stage, or with 0 hand it back. The heartbeat runs
/// between the two, so the whole of a stage's work is covered without any of
/// it carrying the dog; the interrupt is off while the halves of the deadline
/// are written, so the beat cannot read one of them from either side.
pub fn set_deadline(end_at: u64) {
    crate::idle::heartbeat_off();
    DEADLINE_HI.store((end_at >> 32) as u32, Ordering::Relaxed);
    DEADLINE_LO.store(end_at as u32, Ordering::Relaxed);
    if end_at != 0 {
        kick(end_at);
        LAST_BEAT_US.store(stc::now() as u32, Ordering::Relaxed);
        crate::idle::heartbeat_on(FEED_INTERVAL_US);
    }
}

pub fn deadline() -> u64 {
    let lo = DEADLINE_LO.load(Ordering::Relaxed);
    let hi = DEADLINE_HI.load(Ordering::Relaxed);
    (hi as u64) << 32 | lo as u64
}

/// [`kick`] against [`deadline`]: one beat of the heartbeat, called from the
/// third compare's handler and from nowhere else. The register write races a
/// [`kick`] or an [`arm_ticks`] in the interrupted code, and either value is a
/// valid reload of a counter that is already running.
pub(crate) fn beat() {
    let end_at = deadline();
    if end_at != 0 {
        kick(end_at);
        LAST_BEAT_US.store(stc::now() as u32, Ordering::Relaxed);
    }
}

/// When the dog was last reloaded, for [`beat_from_wait`] to tell a heartbeat
/// that is running from one that is only armed.
static LAST_BEAT_US: AtomicU32 = AtomicU32::new(0);

/// A beat from a wait that has been going for a while, for when the heartbeat
/// is not the one beating.
///
/// The interrupt is the mechanism, and it stays that way: nothing that does the
/// work should have to carry the dog, and a beat inside every wait is what once
/// hid a stall from the dog entirely. But a stage whose beat is not running --
/// the heartbeat needs the vectors, the third compare and interrupts enabled,
/// and a board is the only place that can say whether all three took -- would
/// otherwise be reset in the middle of a boot that is going fine. So a wait
/// beats only while [`crate::idle::heartbeat_running`] says nothing else is.
pub fn beat_from_wait() {
    let end_at = deadline();
    if end_at == 0 {
        return;
    }
    let now = stc::now() as u32;
    let since = now.wrapping_sub(LAST_BEAT_US.load(Ordering::Relaxed));
    // A heartbeat that is beating is left to it. One that is merely armed is
    // not: on a board this stage's beat never arrived -- the dog kept the one
    // reload `set_deadline` gave it and reset the board sixteen seconds later,
    // in the middle of a boot that was going fine -- and asking
    // `heartbeat_running` cannot tell the two apart, since it only says the
    // compare was armed.
    if crate::idle::heartbeat_running() && since < 2 * FEED_INTERVAL_US {
        return;
    }
    kick(end_at);
    LAST_BEAT_US.store(now, Ordering::Relaxed);
}

/// Arm the dog for this many ticks and ask for a full reset when it expires
/// (start4 `0x0ED6231E`). This is the dog `kernel_watchdog_timeout` and the
/// early watchdog hand the kernel, which Linux's `bcm2835_wdt` then finds
/// running and keeps fed.
pub fn arm_ticks(ticks: u32) {
    mmio::write(PM_WDOG, PASSWD | (ticks & WDOG_MAX));
    let rstc = mmio::read(PM_RSTC) & !RSTC_WRCFG | RSTC_WRCFG_FULL_RESET;
    mmio::write(PM_RSTC, PASSWD | rstc);
}

/// The same, over a span of microseconds (start4 `0x0ED49674`).
pub fn arm_us(us: u64) {
    arm_ticks(ticks(us));
}

/// Take the dog off and leave `PM_RSTC` the way every stage leaves it:
/// `WRCFG` cleared, bits 9:8 set to 2 and bits 1:0 set to 2, one
/// read-modify-write each.
pub fn quiesce() {
    for (clear, set) in [(RSTC_WRCFG, 0), (0x300, 0x200), (0x3, 0x2)] {
        let rstc = mmio::read(PM_RSTC) & !clear | set;
        mmio::write(PM_RSTC, PASSWD | rstc);
    }
}

/// How long the dog is beaten for after `ExitBootServices`: the time the
/// operating system has to start its own driver for the dog, which finds it
/// running and keeps it fed (Linux's `bcm2835_wdt`, a module on most
/// distributions).
pub const OS_WINDOW_S: u32 = 120;

/// The end of the span the dog is carried over after `ExitBootServices`, in two
/// halves. 0: not carrying.
static CARRY_LO: AtomicU32 = AtomicU32::new(0);
static CARRY_HI: AtomicU32 = AtomicU32::new(0);
/// The last UEFI request seen.
static CARRY_SEEN: AtomicU32 = AtomicU32::new(0);
/// The dog is the ARM's: UEFI reloads it, and the VPU only waits for
/// `ExitBootServices`.
static ARM_OWNS: AtomicBool = AtomicBool::new(false);

fn carry_until(end_at: u64) {
    CARRY_HI.store((end_at >> 32) as u32, Ordering::Relaxed);
    CARRY_LO.store(end_at as u32, Ordering::Relaxed);
}

fn carry_end() -> u64 {
    (CARRY_HI.load(Ordering::Relaxed) as u64) << 32 | CARRY_LO.load(Ordering::Relaxed) as u64
}

/// Give the dog to the ARM, with a full reload to start it from: UEFI beats it
/// from its first moments, so a stuck ARM is one that stops, and the board
/// resets up to 16 s later. The dog has to be armed already.
pub fn hand_over() {
    CARRY_SEEN.store(crate::arm::watchdog_request().0, Ordering::Relaxed);
    ARM_OWNS.store(true, Ordering::Relaxed);
    reload_full();
}

/// A full reload, 16 s. The carried dog is never loaded with just what is left
/// of the span: an operating system that has taken it on beats it on its own
/// period, and a short last reload from here would run out between two of
/// its beats.
fn reload_full() {
    mmio::write(PM_WDOG, PASSWD | WDOG_MAX);
}

/// One beat of the thread that watches the dog, at least once a second. While
/// the ARM has the dog it looks for `ExitBootServices`, and takes the dog back
/// for [`OS_WINDOW_S`]. Once the window is over the dog is left to run out, and
/// resets the board up to 16 s later unless the operating system has taken it
/// on.
pub fn carry_poll() {
    if ARM_OWNS.load(Ordering::Relaxed) {
        let (seq, what, _) = crate::arm::watchdog_request();
        if seq != CARRY_SEEN.load(Ordering::Relaxed) && what == crate::arm::WATCHDOG_EXIT {
            CARRY_SEEN.store(seq, Ordering::Relaxed);
            ARM_OWNS.store(false, Ordering::Relaxed);
            crate::info!("watchdog", "UEFI started the OS, the boot watchdog is its to take over";
                span_s = OS_WINDOW_S);
            carry_until(stc::now() + OS_WINDOW_S as u64 * 1_000_000);
            reload_full();
        }
        return;
    }
    let end_at = carry_end();
    if end_at == 0 {
        return;
    }
    if stc::now() >= end_at {
        crate::warn!("watchdog", "the OS did not take the watchdog in time, letting the board reset";
            left_ms = remaining_us() / 1000);
        carry_until(0);
        return;
    }
    reload_full();
}

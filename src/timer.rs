//! The free-running 1 MHz system timer (`0x7E00_3000`).
//!
//! Nothing here touches the boot watchdog: it is beaten from the system
//! timer's first compare instead (`src/idle.rs`), so a wait is a wait.
//!
//! Every wait on hardware goes through [`wait`] or [`poll`] rather than a
//! loop of its own, so there is one place that knows what waiting means: it
//! is what lets a wait beat the dog when the heartbeat is not running, and
//! what a wait would have to yield from if this firmware ever ran more than
//! one thread.

use crate::mmio;

const CLO: u32 = 0x7e00_3004;

/// Microseconds since the timer started, wrapping.
pub fn now() -> u32 {
    mmio::read(CLO)
}

pub fn delay_us(us: u32) {
    let start = now();
    while now().wrapping_sub(start) < us {}
}

/// Polls `done` every `interval_us` until it holds or `timeout_us` has
/// passed, the way the stock bootloader's helper does (`0xA9038`): the time
/// is checked after each miss, and the wait starts a microsecond early.
pub fn poll(timeout_us: u32, interval_us: u32, mut done: impl FnMut() -> bool) -> bool {
    let start = now().wrapping_sub(1);
    loop {
        if done() {
            return true;
        }
        if now().wrapping_sub(start) >= timeout_us {
            return false;
        }
        crate::sched::yield_now();
        if interval_us != 0 {
            delay_us(interval_us);
        }
    }
}

/// Polls `done` until it holds or `timeout_us` has passed; whether it held.
///
/// Inlined, and the clock is read only once the first check has missed: a
/// transfer clocking a byte at a time waits twice a byte, and the read would
/// then be most of what the loop does.
#[inline(always)]
pub fn wait(timeout_us: u32, mut done: impl FnMut() -> bool) -> bool {
    if done() {
        return true;
    }
    let start = now();
    let mut beat_at = start.wrapping_add(crate::watchdog::FEED_INTERVAL_US);
    loop {
        crate::sched::yield_now();
        if done() {
            return true;
        }
        let now = now();
        if now.wrapping_sub(beat_at) < u32::MAX / 2 {
            beat_at = now.wrapping_add(crate::watchdog::FEED_INTERVAL_US);
            crate::watchdog::beat_from_wait();
        }
        if now.wrapping_sub(start) > timeout_us {
            return done();
        }
    }
}

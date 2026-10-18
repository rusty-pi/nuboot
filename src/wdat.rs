//! The watchdog an operating system finds in the ACPI tables' WDAT: a page of
//! the ARM's memory the VPU serves, so the operating system's generic
//! `wdat_wdt` driver arms, pings and stops it without a driver for this SoC's
//! power manager, whose watchdog registers take a password in every write that
//! WDAT cannot put in a count.
//!
//! The page holds four words. The operating system writes `CONTROL` (bit 0,
//! running), `COUNT` (the timeout in seconds) and `RELOAD` (any non-zero word
//! reloads the countdown); the VPU writes `LEFT`, and clears `RELOAD` when it
//! has read it. The board's own dog is the VPU's to beat: it reloads it every
//! time it looks while the operating system's countdown has time left, and
//! when the countdown runs out asks it for a reset at once, so the timeout the
//! operating system set is the timeout it gets, to the poll. A VPU that stops
//! looking stops beating, and the dog resets the board within 16 s.
//!
//! At `ExitBootServices` the boot watchdog's window opens ([`crate::watchdog`])
//! with the page saying the dog is running and `COUNT` zero. The first word the
//! operating system writes to `COUNT` or `RELOAD` is the driver having taken
//! the dog over; an operating system that arms the power manager's own dog
//! instead leaves the page alone and the window ends the way it always has.
//!
//! The page is the operating system's to write, so nothing in it is trusted
//! but its words as numbers: the timeout is clamped to what the tables say.

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};

use crate::{info, stc, warn, watchdog};

pub const SIZE: u32 = 0x1000;

const CONTROL: usize = 0x00;
const COUNT: usize = 0x04;
const RELOAD: usize = 0x08;
const LEFT: usize = 0x0c;

const RUNNING: u32 = 1;

/// The shortest and the longest timeout the tables offer, in seconds.
pub const MIN_S: u32 = 2;
pub const MAX_S: u32 = 3600;

/// How often the page is looked at.
const POLL_US: u32 = 50_000;

/// What `PM_WDOG` is given to reset the board at once: ten ticks, about 150 µs.
const RESET_TICKS: u32 = 10;

const CLOSED: u8 = 0;
const WINDOW: u8 = 1;
const ARMED: u8 = 2;
const STOPPED: u8 = 3;

static STATE: AtomicU8 = AtomicU8::new(CLOSED);
/// The end of the operating system's countdown on the system timer, in halves.
static DEADLINE_LO: AtomicU32 = AtomicU32::new(0);
static DEADLINE_HI: AtomicU32 = AtomicU32::new(0);
/// `COUNT` as it was when it was last read, for a write of a new timeout to
/// reload the countdown the way it does in the hardware the table stands for.
static LAST_COUNT: AtomicU32 = AtomicU32::new(0);
static LOOKED: AtomicU32 = AtomicU32::new(0);

/// The page, as the VPU reaches it.
pub struct Window {
    pointer: *mut u8,
}

impl Window {
    pub const fn new(pointer: *mut u8) -> Window {
        Window { pointer }
    }

    fn read(&self, offset: usize) -> u32 {
        unsafe { read_volatile(self.pointer.add(offset) as *const u32) }
    }

    fn write(&self, offset: usize, value: u32) {
        unsafe { write_volatile(self.pointer.add(offset) as *mut u32, value) }
    }

    /// The page as a watchdog that has not been started leaves it.
    pub fn reset(&self) {
        for offset in (0..SIZE as usize).step_by(4) {
            self.write(offset, 0);
        }
        STATE.store(CLOSED, Ordering::Relaxed);
    }
}

fn deadline() -> u64 {
    (DEADLINE_HI.load(Ordering::Relaxed) as u64) << 32 | DEADLINE_LO.load(Ordering::Relaxed) as u64
}

fn set_deadline(end_at: u64) {
    DEADLINE_HI.store((end_at >> 32) as u32, Ordering::Relaxed);
    DEADLINE_LO.store(end_at as u32, Ordering::Relaxed);
}

fn timeout_s(raw: u32) -> u32 {
    raw.clamp(MIN_S, MAX_S)
}

fn load(count: u32) {
    set_deadline(stc::now() + timeout_s(count) as u64 * 1_000_000);
}

/// The window the operating system has to start its driver opens: the page
/// says the dog is running, with nothing set yet.
pub fn open_window(page: &Window, window_s: u32) {
    page.write(COUNT, 0);
    page.write(RELOAD, 0);
    page.write(LEFT, window_s);
    page.write(CONTROL, RUNNING);
    LAST_COUNT.store(0, Ordering::Relaxed);
    STATE.store(WINDOW, Ordering::Relaxed);
}

/// The window is over, by running out or because the operating system armed
/// the power manager's dog itself: the page stops saying the dog is running.
pub fn window_ended(page: &Window) {
    if STATE.load(Ordering::Relaxed) == WINDOW {
        page.write(CONTROL, 0);
        page.write(LEFT, 0);
        STATE.store(CLOSED, Ordering::Relaxed);
    }
}

/// Leave the dog alone from here on: the board is going to stand-by.
pub fn stop() {
    STATE.store(CLOSED, Ordering::Relaxed);
}

/// Look at the page, at least every [`POLL_US`], from the thread that carries
/// the boot watchdog.
pub fn poll(page: &Window) {
    let state = STATE.load(Ordering::Relaxed);
    if state == CLOSED {
        return;
    }
    let now = crate::timer::now();
    if now.wrapping_sub(LOOKED.load(Ordering::Relaxed)) < POLL_US {
        return;
    }
    LOOKED.store(now, Ordering::Relaxed);
    match state {
        WINDOW => {
            if !watchdog::carrying() {
                window_ended(page);
            } else if page.read(COUNT) != 0 || page.read(RELOAD) != 0 {
                take_over(page);
            }
        }
        ARMED => armed(page),
        STOPPED => {
            if page.read(CONTROL) & RUNNING != 0 {
                start(page);
            }
        }
        _ => {}
    }
}

fn take_over(page: &Window) {
    watchdog::stop_carrying();
    let count = page.read(COUNT);
    info!("wdat", "the OS has the boot watchdog, through the WDAT table"; timeout_s = timeout_s(count));
    LAST_COUNT.store(count, Ordering::Relaxed);
    page.write(RELOAD, 0);
    start(page);
}

fn start(page: &Window) {
    load(page.read(COUNT));
    if !watchdog::armed() {
        watchdog::arm_ticks(watchdog::WDOG_MAX);
    }
    watchdog::beat_full();
    page.write(CONTROL, RUNNING);
    STATE.store(ARMED, Ordering::Relaxed);
}

fn armed(page: &Window) {
    if page.read(CONTROL) & RUNNING == 0 {
        watchdog::quiesce();
        page.write(LEFT, 0);
        STATE.store(STOPPED, Ordering::Relaxed);
        return;
    }
    let count = page.read(COUNT);
    let reload = page.read(RELOAD);
    if reload != 0 {
        page.write(RELOAD, 0);
    }
    if reload != 0 || count != LAST_COUNT.load(Ordering::Relaxed) {
        LAST_COUNT.store(count, Ordering::Relaxed);
        load(count);
    }
    let now = stc::now();
    let end_at = deadline();
    if now >= end_at {
        warn!("wdat", "the OS did not ping the watchdog in time, resetting the board"; timeout_s = timeout_s(count));
        STATE.store(CLOSED, Ordering::Relaxed);
        page.write(LEFT, 0);
        watchdog::arm_ticks(RESET_TICKS);
        return;
    }
    page.write(LEFT, ((end_at - now) / 1_000_000) as u32 + 1);
    watchdog::beat_full();
}

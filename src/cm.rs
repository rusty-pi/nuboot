//! The clock manager (`0x7E10_1000`): the generators of the peripheral
//! clocks this firmware drives.

use crate::mmio::{self, PASSWD};
use crate::timer;

const BASE: u32 = 0x7e10_1000;

/// The PL011's generator; its divider is the word after it.
pub const UART_CTL: u32 = 0x0f0;

const OSC_HZ: u64 = 54_000_000;

/// The 12.12 fixed-point divider that takes the oscillator to `hz`.
pub const fn osc_div(hz: u32) -> u32 {
    ((OSC_HZ << 12) / hz as u64) as u32
}

/// Generator sources, numbered the way the peripheral clocks number them.
pub const SRC_OSC: u32 = 1;
pub const ENAB: u32 = 1 << 4;
const BUSY: u32 = 1 << 7;
/// Stops a generator at once, mid-cycle (Linux's `CM_KILL`).
const KILL: u32 = 1 << 5;

/// How long to give a generator to stop or start before going on regardless.
const SETTLE_US: u32 = 1000;

/// Stop a clock generator, give it a new divider and restart it with `ctl`
/// (source and enable).
///
/// A generator still `BUSY` when it is given a new divider or source stays
/// stuck, so it is stopped first and killed if it does not stop; and one that
/// has been asked to run is not running until `BUSY` says so, so whatever it
/// clocks is not used before then. Both waits are bounded, since the model
/// holds `BUSY` clear.
pub fn set_generator(ctl_off: u32, div: u32, ctl: u32) {
    let reg = BASE + ctl_off;
    mmio::write(reg, PASSWD);
    if !timer::wait(SETTLE_US, || mmio::read(reg) & BUSY == 0) {
        mmio::write(reg, PASSWD | KILL);
        timer::wait(SETTLE_US, || mmio::read(reg) & BUSY == 0);
    }
    mmio::write(reg + 4, PASSWD | div);
    mmio::write(reg, PASSWD | ctl);
    if ctl & ENAB != 0 {
        timer::wait(SETTLE_US, || mmio::read(reg) & BUSY != 0);
    }
}

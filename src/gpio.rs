//! The SoC's own GPIO bank (`0x7E20_0000`), and the pad controls for it in the
//! power manager's window.

use crate::mmio::{self, PASSWD};

const BASE: u32 = 0x7e20_0000;
const GPSET0: u32 = BASE + 0x1c;
const GPCLR0: u32 = BASE + 0x28;
const GPLEV0: u32 = BASE + 0x34;
/// The BCM2711's pull controls: two bits a pin, GPIO 0 upwards.
const PULL0: u32 = BASE + 0xe4;

/// Pad control for the three banks (GPIO 0-27, 28-45, 46 up): drive strength
/// in the low three bits, input hysteresis, and slew rate limiting off.
/// Linux's `bcm2835-power` numbers these `PM_PADS2`, `PM_PADS3` and
/// `PM_PADS4`; its `PM_PADS0` is the word before them, at `+0x28`.
const PADS2: u32 = 0x7e10_002c;
const PAD_HYSTERESIS: u32 = 1 << 3;
const PAD_SLEW_UNLIMITED: u32 = 1 << 4;

pub const INPUT: u32 = 0b000;
pub const OUTPUT: u32 = 0b001;
pub const ALT0: u32 = 0b100;
pub const ALT1: u32 = 0b101;
pub const ALT2: u32 = 0b110;
pub const ALT3: u32 = 0b111;
pub const ALT4: u32 = 0b011;
pub const ALT5: u32 = 0b010;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Pull {
    Off = 0,
    Up = 1,
    Down = 2,
}

pub fn function(pin: u32) -> u32 {
    mmio::read(BASE + 4 * (pin / 10)) >> ((pin % 10) * 3) & 0b111
}

pub fn set_function(pin: u32, function: u32) {
    let reg = BASE + 4 * (pin / 10);
    let shift = (pin % 10) * 3;
    let v = mmio::read(reg);
    mmio::write(reg, (v & !(0b111 << shift)) | function << shift);
}

pub fn set_pull(pin: u32, pull: Pull) {
    let reg = PULL0 + 4 * (pin / 16);
    let shift = (pin % 16) * 2;
    let v = mmio::read(reg);
    mmio::write(reg, (v & !(0b11 << shift)) | (pull as u32) << shift);
}

/// Whether `pin` reads high, whatever it is set to do.
pub fn level(pin: u32) -> bool {
    mmio::read(GPLEV0 + 4 * (pin / 32)) >> (pin % 32) & 1 != 0
}

pub fn set(pin: u32) {
    mmio::write(GPSET0 + 4 * (pin / 32), 1 << (pin % 32));
}

pub fn clear(pin: u32) {
    mmio::write(GPCLR0 + 4 * (pin / 32), 1 << (pin % 32));
}

/// Which pad bank `pin` is in.
pub fn bank(pin: u32) -> usize {
    match pin {
        0..=27 => 0,
        28..=45 => 1,
        _ => 2,
    }
}

/// Set a bank's pads to `drive` (the register's three-bit code), with
/// hysteresis on and the slew rate not limited, as the stock firmware leaves
/// them.
pub fn set_pads(bank: usize, drive: u32) {
    let value = PAD_SLEW_UNLIMITED | PAD_HYSTERESIS | drive & 0b111;
    mmio::write(PADS2 + 4 * bank as u32, PASSWD | value);
}

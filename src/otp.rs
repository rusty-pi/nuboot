//! The one-time-programmable fuses, through the config/OTP block
//! (`0x7E20_F000`).

use crate::{mmio, timer};

const BASE: u32 = 0x7e20_f000;
const CLKMUX: u32 = BASE + 0x04;
const PARAM_A: u32 = BASE + 0x08;
const PARAM_B: u32 = BASE + 0x0c;
const STATUS: u32 = BASE + 0x10;
const DATA: u32 = BASE + 0x18;
const KEY: u32 = BASE + 0x1c;

const PARAM_A_GO: u32 = 1 << 0;
const STATUS_DONE: u32 = 1 << 1;
/// How long each half of the poll waits; a row takes microseconds.
const TIMEOUT_US: u32 = 1000;

/// The board's serial number.
pub const SERIAL: u32 = 28;
/// The board's revision code (`0x00d03115`: a Pi 4B rev 1.5).
pub const REVISION: u32 = 30;
/// The boot mode row, which the boot ROM reads as it starts.
pub const BOOTMODE: u32 = 17;
/// The MAC address rows: the customer's, or blank.
pub const MAC_HIGH: u32 = 65;
pub const MAC_LOW: u32 = 64;
/// The extended revision: its bits 8-16 describe the SDRAM parts.
pub const EXT_REVISION: u32 = 33;

fn open() {
    mmio::write(CLKMUX, 3);
    timer::delay_us(10);
    mmio::write(PARAM_B, 0);
    mmio::write(PARAM_A, 0);
    timer::delay_us(10);
    mmio::write(CLKMUX, 2);
    timer::delay_us(10);
}

fn close() {
    mmio::write(PARAM_B, 0);
    mmio::write(PARAM_A, 0);
    mmio::write(CLKMUX, 0);
}

/// One row. `STATUS.DONE` says the block is idle, so it is already set when
/// the command goes in and the poll has to watch it fall and rise again: a
/// poll that only looks for it set returns while the previous command's flag
/// still stands, and `DATA` is then read before the row arrives. Measured on a
/// 4B rev 1.5, where it read row 30 as 0 — `board: boardrev 0 otp 0`, a Pi 3
/// device tree chosen for a 4B, and no GPIO expander, so the kernel lost the
/// card's regulators and the rootfs with them.
pub fn read(row: u32) -> u32 {
    open();
    mmio::write(KEY, row);
    mmio::write(PARAM_B, 0);
    mmio::write(PARAM_A, 0);
    mmio::write(PARAM_A, mmio::read(PARAM_A) | PARAM_A_GO);
    timer::wait(TIMEOUT_US, || mmio::read(STATUS) & STATUS_DONE == 0);
    timer::wait(TIMEOUT_US, || mmio::read(STATUS) & STATUS_DONE != 0);
    mmio::write(PARAM_B, 0);
    mmio::write(PARAM_A, 0);
    let value = mmio::read(DATA);
    close();
    value
}

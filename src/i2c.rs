//! The board I2C bus (BSC at `0x7E20_5E00`), polled, as the first stage
//! drives it: the FXL6408 GPIO expander and the PMICs hang off it.

use crate::{cm, mmio, timer, warn};

const C: u32 = 0x00;
const S: u32 = 0x04;
const DLEN: u32 = 0x08;
const A: u32 = 0x0c;
const FIFO: u32 = 0x10;
const DIV: u32 = 0x14;
const DEL: u32 = 0x18;
const CLKT: u32 = 0x1c;

const BUS_HZ: u32 = 100_000;

const C_I2CEN: u32 = 1 << 15;
const C_ST: u32 = 1 << 7;
const C_CLEAR: u32 = 0b11 << 4;
const C_READ: u32 = 1 << 0;

const S_TA: u32 = 1 << 0;
const S_DONE: u32 = 1 << 1;
const S_TXD: u32 = 1 << 4;
const S_RXD: u32 = 1 << 5;
const S_ERR: u32 = 1 << 8;
const S_CLKT: u32 = 1 << 9;
/// The master's own state, in the top nibble of `S` (undocumented): 0, 4 or 5
/// when it will take a fresh `ST`, something else while a byte is still
/// clocking out.
const S_STATE: u32 = 0xf << 28;
const S_STATE_SHIFT: u32 = 28;
const S_CLEAR: u32 = S_CLKT | S_ERR | S_DONE;

const TIMEOUT_US: u32 = 10_000;

const BASE: u32 = 0x7e20_5e00;

fn reg(off: u32) -> u32 {
    BASE + off
}

fn ready(s: u32) -> bool {
    matches!((s & S_STATE) >> S_STATE_SHIFT, 0 | 4 | 5)
}

fn clear_fifo() {
    mmio::write(reg(C), mmio::read(reg(C)) | C_CLEAR);
}

/// Abort whatever is in flight and set the bus up for `addr` at 100 kHz off
/// the VPU's clock as it stands, the falling edge delayed an eighth of the
/// divider and the rising one half, as the stock first stage does.
fn setup(addr: u8) {
    mmio::write(reg(S), S_CLEAR);
    clear_fifo();
    mmio::write(reg(DLEN), 0);
    mmio::write(reg(C), 0);
    mmio::write(reg(C), C_I2CEN);
    mmio::write(reg(A), addr as u32);
    let div = cm::bootcode_vpu_hz() / BUS_HZ;
    mmio::write(reg(DIV), div);
    mmio::write(reg(CLKT), 0x100);
    mmio::write(reg(DEL), (div / 8).max(1) << 16 | (div / 2).max(1));
}

fn start(len: u32, read: bool) {
    mmio::write(reg(S), S_CLEAR);
    mmio::write(reg(DLEN), len);
    mmio::write(reg(C), C_I2CEN | C_ST | if read { C_READ } else { 0 });
}

fn finish() -> bool {
    let ok = timer::wait(TIMEOUT_US, || mmio::read(reg(S)) & (S_DONE | S_TA) == S_DONE);
    let s = mmio::read(reg(S));
    mmio::write(reg(S), S_CLEAR);
    ok && s & (S_ERR | S_CLKT) == 0
}

fn put(b: u8) -> bool {
    let ok = timer::wait(TIMEOUT_US, || mmio::read(reg(S)) & S_TXD != 0);
    mmio::write(reg(FIFO), b as u32);
    ok
}

/// A register read: the register number written, then one byte read back in
/// a repeated start. The read is armed once the master's state says the
/// register byte is out, not on the write's `DONE`, which this controller
/// raises only after the read.
pub fn read_reg(addr: u8, register: u8) -> Option<u8> {
    setup(addr);
    clear_fifo();
    start(1, false);
    if !timer::wait(TIMEOUT_US, || mmio::read(reg(S)) & (S_TA | S_ERR) != 0) {
        return None;
    }
    mmio::write(reg(FIFO), register as u32);
    let settled = timer::wait(TIMEOUT_US, || {
        let s = mmio::read(reg(S));
        ready(s) || s & (S_ERR | S_CLKT) != 0
    });
    if !settled || mmio::read(reg(S)) & (S_ERR | S_CLKT) != 0 {
        let s = mmio::read(reg(S));
        finish();
        warn!("i2c", "register write stuck"; addr = format_args!("{addr:#04x}"),
            register = format_args!("{register:#04x}"), status = format_args!("{s:#010x}"));
        return None;
    }
    start(1, true);
    if !timer::wait(TIMEOUT_US, || mmio::read(reg(S)) & S_RXD != 0) {
        let s = mmio::read(reg(S));
        finish();
        warn!("i2c", "no data"; addr = format_args!("{addr:#04x}"),
            register = format_args!("{register:#04x}"), status = format_args!("{s:#010x}"));
        return None;
    }
    let v = mmio::read(reg(FIFO)) as u8;
    finish().then_some(v)
}

pub fn write_reg(addr: u8, register: u8, value: u8) -> bool {
    setup(addr);
    clear_fifo();
    start(2, false);
    let ok = put(register) && put(value);
    finish() && ok
}

/// The FXL6408 at 0x43: SD card power and signalling voltage, and the power
/// LED.
pub mod expander {
    use super::{read_reg, write_reg};

    const ADDR: u8 = 0x43;

    const DEVICE_ID: u8 = 0x01;
    const IO_DIR: u8 = 0x03;
    const OUTPUT: u8 = 0x05;
    const OUTPUT_HIGH_Z: u8 = 0x07;
    const PULL_ENABLE: u8 = 0x0b;
    const PULL_UP: u8 = 0x0d;
    const INPUT_STATUS: u8 = 0x0f;

    /// Pins, per the Pi 4's `expgpio`.
    pub const PWR_LED_OFF: u8 = 1 << 2;
    pub const VDD_SD_IO_SEL: u8 = 1 << 4;
    pub const SD_PWR_ON: u8 = 1 << 6;
    const SD_OC_N: u8 = 1 << 7;

    fn read(register: u8) -> u8 {
        read_reg(ADDR, register).unwrap_or(0)
    }

    fn write(register: u8, value: u8) {
        write_reg(ADDR, register, value);
    }

    /// Reset the expander and drive its outputs: SD card power on, 3.3 V
    /// signalling, the power LED lit; SD_OC_N an input with a pull-up.
    pub fn init() {
        read(DEVICE_ID);
        read(IO_DIR);
        read(INPUT_STATUS);
        read(OUTPUT);
        write(DEVICE_ID, 1);
        write(OUTPUT, SD_PWR_ON);
        write(IO_DIR, !SD_OC_N);
        write(PULL_ENABLE, SD_OC_N);
        write(PULL_UP, SD_OC_N);
        write(OUTPUT_HIGH_Z, 0);
    }

    /// Read-modify-write of the direction and output registers.
    pub fn update(dir_clear: u8, dir_set: u8, out_clear: u8, out_set: u8) {
        let dir = read(IO_DIR);
        let out = read(OUTPUT);
        let hiz = read(OUTPUT_HIGH_Z);
        write(IO_DIR, (dir & !dir_clear) | dir_set);
        write(OUTPUT, (out & !out_clear) | out_set);
        write(OUTPUT_HIGH_Z, hiz);
    }
}

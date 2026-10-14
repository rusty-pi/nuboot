//! The master the board's PMICs hang off (`0x7E20_5E00`), polled, one register
//! at a time. The bootloader's timing: 100 kHz off the VPU's clock as it
//! stands.

use crate::{cm, mmio, timer};

const BASE: u32 = 0x7e20_5e00;
const C: u32 = BASE;
const S: u32 = BASE + 0x04;
const DLEN: u32 = BASE + 0x08;
const A: u32 = BASE + 0x0c;
const FIFO: u32 = BASE + 0x10;
const DIV: u32 = BASE + 0x14;
const DEL: u32 = BASE + 0x18;
const CLKT: u32 = BASE + 0x1c;

const C_I2CEN: u32 = 1 << 15;
const C_ST: u32 = 1 << 7;
const C_CLEAR: u32 = 0b11 << 4;
const C_READ: u32 = 1;

const S_TA: u32 = 1;
const S_DONE: u32 = 1 << 1;
const S_TXD: u32 = 1 << 4;
const S_RXD: u32 = 1 << 5;
const S_ERR: u32 = 1 << 8;
const S_CLKT: u32 = 1 << 9;
const S_FAILED: u32 = S_ERR | S_CLKT;
const S_CLEAR: u32 = S_CLKT | S_ERR | S_DONE;
/// The master's state field, which the stock bootloader polls between the
/// register byte of a read and its second start: 0, 4 and 5 take a new start.
const S_STATE_SHIFT: u32 = 28;

const BUS_HZ: u32 = 100_000;
const CLOCK_STRETCH_TICKS: u32 = 0x100;
const TIMEOUT_US: u32 = 10_000;

fn ready(status: u32) -> bool {
    matches!(status >> S_STATE_SHIFT, 0 | 4 | 5)
}

fn setup(addr: u8) {
    mmio::write(S, S_CLEAR);
    mmio::write(C, mmio::read(C) | C_CLEAR);
    mmio::write(DLEN, 0);
    mmio::write(C, 0);
    mmio::write(C, C_I2CEN);
    mmio::write(A, addr as u32);
    let div = cm::vpu_hz() / BUS_HZ;
    mmio::write(DIV, div);
    mmio::write(CLKT, CLOCK_STRETCH_TICKS);
    mmio::write(DEL, (div / 8).max(1) << 16 | (div / 2).max(1));
}

fn start(len: u32, read: bool) {
    mmio::write(S, S_CLEAR);
    mmio::write(DLEN, len);
    mmio::write(C, C_I2CEN | C_ST | if read { C_READ } else { 0 });
}

fn finish() -> bool {
    let ended = timer::wait(TIMEOUT_US, || mmio::read(S) & (S_DONE | S_TA) == S_DONE);
    let status = mmio::read(S);
    mmio::write(S, S_CLEAR);
    ended && status & S_FAILED == 0
}

fn put(byte: u8) -> bool {
    let room = timer::wait(TIMEOUT_US, || mmio::read(S) & S_TXD != 0);
    mmio::write(FIFO, byte as u32);
    room
}

/// Read register `reg` of the part at `addr`.
pub fn read_reg(addr: u8, reg: u8) -> Option<u8> {
    setup(addr);
    start(1, false);
    if !timer::wait(TIMEOUT_US, || mmio::read(S) & (S_TA | S_ERR) != 0) {
        return None;
    }
    mmio::write(FIFO, reg as u32);
    let settled = timer::wait(TIMEOUT_US, || {
        let status = mmio::read(S);
        ready(status) || status & S_FAILED != 0
    });
    if !settled || mmio::read(S) & S_FAILED != 0 {
        finish();
        return None;
    }
    start(1, true);
    if !timer::wait(TIMEOUT_US, || mmio::read(S) & S_RXD != 0) {
        finish();
        return None;
    }
    let value = mmio::read(FIFO) as u8;
    finish().then_some(value)
}

/// Write `value` to register `reg` of the part at `addr`; whether it went
/// through.
pub fn write_reg(addr: u8, reg: u8, value: u8) -> bool {
    setup(addr);
    start(2, false);
    let queued = put(reg) && put(value);
    finish() && queued
}

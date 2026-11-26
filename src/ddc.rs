//! HDMI0's DDC master (`0x7EF0_4500`), the I2C bus a display's EDID ROM is
//! on, polled. It is the set-top-box master Linux drives with
//! `i2c-brcmstb.c`, not the BSC of [`crate::i2c`]: a transfer is at most 32
//! bytes, and a longer read is continued without a new start.

use crate::{mmio, timer};

const BASE: u32 = 0x7ef0_4500;
const CHIP_ADDRESS: u32 = BASE;
const DATA_IN: u32 = BASE + 0x04;
const CNT: u32 = BASE + 0x24;
const CTL: u32 = BASE + 0x28;
const IIC_ENABLE: u32 = BASE + 0x2c;
const DATA_OUT: u32 = BASE + 0x30;
const CTLHI: u32 = BASE + 0x50;

const CTL_READ: u32 = 1;
/// 97.5 kHz: the 390 kHz selection with the divider by four.
const CTL_SPEED: u32 = 1 << 7 | 1 << 4;
const CTLHI_WORD_DATA: u32 = 1 << 6;

const ENABLE: u32 = 1;
const INTRP: u32 = 1 << 1;
const NOACK: u32 = 1 << 2;
const NOSTOP: u32 = 1 << 4;
const NOSTART: u32 = 1 << 5;
const RESTART: u32 = 1 << 6;

const CHUNK: usize = 32;
const TIMEOUT_US: u32 = 100_000;

fn run(conditions: u32) -> bool {
    mmio::write(IIC_ENABLE, conditions | ENABLE);
    let done = timer::wait(TIMEOUT_US, || mmio::read(IIC_ENABLE) & INTRP != 0);
    let acked = mmio::read(IIC_ENABLE) & NOACK == 0;
    mmio::write(CNT, 0);
    mmio::write(IIC_ENABLE, 0);
    done && acked
}

fn send(byte: u8, conditions: u32) -> bool {
    mmio::write(CTL, CTL_SPEED);
    mmio::write(CNT, 1);
    mmio::write(DATA_IN, byte as u32);
    run(conditions)
}

fn receive(out: &mut [u8], conditions: u32) -> bool {
    mmio::write(CTL, CTL_SPEED | CTL_READ);
    mmio::write(CNT, out.len() as u32);
    if !run(conditions) {
        return false;
    }
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = (mmio::read(DATA_OUT + (i as u32 / 4) * 4) >> (8 * (i % 4))) as u8;
    }
    true
}

/// Read `out.len()` bytes from the device at `address`, starting at its
/// register `offset`. Whether the device answered every transfer.
pub fn read(address: u8, offset: u8, out: &mut [u8]) -> bool {
    mmio::write(CTLHI, CTLHI_WORD_DATA);
    mmio::write(CHIP_ADDRESS, (address as u32) << 1);
    if !send(offset, RESTART | NOSTOP) {
        return false;
    }
    mmio::write(CHIP_ADDRESS, (address as u32) << 1 | 1);
    let chunks = out.len().div_ceil(CHUNK);
    for (i, chunk) in out.chunks_mut(CHUNK).enumerate() {
        let start = if i == 0 { 0 } else { NOSTART };
        let stop = if i + 1 == chunks { 0 } else { NOSTOP };
        if !receive(chunk, start | stop) {
            return false;
        }
    }
    true
}

//! The hardware random number generator (RNG200, `0x7E10_4000`).

use crate::{mmio, timer};

const BASE: u32 = 0x7e10_4000;
const CTRL: u32 = BASE;
const RNG_SOFT_RESET: u32 = BASE + 0x04;
const RBG_SOFT_RESET: u32 = BASE + 0x08;
const CTRL_RBGEN: u32 = 0x1fff;
const FIFO_DATA: u32 = BASE + 0x20;
const FIFO_COUNT: u32 = BASE + 0x24;
/// How long a word is given to arrive.
const WORD_US: u32 = 100_000;

/// Start the generator unless something before this has.
pub fn start() {
    if mmio::read(CTRL) & CTRL_RBGEN != 0 && mmio::read(RNG_SOFT_RESET) & 1 == 0 && mmio::read(RBG_SOFT_RESET) & 1 == 0 {
        return;
    }
    mmio::write(CTRL, mmio::read(CTRL) & !CTRL_RBGEN);
    mmio::write(RBG_SOFT_RESET, 1);
    mmio::write(RNG_SOFT_RESET, 1);
    mmio::write(RNG_SOFT_RESET, 0);
    mmio::write(RBG_SOFT_RESET, 0);
    mmio::write(CTRL, mmio::read(CTRL) | 1);
}

/// Fill `buf` from the generator; false if it ran dry.
pub fn fill(buf: &mut [u8]) -> bool {
    start();
    for chunk in buf.chunks_mut(4) {
        if !timer::wait(WORD_US, || mmio::read(FIFO_COUNT) & 0xff != 0) {
            return false;
        }
        chunk.copy_from_slice(&mmio::read(FIFO_DATA).to_le_bytes()[..chunk.len()]);
    }
    true
}

/// Leave the block's interrupts off, as start4 does just before the ARM
/// starts.
pub fn quiesce() {
    mmio::write(BASE + 0x1c, 0);
}

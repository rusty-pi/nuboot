//! The board's power-management ICs, as far as the first stage sets them up.

use crate::i2c;

const SYSTEM: u8 = 0x1d;

/// 0x1D's rail 1, which the first stage idles where 0x1E has the core rail,
/// and a word whose low nibble it steps to 9. What that word controls is not
/// known; its top three bits are written set.
const SYSTEM_RAIL1: u8 = 0x14;
const SYSTEM_RAIL1_IDLE: u8 = 0xa5;
const SYSTEM_REG_19: u8 = 0x19;
const SYSTEM_REG_19_TARGET: u8 = 9;
const SYSTEM_REG_19_HIGH: u8 = 0xe0;

/// What the stock first stage does to 0x1D on a board whose core rail is on
/// 0x1E (a 4B rev 1.4, a Pi 400, a CM4): rail 1 to 0xA5, then register 0x19's
/// low nibble stepped to 9, one write at a time.
pub fn bootcode_setup() {
    i2c::write_reg(SYSTEM, SYSTEM_RAIL1, SYSTEM_RAIL1_IDLE);
    let mut step = i2c::read_reg(SYSTEM, SYSTEM_REG_19).unwrap_or(0) & 0xf;
    while step != SYSTEM_REG_19_TARGET {
        step = if step < SYSTEM_REG_19_TARGET { step + 1 } else { step - 1 };
        i2c::write_reg(SYSTEM, SYSTEM_REG_19, SYSTEM_REG_19_HIGH | step);
    }
}

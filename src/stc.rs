//! The 64-bit free-running system timer counter (`0x7E00_3004`), which
//! `start4.elf` stamps its `MESS:` lines with.

use crate::mmio;

const CLO: u32 = 0x7e00_3004;
const CHI: u32 = 0x7e00_3008;

/// Microseconds since the timer started.
pub fn now() -> u64 {
    loop {
        let hi = mmio::read(CHI);
        let lo = mmio::read(CLO);
        if mmio::read(CHI) == hi {
            return (hi as u64) << 32 | lo as u64;
        }
    }
}

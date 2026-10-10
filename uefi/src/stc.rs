//! The system timer: a 1 MHz count the VPU firmware's log is timed by too,
//! so the two logs share one clock.

const CLO: u64 = 0xFE00_3004;
const CHI: u64 = 0xFE00_3008;

/// Microseconds since the timer started.
pub fn now() -> u64 {
    loop {
        let hi = crate::util::read32(CHI);
        let lo = crate::util::read32(CLO);
        if crate::util::read32(CHI) == hi {
            return (hi as u64) << 32 | lo as u64;
        }
    }
}

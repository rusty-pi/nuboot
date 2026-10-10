//! What the fuses say about the board.

use core::fmt;

use crate::otp;

/// The board's revision code, as `/proc/cpuinfo` prints it (`d03115`).
#[derive(Clone, Copy)]
pub struct Revision(pub u32);

impl Revision {
    pub fn read() -> Revision {
        Revision(otp::read(otp::REVISION))
    }

    pub fn kind(self) -> u32 {
        (self.0 >> 4) & 0xff
    }

    /// The board, as its maker names it.
    pub fn model(self) -> &'static str {
        match self.kind() {
            0x11 => "Raspberry Pi 4 Model B",
            0x13 => "Raspberry Pi 400",
            0x14 => "Compute Module 4",
            0x15 => "Compute Module 4S",
            _ => "unknown board",
        }
    }

    /// The PCB revision, `1.5` on a 4B `d03115`.
    pub fn pcb(self) -> Pcb {
        Pcb(self.0 & 0xf)
    }
}

impl fmt::Display for Revision {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:06x}", self.0)
    }
}

pub struct Pcb(u32);

impl fmt::Display for Pcb {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "1.{}", self.0)
    }
}

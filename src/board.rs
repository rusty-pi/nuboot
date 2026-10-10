//! What the fuses say about the board.

use core::fmt;

use crate::otp;

/// Board types in the revision code.
pub const TYPE_4B: u32 = 0x11;

/// The identity rows the SDRAM bring-up needs.
#[derive(Clone, Copy)]
pub struct Board {
    /// The revision code (`0x00d03115`: a Pi 4B rev 1.5).
    pub revision: u32,
    pub ext_revision: u32,
    pub serial: u32,
}

impl Board {
    pub fn read() -> Board {
        Board {
            revision: otp::read(otp::REVISION),
            ext_revision: otp::read(otp::EXT_REVISION),
            serial: otp::read(otp::SERIAL),
        }
    }

    pub fn kind(&self) -> u32 {
        (self.revision >> 4) & 0xff
    }

    pub fn maker(&self) -> u32 {
        (self.revision >> 16) & 0xf
    }
}

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

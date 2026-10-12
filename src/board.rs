//! What the fuses say about the board.

use core::fmt;

use crate::otp;

/// Board types in the revision code.
pub const TYPE_4B: u32 = 0x11;
pub const TYPE_400: u32 = 0x13;
pub const TYPE_CM4: u32 = 0x14;

/// The first 4B PCB revision whose VL805 has no SPI flash of its own and
/// takes its firmware from the host.
const VL805_FROM_HOST_PCB: u32 = 4;

/// Which power-management parts a board has on its board I2C bus, by board
/// revision as the stock firmware picks them.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Pmics {
    /// 0x1D alone, with every rail: a 4B up to rev 1.3.
    System,
    /// 0x1D, with the core rail on 0x1E: a 4B rev 1.4, a Pi 400 or a CM4.
    SystemAndCore,
    /// 0x1B for the SDRAM and I/O rails, 0x1E for the core: a 4B rev 1.5.
    RailsAndCore,
    Unknown,
}

/// The BCM2711 silicon revision, as the VPU's `version` value gives it:
/// `0x0400_0162` on C0, `0x0400_0161` on B0.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Stepping {
    B0,
    C0,
}

const VERSION_C0: u32 = 0x0400_0162;

core::arch::global_asm!(
    ".pushsection .text.vpu_version, \"ax\"",
    ".globl vpu_version",
    "vpu_version:",
    "    version r0",
    "    rts",
    ".popsection",
);

unsafe extern "C" {
    /// This core's `version` value (core 1 has bit 16 set as well).
    pub safe fn vpu_version() -> u32;
}

pub fn stepping() -> Stepping {
    const CORE_1: u32 = 1 << 16;
    if vpu_version() & !CORE_1 == VERSION_C0 { Stepping::C0 } else { Stepping::B0 }
}

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

    pub fn pmics(&self) -> Pmics {
        Revision(self.revision).pmics()
    }

    /// Whether the VL805 needs its firmware from the host: every board but a
    /// 4B before rev 1.4.
    pub fn vl805_from_host(&self) -> bool {
        self.kind() != TYPE_4B || self.revision & 0xf >= VL805_FROM_HOST_PCB
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

    pub fn pmics(self) -> Pmics {
        match self.kind() {
            TYPE_4B => match self.0 & 0xf {
                0..=3 => Pmics::System,
                4 => Pmics::SystemAndCore,
                _ => Pmics::RailsAndCore,
            },
            TYPE_400 | TYPE_CM4 => Pmics::SystemAndCore,
            _ => Pmics::Unknown,
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

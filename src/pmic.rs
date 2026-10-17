//! The SoC core rail and the status of the power-management parts on the board
//! I2C bus. Which parts a board has depends on its revision ([`Pmics`]): the
//! core rail is on the PMIC at `0x1E` on a 4B rev 1.4 or 1.5, a Pi 400 and a
//! CM4, and on rail 1 of the one at `0x1D` on an older 4B.

use crate::board::Pmics;
use crate::{i2c, timer};

const SYSTEM: u8 = 0x1d;
const RAILS: u8 = 0x1b;
const CORE: u8 = 0x1e;

/// How the core rail is set on a part: the setpoint register and the voltage
/// of a step, the status register and the bit that says the rail has reached
/// its setpoint, and a mode word if the part has one.
#[derive(Clone, Copy)]
struct CorePart {
    addr: u8,
    setpoint: u8,
    step_uv: u32,
    status: u8,
    settled: u8,
    mode: Option<u8>,
}

/// `0x1E`: 10 mV a step, with a mode word set to 5 while the ARM runs above
/// [`TURBO_THRESHOLD_MHZ`] and to 15 otherwise.
const CORE_PART: CorePart =
    CorePart { addr: CORE, setpoint: 0x25, step_uv: 10_000, status: 0x02, settled: 1 << 3, mode: Some(0x24) };
/// `0x1D`'s rail 1: 6.25 mV a step, no mode word.
const SYSTEM_PART: CorePart =
    CorePart { addr: SYSTEM, setpoint: 0x14, step_uv: 6_250, status: 0x1a, settled: 1 << 4, mode: None };
const MODE_FAST: u8 = 5;
const MODE_NORMAL: u8 = 15;

/// Above this ARM rate the core PMIC runs in its fast mode.
pub const TURBO_THRESHOLD_MHZ: u32 = 600;

/// The core voltage the SoC starts at, and the range the rail is kept in
/// (tighter than the parts' own).
pub const CORE_BASE_UV: u32 = 880_000;
const CORE_MIN_UV: u32 = 835_000;
pub const CORE_MAX_UV: u32 = 1_100_000;
/// How long a write may keep failing, and how long the rail may take.
const WRITE_US: u32 = 10_000;
const SETTLE_US: u32 = 100_000;

/// The SoC core rail. It remembers the voltage last asked for and the setpoint
/// last written, and talks to the part only when the setpoint changes.
pub struct CoreRail {
    part: CorePart,
    uv: u32,
    setpoint: u8,
    mode: u8,
}

impl CoreRail {
    /// The rail on the part that has it among `pmics`, if the board's parts are
    /// known.
    pub const fn new(pmics: Pmics) -> Option<CoreRail> {
        let part = match pmics {
            Pmics::System => SYSTEM_PART,
            Pmics::SystemAndCore | Pmics::RailsAndCore => CORE_PART,
            Pmics::Unknown => return None,
        };
        Some(CoreRail { part, uv: 0, setpoint: 0, mode: 0 })
    }

    /// The voltage last asked for, not read back.
    pub fn uv(&self) -> u32 {
        self.uv
    }

    /// Ask for `uv`, rounded up to the next setpoint, and wait for the rail to
    /// settle if the setpoint moved.
    pub fn set_uv(&mut self, uv: u32) {
        let uv = uv.clamp(CORE_MIN_UV, CORE_MAX_UV);
        if uv == self.uv {
            return;
        }
        self.uv = uv;
        let part = self.part;
        let setpoint = uv.div_ceil(part.step_uv) as u8;
        if setpoint == self.setpoint {
            return;
        }
        self.setpoint = setpoint;
        timer::wait(WRITE_US, || i2c::write_reg(part.addr, part.setpoint, setpoint));
        timer::wait(SETTLE_US, || i2c::read_reg(part.addr, part.status).is_none_or(|status| status & part.settled != 0));
    }

    /// The voltage the part is set to, read from it.
    pub fn read_uv(&self) -> Option<u32> {
        let part = self.part;
        i2c::read_reg(part.addr, part.setpoint).map(|setpoint| setpoint as u32 * part.step_uv)
    }

    /// Put the part in its fast mode, or take it out, if it has one.
    pub fn set_fast(&mut self, fast: bool) {
        let Some(register) = self.part.mode else {
            return;
        };
        let mode = if fast { MODE_FAST } else { MODE_NORMAL };
        if mode != self.mode && i2c::write_reg(self.part.addr, register, mode) {
            self.mode = mode;
        }
    }
}

/// The status words the parts report trouble with the power in. `0x1B`'s and
/// `0x1E`'s are latched and written back to clear. `0x1D`'s is good while bit 5
/// is set and bit 6 clear, and bit 6 is cleared by writing it.
const RAILS_STATUS: u8 = 0x00;
const RAILS_FAULTS: u8 = 0x60;
const CORE_STATUS: u8 = 0x05;
const CORE_FAULT: u8 = 1 << 1;
const SYSTEM_STATUS: u8 = 0x1a;
const SYSTEM_GOOD_MASK: u8 = 0x60;
const SYSTEM_GOOD: u8 = 1 << 5;
const SYSTEM_LATCHED: u8 = 1 << 6;
/// How often the status words are looked at.
pub const POLL_US: u32 = 100_000;

/// Whether any of the board's parts reports trouble with the power, which is
/// what an OS reads as under-voltage. A part that does not answer counts as
/// trouble.
pub fn fault(pmics: Pmics) -> bool {
    let mut fault = match pmics {
        Pmics::System | Pmics::SystemAndCore => system_fault(),
        Pmics::RailsAndCore => latched_fault(RAILS, RAILS_STATUS, RAILS_FAULTS, false),
        Pmics::Unknown => return false,
    };
    if pmics != Pmics::System {
        fault |= latched_fault(CORE, CORE_STATUS, CORE_FAULT, true);
    }
    fault
}

/// A status word whose `faults` bits latch: they are written back to clear
/// them, the whole word or, with `masked`, just those bits.
fn latched_fault(addr: u8, register: u8, faults: u8, masked: bool) -> bool {
    let Some(status) = i2c::read_reg(addr, register) else {
        return true;
    };
    if status & faults == 0 {
        return false;
    }
    i2c::write_reg(addr, register, if masked { status & faults } else { status });
    true
}

fn system_fault() -> bool {
    let Some(status) = i2c::read_reg(SYSTEM, SYSTEM_STATUS) else {
        return true;
    };
    if status & SYSTEM_LATCHED != 0 {
        i2c::write_reg(SYSTEM, SYSTEM_STATUS, SYSTEM_LATCHED);
    }
    status & SYSTEM_GOOD_MASK != SYSTEM_GOOD
}

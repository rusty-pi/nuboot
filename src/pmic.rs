//! The SoC core rail, which a Pi 4B rev 1.4 or 1.5 has on the PMIC at `0x1E`.
//!
//! Its setpoint is a word in 10 mV steps. The stock firmware keeps the rail
//! between 0.84 V and 1.1 V; [`lower_core`] never goes below the bottom of
//! that range, and [`restore_core`] puts back the setpoint the rail had.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::{i2c, info, timer, warn};

const CORE: u8 = 0x1e;
const CORE_SETPOINT: u8 = 0x25;
const CORE_STATUS: u8 = 0x02;
const CORE_SETTLED: u8 = 1 << 3;
const CORE_STEP_MV: u32 = 10;
/// The stock firmware's lowest core voltage, as a setpoint: 0.84 V.
pub const CORE_MIN_SETPOINT: u8 = 84;
const SETTLE_US: u32 = 100_000;

/// The setpoint to go back to, or 0 while the rail is as the board left it.
static ORIGINAL: AtomicU32 = AtomicU32::new(0);

/// The core rail's setpoint as the PMIC holds it, if there is a PMIC to ask.
pub fn core_setpoint() -> Option<u8> {
    i2c::read_reg(CORE, CORE_SETPOINT)
}

/// Move the core rail down to `setpoint`, which must be below where it is and
/// not below [`CORE_MIN_SETPOINT`]; whether it moved.
pub fn lower_core(setpoint: u8) -> bool {
    let Some(current) = core_setpoint() else {
        warn!("pmic", "the core rail's PMIC does not answer");
        return false;
    };
    if setpoint < CORE_MIN_SETPOINT || setpoint >= current {
        warn!("pmic", "not moving the core rail"; asked = setpoint, current = current);
        return false;
    }
    if ORIGINAL.load(Ordering::Relaxed) == 0 {
        ORIGINAL.store(current as u32, Ordering::Relaxed);
    }
    let written = i2c::write_reg(CORE, CORE_SETPOINT, setpoint);
    let settled = timer::wait(SETTLE_US, || {
        i2c::read_reg(CORE, CORE_STATUS).is_none_or(|status| status & CORE_SETTLED != 0)
    });
    info!("pmic", "lowered the core rail";
        mv = setpoint as u32 * CORE_STEP_MV, written = written, settled = settled);
    written
}

/// Put the core rail back where [`lower_core`] found it.
pub fn restore_core() {
    let original = ORIGINAL.load(Ordering::Relaxed);
    if original == 0 {
        return;
    }
    let written = i2c::write_reg(CORE, CORE_SETPOINT, original as u8);
    let settled = timer::wait(SETTLE_US, || {
        i2c::read_reg(CORE, CORE_STATUS).is_none_or(|status| status & CORE_SETTLED != 0)
    });
    info!("pmic", "restored the core rail";
        mv = original * CORE_STEP_MV, written = written, settled = settled);
    ORIGINAL.store(0, Ordering::Relaxed);
}

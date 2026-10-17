//! The ARM's clock and the voltage it runs at. The core rail is characterised
//! for this die before the ARM starts ([`crate::avs`]), set for the rate the
//! board runs at, and then the clock is kept inside what the die and the
//! supply can do: it drops to 600 MHz, which needs no more than the rail's
//! base voltage, while the SoC is hot or the PMICs report trouble with the
//! power, and goes back once they stop.

use crate::board::{Board, Pmics, TYPE_400, TYPE_4B};
use crate::{avs, cm, info, pmic, thermal, timer, warn};

/// The first 4B PCB revision that runs boosted by default.
const BOOST_PCB: u32 = 4;
/// Each 1% of the nominal rate above it needs 3.3 mV more.
const BOOST_UV: u32 = 330_000;

/// The temperature the SoC is kept under, in millidegrees. The ARM slows from
/// 5 °C below it and goes back to its rate 10 °C below it.
const LIMIT_MDEG: i32 = 85_000;
const THROTTLE_AT_MDEG: i32 = LIMIT_MDEG - 5_000;
const RELEASE_AT_MDEG: i32 = LIMIT_MDEG - 10_000;

/// The rate the ARM runs at on `board`: the boosted rate on a Pi 400 and a 4B
/// from rev 1.4, whose core PMIC and silicon take it, and the nominal rate on
/// the rest.
pub fn rate(board: &Board) -> u32 {
    let boosted = match board.kind() {
        TYPE_400 => true,
        TYPE_4B => board.revision & 0xf >= BOOST_PCB,
        _ => false,
    };
    if boosted { cm::ARM_BOOST_MHZ } else { cm::ARM_MHZ }
}

struct Governor {
    core: pmic::CoreRail,
    pmics: Pmics,
    /// How far the characterisation put the rail above its base voltage.
    avs_uv: i32,
    /// The rate to run at when nothing holds the ARM back.
    mhz: u32,
    hot: bool,
    under_voltage: bool,
    slowed: bool,
    running: bool,
    /// When the temperature and the power parts were last looked at.
    looked: u32,
}

static mut GOVERNOR: Option<Governor> = None;

fn governor() -> Option<&'static mut Governor> {
    unsafe { (*(&raw mut GOVERNOR)).as_mut() }
}

/// The voltage the rail needs for the ARM to run at `mhz`.
fn core_uv(avs_uv: i32, mhz: u32) -> u32 {
    let boost = mhz.saturating_sub(cm::ARM_MHZ) * BOOST_UV / cm::ARM_MHZ;
    (pmic::CORE_BASE_UV as i32 + avs_uv) as u32 + boost
}

/// Set the rail for an ARM rate. Going down, the voltage goes first and the
/// fast mode after; going up, the other way round.
fn set_core(core: &mut pmic::CoreRail, avs_uv: i32, mhz: u32) {
    let fast = mhz > pmic::TURBO_THRESHOLD_MHZ;
    let uv = core_uv(avs_uv, mhz);
    if uv < core.uv() {
        core.set_uv(uv);
        core.set_fast(fast);
    } else {
        core.set_fast(fast);
        core.set_uv(uv);
    }
}

/// Characterise the core rail and set it for the rate `board` runs at. The
/// rate the ARM can be started at: the board's, or the slow one where the rail
/// cannot be set.
pub fn start(board: &Board) -> u32 {
    let pmics = board.pmics();
    let Some(mut core) = pmic::CoreRail::new(pmics) else {
        warn!("dvfs", "the board's power parts are not known, the ARM stays slow");
        return cm::ARM_SLOW_MHZ;
    };
    let avs_uv = avs::run(&mut core);
    let mhz = rate(board);
    set_core(&mut core, avs_uv, mhz);
    let read = core.read_uv();
    let wanted = core.uv();
    if read.is_none_or(|uv| uv.abs_diff(wanted) > 20_000) {
        warn!("dvfs", "the core rail did not take its setpoint, the ARM stays slow";
            wanted_mv = wanted / 1000, read_mv = read.map_or(0, |uv| uv / 1000));
        return cm::ARM_SLOW_MHZ;
    }
    info!("dvfs", "core rail set"; core_mv = wanted / 1000, read_mv = read.map_or(0, |uv| uv / 1000),
        characterised_mv = avs_uv / 1000, arm_mhz = mhz);
    unsafe {
        *(&raw mut GOVERNOR) = Some(Governor {
            core,
            pmics,
            avs_uv,
            mhz,
            hot: false,
            under_voltage: false,
            slowed: false,
            running: true,
            looked: timer::now(),
        });
    }
    mhz
}

/// Look at the temperature and at the power parts, and slow the ARM or give it
/// its rate back, once in each [`pmic::POLL_US`]: the thread that calls this
/// wakes more often than that.
pub fn poll() {
    let Some(g) = governor().filter(|g| g.running) else {
        return;
    };
    if timer::now().wrapping_sub(g.looked) < pmic::POLL_US {
        return;
    }
    g.looked = timer::now();
    if let Some(temperature) = thermal::latest() {
        if temperature >= THROTTLE_AT_MDEG {
            g.hot = true;
        } else if temperature < RELEASE_AT_MDEG {
            g.hot = false;
        }
    }
    g.under_voltage = pmic::fault(g.pmics);
    let slow = g.hot || g.under_voltage;
    if slow == g.slowed {
        return;
    }
    if slow {
        cm::slow_arm();
        set_core(&mut g.core, g.avs_uv, cm::ARM_SLOW_MHZ);
    } else {
        set_core(&mut g.core, g.avs_uv, g.mhz);
        cm::speed_up_arm(g.mhz);
    }
    g.slowed = slow;
    let core_mv = g.core.read_uv().map_or(0, |uv| uv / 1000);
    if slow {
        info!("dvfs", "ARM slowed"; arm_mhz = cm::ARM_SLOW_MHZ, core_mv = core_mv, hot = g.hot, under_voltage = g.under_voltage);
    } else {
        info!("dvfs", "ARM back to its rate"; arm_mhz = g.mhz, core_mv = core_mv);
    }
}

/// Leave the clock and the rail as they are: the ARM is about to be held.
pub fn stop() {
    if let Some(g) = governor() {
        g.running = false;
    }
}

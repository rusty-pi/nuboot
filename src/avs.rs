//! The SoC's own voltage and speed monitors, and the core-voltage
//! characterisation that sets the rail with them before the ARM's clock goes
//! up.
//!
//! The AVS block (`0x7D5D_2000`) samples a few analogue channels — the
//! temperature sensor on channel 0, the core rail on channel 3 — and counts
//! 24 ring oscillators spread over the die. The PVT block (`0x7D5D_8000`)
//! has 18 more speed monitors, each reporting a pair of counts. The firmware
//! measures all of them at two core voltages 32 steps apart, works out for
//! each the voltage at which it would run exactly at its target speed, and
//! sets the rail to the highest of those, within 0.83..1.1 V. It then writes
//! each monitor's target window, so later passes only have to compare.
//!
//! The die differs from one board to the next, which is why the voltage is
//! measured: a rail set for the worst die would waste power on every other.
//!
//! Voltages here are core-rail readings in tenths of a millivolt, or rail
//! codes: the stock firmware's own steps of about 1.76 mV.

use crate::pmic::{CORE_BASE_UV, CORE_MAX_UV, CoreRail};
use crate::{mmio, otp, timer};

const AVS: u32 = 0x7d5d_2000;
/// Channels whose bit is set are masked off.
const DISABLE_MASK: u32 = AVS + 0x03c;
const DISABLE_MASK_CHANNELS: u32 = 0x7f;
/// Two masks set for the length of a measurement.
const REG_040: u32 = AVS + 0x040;
const REG_044: u32 = AVS + 0x044;
/// Three words the firmware sets up before its first measurement: 0x74 gets
/// its low seven bits set, 0x78 a 1, 0x6C a pulse of all-ones.
const REG_06C: u32 = AVS + 0x06c;
const REG_074: u32 = AVS + 0x074;
const REG_078: u32 = AVS + 0x078;
const RESULT: u32 = AVS + 0x200;
const RESULT_COUNT: u32 = 0x3ff;
const RESULT_VALID: u32 = 1 << 10;
const RESULT_SETTLED: u32 = 1 << 16;
const RING: u32 = AVS + 0x220;
const RING_COUNT: u32 = 0x7fff;
const RING_SETTLED: u32 = 1 << 16;
/// Each ring oscillator's target window, as counts.
const LOWER: u32 = AVS + 0xd00;
const UPPER: u32 = AVS + 0xe00;
/// A window slot past the oscillators that the firmware opens all the way.
const SLOT_34: u32 = 0x34;

const PVT: u32 = 0x7d5d_8000;
const PVT_STRIDE: u32 = 0x40;
const PVT_MAGIC: u32 = 0x10;
const PVT_WINDOW_UPPER_HALF: u32 = 0x14;
const PVT_WINDOW_LOWER_HALF: u32 = 0x18;
const PVT_READING: u32 = 0x1c;
/// What a monitor's magic word holds once the firmware has armed it.
const PVT_ARMED: u32 = 0x7fff_50cf;
/// Readings below this are treated as no reading.
const PVT_MIN_READING: u16 = 10;

const REG_1800: u32 = 0x7d5d_1800;
/// Set when the core rail reads below 0.94 V.
const REG_1800_LOW_CORE: u32 = 1 << 2;
const REG_1814: u32 = 0x7d5d_1814;
const REG_1814_RAISE: u32 = 0x14;
const REG_1818: u32 = 0x7d5d_1818;
/// A per-die word: bit 10 says the rest holds a process corner the core
/// voltage must not go below.
const PROCESS: u32 = 0x7d5d_1820;
const PROCESS_VALID: u32 = 1 << 10;
/// The firmware's own "characterised" flag, which outlives a reset.
const CHAR_DONE: u32 = 0x7d5d_183c;
const REG_A000: u32 = 0x7d5d_a000;

const CORE: u32 = 3;
/// `(count * scale) >> shift`.
const CORE_SCALE: i32 = 100_571;
const CORE_SHIFT: u32 = 13;
const SAMPLES: u32 = 150;
const SAMPLE_POLLS: u32 = 10;

const RINGS: u32 = 24;
const RING_SKIPPED: u32 = 0x00c0_0000;
const RING_POLLS: u32 = 10;
const RING_POLL_US: u32 = 1_000;
const PVTS: u32 = 18;
const PVT_SKIPPED: u32 = 0xc;

/// Per ring oscillator: its target speed, and how much faster it gets per
/// volt (both in the units [`speed`] returns).
const RING_TARGET: [u32; RINGS as usize] = [
    27489, 25952, 21251, 13756, 37254, 34551, 28331, 18508, 107220, 98360, 81625, 52245, 77715,
    68730, 57190, 35983, 72590, 63300, 53105, 34723, 42322, 36809, 31272, 19911,
];
const RING_SLOPE: [u32; RINGS as usize] = [
    50818, 59975, 49028, 47784, 68514, 78909, 64825, 63529, 195285, 220103, 188080, 178756, 154709,
    169321, 143659, 133709, 144050, 154690, 128716, 123365, 87190, 91927, 78417, 72607,
];
/// The PVT monitors' target speeds, for the upper and the lower half of a
/// reading, and the oscillators whose slopes their windows borrow.
const PVT_TARGET_UPPER: u32 = 13756;
const PVT_TARGET_LOWER: u32 = 25952;
const PVT_SLOPE_LOWER: u32 = RING_SLOPE[1];
const PVT_SLOPE_UPPER_FIRST: u32 = RING_SLOPE[1];
const PVT_SLOPE_UPPER_REST: u32 = RING_SLOPE[3];
const PVT_FIRST: u32 = 3;
/// A window is the target speed and the speed 10 mV above it.
const WINDOW_TENTHS_MV: u32 = 100;

/// The process-corner floors, in millivolts, indexed by two fields of
/// [`PROCESS`].
const FLOOR_A_MV: [u32; 16] =
    [808, 798, 788, 778, 768, 758, 748, 738, 818, 828, 838, 848, 858, 868, 878, 888];
const FLOOR_B_MV: [u32; 8] = [808, 803, 798, 788, 813, 818, 828, 838];
const FLOOR_MARGIN: u32 = 500;

/// The reading the search starts from, and how close it has to get.
const SETTLE_TARGET: u32 = 10_300;
const SETTLE_SLACK: u32 = 50;
const SETTLE_TRIES: u32 = 100;
/// The low measuring point, in codes below the high one.
const SPAN: i32 = 32;
/// Two readings closer than this mean the rail did not move.
const MIN_SPREAD: i32 = 100;
const ROUNDS: u32 = 2;
/// The range the result is held to.
const MIN_READING: u32 = 8_300;
const MAX_READING: u32 = 11_000;
/// A result below this moves the low measuring point up for the next round.
const LOW_READING: u32 = 9_400;
const LOW_STEP: i32 = 16;
/// Codes per step as the rail is walked, and the pause after each.
const WALK_STEP: i32 = 12;
const WALK_PAUSE_US: u32 = 300;
/// How long the rail gets after a move before it is measured.
const SETTLE_US: u32 = 32_000;
/// A monitoring pass lowers the rail by one step, or raises it by two.
const TRIM_STEP: i32 = 2;
const REG_1818_PAUSE_US: u32 = 5_000;
const PVT_PAUSE_US: u32 = 2;
const MASK_PAUSE_US: u32 = 20;
const SAMPLE_PAUSE_US: u32 = 4;
/// The OTP row whose set bits each add 10 mV to the core voltage.
const OTP_BOOST: u32 = otp::CORE_BOOST;
const OTP_BOOST_UV: i32 = 10_000;

fn bit(mask: u32, ch: u32) -> bool {
    mask & 1 << ch != 0
}

/// A rail code's voltage in microvolts, and back.
fn code_uv(code: i32) -> u32 {
    ((code as u32).wrapping_mul(0x0011_9400) >> 16) * 100
}

fn uv_code(uv: u32) -> i32 {
    ((uv / 100).wrapping_mul(0xe904) >> 20) as i32
}

/// A ring or PVT count as a speed, and a speed as a count.
fn speed(count: u32) -> u32 {
    count * 54_000 / 0x7fff * 10
}

const fn count(speed: u32) -> u32 {
    speed / 54 * 0x7fff / 10_000
}

fn window(target: u32, slope: u32) -> (u32, u32) {
    (count(target), count(slope * WINDOW_TENTHS_MV / 10_000 + target))
}

/// One sample of an analogue channel, 0 if it has none.
fn sample(ch: u32) -> u32 {
    let mut value = 0;
    for _ in 0..SAMPLE_POLLS {
        value = mmio::read(RESULT + ch * 4);
        if value & RESULT_VALID != 0 && value & RESULT_SETTLED != 0 {
            break;
        }
    }
    if value & RESULT_VALID == 0 { 0 } else { value & RESULT_COUNT }
}

/// The average of up to 150 samples of one channel, the others masked off.
fn average(ch: u32) -> u32 {
    mmio::write(DISABLE_MASK, !(1 << ch) & DISABLE_MASK_CHANNELS);
    mmio::write(REG_040, !0);
    mmio::write(REG_044, !0);
    timer::delay_us(MASK_PAUSE_US);
    let (mut sum, mut taken) = (0, 0);
    for _ in 0..SAMPLES {
        let value = sample(ch);
        if value != 0 {
            sum += value;
            taken += 1;
            timer::delay_us(SAMPLE_PAUSE_US);
        }
    }
    mmio::write(DISABLE_MASK, 0);
    let average = if taken != 0 { sum / taken } else { 0 };
    mmio::write(REG_040, 0);
    mmio::write(REG_044, 0);
    average
}

/// The core rail, in tenths of a millivolt.
fn core_reading() -> u32 {
    (average(CORE) as i32 * CORE_SCALE >> CORE_SHIFT) as u32
}

/// A ring oscillator's count, 0 if it never settles.
fn ring(ch: u32) -> u32 {
    for _ in 0..RING_POLLS {
        let value = mmio::read(RING + ch * 4);
        if value & RING_SETTLED != 0 {
            return value & RING_COUNT;
        }
        timer::delay_us(RING_POLL_US);
    }
    0
}

fn pvt(ch: u32, reg: u32) -> u32 {
    PVT + ch * PVT_STRIDE + reg
}

/// A PVT monitor's reading as its upper and lower half, (0, 0) if the
/// monitor is not armed.
fn pvt_reading(ch: u32) -> (u16, u16) {
    if mmio::read(pvt(ch, PVT_MAGIC)) != PVT_ARMED {
        return (0, 0);
    }
    let value = mmio::read(pvt(ch, PVT_READING));
    let keep = |half: u16| if half < PVT_MIN_READING { 0 } else { half };
    timer::delay_us(PVT_PAUSE_US);
    (keep((value >> 16) as u16), keep(value as u16))
}

fn pvt_window(ch: u32, reg: u32) -> (u32, u32) {
    let value = mmio::read(pvt(ch, reg));
    timer::delay_us(PVT_PAUSE_US);
    (value & 0xffff, value >> 16)
}

fn set_pvt_window(ch: u32, reg: u32, (lower, upper): (u32, u32)) {
    mmio::write(pvt(ch, reg), lower & 0xffff | upper << 16);
    timer::delay_us(PVT_PAUSE_US);
}

/// The monitors' set-up, done again whenever a measurement starts.
fn arm(pvt_skipped: u32) {
    mmio::write(REG_074, mmio::read(REG_074) | 0x7f);
    mmio::write(REG_078, 1);
    mmio::write(REG_06C, !0);
    mmio::write(REG_06C, 0);
    mmio::write(LOWER + SLOT_34 * 4, !0);
    mmio::write(UPPER + SLOT_34 * 4, !0);
    for ch in (0..PVTS).filter(|&ch| !bit(pvt_skipped, ch)) {
        mmio::write(pvt(ch, PVT_MAGIC), PVT_ARMED);
        timer::delay_us(PVT_PAUSE_US);
    }
}

/// The voltage at which a monitor would run at `target`, given its counts at
/// the two measuring points; the low point if it barely moved.
fn crossing(count_high: u32, count_low: u32, low: i32, high: i32, target: u32) -> i32 {
    if count_high.abs_diff(count_low) <= 1 {
        return low;
    }
    let (speed_high, speed_low) = (speed(count_high), speed(count_low));
    let per_volt =
        speed_high.wrapping_sub(speed_low).wrapping_mul(10_000) / high.wrapping_sub(low) as u32;
    if per_volt == 0 {
        return low;
    }
    let offset =
        (target.wrapping_sub(speed_low).wrapping_mul(10_000) as i32).wrapping_div(per_volt as i32);
    low.wrapping_add(offset)
}

/// The floor this die's process corner sets, 0 if it sets none.
fn process_floor() -> u32 {
    if mmio::read(PROCESS) & PROCESS_VALID == 0 {
        return 0;
    }
    let fields = (mmio::read(PROCESS) & 0x00ff_f800) >> 11;
    let _ = mmio::read(PROCESS);
    let a = FLOOR_A_MV[(fields >> 6 & 0xf) as usize] * 10;
    let b = FLOOR_B_MV[(fields >> 3 & 0x7) as usize] * 10;
    a.max(b) + FLOOR_MARGIN
}

fn low_core_flag() {
    let low = core_reading() < LOW_READING;
    let value = mmio::read(REG_1800) & !REG_1800_LOW_CORE;
    mmio::write(REG_1800, value | if low { REG_1800_LOW_CORE } else { 0 });
}

fn clear_1818() {
    mmio::write(REG_1818, 0);
    timer::delay_us(REG_1818_PAUSE_US);
}

struct Monitors<'a> {
    core: &'a mut CoreRail,
    pvt_skipped: u32,
}

impl Monitors<'_> {
    fn code(&self) -> i32 {
        uv_code(self.core.uv())
    }

    /// Walk the rail to `code` in steps of 12, asking for the final voltage
    /// each time, and give it time to settle.
    fn move_to(&mut self, code: i32) {
        let mut at = self.code();
        while at != code {
            let left = code - at;
            if left < WALK_STEP + 1 {
                at -= WALK_STEP;
                if left > -(WALK_STEP + 1) {
                    at = code;
                }
            } else {
                at += WALK_STEP;
            }
            self.core.set_uv(code_uv(code));
            timer::delay_us(WALK_PAUSE_US);
        }
        timer::delay_us(SETTLE_US);
    }

    fn measure(&mut self, code: i32) -> i32 {
        self.move_to(code);
        core_reading() as i32
    }

    /// The code at which the rail reads 1.03 V, found by stepping towards
    /// it; `start` if it cannot be found.
    fn settle(&mut self, start: i32) -> i32 {
        let mut code = start;
        for _ in 0..SETTLE_TRIES {
            let reading = self.measure(code) as u32;
            if reading.abs_diff(SETTLE_TARGET) <= SETTLE_SLACK {
                return code;
            }
            let error = SETTLE_TARGET.wrapping_sub(reading) as i32;
            code += error.wrapping_mul(0xe904) >> 20;
        }
        start
    }

    /// Measure every monitor at `high` and at `low`: the highest voltage any
    /// of them needs, and the rail's two readings.
    fn round(&mut self, low: i32, high: i32) -> Option<(i32, i32, i32)> {
        let reading_high = self.measure(high);
        let mut rings = [0; RINGS as usize];
        for ch in (0..RINGS).filter(|&ch| !bit(RING_SKIPPED, ch)) {
            rings[ch as usize] = ring(ch);
        }
        let mut pvts = [(0, 0); PVTS as usize];
        for ch in (0..PVTS).filter(|&ch| !bit(self.pvt_skipped, ch)) {
            pvts[ch as usize] = pvt_reading(ch);
        }
        let reading_low = self.measure(low);
        if reading_high - reading_low < MIN_SPREAD {
            return None;
        }

        let at = |high: u32, low: u32, target: u32| {
            crossing(high, low, reading_low, reading_high, target)
        };
        let mut needed = 0;
        for ch in (0..RINGS).filter(|&ch| !bit(RING_SKIPPED, ch)) {
            let (high, low) = (rings[ch as usize], ring(ch));
            if high != 0 && low != 0 {
                needed = needed.max(at(high, low, RING_TARGET[ch as usize]));
            }
        }
        for ch in (0..PVTS).filter(|&ch| !bit(self.pvt_skipped, ch)) {
            let (upper, lower) = pvt_reading(ch);
            let (high_upper, high_lower) = pvts[ch as usize];
            if high_upper != 0 && high_lower != 0 && upper != 0 && lower != 0 {
                let upper = at(high_upper as u32, upper as u32, PVT_TARGET_UPPER);
                let lower = at(high_lower as u32, lower as u32, PVT_TARGET_LOWER);
                needed = needed.max(upper).max(lower);
            }
        }
        Some((needed, reading_low, reading_high))
    }

    /// Find the core voltage every monitor is happy at and set the rail to
    /// it; `None` if the rail did not respond.
    fn characterise(&mut self) -> Option<()> {
        let floor = process_floor();
        let start = self.code();
        self.core.set_uv(code_uv(start));
        let high = self.settle(start);
        let mut low = high - SPAN;
        let mut code = 0;
        for _ in 0..ROUNDS {
            let (needed, reading_low, reading_high) = self.round(low, high)?;
            let mut wanted = (needed as u32).clamp(MIN_READING, MAX_READING);
            if floor != 0 && wanted < floor {
                wanted = floor;
            }
            let per_tenth = (high - low) * 10_000 / (reading_high - reading_low);
            let above_low = wanted.wrapping_sub(reading_low as u32).wrapping_mul(per_tenth as u32);
            code = above_low as i32 / 10_000 + low;
            if wanted < LOW_READING {
                low = code + LOW_STEP;
            }
        }
        if mmio::read(PROCESS) & PROCESS_VALID != 0 {
            core_reading();
            clear_1818();
            while mmio::read(REG_1814) & REG_1814_RAISE != 0 && code_uv(code) < CORE_MAX_UV {
                clear_1818();
                code += LOW_STEP;
                self.measure(code);
            }
        }
        low_core_flag();
        self.measure(code);
        Some(())
    }

    /// Write every monitor's target window. With this firmware's parameters
    /// the windows do not depend on the measurement.
    fn set_windows(&self) {
        for ch in (0..RINGS).filter(|&ch| !bit(RING_SKIPPED, ch)) {
            let (lower, upper) = window(RING_TARGET[ch as usize], RING_SLOPE[ch as usize]);
            mmio::write(LOWER + ch * 4, lower);
            mmio::write(UPPER + ch * 4, upper);
        }
        for ch in (0..PVTS).filter(|&ch| !bit(self.pvt_skipped, ch)) {
            let lower = window(PVT_TARGET_LOWER, PVT_SLOPE_LOWER);
            set_pvt_window(ch, PVT_WINDOW_LOWER_HALF, lower);
            let slope = if ch < PVT_FIRST { PVT_SLOPE_UPPER_FIRST } else { PVT_SLOPE_UPPER_REST };
            set_pvt_window(ch, PVT_WINDOW_UPPER_HALF, window(PVT_TARGET_UPPER, slope));
        }
    }

    /// One monitoring pass: pull the rail back into range if it has left it,
    /// otherwise raise it if any monitor is below its window, or lower it if
    /// none is inside its window.
    fn trim(&mut self) {
        let reading = core_reading();
        if !(MIN_READING..=MAX_READING).contains(&reading) {
            let step = if reading > MAX_READING { -2 * TRIM_STEP } else { 2 * TRIM_STEP };
            let code = self.code() + step;
            self.move_to(code);
            return;
        }

        let (mut can_lower, mut raise) = (true, false);
        for ch in (0..RINGS).filter(|&ch| !bit(RING_SKIPPED, ch)) {
            let count = ring(ch);
            if count == 0 {
                continue;
            }
            let (low, high) = (mmio::read(LOWER + ch * 4), mmio::read(UPPER + ch * 4));
            if low != 0 && count < low {
                raise = true;
            } else if high != 0 && count <= high {
                can_lower = false;
            }
        }
        for ch in 0..PVTS {
            if bit(self.pvt_skipped, ch) {
                continue;
            }
            let (upper, lower_half) = pvt_reading(ch);
            if upper == 0 && lower_half == 0 {
                self.pvt_skipped |= 1 << ch;
            }
            if upper == 0 || lower_half == 0 {
                continue;
            }
            let (upper, lower_half) = (upper as u32, lower_half as u32);
            let (upper_low, upper_high) = pvt_window(ch, PVT_WINDOW_UPPER_HALF);
            let (lower_low, lower_high) = pvt_window(ch, PVT_WINDOW_LOWER_HALF);
            let slow =
                (lower_low != 0 && lower_half < lower_low) || (upper_low != 0 && upper < upper_low);
            if slow {
                raise = true;
            } else if (lower_high != 0 && lower_half <= lower_high)
                || (upper_high != 0 && upper <= upper_high)
            {
                can_lower = false;
            }
        }

        let at = self.code();
        let reading = core_reading();
        raise |= reading < MIN_READING;
        can_lower |= reading > MAX_READING;
        let code = if raise {
            at + 2 * TRIM_STEP
        } else if can_lower {
            at - TRIM_STEP
        } else {
            at
        };
        if code != at {
            self.move_to(code);
        }
    }
}

/// Characterise the core rail (once per power-up) and trim it. Returns how far
/// the rail ended up above the 880 mV it started at, in microvolts, which the
/// ARM's voltage is computed from.
pub fn run(core: &mut CoreRail) -> i32 {
    core.set_uv(CORE_BASE_UV);
    arm(0);

    let mut monitors = Monitors { core, pvt_skipped: PVT_SKIPPED };
    let done = mmio::read(CHAR_DONE) != 0;
    mmio::write(CHAR_DONE, 0);
    mmio::write(REG_A000, 0xa0);
    let characterised = done || {
        for ch in (0..PVTS).filter(|&ch| !bit(PVT_SKIPPED, ch)) {
            pvt_reading(ch);
        }
        arm(PVT_SKIPPED);
        let characterised = monitors.characterise().is_some();
        if characterised {
            monitors.set_windows();
        }
        characterised
    };
    if characterised {
        mmio::write(CHAR_DONE, 1);
    }
    monitors.trim();
    low_core_flag();

    let core = monitors.core;
    let uv = core.read_uv().unwrap_or(core.uv());
    let boost = otp::read(OTP_BOOST).count_ones() as i32 * OTP_BOOST_UV;
    uv as i32 - CORE_BASE_UV as i32 + boost
}

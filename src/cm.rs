//! The clock manager (`0x7E10_1000`): the generators of the peripheral
//! clocks this firmware drives.

use crate::board::{self, Stepping};
use crate::mmio::{self, PASSWD};
use crate::timer;

const BASE: u32 = 0x7e10_1000;

/// The PL011's generator; its divider is the word after it.
pub const UART_CTL: u32 = 0x0f0;

const OSC_HZ: u64 = 54_000_000;

/// The 12.12 fixed-point divider that takes the oscillator to `hz`.
pub const fn osc_div(hz: u32) -> u32 {
    ((OSC_HZ << 12) / hz as u64) as u32
}

/// Generator sources, numbered the way the peripheral clocks number them.
pub const SRC_OSC: u32 = 1;
pub const ENAB: u32 = 1 << 4;
const BUSY: u32 = 1 << 7;
/// Stops a generator at once, mid-cycle (Linux's `CM_KILL`).
const KILL: u32 = 1 << 5;

/// How long to give a generator to stop or start before going on regardless.
const SETTLE_US: u32 = 1000;

/// Stop a clock generator, give it a new divider and restart it with `ctl`
/// (source and enable).
///
/// A generator still `BUSY` when it is given a new divider or source stays
/// stuck, so it is stopped first and killed if it does not stop; and one that
/// has been asked to run is not running until `BUSY` says so, so whatever it
/// clocks is not used before then. Both waits are bounded, since the model
/// holds `BUSY` clear.
pub fn set_generator(ctl_off: u32, div: u32, ctl: u32) {
    let reg = BASE + ctl_off;
    mmio::write(reg, PASSWD);
    if !timer::wait(SETTLE_US, || mmio::read(reg) & BUSY == 0) {
        mmio::write(reg, PASSWD | KILL);
        timer::wait(SETTLE_US, || mmio::read(reg) & BUSY == 0);
    }
    mmio::write(reg + 4, PASSWD | div);
    mmio::write(reg, PASSWD | ctl);
    if ctl & ENAB != 0 {
        timer::wait(SETTLE_US, || mmio::read(reg) & BUSY != 0);
    }
}

/// An A2W register the first stage writes before it starts the PLLs.
pub const A2W_1390: u32 = 0x1390;

/// The VPU's clock once the bootloader has started the PLLs and moved it onto
/// one, which is where it hands over: the board I2C bus divides down from it.
const VPU_HZ_ON_PLL: u32 = 500_000_000;

/// A clock manager or A2W register, by its offset from `0x7E10_1000`; the
/// password goes in with the value.
pub fn write(off: u32, value: u32) {
    mmio::write(BASE + off, PASSWD | value);
}

pub fn read(off: u32) -> u32 {
    mmio::read(BASE + off)
}

pub const PERII_CTL: u32 = 0x020;
pub const ISP_DIV: u32 = 0x034;
/// Another pair Linux does not list, written with 0x36 and 0 as start4 applies
/// `config.txt`. Not known to be a generator.
pub const REG_128: u32 = 0x128;
pub const REG_12C: u32 = 0x12c;
/// A divider of 1.
pub const DIV_ONE: u32 = 1 << 12;
pub const V3D_CTL: u32 = 0x038;
pub const H264_CTL: u32 = 0x028;
pub const ISP_CTL: u32 = 0x030;
pub const GEN_1C8_CTL: u32 = 0x1c8;
pub const GEN_208_CTL: u32 = 0x208;
/// The two generators the Ethernet MAC runs from.
pub const GEN_1E8_CTL: u32 = 0x1e8;
/// Generators the stock firmware enables for peripherals this firmware does
/// not identify.
pub const GEN_1F0_CTL: u32 = 0x1f0;
pub const GEN_1F8_CTL: u32 = 0x1f8;
pub const GEN_200_CTL: u32 = 0x200;
pub const GEN_22C_CTL: u32 = 0x22c;
pub const GEN_210_CTL: u32 = 0x210;
pub const SRC_PLLA_CORE: u32 = 4;
pub const SRC_PLLC_PER: u32 = 5;
pub const SRC_PLLD_PER: u32 = 6;
pub const EMMC2_CTL: u32 = 0x1d0;

/// PLLD's peripheral channel, which the UART and SD generators run from.
const PLLD_PER_HZ: u64 = 750_000_000;

/// The 12.12 fixed-point divider that takes PLLD's peripheral channel to `hz`.
pub const fn plld_per_div(hz: u32) -> u32 {
    ((PLLD_PER_HZ << 12) / hz as u64) as u32
}
const SRC: u32 = 0xf;
/// Set with a generator's source before it is enabled (Linux's clk-bcm2835
/// calls the bit `CM_GATE`).
pub const GATE: u32 = 1 << 6;
const DIV_PENDING: u32 = 1 << 8;
const COUNTDOWN: u32 = 0x100;
const CM_LOCK: u32 = 0x114;


/// Write `ctl`, which has `ENAB` clear, and wait for the generator to stop;
/// kill it if it does not. One whose source has stopped never finishes its
/// cycle, and one given a new divider or source while still `BUSY` stays
/// stuck: after a warm restart that left the UART's generator on PLLD, the
/// PL011 had no clock until start4 moved it again, and every byte the stages
/// printed waited out its timeout. start4 kills a generator the same way
/// (`0x3EC7F908`..`0x3EC7F928`).
fn stop(reg: u32, ctl: u32) {
    mmio::write(reg, PASSWD | ctl);
    if !timer::wait(1000, || mmio::read(reg) & BUSY == 0) {
        mmio::write(reg, PASSWD | ctl | KILL);
        timer::wait(1000, || mmio::read(reg) & BUSY == 0);
    }
}


/// Run a generator from `src` with a new divider, the way start4 does. A
/// running generator that keeps its source just gets the new divider. One
/// that is off or changes source is stopped first and enabled again at the
/// end; its divider goes in before the source when it slows the clock down
/// and after it otherwise, so the output never runs faster than its old or
/// new rate.
pub fn switch_generator(ctl_off: u32, div: u32, src: u32) {
    let reg = BASE + ctl_off;
    let ctl = mmio::read(reg);
    let restart = ctl & SRC != src || ctl & ENAB == 0;
    if restart {
        stop(reg, ctl & !ENAB);
    }
    let div_first = !restart || div > mmio::read(reg + 4);
    if div_first {
        mmio::write(reg + 4, PASSWD | div);
        if !restart {
            timer::wait(1000, || mmio::read(reg) & DIV_PENDING == 0);
        }
    }
    let running = if restart { 0 } else { ENAB };
    mmio::write(reg, PASSWD | src | GATE | running);
    if !div_first {
        timer::wait(1000, || mmio::read(reg) & BUSY == 0);
        mmio::write(reg + 4, PASSWD | div);
    }
    mmio::write(reg, PASSWD | src | GATE | ENAB);
}

/// Wait out `ticks` on the countdown.
pub fn countdown(ticks: u32) {
    write(COUNTDOWN, ticks);
    timer::wait(10_000, || read(COUNTDOWN) == 0);
}

/// The clock the SCB peripherals run from: the PCIe root complex, the GENET
/// Ethernet MAC and the AVS/PVT monitors (the `0x7d5x_xxxx` block). It is
/// generator `0x200` off PLLC's peripheral channel, which the stock bootloader
/// starts for `start4` in its `start_pllc`.
///
/// The bootloader leaves it running on an SD or network boot, so this firmware
/// inherited it and never started it; on a boot off a USB drive it does not,
/// and then the first access to any SCB register does not fault but stalls the
/// VPU's bus for about 11 s and reads back zero. A handful of those -- the
/// temperature sensor, `pcie::reset`, `pcie::init` -- overrun the boot
/// watchdog's budget before the ARM starts, and the board resets in a loop.
/// Measured on a Raspberry Pi 4B d03115. Starting it here makes the firmware
/// bring the SCB up itself rather than depend on the medium it booted from.
pub fn start_scb_clock() {
    switch_generator(GEN_200_CTL, 6 << 12, SRC_PLLC_PER);
}

/// A PLL's words: its channel holds and analog reset in the clock manager,
/// and its analog, control and fraction words in the A2W half (Linux's
/// clk-bcm2835 offsets).
pub struct Pll {
    cm: u32,
    ana: u32,
    ctrl: u32,
    frac: u32,
    /// The channel holds start4 sets while it reprograms the PLL.
    hold: u32,
    lock: u32,
}

pub const PLLA: Pll =
    Pll { cm: 0x104, ana: 0x1010, ctrl: 0x1100, frac: 0x1200, hold: 0x6aa, lock: 1 << 8 };
pub const PLLB: Pll =
    Pll { cm: 0x170, ana: 0x10f0, ctrl: 0x11e0, frac: 0x12e0, hold: 1 << 1, lock: 1 << 9 };
pub const PLLC: Pll =
    Pll { cm: 0x108, ana: 0x1030, ctrl: 0x1120, frac: 0x1220, hold: 0x6aa, lock: 1 << 10 };
pub const PLLD: Pll =
    Pll { cm: 0x10c, ana: 0x1050, ctrl: 0x1140, frac: 0x1240, hold: 0x6aa, lock: 1 << 11 };

/// PLL output channels: a divider, and a bit that turns the channel off.
pub const PLLA_CORE: u32 = 0x1400;
pub const PLLB_ARM: u32 = 0x13e0;
pub const PLLC_PER: u32 = 0x1520;
pub const PLLD_PER: u32 = 0x1540;
pub const PLLD_CORE: u32 = 0x1440;
const CHANNEL_DIV: u32 = 0xff;
const CHANNEL_DISABLE: u32 = 1 << 8;

const PLL_ANARST: u32 = 1 << 8;
const PLL_CTRL_NDIV: u32 = 0x3ff;
const PLL_CTRL_PDIV: u32 = 0x7 << 12;
const PLL_CTRL_PRST_DISABLE: u32 = 1 << 17;
/// The analog words, first to fourth (start4 writes them the other way
/// round) as it programs a PLL.
const PLL_ANA: [u32; 4] = [0, 0x0011_c000, 0x4000, 0];
/// Oscillator ticks start4 waits with the analog side held.
const PLL_SETTLE_TICKS: u32 = 0x36;
/// Oscillator ticks (10 µs) start4 waits after each step of a channel divider
/// that comes down.
const CHANNEL_STEP_TICKS: u32 = 540;

/// Program `pll` to `ndiv + frac / 2^20` times the oscillator the way start4
/// does, which is also Linux's clk-bcm2835 order: hold the channels, put the
/// analog side in reset and program it, release it, wait for lock, release
/// the channels, then take the PLL out of its power-on reset. `prepare` runs
/// before the channels are held, `locked` right after they are released.
pub fn start_pll(pll: &Pll, ndiv: u32, frac: u32, prepare: impl FnOnce(), locked: impl FnOnce()) {
    let _ = read(pll.ana + 8);
    let _ = read(pll.ctrl);
    prepare();
    let _ = read(pll.cm);
    for word in (0..4).rev() {
        let _ = read(pll.ana + 4 * word);
    }
    write(pll.cm, read(pll.cm) | pll.hold);
    countdown(PLL_SETTLE_TICKS);
    write(pll.cm, read(pll.cm) | PLL_ANARST);
    for (word, value) in PLL_ANA.iter().enumerate().rev() {
        write(pll.ana + 4 * word as u32, *value);
    }
    write(pll.frac, frac);
    let ctrl = read(pll.ctrl) & !(PLL_CTRL_NDIV | PLL_CTRL_PDIV);
    write(pll.ctrl, ctrl | 1 << 12 | ndiv);
    write(pll.cm, read(pll.cm) & !PLL_ANARST);
    timer::wait(100_000, || read(CM_LOCK) & pll.lock != 0);
    write(pll.cm, read(pll.cm) & !pll.hold);
    locked();
    write(pll.ctrl, read(pll.ctrl) | PLL_CTRL_PRST_DISABLE);
}

/// Take a running PLL to `ndiv + frac / 2^20` times the oscillator the way
/// start4 changes the ARM's rate: the fraction first, then the multiplier one
/// step at a time, then the analog reset released and the lock awaited as
/// after a cold start, and the bits the PLL's clock manager word had before
/// put back.
pub fn ramp_pll(pll: &Pll, ndiv: u32, frac: u32) {
    let _ = read(pll.ana + 8);
    let _ = read(pll.ctrl);
    let before = read(pll.cm);
    let mut at = read(pll.ctrl) & PLL_CTRL_NDIV;
    write(pll.frac, frac);
    while at != ndiv {
        at = if at < ndiv { at + 1 } else { at - 1 };
        let ctrl = read(pll.ctrl) & !(PLL_CTRL_NDIV | PLL_CTRL_PDIV);
        write(pll.ctrl, ctrl | 1 << 12 | at);
    }
    write(pll.cm, read(pll.cm) & !PLL_ANARST);
    timer::wait(100_000, || read(CM_LOCK) & pll.lock != 0);
    write(pll.cm, read(pll.cm) & before);
}

/// `pll`'s integer multiplier.
pub fn ndiv(pll: &Pll) -> u32 {
    read(pll.ctrl) & PLL_CTRL_NDIV
}

/// Turn a PLL channel on with divider `div`.
pub fn start_channel(pll: &Pll, channel: u32, div: u32) {
    let value = read(channel) & !(CHANNEL_DISABLE | CHANNEL_DIV);
    write(channel, value | div);
    write(pll.cm, read(pll.cm) & !pll.hold);
}

/// Give a running PLL channel divider `div` the way start4's rate code does: a
/// divider that comes down (a faster clock) steps there one at a time, 10 µs
/// apart; the channel's hold is released at the end.
pub fn set_channel(pll: &Pll, channel: u32, div: u32) {
    let mut at = read(channel) & CHANNEL_DIV;
    while at > div {
        at -= 1;
        write(channel, at);
        countdown(CHANNEL_STEP_TICKS);
    }
    write(channel, div);
    write(pll.cm, read(pll.cm) & !pll.hold);
}

/// Turn a generator off, keeping its source and divider, and wait for it to
/// stop.
pub fn stop_generator(ctl_off: u32) {
    let reg = BASE + ctl_off;
    write(ctl_off, mmio::read(reg) & !ENAB);
    timer::wait(1000, || mmio::read(reg) & BUSY == 0);
}

/// The ARM rates start4 runs a board at: the default, and what `arm_boost`
/// gives a board that takes it.
pub const ARM_MHZ: u32 = 1500;
pub const ARM_BOOST_MHZ: u32 = 1800;
/// The ARM channel halves PLLB for the ARM at full rate.
const ARM_DIV: u32 = 2;
/// PLLB runs no slower than this for the ARM: the rate `slow_arm` keeps it at
/// while the channel divides by three for 600 MHz.
const ARM_PLL_MIN_MHZ: u32 = 1800;
/// The largest divider the ARM channel is given.
const ARM_DIV_MAX: u32 = 8;

/// The ARM channel's divider for `arm_mhz`: the smallest from [`ARM_DIV`] that
/// leaves PLLB at [`ARM_PLL_MIN_MHZ`] or above, so a rate below 900 MHz runs
/// the PLL where `slow_arm` already runs it rather than under it.
pub const fn arm_div(arm_mhz: u32) -> u32 {
    let mut div = ARM_DIV;
    while div < ARM_DIV_MAX && arm_mhz * div < ARM_PLL_MIN_MHZ {
        div += 1;
    }
    div
}

const _: () = {
    assert!(arm_div(1800) == 2 && arm_div(1500) == 2 && arm_div(900) == 2);
    assert!(arm_div(800) == 3 && arm_div(ARM_SLOW_MHZ) == ARM_SLOW_DIV);
};
/// The 600 MHz start4 slows the ARM to once it runs: PLLB at 1800 MHz,
/// divided by 3.
pub const ARM_SLOW_MHZ: u32 = 600;
const ARM_SLOW_DIV: u32 = 3;

/// PLLB's multiplier and 20-bit fraction for `mhz`, rounded to the nearest
/// fraction step: 3600 MHz is `0x42 + 0xaaaab / 2^20` times 54 MHz, 3000 MHz
/// `0x37 + 0x8e38e / 2^20` and 1800 MHz `0x21 + 0x55555 / 2^20`, which is
/// what start4 writes for each.
const fn pllb_for(mhz: u32) -> (u32, u32) {
    let osc_mhz = (OSC_HZ / 1_000_000) as u32;
    let ndiv = mhz / osc_mhz;
    let rest = (mhz % osc_mhz) as u64;
    let frac = ((rest << 20) + osc_mhz as u64 / 2) / osc_mhz as u64;
    (ndiv, frac as u32)
}

const _: () = {
    let checks = [(3600, 0x42, 0x000a_aaab), (3000, 0x37, 0x0008_e38e), (1800, 0x21, 0x0005_5555)];
    let mut i = 0;
    while i < checks.len() {
        let (mhz, ndiv, frac) = checks[i];
        let got = pllb_for(mhz);
        assert!(got.0 == ndiv && got.1 == frac);
        i += 1;
    }
};

/// PLLH's analog words, which start4 programs with PLLB: from the last to the
/// first, word 0 keeping its value. Word 2 carries a divider in bits 6:5, 2 on
/// C0 silicon or for an ARM above 1500 MHz and 1 otherwise (start4
/// `0x3EC7CC84`).
const PLLH_ANA: u32 = 0x1070;
const PLLH_ANA_FOR_PLLB: [u32; 3] = [0, 0xc, 0x2c00];
const PLLH_ANA2_DIV_SHIFT: u32 = 5;

fn pllh_div(arm_mhz: u32) -> u32 {
    if board::stepping() == Stepping::C0 || arm_mhz > ARM_MHZ { 2 } else { 1 }
}

/// PLLB and its ARM channel, which the ARM cores run from: PLLB at twice
/// `arm_mhz`, halved.
pub fn start_arm_pll(arm_mhz: u32) {
    let mut words = PLLH_ANA_FOR_PLLB;
    words[1] |= pllh_div(arm_mhz) << PLLH_ANA2_DIV_SHIFT;
    let pllh = || {
        let word0 = read(PLLH_ANA);
        for word in 1..4 {
            let _ = read(PLLH_ANA + 4 * word);
        }
        for (word, value) in words.iter().enumerate() {
            write(PLLH_ANA + 4 * (3 - word as u32), *value);
        }
        write(PLLH_ANA, word0);
    };
    let div = arm_div(arm_mhz);
    let (ndiv, frac) = pllb_for(arm_mhz * div);
    start_pll(&PLLB, ndiv, frac, pllh, || {});
    start_channel(&PLLB, PLLB_ARM, div);
}

/// Slow the running ARM to 600 MHz, PLLB first.
pub fn slow_arm() {
    let (ndiv, frac) = pllb_for(ARM_SLOW_MHZ * ARM_SLOW_DIV);
    ramp_pll(&PLLB, ndiv, frac);
    set_channel(&PLLB, PLLB_ARM, ARM_SLOW_DIV);
}

/// Take the running ARM back to `arm_mhz`, PLLB first.
pub fn speed_up_arm(arm_mhz: u32) {
    let div = arm_div(arm_mhz);
    let (ndiv, frac) = pllb_for(arm_mhz * div);
    ramp_pll(&PLLB, ndiv, frac);
    set_channel(&PLLB, PLLB_ARM, div);
}

/// The VPU's own clock generator.
const VPU_CTL: u32 = 0x008;

/// The VPU's clock rate: the oscillator's once [`slow_vpu`] has run, else what
/// the PLLs the bootloader started give it.
pub fn vpu_hz() -> u32 {
    if read(VPU_CTL) & 0xf == SRC_OSC { OSC_HZ as u32 } else { VPU_HZ_ON_PLL }
}

/// Put the VPU on the oscillator, the clock it starts on.
pub fn slow_vpu() {
    write(VPU_CTL, read(VPU_CTL) & !0xf | SRC_OSC);
}

/// Generators the board does not need while it waits for a magic packet: the
/// 3D unit's, the SD host's, the two the ARM's timer reads, and four of the
/// peripheral generators above. With `0x1d8` and `0x1e0` stopped as well the
/// detector never fires, so one of them has to run.
const IDLE_GENERATORS: [u32; 8] =
    [V3D_CTL, EMMC2_CTL, GEN_1C8_CTL, GEN_208_CTL, GEN_1F0_CTL, GEN_1F8_CTL, GEN_200_CTL, GEN_22C_CTL];

pub fn stop_idle_generators() {
    for ctl in IDLE_GENERATORS {
        stop_generator(ctl);
    }
}

/// Hold PLLB's ARM channel, which stops the ARM cores' clock, or release it.
pub fn hold_arm(hold: bool) {
    let cm = read(PLLB.cm);
    write(PLLB.cm, if hold { cm | PLLB.hold } else { cm & !PLLB.hold });
}


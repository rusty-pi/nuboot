//! HDMI0 in the mode its display prefers: one XRGB8888 framebuffer in the
//! ARM's memory ([`BASE`]) scanned out by the HVS through PixelValve 2 to the
//! HDMI encoder, as DVI (no infoframes, no audio) in full-range RGB. The mode
//! is the first detailed timing of the display's EDID that the output can
//! make ([`MAX_PIXEL_KHZ`], [`MAX_SIZE`]), and 1280x720 at 60 Hz when no
//! display answers.
//!
//! The register sequence is the one Linux's vc4 driver runs on BCM2711, with
//! the clocks the stock firmware gives it.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::edid::{self, Mode};
use crate::{cm, ddc, mmio, timer};

/// The framebuffer's address in the ARM's memory, which the device tree
/// reserves ([`crate::arm`]), and the most it takes: up to the watchdog's
/// page, room for 1920x1200.
pub const BASE: u32 = 0x3e30_0000;
pub const MAX_SIZE: u32 = 0x008f_e000;
const _: () = assert!(1920 * 1200 * 4 <= MAX_SIZE);

/// The fastest pixel clock the output is set up for: single-link DVI's.
pub const MAX_PIXEL_KHZ: u32 = 165_000;
const MIN_PIXEL_KHZ: u32 = 25_000;

/// CEA mode 4.
const MODE_720P: Mode = Mode {
    pixel_khz: 74_250,
    width: 1280,
    hfp: 110,
    hsync: 40,
    hbp: 220,
    height: 720,
    vfp: 5,
    vsync: 5,
    vbp: 20,
    hsync_positive: true,
    vsync_positive: true,
};

/// CEA mode 16, for a display whose own mode is beyond the output.
const MODE_1080P: Mode = Mode {
    pixel_khz: 148_500,
    width: 1920,
    hfp: 88,
    hsync: 44,
    hbp: 148,
    height: 1080,
    vfp: 4,
    vsync: 5,
    vbp: 36,
    hsync_positive: true,
    vsync_positive: true,
};

static WIDTH: AtomicU32 = AtomicU32::new(0);
static HEIGHT: AtomicU32 = AtomicU32::new(0);

/// The lit mode's size in pixels, zero before [`start`].
pub fn width() -> u32 {
    WIDTH.load(Ordering::Relaxed)
}

pub fn height() -> u32 {
    HEIGHT.load(Ordering::Relaxed)
}

/// The length of a line in bytes, and of the framebuffer.
pub fn pitch() -> u32 {
    width() * 4
}

pub fn size() -> u32 {
    pitch() * height()
}

/// The bus address of the framebuffer, through the ARM's uncached alias.
const BUS: u32 = 0xc000_0000 | BASE;

/// The generator of the HSM clock, which the HDMI registers need: bus access
/// to them hangs while it is stopped. It runs faster than the pixel clock:
/// PLLD's channel by five up to 100 MHz, by three above. PLLC's channel
/// feeds the pixel BVB clock, at least 75 MHz and twice that above 148.5 MHz.
const HSM_DIV: u32 = 0x5000;
const HSM_DIV_FAST: u32 = 0x3000;
const HSM_FAST_ABOVE_KHZ: u32 = 100_000;
const BVB_DIV: u32 = 0x8a40;
const BVB_FAST_ABOVE_KHZ: u32 = 148_500;

const HVS: u32 = 0x7e40_0000;
const HVS_DISPCTRL: u32 = HVS;
const HVS_DISPECTRL: u32 = HVS + 0x0c;
const HVS_DISPDITHER: u32 = HVS + 0x14;
const HVS_DISPEOLN: u32 = HVS + 0x18;
const HVS_DISPLIST0: u32 = HVS + 0x20;
const HVS_DISPCTRL0: u32 = HVS + 0x40;
const HVS_DISPBKGND0: u32 = HVS + 0x44;
const HVS_DISPBASE0: u32 = HVS + 0x4c;
const HVS_DISPBASE1: u32 = HVS + 0x5c;
const HVS_DISPBASE2: u32 = HVS + 0x6c;
const HVS_DLIST: u32 = 0x7e40_4000;

const PV: u32 = 0x7e20_a000;
const PV_CONTROL: u32 = PV;
const PV_V_CONTROL: u32 = PV + 0x04;
const PV_VSYNCD_EVEN: u32 = PV + 0x08;
const PV_HORZA: u32 = PV + 0x0c;
const PV_HORZB: u32 = PV + 0x10;
const PV_VERTA: u32 = PV + 0x14;
const PV_VERTB: u32 = PV + 0x18;
const PV_MUX_CFG: u32 = PV + 0x34;

const HDMI: u32 = 0x7ef0_0700;
const HDMI_FIFO_CTL: u32 = HDMI + 0x74;
const HDMI_SCHEDULER_CONTROL: u32 = HDMI + 0xe0;
const HDMI_HORZA: u32 = HDMI + 0xe4;
const HDMI_HORZB: u32 = HDMI + 0xe8;
const HDMI_VERTA0: u32 = HDMI + 0xec;
const HDMI_VERTB0: u32 = HDMI + 0xf0;
const HDMI_VERTA1: u32 = HDMI + 0xf4;
const HDMI_VERTB1: u32 = HDMI + 0xf8;
const HDMI_MISC_CONTROL: u32 = HDMI + 0x100;
const HDMI_DEEP_COLOR_CONFIG_1: u32 = HDMI + 0x170;
const HDMI_GCP_CONFIG: u32 = HDMI + 0x178;
const HDMI_GCP_WORD_1: u32 = HDMI + 0x17c;
const HDMI_HOTPLUG: u32 = HDMI + 0x1a8;

const CSC: u32 = 0x7ef0_0200;
const DVP: u32 = 0x7ef0_0300;
const DVP_CLOCK_STOP: u32 = DVP + 0xbc;
const DVP_VEC_INTERFACE_CFG: u32 = DVP + 0xec;
const DVP_VEC_INTERFACE_XBAR: u32 = DVP + 0xf0;

const HD: u32 = 0x7ef2_0000;
const HD_DVP_CTL: u32 = HD;
const HD_VID_CTL: u32 = HD + 0x44;

const PHY: u32 = 0x7ef0_0f00;
const RM: u32 = 0x7ef0_0f80;

fn rmw(addr: u32, clear: u32, set: u32) {
    mmio::write(addr, mmio::read(addr) & !clear | set);
}

fn start_hsm(div: u32) {
    cm::switch_generator(cm::GEN_22C_CTL, div, cm::SRC_PLLD_PER);
}

fn start_clocks(mode: &Mode) {
    start_hsm(if mode.pixel_khz > HSM_FAST_ABOVE_KHZ { HSM_DIV_FAST } else { HSM_DIV });
    let bvb = if mode.pixel_khz > BVB_FAST_ABOVE_KHZ { BVB_DIV / 2 } else { BVB_DIV };
    cm::switch_generator(cm::GEN_208_CTL, bvb, cm::SRC_PLLC_PER);
}

fn start_hvs() {
    mmio::write(HVS_DISPCTRL, 0xaa0c_0000);
    rmw(HVS_DISPECTRL, 1 << 31, 0);
    mmio::write(HVS_DISPDITHER, 0xc000_0000);
    rmw(HVS_DISPEOLN, 3 << 30, 0);
    mmio::write(HVS_DISPBASE2, 0x3000_0000);
    mmio::write(HVS_DISPBASE1, 0x6010_3010);
    mmio::write(HVS_DISPBASE0, 0xad80_6020);
}

/// One XRGB8888 plane over the whole screen, then the end of the list.
fn write_display_list(mode: &Mode) {
    let words = [
        0x4800_d807,
        0,
        0x4000_fff0,
        (mode.height << 16) | mode.width,
        0xc0c0_c0c0,
        BUS,
        0xc0c0_c0c0,
        mode.width * 4,
        0x8000_0000,
    ];
    for (i, word) in words.iter().enumerate() {
        mmio::write(HVS_DLIST + 4 * i as u32, *word);
    }
    mmio::write(HVS_DISPLIST0, 0);
    mmio::write(HVS_DISPBKGND0, 0x0100_0000);
    mmio::write(HVS_DISPCTRL0, 0);
    mmio::write(HVS_DISPCTRL0, 1 << 30);
    mmio::write(HVS_DISPCTRL0, 0);
    mmio::write(HVS_DISPCTRL0, 1 << 31 | mode.width << 16 | mode.height);
}

const CRYSTAL_HZ: u64 = 54_000_000;
const VCO_MIN_HZ: u64 = 3_000_000_000;

/// The PLL's oscillator: ten times the pixel clock times the least divider
/// that takes it to 3 GHz.
fn vco(pixel_khz: u32) -> (u64, u32) {
    let bit_hz = pixel_khz as u64 * 10_000;
    let div = VCO_MIN_HZ.div_ceil(bit_hz) as u32;
    (bit_hz * div as u64, div)
}

/// The oscillator's rate against the crystal, in the rate manager's 9.22
/// fixed point.
fn rm_offset(vco_hz: u64) -> u32 {
    ((((vco_hz * 2) << 22) / CRYSTAL_HZ) >> 2) as u32
}

fn vco_gain(vco_hz: u64) -> u32 {
    match vco_hz {
        ..3_350_000_000 => 0xf,
        ..3_700_000_000 => 0xc,
        ..4_050_000_000 => 0x6,
        ..4_800_000_000 => 0x5,
        ..5_200_000_000 => 0x7,
        _ => 0x2,
    }
}

/// The PHY's PLL on the mode's pixel clock, from the 54 MHz crystal, and its
/// lanes' drive.
fn start_phy(mode: &Mode) {
    let (vco_hz, vco_div) = vco(mode.pixel_khz);
    let high_band = vco_hz > 4_500_000_000;
    let charge_pump = if vco_hz < 3_700_000_000 { 0x1c } else { 0x18 };
    let (data_drive, clock_drive, clock_termination) = if mode.pixel_khz <= 50_000 { (0x0a, 0x0a, 0) } else { (0x09, 0x0c, 3) };
    mmio::write(PHY, 0x0f);
    mmio::write(PHY + 0x04, 0x400);
    mmio::write(PHY + 0x04, 0x10);
    rmw(PHY, 0xf, 0);
    rmw(RM, 0, 0x000a_0010);
    rmw(PHY + 0x50, 0x0fff_ffff, 0);
    rmw(PHY + 0x54, 0x0fff_ffff, 0);
    mmio::write(RM + 0x18, 1 << 31 | rm_offset(vco_hz));
    mmio::write(PHY + 0x28, vco_div << 8);
    mmio::write(PHY + 0x5c, 0x0e14_e147);
    mmio::write(PHY + 0x1c, 0x0000_2060 | (high_band as u32) << 9);
    rmw(PHY + 0x20, 0, 0x008a_7800);
    rmw(RM + 0x1c, 0, 0x0200_0000);
    rmw(PHY + 0x34, 0, 1);
    mmio::write(PHY + 0x44, 0);
    mmio::write(PHY + 0x14, 0x0008_65c0 | charge_pump);
    mmio::write(PHY + 0x08, data_drive << 24 | data_drive << 16 | data_drive << 8 | clock_drive);
    rmw(PHY + 0x0c, 0, 0x0009_4a58);
    mmio::write(PHY + 0x10, vco_gain(vco_hz) << 16 | clock_termination);
    mmio::write(PHY + 0x4c, 0x0000_3210);
    rmw(PHY, 0x30, 0);
    rmw(PHY, 0, 0x30);
    timer::delay_us(1000);
}

fn set_timings(mode: &Mode) {
    rmw(HDMI_SCHEDULER_CONTROL, 0, 1 << 15 | 1 << 5);
    mmio::write(HDMI_HORZA, mode.hfp << 16 | (mode.vsync_positive as u32) << 15 | (mode.hsync_positive as u32) << 14 | mode.width);
    mmio::write(HDMI_HORZB, mode.hbp << 16 | mode.hsync);
    let verta = mode.vsync << 24 | mode.vfp << 16 | mode.height;
    mmio::write(HDMI_VERTA0, verta);
    mmio::write(HDMI_VERTA1, verta);
    mmio::write(HDMI_VERTB0, mode.vbp);
    let line = mode.width + mode.hfp + mode.hsync + mode.hbp;
    mmio::write(HDMI_VERTB1, (line / 2) << 16 | mode.vbp);
    rmw(HDMI_DEEP_COLOR_CONFIG_1, 0x70f, 0x200);
    rmw(HDMI_GCP_WORD_1, 0xffff, 0x10);
    rmw(HDMI_GCP_CONFIG, 0, 1 << 31);
    rmw(HDMI_MISC_CONTROL, 0xf, 0);
    mmio::write(DVP_CLOCK_STOP, 0);
}

/// The pixel valve takes two pixels a clock, so its horizontal values are
/// half the mode's.
fn start_pixel_valve(mode: &Mode) {
    rmw(PV_CONTROL, 1, 0);
    rmw(PV_CONTROL, 0, 1 << 1);
    mmio::write(PV_HORZA, (mode.hbp / 2) << 16 | mode.hsync / 2);
    mmio::write(PV_HORZB, (mode.hfp / 2) << 16 | mode.width / 2);
    mmio::write(PV_V_CONTROL, 0x2);
    mmio::write(PV_VSYNCD_EVEN, 0);
    mmio::write(PV_VERTA, mode.vbp << 16 | mode.vsync);
    mmio::write(PV_VERTB, mode.vfp << 16 | mode.height);
    mmio::write(PV_MUX_CFG, 0x20);
    mmio::write(PV_CONTROL, 0x0617_7002);
    mmio::write(PV_CONTROL, 0x0617_7003);
}

/// Identity colour conversion, then the encoder's FIFO and video.
fn start_encoder() {
    for (offset, value) in [(0x04, 0x2000), (0x08, 0), (0x0c, 0x2000_0000), (0x10, 0), (0x14, 0), (0x18, 0x2000)] {
        mmio::write(CSC + offset, value);
    }
    mmio::write(DVP_VEC_INTERFACE_CFG, 0);
    mmio::write(DVP_VEC_INTERFACE_XBAR, 0x0035_4021);
    mmio::write(CSC + 0x2c, 0);
    mmio::write(CSC, 0x7);
    mmio::write(HDMI_FIFO_CTL, 1);
    rmw(PV_V_CONTROL, 0, 1);
    rmw(HD_VID_CTL, 1 << 28 | 1 << 27, 1 << 31 | 1 << 30 | 1 << 29 | 1 << 23 | 1 << 16);
    rmw(HD_VID_CTL, 1 << 18, 0);
    rmw(HDMI_SCHEDULER_CONTROL, 1, 0);
    timer::wait(1_000_000, || mmio::read(HDMI_SCHEDULER_CONTROL) & 2 == 0);
}

fn recenter_fifo() {
    let center = || {
        let fifo = mmio::read(HDMI_FIFO_CTL) & 0xefff;
        mmio::write(HDMI_FIFO_CTL, fifo & !(1 << 6));
        mmio::write(HDMI_FIFO_CTL, fifo | 1 << 6);
    };
    center();
    timer::delay_us(1000);
    center();
    timer::wait(1000, || mmio::read(HDMI_FIFO_CTL) & 1 << 14 != 0);
}

const EDID_ADDRESS: u8 = 0x50;

fn fits(mode: &Mode) -> bool {
    (MIN_PIXEL_KHZ..=MAX_PIXEL_KHZ).contains(&mode.pixel_khz)
        && mode.width % 2 == 0
        && mode.width * mode.height * 4 <= MAX_SIZE
        && mode.hfp < 1 << 13
        && mode.hbp < 1 << 11
        && mode.hsync < 1 << 11
        && mode.vfp < 1 << 7
        && mode.vsync < 1 << 5
        && mode.vbp < 1 << 8
}

/// Where the mode came from, for the log.
#[derive(Clone, Copy, Debug)]
pub enum Source {
    /// No display answered with an EDID.
    Default,
    /// A detailed timing of the display's EDID.
    Edid,
    /// The display's own timings are beyond the output, and it is at least
    /// 1920x1080.
    Reduced,
}

fn choose() -> (Mode, Source) {
    let mut block = [0u8; edid::BLOCK];
    if !ddc::read(EDID_ADDRESS, 0, &mut block) || !edid::valid(&block) {
        return (MODE_720P, Source::Default);
    }
    if let Some(mode) = edid::modes(&block).find(fits) {
        return (mode, Source::Edid);
    }
    match edid::modes(&block).next() {
        Some(native) if native.width >= MODE_1080P.width && native.height >= MODE_1080P.height => (MODE_1080P, Source::Reduced),
        _ => (MODE_720P, Source::Default),
    }
}

/// What [`start`] found and lit.
pub struct Started {
    pub source: Source,
    pub refresh_hz: u32,
    /// Whether a display answered the hot-plug line.
    pub display: bool,
}

/// Light HDMI0 in the display's mode, scanning out the framebuffer.
pub fn start() -> Started {
    start_hsm(HSM_DIV);
    let (mode, source) = choose();
    WIDTH.store(mode.width, Ordering::Relaxed);
    HEIGHT.store(mode.height, Ordering::Relaxed);
    start_clocks(&mode);
    mmio::write(HD_DVP_CTL, 0);
    rmw(DVP_CLOCK_STOP, 0, 1 << 1);
    start_hvs();
    write_display_list(&mode);
    start_phy(&mode);
    set_timings(&mode);
    start_pixel_valve(&mode);
    start_encoder();
    recenter_fifo();
    let total = (mode.width + mode.hfp + mode.hsync + mode.hbp) * (mode.height + mode.vfp + mode.vsync + mode.vbp);
    Started { source, refresh_hz: (mode.pixel_khz * 1000 + total / 2) / total, display: mmio::read(HDMI_HOTPLUG) & 1 != 0 }
}

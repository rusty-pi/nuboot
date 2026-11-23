//! HDMI0 at 1280x720, 60 Hz: one XRGB8888 framebuffer in the ARM's memory
//! ([`BASE`]) scanned out by the HVS through PixelValve 2 to the HDMI
//! encoder, as DVI (no infoframes, no audio) in full-range RGB. No EDID is read:
//! the mode is the same for every display.
//!
//! The register sequence is the one Linux's vc4 driver runs for this mode on
//! BCM2711, with the clocks the stock firmware gives it.

use crate::{cm, mmio, timer};

/// The framebuffer's address in the ARM's memory, which the device tree
/// reserves ([`crate::arm`]).
pub const BASE: u32 = 0x3e80_0000;
pub const WIDTH: u32 = 1280;
pub const HEIGHT: u32 = 720;
pub const PITCH: u32 = WIDTH * 4;
pub const SIZE: u32 = PITCH * HEIGHT;

/// The bus address of the framebuffer, through the ARM's uncached alias.
const BUS: u32 = 0xc000_0000 | BASE;

/// The generator of the HSM clock, which the HDMI registers need: bus access
/// to them hangs while it is stopped. `0x5000` is 120 MHz, the least Linux
/// asks for; PLLC's channel feeds the pixel BVB clock, at least 75 MHz.
const HSM_DIV: u32 = 0x5000;
const BVB_DIV: u32 = 0x8a40;

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

fn start_clocks() {
    cm::switch_generator(cm::GEN_22C_CTL, HSM_DIV, cm::SRC_PLLD_PER);
    cm::switch_generator(cm::GEN_208_CTL, BVB_DIV, cm::SRC_PLLC_PER);
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
fn write_display_list() {
    let words = [
        0x4800_d807,
        0,
        0x4000_fff0,
        (HEIGHT << 16) | WIDTH,
        0xc0c0_c0c0,
        BUS,
        0xc0c0_c0c0,
        PITCH,
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
    mmio::write(HVS_DISPCTRL0, 1 << 31 | WIDTH << 16 | HEIGHT);
}

/// The PHY's PLL at 3.7125 GHz (five times 74.25 MHz times ten, from the
/// 54 MHz crystal) and its lanes' drive.
fn start_phy() {
    mmio::write(PHY, 0x0f);
    mmio::write(PHY + 0x04, 0x400);
    mmio::write(PHY + 0x04, 0x10);
    rmw(PHY, 0xf, 0);
    rmw(RM, 0, 0x000a_0010);
    rmw(PHY + 0x50, 0x0fff_ffff, 0);
    rmw(PHY + 0x54, 0x0fff_ffff, 0);
    mmio::write(RM + 0x18, 0x8898_0000);
    mmio::write(PHY + 0x28, 0x0000_0500);
    mmio::write(PHY + 0x5c, 0x0e14_e147);
    mmio::write(PHY + 0x1c, 0x0000_2060);
    rmw(PHY + 0x20, 0, 0x008a_7800);
    rmw(RM + 0x1c, 0, 0x0200_0000);
    rmw(PHY + 0x34, 0, 1);
    mmio::write(PHY + 0x44, 0);
    mmio::write(PHY + 0x14, 0x0008_65d8);
    mmio::write(PHY + 0x08, 0x0909_090c);
    rmw(PHY + 0x0c, 0, 0x0009_4a58);
    mmio::write(PHY + 0x10, 0x0006_0003);
    mmio::write(PHY + 0x4c, 0x0000_3210);
    rmw(PHY, 0x30, 0);
    rmw(PHY, 0, 0x30);
    timer::delay_us(1000);
}

/// CEA mode 4: 1650 by 750 in all, syncs positive.
fn set_timings() {
    rmw(HDMI_SCHEDULER_CONTROL, 0, 1 << 15 | 1 << 5);
    mmio::write(HDMI_HORZA, 0x006e_c500);
    mmio::write(HDMI_HORZB, 0x00dc_0028);
    mmio::write(HDMI_VERTA0, 0x0505_02d0);
    mmio::write(HDMI_VERTA1, 0x0505_02d0);
    mmio::write(HDMI_VERTB0, 0x0000_0014);
    mmio::write(HDMI_VERTB1, 0x0339_0014);
    rmw(HDMI_DEEP_COLOR_CONFIG_1, 0x70f, 0x200);
    rmw(HDMI_GCP_WORD_1, 0xffff, 0x10);
    rmw(HDMI_GCP_CONFIG, 0, 1 << 31);
    rmw(HDMI_MISC_CONTROL, 0xf, 0);
    mmio::write(DVP_CLOCK_STOP, 0);
}

/// The pixel valve takes two pixels a clock, so its horizontal values are
/// half the mode's.
fn start_pixel_valve() {
    rmw(PV_CONTROL, 1, 0);
    rmw(PV_CONTROL, 0, 1 << 1);
    mmio::write(PV_HORZA, 0x006e_0014);
    mmio::write(PV_HORZB, 0x0037_0280);
    mmio::write(PV_V_CONTROL, 0x2);
    mmio::write(PV_VSYNCD_EVEN, 0);
    mmio::write(PV_VERTA, 0x0014_0005);
    mmio::write(PV_VERTB, 0x0005_02d0);
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

/// Light HDMI0, scanning out the framebuffer. Whether a display answered the
/// hot-plug line.
pub fn start() -> bool {
    start_clocks();
    mmio::write(HD_DVP_CTL, 0);
    rmw(DVP_CLOCK_STOP, 0, 1 << 1);
    start_hvs();
    write_display_list();
    start_phy();
    set_timings();
    start_pixel_valve();
    start_encoder();
    recenter_fifo();
    mmio::read(HDMI_HOTPLUG) & 1 != 0
}

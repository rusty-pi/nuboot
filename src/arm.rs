//! Starting the ARM: the image its cores run first goes at ARM physical 0,
//! the device tree at [`TREE_ADDR`] with the board's memory in it, and then
//! the cores come out of reset.
//!
//! The image is `uefi/stub`: an armstub that takes each core from EL3 to EL2,
//! with the primary core going on to decompress the UEFI payload. The
//! address of the tree goes in the image's word at [`IMAGE_TREE_WORD`].

use crate::{board, cm, expander, fdt, handover, mmio, otp, timer, tpm_crb, wdat};

/// The ARM control block, and the bit that lets the cores out of reset.
const ARMCTRL: u32 = 0x7e00_b000;
const ARMCTRL_RELEASE: u32 = 0x1000;

/// Where the image reads the address of the device tree from.
const IMAGE_TREE_WORD: usize = 0xf8;
/// The word after it, where the UEFI firmware says what it wants of the boot
/// watchdog ([`crate::watchdog::carry_poll`]): a sequence number in bits
/// 31:24, so the same request twice is two requests, and what happened in 23:20
/// (2: `ExitBootServices`).
const IMAGE_WATCHDOG_WORD: u32 = 0xfc;
pub const WATCHDOG_EXIT: u32 = 2;

/// The UEFI firmware's last watchdog request: (sequence, what, seconds), all
/// zero until it makes one.
pub fn watchdog_request() -> (u32, u32, u32) {
    let w = mmio::read(0xc000_0000 | IMAGE_WATCHDOG_WORD);
    (w >> 24, (w >> 20) & 0xf, w & 0xf_ffff)
}

/// Where the device tree goes: under the payload at 16 MiB, above the image.
pub const TREE_ADDR: u32 = 0x00f0_0000;
const TREE_MAX: usize = 0x0010_0000;

/// Where the VPU firmware's own memory starts (`start4.ld`), and with it the
/// end of the ARM's share of the first gigabyte.
pub const VPU_BASE: u32 = 0x3ec0_0000;

/// What the OS's driver for the TPM on the VPU matches (`tools/tpm-vpu`).
const TPM_COMPATIBLE: &[u8] = b"rusty-pi,pi4-vpu-tpm\0";

/// The page of the ARM's memory the TPM's command response buffer is in: the
/// last one below the VPU's own. The device tree reserves it, and the UEFI
/// firmware tells the OS about it in the ACPI tables.
pub const CRB_BASE: u32 = VPU_BASE - tpm_crb::SIZE;
const CRB_NODE: &[u8] = b"tpm-crb@3ebff000";
const _: () = assert!(CRB_BASE == 0x3ebf_f000);

fn crb_reg() -> [u8; 12] {
    let mut reg = [0u8; 12];
    reg[4..8].copy_from_slice(&CRB_BASE.to_be_bytes());
    reg[8..12].copy_from_slice(&tpm_crb::SIZE.to_be_bytes());
    reg
}

/// The TPM's command response buffer.
pub fn crb() -> tpm_crb::Window {
    tpm_crb::Window::new((0xc000_0000 | CRB_BASE) as usize as *mut u8, CRB_BASE)
}

/// The page below it, the register block of the watchdog the ACPI tables' WDAT
/// describes ([`crate::wdat`]). The device tree reserves it and the UEFI
/// firmware tells the OS about it in the tables.
pub const WDAT_BASE: u32 = CRB_BASE - wdat::SIZE;
const WDAT_NODE: &[u8] = b"os-watchdog@3ebfe000";
const _: () = assert!(WDAT_BASE == 0x3ebf_e000);

fn wdat_reg() -> [u8; 12] {
    let mut reg = [0u8; 12];
    reg[4..8].copy_from_slice(&WDAT_BASE.to_be_bytes());
    reg[8..12].copy_from_slice(&wdat::SIZE.to_be_bytes());
    reg
}

/// The WDAT watchdog's register page.
pub fn wdat() -> wdat::Window {
    wdat::Window::new((0xc000_0000 | WDAT_BASE) as usize as *mut u8)
}

/// The second bank the ARM gets, above the first gigabyte, and how far it can
/// reach: the peripherals sit in the 64 MiB below 4 GiB.
const HIGH_MEMORY: u32 = 0x4000_0000;
const HIGH_MEMORY_MAX: u32 = 0xbc00_0000;
/// Where the banks above the 32-bit window start, and how much of one a
/// range with a 32-bit size cell carries.
const BANK_ABOVE_4G: u64 = 0x1_0000_0000;
const BANK_STEP: u32 = 0x8000_0000;
/// Ranges of two address cells and one size cell: the low one, the high one,
/// and up to 8 GiB above 4 GiB.
const MEMORY_REG_MAX: usize = 12 * 6;

/// The generators the ARM's timer reads, which start4 puts on PLLA's core
/// channel before the ARM starts, and what it sets the PLLC-fed generator at
/// 0x208 to then: 648 MHz over 8.640625, 75 MHz.
const ARM_TIME_CLOCKS: [u32; 4] = [cm::V3D_CTL, cm::H264_CTL, cm::ISP_CTL, cm::GEN_1C8_CTL];
const GEN_208_ARM_DIV: u32 = 0x8a40;

/// A word of a neighbouring block no documentation covers: start4 sets its
/// bits 20:16 to `0x13` once it has handed the SD card over.
const REG_7EC10008: u32 = 0x7ec1_0008;
const REG_7EC10008_FIELD: u32 = 0x1f << 16;
const REG_7EC10008_VALUE: u32 = 0x13 << 16;
const REG_7EC11018: u32 = 0x7ec1_1018;
const REG_7EC1101C: u32 = 0x7ec1_101c;
/// A word of the ARM control block whose bit 9 start4 clears once the ARM
/// runs; what it does is not known.
const ARMCTRL_440: u32 = ARMCTRL + 0x440;
const ARMCTRL_440_BIT9: u32 = 1 << 9;
/// The processor power word (Linux's `PM_PROC`), whose low twelve bits start4
/// clears and sets again in three steps once the ARM runs, and a word it
/// reads before and after.
const PM_PROC: u32 = 0x7e10_0110;
const PM_PROC_BITS: u32 = 0xfff;
const PM_PROC_STEPS: [u32; 3] = [0x400, 0x800, 0x3ff];
const PM_REG_FC: u32 = 0x7e10_00fc;
const PROC_CLEAR_TICKS: u32 = 0x10;
const PROC_STEP_TICKS: u32 = 8;
/// Words of another undocumented block that start4's secure side writes
/// right after the release.
const REG_7E500200: [(u32, u32); 4] =
    [(0x7e50_0200, 0x30), (0x7e50_0204, 0xf), (0x7e50_0220, 0x210), (0x7e50_020c, 0xf)];
/// Mailbox 1's configuration word as the VPU sees it.
const MAILBOX_CONFIG1: u32 = 0x7e00_b880 + 0x100 + 0x3c;

const PM_RSTC: u32 = 0x7e10_001c;
/// PM_RSTC bits the stock firmware sets as it starts, before the PLL powers;
/// what they do is not known.
const PM_RSTC_BITS_12_13: u32 = 0x3000;
/// The PLLs' power controls. The stock firmware writes all four before it
/// touches a PLL.
const PM_PLL_POWER: [u32; 4] = [0x7e10_007c, 0x7e10_0080, 0x7e10_0084, 0x7e10_0088];
/// The image power domain: writing `IMAGE_RESETS` releases the resets of its
/// peripherals, H264 block and ISP, and sets bit 9.
const PM_IMAGE: u32 = 0x7e10_0108;
const IMAGE_RESETS: u32 = 0x3c0;
/// The L2 cache's control word. start4 configures it as it starts (clearing
/// bits 1, 3, 4 and 16-19, setting 0x430000) and sets bit 1 as it applies
/// `config.txt`.
const L2_CTRL: u32 = 0x7ee0_1000;
const L2_CTRL_KEEP: u32 = 0xfff0_ffe5;
const L2_CTRL_CONFIG: u32 = 0x0043_0000;
const L2_CTRL_BIT1: u32 = 1 << 1;
const REG_7EC11010: u32 = 0x7ec1_1010;
const REG_7EC11014: u32 = 0x7ec1_1014;

/// What the stock firmware does before it touches the ARM's clocks: the L2
/// cache's control word, the PLLs' power, and the register writes of the
/// routine it applies `config.txt` with, which bring the image power domain
/// out of reset and start the ISP clock on the oscillator.
fn power_up() {
    let l2 = mmio::read(L2_CTRL);
    mmio::write(L2_CTRL, l2 & L2_CTRL_KEEP | L2_CTRL_CONFIG);
    mmio::write(PM_RSTC, mmio::PASSWD | mmio::read(PM_RSTC) | PM_RSTC_BITS_12_13);
    for pm in PM_PLL_POWER {
        mmio::write(pm, mmio::PASSWD | 4);
    }
    mmio::write(L2_CTRL, mmio::read(L2_CTRL) | L2_CTRL_BIT1);
    cm::write(cm::REG_128, 0x36);
    cm::write(cm::REG_12C, 0);
    cm::write(cm::A2W_1390, cm::read(cm::A2W_1390) | 0x0020_0001);
    for reg in [REG_7EC11010, REG_7EC11014] {
        mmio::write(reg, mmio::read(reg) & !1);
    }
    mmio::write(PM_IMAGE, mmio::PASSWD | IMAGE_RESETS);
    cm::write(cm::PERII_CTL, cm::GATE);
    cm::write(cm::ISP_DIV, 0);
    cm::write(cm::ISP_CTL, cm::SRC_OSC);
    cm::write(cm::ISP_CTL, cm::SRC_OSC | cm::ENAB);
}

const EMMC2: u32 = 0x7e34_0000;
const EMMC2_CLOCK_CONTROL: u32 = EMMC2 + 0x2c;
const EMMC2_INT_STATUS: u32 = EMMC2 + 0x30;
const EMMC2_INT_STATUS_EN: u32 = EMMC2 + 0x34;
const EMMC2_INT_SIGNAL_EN: u32 = EMMC2 + 0x38;
const EMMC2_REG_100: u32 = EMMC2 + 0x100;
const EMMC2_REG_154: u32 = EMMC2 + 0x154;
/// The clock the SD host runs from once start4 has applied `config.txt`.
const EMMC2_HZ: u32 = 100_000_000;
const SRST_ALL: u32 = 1 << 24;
const SRST_CMD: u32 = 1 << 25;
const SRST_DAT: u32 = 1 << 26;
const EMMC2_RESET_US: u32 = 1_000_000;
/// The word that says which host the card's pins go to, and the bit that
/// leaves them with the legacy host.
const SD_MUX: u32 = 0x7e20_00d0;
const SD_ON_LEGACY_HOST: u32 = 1 << 1;
const SD_MUX_BIT0: u32 = 1 << 0;

/// Leave the SD host to the ARM the way the stock firmware does before it
/// starts it: interrupts off and cleared, the host reset, then its command
/// and data lines, and the card's pins routed to it.
fn hand_card_to_arm() {
    mmio::write(EMMC2_INT_SIGNAL_EN, 0);
    mmio::write(EMMC2_INT_STATUS_EN, 0);
    mmio::write(EMMC2_INT_STATUS, !0);
    for bits in [SRST_ALL, SRST_CMD | SRST_DAT] {
        mmio::write(EMMC2_CLOCK_CONTROL, mmio::read(EMMC2_CLOCK_CONTROL) | bits);
        timer::wait(EMMC2_RESET_US, || mmio::read(EMMC2_CLOCK_CONTROL) & bits == 0);
    }
    mmio::write(SD_MUX, mmio::read(SD_MUX) & !SD_ON_LEGACY_HOST);
    cm::switch_generator(cm::EMMC2_CTL, cm::plld_per_div(EMMC2_HZ), cm::SRC_PLLD_PER);
    mmio::write(SD_MUX, mmio::read(SD_MUX) | SD_MUX_BIT0);
    mmio::write(EMMC2_REG_154, 1);
    let reg = mmio::read(EMMC2_REG_100);
    mmio::write(EMMC2_REG_100, reg & !(1 << 30) | 1 << 31);
}

/// Give the ARM the SD card as it was when the ARM started, after the OS has
/// used it: its supply cycled, and the host reset and routed as at the start.
/// Whether the supply could be switched.
pub fn prepare_card() -> bool {
    let cycled = expander::power_cycle_card();
    hand_card_to_arm();
    cycled
}

/// What the stock firmware writes before it lets the cores go: two words of
/// the ARM control block, with its own side of the mailbox configured in
/// between.
fn prepare_arm() {
    mmio::write(ARMCTRL, 0x200);
    mmio::write(MAILBOX_CONFIG1, 8);
    mmio::write(MAILBOX_CONFIG1, 1);
    mmio::write(ARMCTRL + 0x41c, 0x1f3);
}

/// What start4 does once the ARM runs: the ARM slowed to 600 MHz for two runs
/// of the `PM_PROC` sequence and taken back to full rate, and the H264 and
/// ISP clocks, which it ran for the ARM's start, off again.
fn after_release(arm_mhz: u32) {
    for (reg, value) in REG_7E500200 {
        mmio::write(reg, value);
    }
    cm::slow_arm();
    proc_sequence();
    proc_sequence();
    mmio::write(ARMCTRL_440, mmio::read(ARMCTRL_440) & !ARMCTRL_440_BIT9);
    for reg in [REG_7EC11018, REG_7EC1101C] {
        mmio::write(reg, mmio::read(reg) & !1);
    }
    for reg in [REG_7EC11018, REG_7EC1101C] {
        timer::wait(1000, || mmio::read(reg) & 1 == 0);
    }
    cm::speed_up_arm(arm_mhz);
    for ctl in [cm::H264_CTL, cm::ISP_CTL] {
        cm::stop_generator(ctl);
    }
}

/// start4's sequence on `PM_PROC`, with the ARM's channel divider set to
/// PLLB's multiplier for the while: the low twelve bits cleared, then set in
/// three steps, each made with the ARM's clock held.
fn proc_sequence() {
    let channel = cm::read(cm::PLLB_ARM);
    cm::write(cm::PLLB_ARM, channel & !0xff | cm::ndiv(&cm::PLLB));
    let _ = mmio::read(PM_REG_FC);
    mmio::write(PM_PROC, mmio::PASSWD | mmio::read(PM_PROC) & !PM_PROC_BITS);
    cm::countdown(PROC_CLEAR_TICKS);
    for bits in PM_PROC_STEPS {
        cm::hold_arm(true);
        cm::countdown(PROC_STEP_TICKS);
        mmio::write(PM_PROC, mmio::PASSWD | mmio::read(PM_PROC) | bits);
        cm::countdown(PROC_STEP_TICKS);
        cm::hold_arm(false);
        cm::countdown(PROC_STEP_TICKS);
    }
    cm::write(cm::PLLB_ARM, channel);
    let _ = mmio::read(PM_REG_FC);
}

/// The VPU's uncached view of ARM physical memory.
fn arm_memory(addr: u32, len: usize) -> &'static mut [u8] {
    unsafe { core::slice::from_raw_parts_mut((0xc000_0000 | addr) as usize as *mut u8, len) }
}

/// `/memory@0`'s `reg` for a board with `total` bytes of SDRAM: the ARM's
/// share of the first gigabyte, the rest of the low 4 GiB less the
/// peripherals' window, and whole banks above 4 GiB.
fn memory_reg(total: u64, out: &mut [u8; MEMORY_REG_MAX]) -> usize {
    let mut range = |at: usize, base: u64, size: u32| {
        out[at..at + 8].copy_from_slice(&base.to_be_bytes());
        out[at + 8..at + 12].copy_from_slice(&size.to_be_bytes());
        at + 12
    };
    let mut at = range(0, 0, VPU_BASE);
    if total > HIGH_MEMORY as u64 {
        let high = (total - HIGH_MEMORY as u64).min(HIGH_MEMORY_MAX as u64) as u32;
        at = range(at, HIGH_MEMORY as u64, high);
    }
    let mut base = BANK_ABOVE_4G;
    while base < total && at + 12 <= MEMORY_REG_MAX {
        at = range(at, base, (total - base).min(BANK_STEP as u64) as u32);
        base += BANK_STEP as u64;
    }
    at
}

pub enum Error {
    /// The built-in device tree is not one, or has no `/memory@0` `reg` or no `/reserved-memory`.
    Tree,
}

/// What [`start`] handed the ARM.
pub struct Started {
    pub image_bytes: usize,
    pub tree_bytes: usize,
    pub memory_mib: u64,
    pub ethernet: [u8; 6],
}

const ETHERNET_NODE: &[&[u8]] = &[b"", b"scb", b"ethernet@7d580000"];

/// The address the network interface gets, the same at every boot of a board:
/// the one in the OTP's MAC rows, which is the address Raspberry Pi's firmware
/// gives the board. A board whose rows are blank or hold a group address gets a
/// locally administered, unicast one from its serial number.
pub fn ethernet_address(serial: u32) -> [u8; 6] {
    let (high, low) = (otp::read(otp::MAC_HIGH).to_be_bytes(), otp::read(otp::MAC_LOW).to_be_bytes());
    let fused = [high[0], high[1], high[2], high[3], low[0], low[1]];
    if fused != [0; 6] && fused[0] & 1 == 0 {
        return fused;
    }
    let mut message = [0u8; 32];
    let label = b"nuboot ethernet";
    message[..label.len()].copy_from_slice(label);
    message[label.len()..label.len() + 4].copy_from_slice(&serial.to_le_bytes());
    let digest = crate::sha256::digest(&message[..label.len() + 4]);
    [0x02, digest[0], digest[1], digest[2], digest[3], digest[4]]
}

/// The nodes for the wireless chip, which a headless server does not use and
/// whose SD host has no clock here: described as disabled, as the stock
/// `disable-wifi` and `disable-bt` overlays do.
const WIRELESS_NODES: &[&[&[u8]]] = &[&[b"", b"soc", b"mmcnr@7e300000"], &[b"", b"soc", b"serial@7e201000", b"bluetooth"]];

/// The SD host's bus. The tree describes its DMA window as the first gigabyte at
/// the bus address `0xC000_0000`, which is right for BCM2711 B0; C0 reaches the
/// low 4 GiB, less the peripherals' window, at its own addresses, as the stock
/// firmware tells the OS.
const EMMC2_BUS_NODE: &[&[u8]] = &[b"", b"emmc2bus"];
const C0_EMMC2_DMA_RANGES: [u8; 20] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfc, 0, 0, 0];

/// The root property the revision code goes in, which nothing but UEFI reads
/// (for the identity SMBIOS gives).
const REVISION_PROPERTY: &[u8] = b"rusty-pi,board-revision";

/// The serial number as a device tree string: eight hex digits, as the
/// bootloader names the board (`serial 1a2b3c4d`), and the NUL.
fn serial_text(serial: u32) -> [u8; 9] {
    let mut text = [0u8; 9];
    for (i, digit) in text[..8].iter_mut().enumerate() {
        *digit = b"0123456789abcdef"[(serial >> (28 - 4 * i) & 0xf) as usize];
    }
    text
}

/// Put `image` at ARM physical 0 and `tree`, with the board's memory, network
/// address and identity filled in, at [`TREE_ADDR`], then let the cores out of
/// reset.
pub fn start(image: &[u8], tree: &[u8], serial: u32, revision: u32, arm_mhz: u32) -> Result<Started, Error> {
    let total = if handover::present() { handover::sdram_mib() as u64 } else { 1024 } << 20;
    let mut reg = [0u8; MEMORY_REG_MAX];
    let reg_len = memory_reg(total, &mut reg);
    let ethernet = ethernet_address(serial);
    // The tree is copied through the windows of its space, each copy with one
    // change: the TPM's node, the TPM's buffer and the watchdog's page in the reserved memory, the
    // network address, the board's serial number and revision, and the
    // memory's `reg`. The last copy is at `TREE_ADDR`.
    let window = TREE_MAX / 4;
    let window_at = |n: usize| TREE_ADDR + (n * window) as u32;
    let with_tpm = fdt::copy_with_node(
        tree,
        arm_memory(window_at(1), window),
        &[b""],
        b"vpu-tpm",
        &[(b"compatible", TPM_COMPATIBLE)],
    )
    .ok_or(Error::Tree)?;
    let with_buffer = fdt::copy_with_node(
        arm_memory(window_at(1), with_tpm),
        arm_memory(window_at(2), window),
        &[b"", b"reserved-memory"],
        CRB_NODE,
        &[(b"reg", &crb_reg()), (b"no-map", b"")],
    )
    .ok_or(Error::Tree)?;
    let with_watchdog = fdt::copy_with_node(
        arm_memory(window_at(2), with_buffer),
        arm_memory(window_at(1), window),
        &[b"", b"reserved-memory"],
        WDAT_NODE,
        &[(b"reg", &wdat_reg()), (b"no-map", b"")],
    )
    .ok_or(Error::Tree)?;
    let (with_address_at, with_address) = match fdt::copy_with_new_property(
        arm_memory(window_at(1), with_watchdog),
        arm_memory(window_at(2), window),
        ETHERNET_NODE,
        b"local-mac-address",
        &ethernet,
    ) {
        Some(len) => (window_at(2), len),
        None => (window_at(1), with_watchdog),
    };
    // The board's identity, where the tree has none: its serial number, which
    // the device tree specification names, and its revision code.
    let spare = |at: u32| if at == window_at(1) { window_at(2) } else { window_at(1) };
    let serial_at = spare(with_address_at);
    let (with_serial_at, with_serial) = match fdt::copy_with_new_property(
        arm_memory(with_address_at, with_address),
        arm_memory(serial_at, window),
        &[b""],
        b"serial-number",
        &serial_text(serial),
    ) {
        Some(len) => (serial_at, len),
        None => (with_address_at, with_address),
    };
    let revision_at = spare(with_serial_at);
    let (with_revision_at, with_revision) = match fdt::copy_with_new_property(
        arm_memory(with_serial_at, with_serial),
        arm_memory(revision_at, window),
        &[b""],
        REVISION_PROPERTY,
        &revision.to_be_bytes(),
    ) {
        Some(len) => (revision_at, len),
        None => (with_serial_at, with_serial),
    };
    let (mut tree_at, mut tree_len) = (with_revision_at, with_revision);
    for node in WIRELESS_NODES {
        let to = spare(tree_at);
        if let Some(len) = fdt::copy_with_property(arm_memory(tree_at, tree_len), arm_memory(to, window), node, b"status", b"disabled\0") {
            (tree_at, tree_len) = (to, len);
        }
    }
    if board::stepping() == board::Stepping::C0 {
        let to = spare(tree_at);
        if let Some(len) =
            fdt::copy_with_property(arm_memory(tree_at, tree_len), arm_memory(to, window), EMMC2_BUS_NODE, b"dma-ranges", &C0_EMMC2_DMA_RANGES)
        {
            (tree_at, tree_len) = (to, len);
        }
    }
    let tree_bytes = fdt::copy_with_property(
        arm_memory(tree_at, tree_len),
        arm_memory(TREE_ADDR, window),
        &[b"", b"memory@0"],
        b"reg",
        &reg[..reg_len],
    )
    .ok_or(Error::Tree)?;
    crb().reset();
    wdat().reset();

    let at = arm_memory(0, image.len());
    at.copy_from_slice(image);
    at[IMAGE_TREE_WORD..IMAGE_TREE_WORD + 4].copy_from_slice(&TREE_ADDR.to_le_bytes());

    power_up();
    crate::rng::quiesce();
    cm::start_arm_pll(arm_mhz);
    for ctl in ARM_TIME_CLOCKS {
        cm::switch_generator(ctl, cm::DIV_ONE, cm::SRC_PLLA_CORE);
    }
    cm::switch_generator(cm::GEN_208_CTL, GEN_208_ARM_DIV, cm::SRC_PLLC_PER);
    prepare_arm();
    hand_card_to_arm();
    mmio::write(REG_7EC10008, mmio::read(REG_7EC10008) & !REG_7EC10008_FIELD | REG_7EC10008_VALUE);
    mmio::write(ARMCTRL + 0x41c, 0xa);
    mmio::write(ARMCTRL + 0x008, 0x3030);
    mmio::write(ARMCTRL, ARMCTRL_RELEASE);
    after_release(arm_mhz);

    let memory_mib = reg[..reg_len]
        .chunks_exact(12)
        .map(|r| u32::from_be_bytes([r[8], r[9], r[10], r[11]]) as u64)
        .sum::<u64>()
        >> 20;
    Ok(Started { image_bytes: image.len(), tree_bytes, memory_mib, ethernet })
}

//! The PCIe root complex (`0x7D50_0000`) and the one endpoint a Pi 4B has
//! behind it: the VIA VL805 xHCI controller on bus 1.
//!
//! The VPU cannot address the endpoint's registers: the outbound window puts
//! them at ARM physical `0x6_0000_0000`, for the UEFI firmware's xHCI driver.
//! Configuration space is reachable directly: the root port's own is the
//! block's first 4 KiB, and anything else is a 4 KiB view the root complex
//! points at whichever function `EXT_CFG_INDEX` selects.
//!
//! The bring-up follows the stock bootloader's register by register; the
//! notes on what the words mean are Linux's `pcie-brcmstb` names where it has
//! them.

use crate::{mmio, timer};

const BASE: u32 = 0x7d50_0000;

/// The root port's PCI Express capability, at `0xac` of its configuration
/// space, at the offsets the capability gives them (`pcie-brcmstb.c`'s
/// `BRCM_PCIE_CAP_REGS`): device control, link capabilities, root control,
/// the second device capability word and the second link control word, and
/// the vendor register that sets the inbound window's endianness.
const RC_CFG_DEVCTL: u32 = BASE + 0x00b4;
const RC_CFG_LNKCAP: u32 = BASE + 0x00b8;
const RC_CFG_RTCTL: u32 = BASE + 0x00c8;
const RC_CFG_DEVCAP2: u32 = BASE + 0x00d0;
const RC_CFG_LNKCTL2: u32 = BASE + 0x00dc;
const RC_CFG_VENDOR_REG1: u32 = BASE + 0x0188;
/// Revision and class code. The root port presents itself as a PCI-to-PCI
/// bridge, which is what makes an operating system walk the bus behind it.
const RC_CFG_PRIV1_ID_VAL3: u32 = BASE + 0x043c;
const CLASS_BRIDGE: u32 = 0x0604_00;
/// Correctable, non-fatal, fatal and unsupported-request reporting.
const DEVCTL_ERRORS: u32 = 0xf;
/// Root control bits the bootloader sets.
const RTCTL_BITS: u32 = 0x18;
/// The link speed the bootloader asks for: 5 GT/s.
const LNKCTL2_SPEED: u32 = 0xf;
const GEN2: u32 = 2;
/// The inbound window's endianness field; clear is little-endian.
const VENDOR_REG1_ENDIAN_BAR2: u32 = 0xc;

const MISC_CTRL: u32 = BASE + 0x4008;
const MEM_WIN0_LO: u32 = BASE + 0x400c;
const MEM_WIN0_HI: u32 = BASE + 0x4010;
const RC_BAR1_CONFIG_LO: u32 = BASE + 0x402c;
const RC_BAR2_CONFIG_LO: u32 = BASE + 0x4034;
const RC_BAR2_CONFIG_HI: u32 = BASE + 0x4038;
const RC_BAR3_CONFIG_LO: u32 = BASE + 0x403c;
const MSI_BAR_CONFIG_LO: u32 = BASE + 0x4044;
const MSI_BAR_CONFIG_HI: u32 = BASE + 0x4048;
const MSI_DATA_CONFIG: u32 = BASE + 0x404c;
/// A word the bootloader sets to 1 once the link is up; Linux does not name
/// it.
const MISC_405C: u32 = BASE + 0x405c;
const MISC_PCIE_STATUS: u32 = BASE + 0x4068;
const MEM_WIN0_BASE_LIMIT: u32 = BASE + 0x4070;
const MEM_WIN0_BASE_HI: u32 = BASE + 0x4080;
const MEM_WIN0_LIMIT_HI: u32 = BASE + 0x4084;
const HARD_DEBUG: u32 = BASE + 0x4204;
const INTR2_CPU_STATUS: u32 = BASE + 0x4300;
const INTR2_CPU_CLR: u32 = BASE + 0x4308;
const INTR2_CPU_MASK_SET: u32 = BASE + 0x4310;
const INTR2_CPU_MASK_CLR: u32 = BASE + 0x4314;
pub const EXT_CFG_DATA: u32 = BASE + 0x8000;
const EXT_CFG_INDEX: u32 = BASE + 0x9000;
const RGR1_SW_INIT_1: u32 = BASE + 0x9210;

/// `MISC_CTRL`: SCB access and UR reads as all-ones, then an SCB0 size of
/// `0x12` in the top five bits.
const MISC_CTRL_ACCESS: u32 = 0x3000;
const MISC_CTRL_SCB0_SIZE: u32 = 0x1f << 27;
const SCB0_SIZE_8G: u32 = 0x12 << 27;
/// `INTR2_CPU_CLR` bit the bootloader clears after its bus scan.
const INTR2_SCAN_DONE: u32 = 0x1000;

/// `RGR1_SW_INIT_1`: the endpoint's reset line, and the bridge's own.
const SW_INIT_PERST: u32 = 1 << 0;
const SW_INIT_BRIDGE: u32 = 1 << 1;

/// `MISC_PCIE_STATUS`: a live link reads `0xb0` — these two and the strap that
/// says the block is a root complex.
const STATUS_PHYLINKUP: u32 = 1 << 4;
const STATUS_DL_ACTIVE: u32 = 1 << 5;
const LINK_UP: u32 = STATUS_PHYLINKUP | STATUS_DL_ACTIVE;

/// `HARD_DEBUG`: the SerDes is powered down out of reset; L1 substates are
/// allowed once the link is up.
const SERDES_IDDQ: u32 = 1 << 27;
const L1SS_ENABLE: u32 = 1 << 21;

/// The inbound window, which is what the endpoint's own DMA comes back
/// through: 8 GiB of memory from zero. The size lives in the low five bits of
/// the low word, and a size of zero turns the window off — an endpoint whose
/// window is off reads back all-ones and has its writes dropped, which is
/// silent. The bootloader puts the window at bus address zero; Linux later
/// moves it to `0x4_0000_0000`, as the board's device tree describes.
const INBOUND_SIZE_8G: u32 = 0x12;
const INBOUND_BUS_HI: u32 = 0;
const INBOUND_SIZE: u32 = 0x1f;

/// The MSI window the bootloader programs.
const MSI_BAR_LO: u32 = 0xffff_fffd;
const MSI_BAR_HI: u32 = 0xf;
const MSI_BAR_DATA: u32 = 0xffe0_6540;

/// The outbound window: the endpoint's registers, CPU side and bus side. The
/// extent is a base in bits 15:4 and a limit in bits 31:20, both in megabytes
/// and both extended by the `_HI` registers, so this is `0x6_0000_0000`
/// through `0x6_3fff_ffff`.
pub const WINDOW_CPU: u64 = 0x6_0000_0000;
const WINDOW_BUS: u32 = 0x8000_0000;
const WINDOW_BASE_LIMIT: u32 = 0x3ff0_0000;
const WINDOW_HI: u32 = 6;

/// Where the endpoint's BAR0 is put on the bus.
pub const BAR0_BUS: u32 = 0x8200_0000;

/// Type 0 and type 1 header words.
const CONFIG_VENDOR: u32 = 0x00;
const CONFIG_DEVICE: u32 = 0x02;
const CONFIG_COMMAND: u32 = 0x04;
const CONFIG_CLASS_REV: u32 = 0x08;
const CONFIG_CACHE_LINE: u32 = 0x0c;
const CONFIG_HEADER_TYPE: u32 = 0x0e;
const CONFIG_BAR0: u32 = 0x10;
const CONFIG_BAR0_HI: u32 = 0x14;
const CONFIG_BAR1: u32 = 0x18;
const CONFIG_INTERRUPT_LINE: u32 = 0x3c;
/// The bridge's windows: memory base and limit, prefetchable base and limit
/// with their upper halves, the I/O upper halves, and the bridge control.
const BRIDGE_MEM_BASE: u32 = 0x20;
const BRIDGE_MEM_LIMIT: u32 = 0x22;
const BRIDGE_PREF_BASE: u32 = 0x24;
const BRIDGE_PREF_LIMIT: u32 = 0x26;
const BRIDGE_PREF_BASE_HI: u32 = 0x28;
const BRIDGE_PREF_LIMIT_HI: u32 = 0x2c;
const BRIDGE_IO_BASE_HI: u32 = 0x30;
const BRIDGE_IO_LIMIT_HI: u32 = 0x32;
const BRIDGE_CONTROL: u32 = 0x3e;
/// What the bootloader leaves in them: the outbound window's bus range for
/// memory, the prefetchable window shut, parity checking on.
const BRIDGE_MEM: (u16, u16) = (0x8000, 0xbff0);
const BRIDGE_PREF: (u16, u16) = (0xfff0, 0);
const BRIDGE_PARITY: u16 = 1;
const RC_INTERRUPT_LINE: u8 = 0x35;
const RC_CACHE_LINE: u8 = 0x10;
/// The MSI capability this part keeps at `0x90`, as the bootloader programs
/// it: four vectors enabled, and the address and data the board runs with.
const CONFIG_MSI_FLAGS: u32 = 0x92;
const CONFIG_MSI_ADDR_LO: u32 = 0x94;
const CONFIG_MSI_ADDR_HI: u32 = 0x98;
const CONFIG_MSI_DATA: u32 = 0x9c;
const MSI_FLAGS: u16 = 0x0085;
const MSI_ADDR_LO: u32 = 0xffff_fffc;
const MSI_ADDR_HI: u32 = 0xf;
const MSI_DATA: u32 = 0x6540;

/// Memory space, bus master, parity and SERR — the command word the board
/// runs with.
pub const COMMAND_ENABLE: u16 = 0x0146;

/// How long the link is given to train.
const LINK_TIMEOUT_US: u32 = 1_000_000;
/// How long the endpoint is held in reset.
const RESET_US: u32 = 10_000;
/// How long after `PERST#` is released the endpoint may take before it
/// answers a configuration request (PCIe CEM 2.2 and 2.3.2; Linux's
/// `pcie-brcmstb` sleeps the same 100 ms on this controller). Link training
/// runs inside it, so it only ever adds what training did not use. The model
/// answers at once, so nothing here shows on it.
const PERST_TO_CONFIG_US: u32 = 100_000;

/// Buses a scan walks. The root complex answers for its own bus and for the
/// one the endpoint is on; everything else reads all-ones.
const BUSES: u32 = 256;
const ABSENT: u16 = 0xffff;

fn rmw(at: u32, clear: u32, set: u32) {
    mmio::write(at, (mmio::read(at) & !clear) | set);
}

/// Put the endpoint and the bridge into reset, and leave them there.
pub fn reset() {
    rmw(RGR1_SW_INIT_1, 0, SW_INIT_BRIDGE);
    rmw(RGR1_SW_INIT_1, 0, SW_INIT_PERST);
    timer::delay_us(RESET_US);
}

/// Put the endpoint and the bridge into reset and power the SerDes down: what
/// `init` undoes. Nothing on the link answers after this.
pub fn power_down() {
    reset();
    rmw(HARD_DEBUG, 0, SERDES_IDDQ);
}

/// Bring the link up the way the bootloader does: release the bridge, power
/// the SerDes, set the windows up, let the endpoint out of reset and wait for
/// it, then set the root port up as a bridge. Whether it trained.
pub fn init() -> bool {
    rmw(RGR1_SW_INIT_1, SW_INIT_BRIDGE, 0);
    rmw(HARD_DEBUG, SERDES_IDDQ, 0);
    timer::delay_us(RESET_US);

    write_back(MISC_CTRL, MISC_CTRL_ACCESS);
    rmw(MISC_CTRL, MISC_CTRL_SCB0_SIZE, SCB0_SIZE_8G);
    let _ = mmio::read(MISC_CTRL);

    set_inbound(INBOUND_SIZE_8G, INBOUND_BUS_HI);
    let msi = [
        (MSI_BAR_CONFIG_LO, MSI_BAR_LO),
        (MSI_BAR_CONFIG_HI, MSI_BAR_HI),
        (MSI_DATA_CONFIG, MSI_BAR_DATA),
    ];
    write_all(&msi);
    // The root complex needs neither of these two windows.
    rmw(RC_BAR1_CONFIG_LO, INBOUND_SIZE, 0);
    rmw(RC_BAR3_CONFIG_LO, INBOUND_SIZE, 0);
    let _ = mmio::read(RC_BAR1_CONFIG_LO);
    let _ = mmio::read(RC_BAR3_CONFIG_LO);
    mmio::write(INTR2_CPU_MASK_SET, !0);
    mmio::write(INTR2_CPU_CLR, !0);
    let _ = mmio::read(RC_CFG_LNKCAP);
    rmw(RC_CFG_LNKCTL2, LNKCTL2_SPEED, GEN2);

    rmw(RGR1_SW_INIT_1, SW_INIT_PERST, 0);
    let _ = mmio::read(RGR1_SW_INIT_1);
    let released = timer::now();
    if !timer::wait(LINK_TIMEOUT_US, || mmio::read(MISC_PCIE_STATUS) & LINK_UP == LINK_UP) {
        return false;
    }
    timer::wait(PERST_TO_CONFIG_US, || {
        timer::now().wrapping_sub(released) >= PERST_TO_CONFIG_US
    });

    rmw(RC_CFG_PRIV1_ID_VAL3, 0xff_ffff, CLASS_BRIDGE);
    rmw(RC_CFG_DEVCTL, 0, DEVCTL_ERRORS);
    rmw(RC_CFG_RTCTL, 0, RTCTL_BITS);
    rmw(RC_CFG_VENDOR_REG1, VENDOR_REG1_ENDIAN_BAR2, 0);
    rmw(HARD_DEBUG, 0, L1SS_ENABLE);
    mmio::write(MISC_405C, 1);
    let window = [
        (MEM_WIN0_LO, WINDOW_BUS),
        (MEM_WIN0_HI, 0),
        (MEM_WIN0_BASE_LIMIT, WINDOW_BASE_LIMIT),
        (MEM_WIN0_BASE_HI, WINDOW_HI),
        (MEM_WIN0_LIMIT_HI, WINDOW_HI),
    ];
    write_all(&window);

    let _ = mmio::read(INTR2_CPU_STATUS);
    let root = Function::ROOT;
    root.write16(BRIDGE_MEM_BASE, BRIDGE_MEM.0);
    root.write16(BRIDGE_MEM_LIMIT, BRIDGE_MEM.1);
    root.write16(BRIDGE_PREF_BASE, BRIDGE_PREF.0);
    root.write16(BRIDGE_PREF_LIMIT, BRIDGE_PREF.1);
    root.write32(BRIDGE_PREF_BASE_HI, 0);
    root.write32(BRIDGE_PREF_LIMIT_HI, 0);
    root.write16(BRIDGE_IO_BASE_HI, 0);
    root.write16(BRIDGE_IO_LIMIT_HI, 0);
    root.write16(BRIDGE_CONTROL, BRIDGE_PARITY);
    root.write8(CONFIG_INTERRUPT_LINE, RC_INTERRUPT_LINE);
    root.write8(CONFIG_CACHE_LINE, RC_CACHE_LINE);
    root.write16(CONFIG_COMMAND, COMMAND_ENABLE);
    mmio::write(INTR2_CPU_MASK_CLR, !0);
    let _ = mmio::read(INTR2_CPU_STATUS);
    let _ = mmio::read(RC_CFG_DEVCAP2);
    true
}

fn write_back(at: u32, value: u32) {
    mmio::write(at, value);
    let _ = mmio::read(at);
}

/// Write each pair, then read them all back.
fn write_all(pairs: &[(u32, u32)]) {
    for &(at, value) in pairs {
        mmio::write(at, value);
    }
    for &(at, _) in pairs {
        let _ = mmio::read(at);
    }
}

fn set_inbound(size: u32, bus_hi: u32) {
    write_all(&[(RC_BAR2_CONFIG_LO, size), (RC_BAR2_CONFIG_HI, bus_hi)]);
}

/// The root complex's latched interrupt causes, which include its bus errors.
pub fn interrupt_status() -> u32 {
    mmio::read(INTR2_CPU_STATUS)
}

/// What the link poll reads, which the bootloader prints when it gives up.
pub fn status() -> u32 {
    mmio::read(MISC_PCIE_STATUS)
}

/// One function's configuration space, reached the way the bootloader's
/// accessors reach it: the root port's directly, anything else with
/// `EXT_CFG_INDEX` selected (and read back) before every access. Every write
/// is read back.
#[derive(Clone, Copy)]
pub struct Function {
    bus: u32,
    /// The root port answers at its own registers, not through the window. A
    /// board puts the endpoint on bus 0 as well, so the bus number alone does
    /// not say which of the two a function is.
    root: bool,
}

impl Function {
    pub const ROOT: Function = Function { bus: 0, root: true };

    pub const fn on_bus(bus: u32) -> Function {
        Function { bus, root: false }
    }

    fn at(&self, off: u32) -> u32 {
        if self.root {
            return BASE + off;
        }
        self.select();
        EXT_CFG_DATA + off
    }

    /// Point `EXT_CFG_INDEX` at the function and read it back.
    pub fn select(&self) {
        select(self.bus);
    }

    /// A long of an endpoint's space, without selecting it first.
    fn read_selected(&self, off: u32) -> u32 {
        mmio::read(EXT_CFG_DATA + off)
    }

    pub fn read8(&self, off: u32) -> u8 {
        mmio::read8(self.at(off))
    }

    pub fn read16(&self, off: u32) -> u16 {
        mmio::read16(self.at(off))
    }

    pub fn read32(&self, off: u32) -> u32 {
        mmio::read(self.at(off))
    }

    pub fn write8(&self, off: u32, value: u8) {
        let at = self.at(off);
        mmio::write8(at, value);
        let _ = mmio::read8(at);
    }

    pub fn write16(&self, off: u32, value: u16) {
        let at = self.at(off);
        mmio::write16(at, value);
        let _ = mmio::read16(at);
    }

    /// Write, and give back what reads back.
    pub fn write32(&self, off: u32, value: u32) -> u32 {
        let at = self.at(off);
        mmio::write(at, value);
        mmio::read(at)
    }

    /// Read-modify-write of the command word.
    pub fn set_command(&self, command: u16) {
        let _ = self.read16(CONFIG_COMMAND);
        self.write16(CONFIG_COMMAND, command);
    }
}

fn select(bus: u32) {
    mmio::write(EXT_CFG_INDEX, bus << 20);
    let _ = mmio::read(EXT_CFG_INDEX);
}

/// Walk the buses for functions that answer, reporting each with its vendor
/// and device, then acknowledge the scan. Bus 0 is looked at through the
/// window too, where the root port does not answer.
pub fn scan(mut found: impl FnMut(u32, u32, u32)) {
    for bus in 0..BUSES {
        select(bus);
        let vendor = mmio::read16(EXT_CFG_DATA + CONFIG_VENDOR);
        if vendor == ABSENT {
            continue;
        }
        let device = mmio::read16(EXT_CFG_DATA + CONFIG_DEVICE);
        let _ = mmio::read(EXT_CFG_DATA + CONFIG_CLASS_REV);
        let _ = mmio::read(EXT_CFG_DATA + CONFIG_BAR0);
        found(bus, vendor as u32, device as u32);
        let _ = mmio::read8(EXT_CFG_DATA + CONFIG_HEADER_TYPE);
    }
    mmio::write(INTR2_CPU_CLR, INTR2_SCAN_DONE);
    let _ = mmio::read(INTR2_CPU_STATUS);
}

/// Turn the endpoint off the bus, size its BARs, put BAR0 in the window and
/// program its MSI capability; it stays off until its firmware is in. What
/// BAR0's sizing read back, which says how big the region is. BAR0 is 64-bit,
/// so its upper half is sized with it.
pub fn assign_bar0(bus: u32) -> u32 {
    let _ = mmio::read(INTR2_CPU_STATUS);
    let ep = Function::on_bus(bus);
    ep.select();
    ep.set_command(0);
    let _ = ep.read_selected(CONFIG_BAR0);
    ep.select();
    let mask = ep.write32(CONFIG_BAR0, !0);
    ep.write32(CONFIG_BAR0_HI, !0);
    for off in [CONFIG_BAR0_HI, CONFIG_BAR0, CONFIG_BAR1] {
        let _ = ep.read_selected(off);
    }
    ep.select();
    ep.write32(CONFIG_BAR1, !0);
    let _ = ep.read_selected(CONFIG_BAR1);
    ep.write32(CONFIG_BAR0, BAR0_BUS);
    ep.write32(CONFIG_BAR0_HI, 0);
    // Whether the window still points at the endpoint when BAR0 reads zero:
    // its own id, its class and BAR0, read one after the other, with what
    // `EXT_CFG_INDEX` holds while they are read.
    ep.write32(CONFIG_BAR0, BAR0_BUS);

    let _ = mmio::read(INTR2_CPU_STATUS);
    ep.write16(CONFIG_MSI_FLAGS, MSI_FLAGS);
    ep.write32(CONFIG_MSI_ADDR_LO, MSI_ADDR_LO);
    ep.write32(CONFIG_MSI_ADDR_HI, MSI_ADDR_HI);
    ep.write32(CONFIG_MSI_DATA, MSI_DATA);
    let _ = mmio::read(INTR2_CPU_STATUS);
    ep.set_command(0);
    mask
}

/// Where a register in the endpoint's BAR0 sits, as the DMA engine addresses
/// it: through the outbound window, which the VPU itself cannot reach.
pub fn bar0_cpu(off: u32) -> u64 {
    WINDOW_CPU + (BAR0_BUS - WINDOW_BUS) as u64 + off as u64
}

/// The inbound window as it stands: its high word, then its low word (size,
/// and the base's low bits), read in that order.
pub fn inbound() -> (u32, u32) {
    let hi = mmio::read(RC_BAR2_CONFIG_HI);
    (hi, mmio::read(RC_BAR2_CONFIG_LO))
}

/// Where memory at `phys` is on the bus, which is how the endpoint has to be
/// given every address it fetches from or posts to.
pub fn bus_addr(phys: u32) -> u64 {
    (INBOUND_BUS_HI as u64) << 32 | phys as u64
}

/// The function `EXT_CFG_INDEX` selects, and a new selection.
pub fn selected() -> u32 {
    mmio::read(EXT_CFG_INDEX)
}

pub fn select_raw(index: u32) {
    mmio::write(EXT_CFG_INDEX, index);
}

/// A byte, word or long of the currently selected function, without
/// selecting it again: how start4 reaches the endpoint once Linux owns the
/// root complex. Each write is followed by a read of the function's first
/// long, as start4's accessor does.
pub mod selected {
    use super::{EXT_CFG_DATA, mmio};

    fn settle() {
        let _ = mmio::read(EXT_CFG_DATA);
    }

    pub fn read16(off: u32) -> u16 {
        mmio::read16(EXT_CFG_DATA + off)
    }

    pub fn read32(off: u32) -> u32 {
        mmio::read(EXT_CFG_DATA + off)
    }

    pub fn write8(off: u32, value: u8) {
        mmio::write8(EXT_CFG_DATA + off, value);
        settle();
    }

    pub fn write16(off: u32, value: u16) {
        mmio::write16(EXT_CFG_DATA + off, value);
        settle();
    }

    pub fn write32(off: u32, value: u32) {
        mmio::write(EXT_CFG_DATA + off, value);
        settle();
    }
}

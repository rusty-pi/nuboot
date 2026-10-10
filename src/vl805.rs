//! The VL805's firmware, which a Pi 4B without an EEPROM of its own for the
//! chip gets from the host every time it is reset: a hub image streamed into
//! the chip through a vendor port in its configuration space, and an MCU image
//! the chip fetches itself from host memory.
//!
//! Both come out of the EEPROM (`vl805hub.bin`, `vl805mcu.bin`). start4 loads
//! them into the top of the VPU's memory, where they stay, and programs the
//! chip; it programs the chip again from those copies whenever Linux resets
//! it.
//!
//! Register indices, values and waits are the stock firmware's; what they
//! mean inside the chip is not documented.

use crate::pcie::{self, Function};
use crate::{mmio, timer};

/// Configuration-space byte that opens the vendor port.
const VENDOR_ACCESS: u32 = 0x43;
/// The port: an index long, then a data long whose bytes can be written
/// singly.
const PORT_INDEX: u32 = 0x78;
const PORT_DATA: u32 = 0x7c;
const PORT_DATA_BYTE1: u32 = 0x7d;
const PORT_DATA_HALF1: u32 = 0x7e;
const COMMAND: u32 = 0x04;

/// Where the hub image goes, a byte an index.
const HUB_IMAGE: u32 = 0x5_2000;
/// Two control words around the hub image: `0x48`/`0` hold the hub, and
/// `0x4c`/`0x80` let it run the image just written.
const HUB_CTRL: u32 = 0x5_1000;
const HUB_CTRL2: u32 = 0x5_1004;
const HUB_HOLD: (u32, u32) = (0x48, 0);
const HUB_RUN: (u32, u32) = (0x4c, 0x80);
/// The MCU image: its bus address in 64-byte units, then control words.
const MCU_ADDR: u32 = 0x3_0000;
const MCU_CTRL: u32 = 0x3_0004;
const MCU_CTRL2: u32 = 0x3_0008;
const MCU_CTRL3: u32 = 0x3_000c;
const MCU_CTRL3_VALUE: u32 = 0x500;
const MCU_CTRL2_HALF1: u16 = 0x1800;
const MCU_ADDR_SHIFT: u32 = 6;

/// The largest images either firmware takes.
const HUB_LIMIT: usize = 12288;
const MCU_LIMIT: u32 = 0x2_0000;

/// How long the bootloader and start4 let the chip settle between steps.
const BOOT_SETTLE_US: u32 = 4_000;
const FIRMWARE_SETTLE_US: u32 = 5_000;

const VENDOR_ID: u16 = 0x1106;
const DEVICE_ID: u16 = 0x3483;
/// The function start4 reloads: bus 1, device 0.
const ENDPOINT_INDEX: u32 = 1 << 20;

/// Where the images sit (the VPU's uncached view, above `start4.elf`'s 16 MiB),
/// and the room each image has.
pub const HUB_AT: u32 = 0xfff0_0000;
pub const MCU_AT: u32 = 0xfff2_0000;
pub const IMAGE_ROOM: usize = 0x2_0000;

/// Where start4 finds the images: addresses as the VPU sees them, and
/// lengths.
#[derive(Clone, Copy)]
pub struct Images {
    pub hub: (u32, u32),
    pub mcu: (u32, u32),
}

impl Images {
    fn hub(&self) -> &'static [u8] {
        let (at, len) = self.hub;
        unsafe { core::slice::from_raw_parts(at as usize as *const u8, len as usize) }
    }
}

/// The copies the chip is reloaded from.
static mut IMAGES: Option<Images> = None;

pub fn keep(images: Images) {
    unsafe { IMAGES = Some(images) };
}

/// The port as the bootloader drives it: every access selects the function
/// and every write is read back; a verify read writes the index straight.
struct BootPort(Function);

/// The port as start4 drives it, with the function already selected: each
/// write is followed by a read of the function's first long.
struct FirmwarePort;

trait Port {
    fn byte(&self, off: u32, value: u8);
    fn half(&self, off: u32, value: u16);
    fn long(&self, off: u32, value: u32);
    /// Point the index at `index` for a read.
    fn index_for_read(&self, index: u32);

    fn set(&self, index: u32, value: u32) {
        self.long(PORT_INDEX, index);
        self.long(PORT_DATA, value);
    }
}

impl Port for BootPort {
    fn byte(&self, off: u32, value: u8) {
        self.0.write8(off, value);
    }
    fn half(&self, off: u32, value: u16) {
        self.0.write16(off, value);
    }
    fn long(&self, off: u32, value: u32) {
        self.0.write32(off, value);
    }
    fn index_for_read(&self, index: u32) {
        mmio::write(pcie::EXT_CFG_DATA + PORT_INDEX, index);
    }
}

impl Port for FirmwarePort {
    fn byte(&self, off: u32, value: u8) {
        pcie::selected::write8(off, value);
    }
    fn half(&self, off: u32, value: u16) {
        pcie::selected::write16(off, value);
    }
    fn long(&self, off: u32, value: u32) {
        pcie::selected::write32(off, value);
    }
    fn index_for_read(&self, index: u32) {
        pcie::selected::write32(PORT_INDEX, index);
    }
}

/// Each byte four times over, which is how the stock firmware fills the data
/// long.
fn spread(byte: u8) -> u32 {
    byte as u32 * 0x0101_0101
}

fn fill_hub<P: Port>(port: &P, len: usize, byte: impl Fn(usize) -> u8) {
    for i in 0..len {
        port.set(HUB_IMAGE + i as u32, spread(byte(i)));
    }
}

fn hub_control<P: Port>(port: &P, (ctrl, ctrl2): (u32, u32)) {
    port.set(HUB_CTRL, ctrl);
    port.set(HUB_CTRL2, ctrl2);
}

/// Read the hub image back; whether it all matched. Both firmwares stop at
/// the first mismatch.
fn verify_hub<P: Port>(port: &P, image: &[u8]) -> bool {
    image.iter().enumerate().all(|(i, &byte)| {
        port.index_for_read(HUB_IMAGE + i as u32);
        pcie::selected::read32(PORT_DATA) & 0xff == byte as u32
    })
}

/// The MCU image's bus address in the chip's units, through the inbound
/// window as it is set up now (its high word read first, as both firmwares
/// do).
fn mcu_address(phys: u32) -> u32 {
    let (hi, lo) = pcie::inbound();
    ((phys & 0x3fff_ffff) | (lo & !0xfff)) >> MCU_ADDR_SHIFT | hi << (32 - MCU_ADDR_SHIFT)
}

/// Point the MCU at its image and start it.
fn start_mcu<P: Port>(port: &P, address: u32) {
    port.set(MCU_ADDR, address);
    port.long(PORT_INDEX, MCU_CTRL);
    port.byte(PORT_DATA, 1);
    port.long(PORT_INDEX, MCU_CTRL);
    port.byte(PORT_DATA_BYTE1, 0);
    port.set(MCU_CTRL3, MCU_CTRL3_VALUE);
    port.long(PORT_INDEX, MCU_CTRL2);
    port.half(PORT_DATA_HALF1, MCU_CTRL2_HALF1);
    port.long(PORT_INDEX, MCU_CTRL2);
    port.byte(PORT_DATA, 1);
}

/// The bootloader's load into the endpoint on `bus`, which it leaves switched
/// off: the hub image in and checked, then the MCU pointed at its image.
/// Whether the hub image read back intact.
pub fn boot_load(bus: u32, hub: &[u8], mcu_phys: u32) -> bool {
    if hub.len() > HUB_LIMIT {
        return false;
    }
    let address = mcu_address(mcu_phys);
    let port = BootPort(Function::on_bus(bus));
    port.byte(VENDOR_ACCESS, 1);
    fill_hub(&port, hub.len(), |i| hub[i]);
    hub_control(&port, HUB_RUN);
    timer::delay_us(BOOT_SETTLE_US);
    let ok = verify_hub(&port, hub);
    if ok {
        hub_control(&port, HUB_HOLD);
        timer::delay_us(BOOT_SETTLE_US);
        start_mcu(&port, address);
    }
    port.byte(VENDOR_ACCESS, 0);
    ok
}

/// What start4 does for Linux's `NOTIFY_XHCI_RESET`: reload the chip from the
/// copies [`keep`] took, the old hub image cleared first. The answer is 0, or
/// all-ones when the images are missing, the device is not a VL805 or the hub
/// image did not read back.
pub fn firmware_reset() -> u32 {
    const FAILED: u32 = !0;
    let images = unsafe { IMAGES };
    let saved = pcie::selected();
    pcie::select_raw(ENDPOINT_INDEX);
    let id = (pcie::selected::read16(0), pcie::selected::read16(2));
    let status = match images {
        Some(images) if id == (VENDOR_ID, DEVICE_ID) => reload(&images),
        _ => FAILED,
    };
    let _ = pcie::selected();
    pcie::select_raw(saved);
    status
}

fn reload(images: &Images) -> u32 {
    const FAILED: u32 = !0;
    let hub = images.hub();
    if hub.len() > HUB_LIMIT || images.mcu.1 > MCU_LIMIT {
        return FAILED;
    }
    let port = FirmwarePort;
    let command = pcie::selected::read16(COMMAND);
    port.half(COMMAND, 0);
    port.byte(VENDOR_ACCESS, 1);
    timer::delay_us(FIRMWARE_SETTLE_US);
    fill_hub(&port, hub.len(), |_| 0);
    timer::delay_us(FIRMWARE_SETTLE_US);
    hub_control(&port, HUB_HOLD);
    timer::delay_us(FIRMWARE_SETTLE_US);

    port.half(COMMAND, 0);
    port.byte(VENDOR_ACCESS, 1);
    timer::delay_us(FIRMWARE_SETTLE_US);
    fill_hub(&port, hub.len(), |i| hub[i]);
    hub_control(&port, HUB_RUN);
    timer::delay_us(FIRMWARE_SETTLE_US);
    let status = if verify_hub(&port, hub) {
        hub_control(&port, HUB_HOLD);
        start_mcu(&port, mcu_address(images.mcu.0));
        0
    } else {
        FAILED
    };

    // The port closes and the command word comes back, with the endpoint on
    // the bus, a byte at a time.
    let command = command | pcie::COMMAND_ENABLE;
    pcie::selected::write8(VENDOR_ACCESS, 0);
    mmio::write8(pcie::EXT_CFG_DATA + COMMAND, command as u8);
    pcie::selected::write8(COMMAND + 1, (command >> 8) as u8);
    status
}

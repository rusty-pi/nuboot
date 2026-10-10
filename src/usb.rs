//! USB: the PCIe link to the VL805 and the controller's firmware, set up so
//! the UEFI firmware finds an xHCI controller with its registers in the
//! outbound window.

use crate::board::Board;
use crate::{eeprom, error, info, pcie, vl805, warn};

const VL805_VENDOR: u32 = 0x1106;
const VL805_DEVICE: u32 = 0x3483;

/// Read the VL805's two images out of the EEPROM to where they stay: the MCU
/// fetches its image from memory whenever the chip is reset. Their lengths.
fn load_images() -> Option<(usize, usize)> {
    let room = |at: u32| unsafe { core::slice::from_raw_parts_mut(at as usize as *mut u8, vl805::IMAGE_ROOM) };
    let load = |name: &[u8], at: u32| match eeprom::load(name, room(at)) {
        Ok(len) => Some(len),
        Err(e) => {
            error!("usb", "VL805 firmware missing from the EEPROM";
                file = core::str::from_utf8(name).unwrap_or("?"), error = format_args!("{e:?}"));
            None
        }
    };
    Some((load(b"vl805hub.bin", vl805::HUB_AT)?, load(b"vl805mcu.bin", vl805::MCU_AT)?))
}

/// Bring the link up, find the VL805, put its registers in the outbound
/// window and give it its firmware if the board does not keep it in flash of
/// its own. Whether the controller is there to use.
pub fn bring_up(board: &Board) -> bool {
    pcie::reset();
    if !pcie::init() {
        error!("pcie", "the link did not come up"; status = format_args!("{:#010x}", pcie::status()));
        return false;
    }
    let mut endpoint = None;
    pcie::scan(|bus, vendor, device| {
        if vendor == VL805_VENDOR && device == VL805_DEVICE {
            endpoint = Some(bus);
        } else {
            warn!("pcie", "unexpected device"; bus = bus,
                vendor = format_args!("{vendor:04x}"), device = format_args!("{device:04x}"));
        }
    });
    let Some(bus) = endpoint else {
        error!("pcie", "no VL805 on the link");
        return false;
    };
    pcie::assign_bar0(bus);
    let mut firmware = "flash";
    if board.vl805_from_host() {
        let Some((hub, mcu)) = load_images() else {
            return false;
        };
        let image = unsafe { core::slice::from_raw_parts(vl805::HUB_AT as *const u8, hub) };
        if !vl805::boot_load(bus, image, vl805::MCU_AT) {
            error!("usb", "the VL805's hub firmware did not read back");
            return false;
        }
        vl805::keep(vl805::Images { hub: (vl805::HUB_AT, hub as u32), mcu: (vl805::MCU_AT, mcu as u32) });
        firmware = "loaded";
    }
    let ep = pcie::Function::on_bus(bus);
    ep.set_command(pcie::COMMAND_ENABLE);
    info!("usb", "VL805 xHCI controller up"; bus = bus, firmware = firmware,
        registers = format_args!("{:#x}", pcie::bar0_cpu(0)));
    true
}

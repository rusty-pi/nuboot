//! The BCM2711's PCIe root complex as CrabEFI's host bridge.
//!
//! The VPU firmware has brought the link up, given the VL805 its firmware and
//! put the controller's BAR0 in the outbound window, so all that is left here
//! is configuration space and the two address translations:
//!
//! - The root port is bus 0, device 0, at the block's own registers. Every
//!   other function is a 4 KiB view at `EXT_CFG_DATA` the root complex points
//!   at whatever `EXT_CFG_INDEX` selects; the only one there is is the VL805
//!   on bus 1, device 0.
//! - Bus addresses `0x8000_0000..0xC000_0000` are ARM physical
//!   `0x6_0000_0000..0x6_4000_0000` (the outbound window), and the inbound
//!   window shows the VL805 memory at bus address 0 as it is.

use crabefi::efi::dma::{DmaCoherency, DmaDomain};

const BASE: u64 = 0xFD50_0000;
const EXT_CFG_DATA: u64 = BASE + 0x8000;
const EXT_CFG_INDEX: u64 = BASE + 0x9000;

const WINDOW_BUS: u64 = 0x8000_0000;
const WINDOW_CPU: u64 = 0x6_0000_0000;
const WINDOW_SIZE: u64 = 0x4000_0000;

/// What the controller may be given to fetch from: the memory below the
/// peripherals, which is all of the first 3 GiB on every board this runs on.
const DMA_SIZE: u64 = 0xC000_0000;

const ABSENT: u32 = u32::MAX;

pub struct RootComplex;

impl RootComplex {
    /// Where a function's dword sits, selecting it first; None for a function
    /// that is not there.
    fn at(&self, bus: u8, device: u8, function: u8, offset: u16) -> Option<u64> {
        if device != 0 || function != 0 {
            return None;
        }
        match bus {
            0 => Some(BASE + offset as u64),
            1 => unsafe {
                core::ptr::write_volatile(EXT_CFG_INDEX as *mut u32, 1 << 20);
                let _ = core::ptr::read_volatile(EXT_CFG_INDEX as *const u32);
                Some(EXT_CFG_DATA + offset as u64)
            },
            _ => None,
        }
    }
}

impl crabefi::PlatformPci for RootComplex {
    fn bus_range(&self) -> (u8, u8) {
        (0, 1)
    }

    fn read32(&self, bus: u8, device: u8, function: u8, offset: u16) -> u32 {
        match self.at(bus, device, function, offset) {
            Some(at) => unsafe { core::ptr::read_volatile(at as *const u32) },
            None => ABSENT,
        }
    }

    fn write32(&self, bus: u8, device: u8, function: u8, offset: u16, value: u32) {
        if let Some(at) = self.at(bus, device, function, offset) {
            unsafe { core::ptr::write_volatile(at as *mut u32, value) };
        }
    }

    fn mmio_to_cpu(&self, bus_address: u64) -> u64 {
        if (WINDOW_BUS..WINDOW_BUS + WINDOW_SIZE).contains(&bus_address) {
            bus_address - WINDOW_BUS + WINDOW_CPU
        } else {
            bus_address
        }
    }

    fn dma_domain(&self) -> Option<DmaDomain> {
        Some(DmaDomain {
            cpu_base: 0,
            device_base: 0,
            size: DMA_SIZE,
            coherency: DmaCoherency::NonCoherent,
        })
    }
}

pub static ROOT_COMPLEX: RootComplex = RootComplex;

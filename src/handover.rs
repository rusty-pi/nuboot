//! The state the EEPROM bootloader leaves for `start4.elf`: the tagged block
//! at ARM physical `0x40000`, whose address it writes into the image's `BSTA`
//! word. This tree's own first stage leaves the same block, with only the
//! fields below filled in.

use crate::mmio;

/// The VPU's uncached view of where the block sits.
const ADDR: u32 = 0xc004_0000;

const MAGIC: u32 = 0x4554_5342; // "BSTE", little-endian

/// Fields, from the start of the block. In `BVER`: the bootloader's version,
/// a NUL-terminated hash of its source, and how much SDRAM the bootcode
/// measured, in gigabits.
const VERSION: u32 = 0x018;
const VERSION_LEN: usize = 41;
const SDRAM_GBIT: u32 = 0x094;
/// In `BSTM`: the medium the firmware came off.
const BOOT_DEVICE: u32 = 0x198;
/// In `BPWR`: when the boot watchdog's budget runs out, as 64-bit system timer
/// microseconds, and the budget itself in seconds.
const BOOT_WATCHDOG_END_AT: u32 = 0x300;
const BOOT_WATCHDOG_TIMEOUT: u32 = 0x308;
/// The whole block as the stock bootcode lays it out.
const LEN: u32 = 0x3b4;
/// The block's header is `BSTE`, its length and where the tags start (12); each
/// tag is its name, its length counting this header, the length again, and its
/// words.
const FIRST_TAG: u32 = 0x008;
const TAG_HEADER: u32 = 12;
/// `RDSK`: where the bootloader put `boot.img` and how long it is, in bytes.
const RAMDISK_TAG: u32 = 0x4b53_4452;

/// The medium code for firmware that came out of the EEPROM itself. Not a
/// stock code: only this tree's first stage writes it.
pub const DEVICE_EEPROM: u32 = 0x10;

/// Leave the block for the next stage: the version (cut to fit), the SDRAM
/// in gigabits, the boot medium and the boot watchdog's deadline and budget,
/// and everything else zero.
pub fn write(version: &[u8], sdram_gbit: u32, device: u32, watchdog_end_at: u64, watchdog_s: u32) {
    for off in (0..LEN).step_by(4) {
        mmio::write(ADDR + off, 0);
    }
    mmio::write(ADDR, MAGIC);
    mmio::write(ADDR + 4, LEN);
    for (i, &b) in version.iter().take(VERSION_LEN - 1).enumerate() {
        mmio::write8(ADDR + VERSION + i as u32, b);
    }
    mmio::write(ADDR + SDRAM_GBIT, sdram_gbit);
    mmio::write(ADDR + BOOT_DEVICE, device);
    mmio::write(ADDR + BOOT_WATCHDOG_END_AT, watchdog_end_at as u32);
    mmio::write(ADDR + BOOT_WATCHDOG_END_AT + 4, (watchdog_end_at >> 32) as u32);
    mmio::write(ADDR + BOOT_WATCHDOG_TIMEOUT, watchdog_s);
}

pub fn present() -> bool {
    mmio::read(ADDR) == MAGIC
}

/// The bootloader's version, up to its NUL.
pub fn version() -> Version {
    let mut text = [0u8; VERSION_LEN];
    for (i, b) in text.iter_mut().enumerate() {
        *b = unsafe { core::ptr::read_volatile((ADDR + VERSION + i as u32) as *const u8) };
    }
    let len = text.iter().position(|&b| b == 0).unwrap_or(VERSION_LEN);
    Version { text, len }
}

pub struct Version {
    text: [u8; VERSION_LEN],
    len: usize,
}

impl core::fmt::Display for Version {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let text = core::str::from_utf8(&self.text[..self.len]).unwrap_or("?");
        f.write_str(text)
    }
}

/// How much SDRAM the board has, in MiB.
pub fn sdram_mib() -> u32 {
    mmio::read(ADDR + SDRAM_GBIT) * 128
}

/// The medium the bootloader loaded this firmware from.
pub fn boot_device() -> BootDevice {
    match mmio::read(ADDR + BOOT_DEVICE) {
        0 => BootDevice::Sd,
        1 => BootDevice::Network,
        2 => BootDevice::Usb,
        4 => BootDevice::UsbC,
        5 => BootDevice::Ramdisk,
        DEVICE_EEPROM => BootDevice::Eeprom,
        other => BootDevice::Other(other),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BootDevice {
    Sd,
    Network,
    /// A drive on the VL805's ports.
    Usb,
    /// A drive on the BCM2711's own xHCI, behind the USB-C socket.
    UsbC,
    Ramdisk,
    /// The EEPROM, with this tree's first stage.
    Eeprom,
    Other(u32),
}

impl core::fmt::Display for BootDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            BootDevice::Sd => f.write_str("sd"),
            BootDevice::Network => f.write_str("network"),
            BootDevice::Usb => f.write_str("usb"),
            BootDevice::UsbC => f.write_str("usb-c"),
            BootDevice::Ramdisk => f.write_str("ramdisk"),
            BootDevice::Eeprom => f.write_str("eeprom"),
            BootDevice::Other(code) => write!(f, "unknown-{code}"),
        }
    }
}

/// The ARM physical address and the length in bytes of the `boot.img` the
/// bootloader checked and started this firmware out of, if it says so.
pub fn ramdisk() -> Option<(u32, u32)> {
    if !present() || boot_device() != BootDevice::Ramdisk {
        return None;
    }
    let end = mmio::read(ADDR + 4).min(LEN);
    let mut at = mmio::read(ADDR + FIRST_TAG);
    while at >= TAG_HEADER && at + TAG_HEADER <= end {
        let len = mmio::read(ADDR + at + 4);
        if len < TAG_HEADER || len % 4 != 0 {
            return None;
        }
        if mmio::read(ADDR + at) == RAMDISK_TAG && len >= TAG_HEADER + 8 {
            return Some((mmio::read(ADDR + at + TAG_HEADER), mmio::read(ADDR + at + TAG_HEADER + 4)));
        }
        at += len;
    }
    None
}

/// When the boot watchdog's budget runs out, in system timer microseconds;
/// 0 when the bootloader armed none.
pub fn boot_watchdog_end_at() -> u64 {
    if !present() {
        return 0;
    }
    let lo = mmio::read(ADDR + BOOT_WATCHDOG_END_AT);
    let hi = mmio::read(ADDR + BOOT_WATCHDOG_END_AT + 4);
    (hi as u64) << 32 | lo as u64
}

/// The boot watchdog's budget in seconds, 0 for none.
pub fn boot_watchdog_timeout() -> u32 {
    if !present() {
        return 0;
    }
    mmio::read(ADDR + BOOT_WATCHDOG_TIMEOUT)
}

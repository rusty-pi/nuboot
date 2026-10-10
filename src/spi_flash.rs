//! The SPI NOR flash that holds `pieeprom.bin`: SPI0 on GPIO 40..43 (ALT4),
//! polled.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::{gpio, mmio, timer};

const CS: u32 = 0x7e20_4000;
const FIFO: u32 = 0x7e20_4004;
const CLK: u32 = 0x7e20_4008;

const CS_TA: u32 = 1 << 7;
const CS_RXD: u32 = 1 << 17;
const CS_TXD: u32 = 1 << 18;

const CMD_READ: u8 = 0x03;
const CMD_FAST_READ: u8 = 0x0b;
const CMD_READ_SFDP: u8 = 0x5a;
const CMD_READ_ID: u8 = 0x9f;

/// SPI0's pins on ALT4. GPIO 42 also drives the activity LED.
const SPI_PINS: [u32; 4] = [43, 40, 41, 42];

/// SPI clock divider, against the VPU's clock: 4 while the core is still on
/// the crystal (13.5 MHz), and [`PLL_DIVIDER`] once it runs off a PLL.
///
/// Every stage has its own copy of this, so a stage entered with the PLLs
/// already up has to set it: left at 4 with the core near 500 MHz the flash is
/// clocked at ~125 MHz, well past what a W25X40 answers at, and every read
/// comes back as zeros (`EEPROM ID 0x000000` on a 4B rev 1.5, where the
/// bootcode's own reads at the same divider had worked).
static DIVIDER: AtomicU32 = AtomicU32::new(4);

/// What both stock stages clock the flash with once the PLLs are running.
pub const PLL_DIVIDER: u32 = 0x20;

pub fn set_divider(div: u32) {
    DIVIDER.store(div, Ordering::Relaxed);
}

/// Hand the pins to SPI0 for `f`, then back as inputs.
pub fn with_pins<R>(f: impl FnOnce() -> R) -> R {
    for pin in SPI_PINS {
        gpio::set_function(pin, gpio::ALT4);
    }
    let r = f();
    mmio::write(CS, 0);
    mmio::write(CLK, 0);
    for pin in SPI_PINS {
        gpio::set_function(pin, gpio::INPUT);
    }
    r
}

/// Inlined so that a bulk loop around it keeps the two register addresses in
/// registers instead of materializing each of them again a byte.
#[inline(always)]
fn xfer(b: u8) -> u8 {
    timer::wait(1000, || mmio::read(CS) & CS_TXD != 0);
    mmio::write(FIFO, b as u32);
    timer::wait(1000, || mmio::read(CS) & CS_RXD != 0);
    mmio::read(FIFO) as u8
}

/// One command, chip select held until it is dropped.
pub struct Transfer;

impl Transfer {
    pub fn start(cmd: u8, addr: Option<u32>, dummy: bool) -> Transfer {
        // The stock stages set nothing but TA (`0x8000B14E`): a transfer
        // clocked a byte at a time leaves the FIFOs empty.
        mmio::write(CLK, DIVIDER.load(Ordering::Relaxed));
        mmio::write(CS, CS_TA);
        xfer(cmd);
        if let Some(a) = addr {
            for b in [(a >> 16) as u8, (a >> 8) as u8, a as u8] {
                xfer(b);
            }
        }
        if dummy {
            xfer(0);
        }
        Transfer
    }

    #[inline(always)]
    pub fn byte(&mut self) -> u8 {
        xfer(0)
    }

    pub fn read(&mut self, buf: &mut [u8]) {
        for b in buf {
            *b = xfer(0);
        }
    }
}

impl Drop for Transfer {
    fn drop(&mut self) {
        mmio::write(CS, mmio::read(CS) & !CS_TA);
    }
}

impl crate::lz4::Source for Transfer {
    fn byte(&mut self) -> u8 {
        Transfer::byte(self)
    }
}

/// JEDEC manufacturer and device id.
pub fn read_id() -> [u8; 3] {
    let mut id = [0; 3];
    Transfer::start(CMD_READ_ID, None, false).read(&mut id);
    id
}

/// The SFDP header and first parameter header, when the part has them.
pub fn read_sfdp(buf: &mut [u8; 256]) {
    Transfer::start(CMD_READ_SFDP, Some(0), true).read(buf);
}

pub fn read(addr: u32, buf: &mut [u8]) {
    Transfer::start(CMD_READ, Some(addr), false).read(buf);
}

/// A fast read from `addr`, streamed.
pub fn fast_read(addr: u32) -> Transfer {
    Transfer::start(CMD_FAST_READ, Some(addr), true)
}

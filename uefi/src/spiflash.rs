//! The SPI NOR flash that holds `pieeprom.bin`, read from the ARM: SPI0 on GPIO
//! 40..42 (ALT4) with the flash's chip select, GPIO 43, driven as an output,
//! the way Linux's `spi-gpio40-45` overlay wires it. The firmware never writes
//! it.

use crate::util::{read32, wait_for, write32};

const GPIO: u64 = 0xFE20_0000;
const GPFSEL4: u64 = GPIO + 0x10;
const GPSET1: u64 = GPIO + 0x20;
const GPCLR1: u64 = GPIO + 0x2C;
const SELECT_PIN: u32 = 43;

const SPI: u64 = 0xFE20_4000;
const CS: u64 = SPI;
const FIFO: u64 = SPI + 0x04;
const CLK: u64 = SPI + 0x08;

const CS_CLEAR: u32 = 0b11 << 4;
const CS_TA: u32 = 1 << 7;
const CS_RXD: u32 = 1 << 17;
const CS_TXD: u32 = 1 << 18;

/// The clock divider both stock stages use once the PLLs run: about 15 MHz.
const DIVIDER: u32 = 0x20;

const READ: u8 = 0x03;
const READ_ID: u8 = 0x9f;

/// GPFSEL4 for pins 40..43: ALT4 on the three SPI pins, an output for the
/// select.
const FUNCTIONS: u32 = (0b011) | (0b011 << 3) | (0b011 << 6) | (0b001 << 9);
const FUNCTION_MASK: u32 = 0xfff;

/// Pins 40..43 handed to SPI0 for as long as it lives.
struct Pins(u32);

impl Pins {
    fn take() -> Pins {
        let saved = read32(GPFSEL4);
        write32(GPFSEL4, saved & !FUNCTION_MASK | FUNCTIONS);
        write32(GPSET1, 1 << (SELECT_PIN - 32));
        write32(CS, CS_CLEAR);
        write32(CLK, DIVIDER);
        Pins(saved)
    }
}

impl Drop for Pins {
    fn drop(&mut self) {
        write32(CS, 0);
        write32(CLK, 0);
        write32(GPFSEL4, read32(GPFSEL4) & !FUNCTION_MASK | self.0 & FUNCTION_MASK);
    }
}

fn xfer(byte: u8) -> u8 {
    wait_for(10_000, || read32(CS) & CS_TXD != 0);
    write32(FIFO, byte as u32);
    wait_for(10_000, || read32(CS) & CS_RXD != 0);
    read32(FIFO) as u8
}

/// One command with the chip selected, until it is dropped.
struct Command;

impl Command {
    fn start(cmd: u8) -> Command {
        write32(CS, CS_CLEAR | CS_TA);
        write32(GPCLR1, 1 << (SELECT_PIN - 32));
        xfer(cmd);
        Command
    }

    fn address(&mut self, addr: u32) {
        for b in [(addr >> 16) as u8, (addr >> 8) as u8, addr as u8] {
            xfer(b);
        }
    }
}

impl Drop for Command {
    fn drop(&mut self) {
        write32(GPSET1, 1 << (SELECT_PIN - 32));
        write32(CS, CS_CLEAR);
    }
}

/// The JEDEC manufacturer and device id; all zeros or ones when nothing
/// answers.
pub fn id() -> [u8; 3] {
    let _pins = Pins::take();
    let _command = Command::start(READ_ID);
    [xfer(0), xfer(0), xfer(0)]
}

pub fn present() -> bool {
    let id = id();
    id != [0; 3] && id != [0xff; 3]
}

pub fn read(addr: u32, buf: &mut [u8]) {
    let _pins = Pins::take();
    let mut command = Command::start(READ);
    command.address(addr);
    for b in buf {
        *b = xfer(0);
    }
}

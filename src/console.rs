//! The PL011 on GPIO 14 and 15, which is where the log goes: 115200 8N1, off
//! the oscillator, whatever the bootloader left it as.
//!
//! It stays quiet until [`init`] has run, and gives a full FIFO 2 ms before
//! dropping a byte: a console that has lost its clock must not turn into a
//! hang.

use core::fmt;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::{cm, mmio, timer};

const UART0_DR: u32 = 0x7e20_1000;
const UART0_FR: u32 = 0x7e20_1018;
const UART0_IBRD: u32 = 0x7e20_1024;
const UART0_FBRD: u32 = 0x7e20_1028;
const UART0_LCRH: u32 = 0x7e20_102c;
const UART0_CR: u32 = 0x7e20_1030;
const FR_TXFF: u32 = 1 << 5;
const FR_BUSY: u32 = 1 << 3;
const CR_UARTEN: u32 = 1 << 0;
/// Enabled, transmitting and receiving.
const CR_TX_RX: u32 = 0x301;
/// Eight bits, no parity, one stop bit, FIFOs on.
const LCRH_8N1_FIFO: u32 = 0x70;
/// The PL011's clock: the 54 MHz oscillator over 5.859375, which the EEPROM
/// stages use too. `9216000 / (16 * 115200)` is 5 exactly, so the divisor
/// has no fractional part.
const UART_HZ: u32 = 9_216_000;
const IBRD_115200: u32 = 5;
const FBRD_115200: u32 = 0;
const _: () = assert!(UART_HZ == 16 * 115_200 * IBRD_115200);

/// The function select for GPIO 10-19, and `ALT0` on the console's pins.
const GPFSEL1: u32 = 0x7e20_0004;
const PINS_MASK: u32 = 0b111_111 << 12;
const PINS_ALT0: u32 = 0b100_100 << 12;

/// How long a byte waits for room in a full FIFO.
const FULL_WAIT_US: u32 = 2000;

static ON: AtomicBool = AtomicBool::new(false);

/// Set once a byte has timed out on a full FIFO, until one goes through: a
/// PL011 that has lost its clock takes nothing more, and waiting on every
/// byte would turn a silent console into minutes of boot.
static STUCK: AtomicBool = AtomicBool::new(false);

/// The console as a [`fmt::Write`]: `\n` goes out as `\r\n`.
pub struct Console;

impl Console {
    pub fn putc(&mut self, b: u8) {
        if !ON.load(Ordering::Relaxed) {
            if mmio::read(UART0_CR) & CR_UARTEN == 0 {
                return;
            }
            ON.store(true, Ordering::Relaxed);
        }
        let wait_us = if STUCK.load(Ordering::Relaxed) { 0 } else { FULL_WAIT_US };
        let room = timer::wait(wait_us, || mmio::read(UART0_FR) & FR_TXFF == 0);
        STUCK.store(!room, Ordering::Relaxed);
        if room {
            mmio::write(UART0_DR, b as u32);
        }
    }
}

impl fmt::Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            if b == b'\n' {
                self.putc(b'\r');
            }
            self.putc(b);
        }
        Ok(())
    }
}

/// Program the PL011 and its clock and pins, and enable it.
///
/// Everything is set every time rather than inherited: a PL011 whose pins
/// are on another function transmits into nothing, and one left disabled by
/// the bootloader would keep the whole log to itself.
pub fn init() {
    if mmio::read(UART0_CR) & CR_UARTEN != 0 {
        // Clearing `UARTEN` mid-character wedges the transmitter.
        timer::wait(FULL_WAIT_US, || mmio::read(UART0_FR) & FR_BUSY == 0);
    }
    mmio::write(UART0_CR, 0);
    cm::set_generator(cm::UART_CTL, cm::osc_div(UART_HZ), cm::SRC_OSC | cm::ENAB);
    mmio::write(GPFSEL1, mmio::read(GPFSEL1) & !PINS_MASK | PINS_ALT0);
    mmio::write(UART0_IBRD, IBRD_115200);
    mmio::write(UART0_FBRD, FBRD_115200);
    mmio::write(UART0_LCRH, LCRH_8N1_FIFO);
    mmio::write(UART0_CR, CR_TX_RX);
    STUCK.store(false, Ordering::Relaxed);
}

/// Wait until everything written has left the wire, for a core about to stop
/// for good.
pub fn drain() {
    timer::wait(50_000, || mmio::read(UART0_FR) & FR_BUSY == 0);
}

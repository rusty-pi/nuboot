//! The PL011 on GPIO 14/15, which `start4.elf` has set up for 115200 8N1:
//! the log's output, and the EFI console's.

use core::fmt;

use crate::util::{read32, write32};

const UART0: u64 = 0xFE20_1000;
const DR: u64 = UART0;
const FR: u64 = UART0 + 0x18;
const FR_TXFF: u32 = 1 << 5;
const FR_RXFE: u32 = 1 << 4;

/// The console as a [`fmt::Write`]: `\n` goes out as `\r\n`.
pub struct Console;

impl Console {
    pub fn putc(&mut self, b: u8) {
        while read32(FR) & FR_TXFF != 0 {
            core::hint::spin_loop();
        }
        write32(DR, b as u32);
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

/// A byte from the receive FIFO, if one is there. The flag is read twice: a
/// character just written makes one read of `FR` say only that the
/// transmitter is busy, without the receiver's flags, which would be taken
/// for a byte that is not there.
pub fn getc() -> Option<u8> {
    if read32(FR) & FR_RXFE != 0 || read32(FR) & FR_RXFE != 0 { None } else { Some(read32(DR) as u8) }
}

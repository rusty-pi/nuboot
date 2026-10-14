//! The TPM's command response buffer (CRB): the interface a TPM 2.0 has in an
//! ACPI-described machine. One page of the ARM's memory holds the control area
//! and the buffer; the operating system puts a command in the buffer, sets
//! `START` and rings the VPU's doorbell, and the VPU answers in the buffer and
//! clears `START` ([`crate::mailbox`] takes the doorbell).
//!
//! The page is the operating system's to write, so the VPU trusts none of it
//! but the command it copies out: where the buffer is and how long it is are
//! the VPU's own.

use core::ptr::{read_volatile, write_volatile};

use crate::tpm2;

pub const SIZE: u32 = 0x1000;

const CONTROL_STATUS: usize = 0x44;
const CONTROL_START: usize = 0x4c;
const COMMAND_SIZE: usize = 0x58;
const COMMAND_ADDRESS_LOW: usize = 0x5c;
const COMMAND_ADDRESS_HIGH: usize = 0x60;
const RESPONSE_SIZE: usize = 0x64;
const RESPONSE_ADDRESS: usize = 0x68;
const BUFFER: usize = 0x80;
const BUFFER_LENGTH: usize = tpm2::MAX_COMMAND;

const START_INVOKE: u32 = 1;
const STATUS_IDLE: u32 = 1 << 1;
const HEADER: usize = 10;

/// The page, as the VPU reaches it (`pointer`) and as the ARM does
/// (`physical`).
pub struct Window {
    pointer: *mut u8,
    physical: u32,
}

impl Window {
    pub const fn new(pointer: *mut u8, physical: u32) -> Window {
        Window { pointer, physical }
    }

    fn read(&self, offset: usize) -> u32 {
        unsafe { read_volatile(self.pointer.add(offset) as *const u32) }
    }

    fn write(&self, offset: usize, value: u32) {
        unsafe { write_volatile(self.pointer.add(offset) as *mut u32, value) }
    }

    fn byte(&self, offset: usize) -> u8 {
        unsafe { read_volatile(self.pointer.add(offset)) }
    }

    fn set_byte(&self, offset: usize, value: u8) {
        unsafe { write_volatile(self.pointer.add(offset), value) }
    }

    /// The page as a TPM that is idle and has a buffer of its own leaves it.
    pub fn reset(&self) {
        for offset in (0..SIZE as usize).step_by(4) {
            self.write(offset, 0);
        }
        let buffer = self.physical + BUFFER as u32;
        self.write(CONTROL_STATUS, STATUS_IDLE);
        self.write(COMMAND_SIZE, BUFFER_LENGTH as u32);
        self.write(COMMAND_ADDRESS_LOW, buffer);
        self.write(COMMAND_ADDRESS_HIGH, 0);
        self.write(RESPONSE_SIZE, BUFFER_LENGTH as u32);
        self.write(RESPONSE_ADDRESS, buffer);
        self.write(RESPONSE_ADDRESS + 4, 0);
    }

    /// Run the command in the buffer, if `START` says there is one, and put
    /// its response there.
    pub fn answer(&self) {
        if self.read(CONTROL_START) & START_INVOKE == 0 {
            return;
        }
        let (command, response) = tpm2::buffers();
        for (n, byte) in command[..HEADER].iter_mut().enumerate() {
            *byte = self.byte(BUFFER + n);
        }
        let declared = u32::from_be_bytes([command[2], command[3], command[4], command[5]]) as usize;
        let length = if (HEADER..=BUFFER_LENGTH).contains(&declared) { declared } else { HEADER };
        for n in HEADER..length {
            command[n] = self.byte(BUFFER + n);
        }
        let out = tpm2::execute(&command[..length], response);
        for (n, byte) in response[..out].iter().enumerate() {
            self.set_byte(BUFFER + n, *byte);
        }
        self.write(CONTROL_START, 0);
    }
}

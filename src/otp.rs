//! The one-time-programmable fuses, through the config/OTP block
//! (`0x7E20_F000`).

use crate::{mmio, timer};

const BASE: u32 = 0x7e20_f000;
const CLKMUX: u32 = BASE + 0x04;
const PARAM_A: u32 = BASE + 0x08;
const PARAM_B: u32 = BASE + 0x0c;
const STATUS: u32 = BASE + 0x10;
const DATA: u32 = BASE + 0x18;
const KEY: u32 = BASE + 0x1c;

const PARAM_A_GO: u32 = 1 << 0;
const STATUS_DONE: u32 = 1 << 1;
const STATUS_PROG_ENABLED: u32 = 1 << 2;
/// How long each half of the poll waits; a row takes microseconds.
const TIMEOUT_US: u32 = 1000;
/// How long a program command and the enabling of programming are given, as
/// the stock firmware gives them: 32000 polls two microseconds apart.
const PROGRAM_TIMEOUT_US: u32 = 64_000;
/// The pause between the register writes of a programming sequence.
const STEP_US: u32 = 2;

const CMD_ENABLE: u32 = 2;
const CMD_DISABLE: u32 = 3;
const CMD_PROGRAM: u32 = 10;
/// The four words, one a `CMD_ENABLE` each, that let the block program.
const ENABLE_WORDS: [u32; 4] = [0xf, 0x4, 0x8, 0xd];

/// The board's serial number.
pub const SERIAL: u32 = 28;
/// The board's revision code (`0x00d03115`: a Pi 4B rev 1.5).
pub const REVISION: u32 = 30;
/// The boot mode row, which the boot ROM reads as it starts.
pub const BOOTMODE: u32 = 17;
/// Bit 14 of the boot mode row, which together with a bit of 18:15 makes the
/// EEPROM bootloader take only signed files.
const BOOTMODE_SIGNED: u32 = 1 << 14;
const BOOTMODE_SIGNED_MORE: u32 = 0xf << 15;
/// The SHA-256 of the customer key, which the bootloader checks its `pubkey.bin`
/// against: eight rows.
const KEY_HASH_FIRST: u32 = 47;
const KEY_HASH_ROWS: u32 = 8;
/// The MAC address rows: the board's address, Raspberry Pi's or the
/// customer's, or blank.
pub const MAC_HIGH: u32 = 65;
pub const MAC_LOW: u32 = 64;
/// The row whose set bits each add 10 mV to the core voltage.
pub const CORE_BOOST: u32 = 44;
/// The extended revision: its bits 8-16 describe the SDRAM parts.
pub const EXT_REVISION: u32 = 33;

fn open() {
    mmio::write(CLKMUX, 3);
    timer::delay_us(10);
    mmio::write(PARAM_B, 0);
    mmio::write(PARAM_A, 0);
    timer::delay_us(10);
    mmio::write(CLKMUX, 2);
    timer::delay_us(10);
}

fn close() {
    mmio::write(PARAM_B, 0);
    mmio::write(PARAM_A, 0);
    mmio::write(CLKMUX, 0);
}

/// One row. `STATUS.DONE` says the block is idle, so it is already set when
/// the command goes in and the poll has to watch it fall and rise again: a
/// poll that only looks for it set returns while the previous command's flag
/// still stands, and `DATA` is then read before the row arrives. Measured on a
/// 4B rev 1.5, where it read row 30 as 0 — `board: boardrev 0 otp 0`, a Pi 3
/// device tree chosen for a 4B, and no GPIO expander, so the kernel lost the
/// card's regulators and the rootfs with them.
pub fn read(row: u32) -> u32 {
    open();
    let value = read_open(row);
    close();
    value
}

fn read_open(row: u32) -> u32 {
    mmio::write(KEY, row);
    mmio::write(PARAM_B, 0);
    mmio::write(PARAM_A, 0);
    mmio::write(PARAM_A, mmio::read(PARAM_A) | PARAM_A_GO);
    timer::wait(TIMEOUT_US, || mmio::read(STATUS) & STATUS_DONE == 0);
    timer::wait(TIMEOUT_US, || mmio::read(STATUS) & STATUS_DONE != 0);
    mmio::write(PARAM_B, 0);
    mmio::write(PARAM_A, 0);
    mmio::read(DATA)
}

/// Whether the board has signed boot programmed: the boot mode bits that make
/// the bootloader take only signed files, and a customer key hash for it to
/// check against.
pub fn signed_boot() -> bool {
    let mode = read(BOOTMODE);
    mode & BOOTMODE_SIGNED != 0
        && mode & BOOTMODE_SIGNED_MORE != 0
        && (KEY_HASH_FIRST..KEY_HASH_FIRST + KEY_HASH_ROWS).any(|row| read(row) != 0)
}

/// Why rows were not programmed.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ProgramError {
    /// The block did not accept the four enable words.
    NotEnabled,
    /// A program command did not complete.
    Command,
}

/// One command of the block, as the stock firmware sends it: the command and
/// the second parameter go in, then the command with the start bit, and the
/// parameters are read back. Whether it ran to the end.
fn command(cmd: u32, timeout_us: u32) -> bool {
    let word = cmd << 1;
    mmio::write(PARAM_A, word);
    mmio::write(PARAM_B, 0);
    mmio::write(PARAM_A, word | PARAM_A_GO);
    if mmio::read(PARAM_B) != 0 || mmio::read(PARAM_A) != word | PARAM_A_GO {
        return false;
    }
    timer::wait(TIMEOUT_US, || mmio::read(STATUS) & STATUS_DONE == 0);
    let done = timer::wait(timeout_us, || mmio::read(STATUS) & STATUS_DONE != 0);
    mmio::write(PARAM_B, 0);
    mmio::write(PARAM_A, 0);
    done
}

fn enable_programming() -> bool {
    for word in ENABLE_WORDS {
        mmio::write(DATA, word);
        timer::delay_us(STEP_US);
        if !command(CMD_ENABLE, PROGRAM_TIMEOUT_US) {
            return false;
        }
    }
    timer::delay_us(STEP_US);
    timer::wait(PROGRAM_TIMEOUT_US, || mmio::read(STATUS) & STATUS_PROG_ENABLED != 0)
}

/// Blow the bits of `bits` into row `row`, which only ever sets bits: the row
/// reads as what it held ORed with them. The block must be open and
/// programming enabled.
fn program_row(row: u32, bits: u32) -> bool {
    let current = read_open(row);
    mmio::write(DATA, current | bits);
    timer::delay_us(STEP_US);
    mmio::write(KEY, row);
    timer::delay_us(STEP_US);
    command(CMD_PROGRAM, PROGRAM_TIMEOUT_US)
}

/// Program `rows` in order, `bits` of each. A fuse cannot be cleared, so rows
/// done stay done when a later one fails; the caller reads them back to see what
/// the fuses hold. The words go through the block's data register, which is
/// zeroed afterwards.
pub fn program(first_row: u32, bits: &[u32]) -> Result<(), ProgramError> {
    open();
    let mut result = Ok(());
    if enable_programming() {
        for (row, &word) in (first_row..).zip(bits) {
            if !program_row(row, word) {
                result = Err(ProgramError::Command);
                break;
            }
        }
    } else {
        result = Err(ProgramError::NotEnabled);
    }
    command(CMD_DISABLE, TIMEOUT_US);
    open();
    mmio::write(KEY, 0);
    mmio::write(DATA, 0);
    close();
    result
}

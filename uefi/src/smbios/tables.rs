//! The SMBIOS 3 tables of a Raspberry Pi 4: the firmware, the system, the board
//! and its enclosure, the processor and the memory, laid out after an entry
//! point.

use alloc::vec::Vec;

/// What the tables say that the board and the firmware decide.
pub struct Board<'a> {
    /// The board as its maker names it.
    pub model: &'a [u8],
    pub serial: &'a [u8],
    /// The revision code, `0xd03115` on a 4B rev 1.5.
    pub revision: Option<u32>,
    pub cores: u32,
    pub ram_mib: u32,
    /// `MIDR_EL1`, which says what the cores are.
    pub midr: u64,
    /// What the firmware was built from, and when (seconds since 1970).
    pub firmware_version: &'a [u8],
    pub firmware_time: u32,
}

/// What the board is, by the type its revision code carries; the device tree
/// the ARM gets is the 4B's whatever the board.
pub fn product_name(revision: u32) -> Option<&'static [u8]> {
    const NEW_STYLE: u32 = 1 << 23;
    if revision & NEW_STYLE == 0 {
        return None;
    }
    match (revision >> 4) & 0xff {
        0x11 => Some(b"Raspberry Pi 4 Model B"),
        0x13 => Some(b"Raspberry Pi 400"),
        0x14 => Some(b"Compute Module 4"),
        0x15 => Some(b"Compute Module 4S"),
        _ => None,
    }
}

/// The rate the ARM runs at, which this firmware sets.
const CLOCK_MHZ: u16 = 600;

const MAKER: &[u8] = b"Raspberry Pi Ltd";
const FAMILY: &[u8] = b"Raspberry Pi 4";
const VENDOR: &[u8] = b"pi4-server-firmware";
const SOC: &[u8] = b"BCM2711";
const CORE: &[u8] = b"Cortex-A72";
const SOC_MAKER: &[u8] = b"Broadcom";
const MEMORY: &[u8] = b"SDRAM";

/// The version of the tables: 3.1.1.
const MAJOR: u8 = 3;
const MINOR: u8 = 1;
const DOCREV: u8 = 1;
const ENTRY_POINT_SIZE: usize = 24;

const HANDLE_BIOS: u16 = 0;
const HANDLE_SYSTEM: u16 = 1;
const HANDLE_BOARD: u16 = 2;
const HANDLE_ENCLOSURE: u16 = 3;
const HANDLE_PROCESSOR: u16 = 4;
const HANDLE_MEMORY_ARRAY: u16 = 0x10;
const HANDLE_MEMORY_DEVICE: u16 = 0x11;
const HANDLE_BOOT: u16 = 0x20;
const HANDLE_END: u16 = 0x7f;
const NOT_PROVIDED: u16 = 0xffff;

/// One structure: the bytes the specification lays out by offset, and the
/// strings they refer to by number.
struct Structure {
    bytes: Vec<u8>,
    strings: Vec<Vec<u8>>,
}

impl Structure {
    fn new(kind: u8, handle: u16, length: usize) -> Structure {
        let mut bytes = alloc::vec![0; length];
        bytes[0] = kind;
        bytes[1] = length as u8;
        bytes[2..4].copy_from_slice(&handle.to_le_bytes());
        Structure { bytes, strings: Vec::new() }
    }

    fn byte(mut self, at: usize, value: u8) -> Structure {
        self.bytes[at] = value;
        self
    }

    fn word(mut self, at: usize, value: u16) -> Structure {
        self.bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
        self
    }

    fn dword(mut self, at: usize, value: u32) -> Structure {
        self.bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
        self
    }

    fn qword(mut self, at: usize, value: u64) -> Structure {
        self.bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
        self
    }

    fn data(mut self, at: usize, value: &[u8]) -> Structure {
        self.bytes[at..at + value.len()].copy_from_slice(value);
        self
    }

    /// A string at `at`, which holds its number (from 1); 0, for none, when it
    /// is empty.
    fn text(mut self, at: usize, value: &[u8]) -> Structure {
        if !value.is_empty() {
            self.strings.push(value.to_vec());
            self.bytes[at] = self.strings.len() as u8;
        }
        self
    }

    fn write(self, out: &mut Vec<u8>) {
        out.extend(&self.bytes);
        for string in &self.strings {
            out.extend(string);
            out.push(0);
        }
        out.extend(if self.strings.is_empty() { &[0, 0][..] } else { &[0][..] });
    }
}

/// The date of `seconds` after 1970 as SMBIOS writes a release date.
fn release_date(seconds: u32) -> Vec<u8> {
    let days = (seconds / 86_400) as i64 + 719_468;
    let era = days / 146_097;
    let day_of_era = days % 146_097;
    let year_of_era = (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 { shifted_month + 3 } else { shifted_month - 9 };
    let year = year_of_era + era * 400 + (month <= 2) as i64;
    alloc::format!("{month:02}/{day:02}/{year}").into_bytes()
}

fn hex(value: u32) -> Vec<u8> {
    alloc::format!("{value:06x}").into_bytes()
}

/// A UUID for the board, the same at every boot of it: from its serial
/// number, in the order the tables store one in (the first three fields
/// little-endian).
fn uuid(serial: &[u8]) -> [u8; 16] {
    if serial.is_empty() {
        return [0xff; 16];
    }
    let mut message = b"pi4-server-firmware smbios uuid ".to_vec();
    message.extend(serial);
    let digest = crate::sha256::digest(&message);
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&digest[..16]);
    uuid[6] = uuid[6] & 0x0f | 0x80;
    uuid[8] = uuid[8] & 0x3f | 0x80;
    uuid[..4].reverse();
    uuid[4..6].reverse();
    uuid[6..8].reverse();
    uuid
}

fn structures(board: &Board) -> Vec<u8> {
    let revision = board.revision.map(hex).unwrap_or_default();
    let ram_mib = board.ram_mib.max(1);
    let mut out = Vec::new();

    Structure::new(0, HANDLE_BIOS, 0x1a)
        .text(4, VENDOR)
        .text(5, board.firmware_version)
        .text(8, &release_date(board.firmware_time))
        .byte(9, 7)
        .qword(0xa, 1 << 3)
        .byte(0x12, 1)
        .byte(0x13, 1 << 3)
        .byte(0x14, 0xff)
        .byte(0x15, 0xff)
        .byte(0x16, 0xff)
        .byte(0x17, 0xff)
        .write(&mut out);

    Structure::new(1, HANDLE_SYSTEM, 0x1b)
        .text(4, MAKER)
        .text(5, board.model)
        .text(6, &revision)
        .text(7, board.serial)
        .data(8, &uuid(board.serial))
        .byte(0x18, 6)
        .text(0x1a, FAMILY)
        .write(&mut out);

    Structure::new(2, HANDLE_BOARD, 0x0f)
        .text(4, MAKER)
        .text(5, board.model)
        .text(6, &revision)
        .text(7, board.serial)
        .byte(9, 1)
        .word(0xb, HANDLE_ENCLOSURE)
        .byte(0xd, 0xa)
        .write(&mut out);

    Structure::new(3, HANDLE_ENCLOSURE, 0x16)
        .text(4, MAKER)
        .byte(5, 0x22)
        .text(6, &revision)
        .text(7, board.serial)
        .byte(9, 3)
        .byte(0xa, 3)
        .byte(0xb, 3)
        .byte(0xc, 3)
        .byte(0x12, 1)
        .write(&mut out);

    Structure::new(4, HANDLE_PROCESSOR, 0x30)
        .text(4, SOC)
        .byte(5, 3)
        .byte(6, 0xfe)
        .text(7, SOC_MAKER)
        .qword(8, board.midr)
        .text(0x10, CORE)
        .byte(0x18, 0x41)
        .byte(0x19, 6)
        .word(0x14, CLOCK_MHZ)
        .word(0x16, CLOCK_MHZ)
        .word(0x1a, NOT_PROVIDED)
        .word(0x1c, NOT_PROVIDED)
        .word(0x1e, NOT_PROVIDED)
        .byte(0x23, board.cores as u8)
        .byte(0x24, board.cores as u8)
        .byte(0x25, board.cores as u8)
        .word(0x26, 1 << 2)
        .word(0x28, 0x101)
        .word(0x2a, board.cores as u16)
        .word(0x2c, board.cores as u16)
        .word(0x2e, board.cores as u16)
        .write(&mut out);

    Structure::new(16, HANDLE_MEMORY_ARRAY, 0x17)
        .byte(4, 3)
        .byte(5, 3)
        .byte(6, 3)
        .dword(7, ram_mib << 10)
        .word(0xb, 0xfffe)
        .word(0xd, 1)
        .write(&mut out);

    Structure::new(17, HANDLE_MEMORY_DEVICE, 0x28)
        .word(4, HANDLE_MEMORY_ARRAY)
        .word(6, 0xfffe)
        .word(8, 32)
        .word(0xa, 32)
        .word(0xc, ram_mib as u16)
        .byte(0xe, 5)
        .text(0x10, MEMORY)
        .byte(0x12, 0x1e)
        .word(0x13, 1 << 7)
        .word(0x15, 3200)
        .write(&mut out);

    Structure::new(32, HANDLE_BOOT, 0x0b).write(&mut out);
    Structure::new(127, HANDLE_END, 4).write(&mut out);
    out
}

fn entry_point(table_size: usize, table_at: u64) -> [u8; ENTRY_POINT_SIZE] {
    let mut e = [0u8; ENTRY_POINT_SIZE];
    e[..5].copy_from_slice(b"_SM3_");
    e[6] = ENTRY_POINT_SIZE as u8;
    e[7] = MAJOR;
    e[8] = MINOR;
    e[9] = DOCREV;
    e[10] = 1;
    e[12..16].copy_from_slice(&(table_size as u32).to_le_bytes());
    e[16..24].copy_from_slice(&table_at.to_le_bytes());
    e[5] = e.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)).wrapping_neg();
    e
}

/// The entry point and, right after it, the structures, as one block that
/// starts at physical address `base`.
pub fn assemble(board: &Board, base: u64) -> Vec<u8> {
    let table = structures(board);
    let mut block = entry_point(table.len(), base + ENTRY_POINT_SIZE as u64).to_vec();
    block.extend(table);
    block
}

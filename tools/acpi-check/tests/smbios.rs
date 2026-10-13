use std::process::Command;

use acpi_check::smbios::tables::{self, Board};
use acpi_check::smbios_sample;

fn board() -> Board<'static> {
    smbios_sample()
}

/// A structure of the table: its type, handle, formatted bytes and strings.
struct Structure {
    kind: u8,
    handle: u16,
    bytes: Vec<u8>,
    strings: Vec<String>,
}

impl Structure {
    /// The string a byte of the formatted area numbers, "" for 0.
    fn text(&self, at: usize) -> &str {
        match self.bytes[at] {
            0 => "",
            n => &self.strings[n as usize - 1],
        }
    }
}

fn entry_point(block: &[u8]) -> &[u8] {
    &block[..24]
}

fn structures(block: &[u8]) -> Vec<Structure> {
    let max = u32::from_le_bytes(entry_point(block)[12..16].try_into().unwrap()) as usize;
    let table = &block[24..24 + max];
    let mut found = Vec::new();
    let mut at = 0;
    while at < table.len() {
        let length = table[at + 1] as usize;
        let bytes = table[at..at + length].to_vec();
        let mut strings = Vec::new();
        let mut end = at + length;
        loop {
            let nul = table[end..].iter().position(|b| *b == 0).unwrap();
            if nul == 0 {
                end += 1;
                if strings.is_empty() {
                    end += 1;
                }
                break;
            }
            strings.push(String::from_utf8(table[end..end + nul].to_vec()).unwrap());
            end += nul + 1;
        }
        found.push(Structure { kind: bytes[0], handle: u16::from_le_bytes([bytes[2], bytes[3]]), bytes, strings });
        at = end;
    }
    assert_eq!(at, table.len(), "the structures end where the entry point says");
    found
}

fn of_type(found: &[Structure], kind: u8) -> &Structure {
    found.iter().find(|s| s.kind == kind).unwrap_or_else(|| panic!("no structure of type {kind}"))
}

#[test]
fn the_entry_point_names_the_structures_that_follow_it() {
    let block = tables::assemble(&board(), 0x1000);
    let entry = entry_point(&block);
    assert_eq!(&entry[..5], b"_SM3_");
    assert_eq!(entry[6], 24);
    assert_eq!(entry.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)), 0, "checksum");
    assert_eq!(entry[7..10], [3, 1, 1]);
    assert_eq!(u64::from_le_bytes(entry[16..24].try_into().unwrap()), 0x1000 + 24);
    assert_eq!(u32::from_le_bytes(entry[12..16].try_into().unwrap()) as usize, block.len() - 24);
}

#[test]
fn the_structures_come_in_order_and_end_with_the_end_of_table() {
    let found = structures(&tables::assemble(&board(), 0));
    let kinds: Vec<u8> = found.iter().map(|s| s.kind).collect();
    assert_eq!(kinds, [0, 1, 2, 3, 4, 16, 17, 32, 127]);
    for s in &found {
        assert_eq!(s.bytes[1] as usize, s.bytes.len());
    }
    let handles: Vec<u16> = found.iter().map(|s| s.handle).collect();
    let mut unique = handles.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), handles.len(), "handles are unique");
}

#[test]
fn the_system_is_the_board_with_its_serial_number_and_a_uuid_that_stays() {
    let found = structures(&tables::assemble(&board(), 0));
    let system = of_type(&found, 1);
    assert_eq!(system.text(4), "Raspberry Pi Ltd");
    assert_eq!(system.text(5), "Raspberry Pi 4 Model B");
    assert_eq!(system.text(6), "d03115");
    assert_eq!(system.text(7), "69738888");
    assert_eq!(system.text(0x1a), "Raspberry Pi 4");
    let uuid = system.bytes[8..24].to_vec();
    assert_eq!(uuid[7] >> 4, 8, "version 8, in the field SMBIOS stores little-endian");
    assert_eq!(uuid[8] >> 6, 2, "the RFC variant");
    let again = structures(&tables::assemble(&board(), 0x5000));
    assert_eq!(of_type(&again, 1).bytes[8..24], uuid[..]);
    let other = structures(&tables::assemble(&Board { serial: b"69738889", ..board() }, 0));
    assert_ne!(of_type(&other, 1).bytes[8..24], uuid[..]);
}

#[test]
fn the_board_and_the_enclosure_agree_on_what_they_are() {
    let found = structures(&tables::assemble(&board(), 0));
    let baseboard = of_type(&found, 2);
    assert_eq!(baseboard.text(5), "Raspberry Pi 4 Model B");
    assert_eq!(baseboard.text(7), "69738888");
    assert_eq!(u16::from_le_bytes([baseboard.bytes[0xb], baseboard.bytes[0xc]]), of_type(&found, 3).handle);
    assert_eq!(of_type(&found, 3).bytes[5], 0x22, "an embedded PC");
}

#[test]
fn the_firmware_has_its_version_and_the_date_it_was_built() {
    let date = |time| {
        let found = structures(&tables::assemble(&Board { firmware_time: time, ..board() }, 0));
        of_type(&found, 0).text(8).to_string()
    };
    assert_eq!(date(0), "01/01/1970");
    assert_eq!(date(951_782_400), "02/29/2000");
    assert_eq!(date(1_791_913_303), "10/13/2026");
    assert_eq!(date(4_102_444_800), "01/01/2100");
    let found = structures(&tables::assemble(&board(), 0));
    let bios = of_type(&found, 0);
    assert_eq!(bios.text(4), "pi4-server-firmware");
    assert_eq!(bios.text(5), "c7bd438");
    assert_ne!(bios.bytes[0x13] & 8, 0, "UEFI is supported");
}

#[test]
fn the_processor_and_the_memory_are_what_the_board_has() {
    let found = structures(&tables::assemble(&board(), 0));
    let processor = of_type(&found, 4);
    assert_eq!(processor.text(4), "BCM2711");
    assert_eq!(processor.text(0x10), "Cortex-A72");
    assert_eq!(u64::from_le_bytes(processor.bytes[8..16].try_into().unwrap()), 0x410f_d083);
    assert_eq!(processor.bytes[0x23..0x26], [4, 4, 4]);
    assert_eq!(u16::from_le_bytes([processor.bytes[0x28], processor.bytes[0x29]]), 0x101);
    let array = of_type(&found, 16);
    assert_eq!(u32::from_le_bytes(array.bytes[7..11].try_into().unwrap()), 8192 * 1024, "KiB");
    let device = of_type(&found, 17);
    assert_eq!(u16::from_le_bytes([device.bytes[4], device.bytes[5]]), array.handle);
    assert_eq!(u16::from_le_bytes([device.bytes[0xc], device.bytes[0xd]]), 8192, "MiB");
    assert_eq!(device.bytes[0x12], 0x1e, "LPDDR4");
}

#[test]
fn what_the_board_does_not_say_is_left_out() {
    let found = structures(&tables::assemble(&Board { serial: b"", revision: None, ..board() }, 0));
    let system = of_type(&found, 1);
    assert_eq!(system.bytes[6], 0, "no version");
    assert_eq!(system.bytes[7], 0, "no serial number");
    assert_eq!(system.bytes[8..24], [0xff; 16], "no UUID");
}

#[test]
fn dmidecode_reads_the_tables() {
    let Ok(version) = Command::new("dmidecode").arg("--version").output() else {
        eprintln!("dmidecode is not installed: the tables are not read with it");
        return;
    };
    assert!(version.status.success());
    let dir = std::env::temp_dir().join(format!("smbios-check-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let dump = dir.join("dump.bin");
    std::fs::write(&dump, tables::assemble(&board(), 0)).unwrap();
    let output = Command::new("dmidecode").arg("--from-dump").arg(&dump).output().unwrap();
    let text = String::from_utf8_lossy(&output.stdout).to_string() + &String::from_utf8_lossy(&output.stderr);
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(output.status.success(), "{text}");
    for needed in [
        "SMBIOS 3.1.1 present",
        "Vendor: pi4-server-firmware",
        "Release Date: 10/13/2026",
        "UEFI is supported",
        "Manufacturer: Raspberry Pi Ltd",
        "Product Name: Raspberry Pi 4 Model B",
        "Serial Number: 69738888",
        "Family: Raspberry Pi 4",
        "Type: Embedded PC",
        "Socket Designation: BCM2711",
        "Version: Cortex-A72",
        "Core Count: 4",
        "Size: 8 GB",
        "Type: LPDDR4",
    ] {
        assert!(text.contains(needed), "dmidecode does not show {needed:?}:\n{text}");
    }
    for complaint in ["Invalid", "invalid", "Wrong", "corrupt"] {
        assert!(!text.contains(complaint), "dmidecode complains ({complaint}):\n{text}");
    }
}

//! The UEFI firmware's ACPI and SMBIOS table code, compiled for the host: the
//! real modules, so that what an operating system reads can be checked with
//! the ACPICA tools and `dmidecode`.

extern crate alloc;

pub mod acpi;
pub mod smbios;

#[path = "../../../src/sha256.rs"]
#[allow(dead_code)]
pub mod sha256;

use acpi::tables::{self, Machine};

/// The address the sample block is laid out for.
pub const BASE: u64 = 0xfbf7_e000;

pub fn sample() -> Machine {
    Machine { tpm: Some(0x3ebf_f000), ethernet: Some([0x02, 0x11, 0x22, 0x33, 0x44, 0x55]), xhci: Some(0x6_0200_0000), cores: 4 }
}

/// A board the SMBIOS tables are laid out for: a Raspberry Pi 4B rev 1.5 with 8 GB.
pub fn smbios_sample() -> smbios::tables::Board<'static> {
    smbios::tables::Board {
        model: b"Raspberry Pi 4 Model B",
        serial: b"1a2b3c4d",
        revision: Some(0xd03115),
        cores: 4,
        ram_mib: 8192,
        midr: 0x410f_d083,
        firmware_version: b"c7bd438",
        firmware_time: 1_791_913_303,
    }
}

/// One table of the block, found the way an operating system finds it.
pub struct Found {
    pub signature: String,
    pub bytes: Vec<u8>,
}

fn le32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn le64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

/// The tables the RSDP leads to: the XSDT first, then what it lists, then
/// the DSDT the FADT names.
pub fn walk(block: &tables::Block, base: u64) -> Vec<Found> {
    let bytes = &block.bytes;
    let table_at = |address: u64| {
        let at = (address - base) as usize;
        let length = le32(bytes, at + 4) as usize;
        Found { signature: String::from_utf8(bytes[at..at + 4].to_vec()).unwrap(), bytes: bytes[at..at + length].to_vec() }
    };
    let xsdt = table_at(le64(bytes, block.rsdp + 24));
    let mut found = Vec::new();
    for entry in xsdt.bytes[36..].chunks_exact(8) {
        let table = table_at(u64::from_le_bytes(entry.try_into().unwrap()));
        if table.signature == "FACP" {
            let dsdt = table_at(le64(&table.bytes, 140));
            found.push(table);
            found.push(dsdt);
        } else {
            found.push(table);
        }
    }
    found.insert(0, xsdt);
    found
}

//! SMBIOS tables, which identify the board to an operating system as the
//! device tree's `model` and `serial-number` do: `/sys/class/dmi/id`,
//! `dmidecode`, `hostnamectl` and fwupd's hardware IDs read them, and an OS on
//! the ACPI tables has no device tree to read them from.

mod tables;

use core::ffi::c_void;

use r_efi::efi;

use crate::util::Hex;
use crate::{esrt, fdt, info, mem, tables as efi_tables, warn};

/// `EFI_SMBIOS3_TABLE_GUID`.
pub const SMBIOS3_TABLE_GUID: efi::Guid =
    efi::Guid::from_fields(0xf2fd1544, 0x9794, 0x4a2c, 0x99, 0x2e, &[0xe5, 0xbb, 0xcf, 0x20, 0xe3, 0x94]);

/// The root properties the VPU firmware gives the tree besides the stock
/// ones.
const ROOT: &[&[u8]] = &[b""];
const REVISION: &[u8] = b"rusty-pi,board-revision";

const CORES: u32 = 4;

/// The text of a device tree string property, without its NUL.
fn text(tree: &fdt::Fdt, name: &[u8]) -> alloc::vec::Vec<u8> {
    let mut value = tree.property(ROOT, name).unwrap_or_default();
    while value.last() == Some(&0) {
        value.pop();
    }
    value
}

fn midr() -> u64 {
    let midr: u64;
    unsafe { core::arch::asm!("mrs {0}, MIDR_EL1", out(reg) midr) };
    midr
}

/// The board's revision code, from the VPU firmware's property in the tree.
pub fn revision(tree: &fdt::Fdt) -> Option<u32> {
    tree.bytes::<4>(ROOT, REVISION).map(u32::from_be_bytes)
}

/// The board's name: from its revision code, else the tree's `model`.
pub fn model(tree: &fdt::Fdt) -> alloc::vec::Vec<u8> {
    revision(tree).and_then(tables::product_name).map_or_else(|| text(tree, b"model"), |name| name.to_vec())
}

/// Offer the tables, for the memory the board has: a power of two in MiB, as
/// the chips are, from what the memory map holds.
pub fn init(tree: &fdt::Fdt) {
    let revision = revision(tree);
    let model = model(tree);
    let serial = text(tree, b"serial-number");
    let board = tables::Board {
        model: &model,
        serial: &serial,
        revision,
        cores: CORES,
        ram_mib: (mem::map().total_mib() as u32).next_power_of_two(),
        midr: midr(),
        firmware_version: crate::COMMIT.as_bytes(),
        firmware_time: esrt::VERSION,
    };
    let size = tables::assemble(&board, 0).len();
    let Ok(at) = mem::pool_alloc(efi::RUNTIME_SERVICES_DATA, size) else {
        warn!("smbios", "no memory for the tables"; bytes = size);
        return;
    };
    let block = tables::assemble(&board, at as u64);
    unsafe { core::ptr::copy_nonoverlapping(block.as_ptr(), at, size) };
    let status = efi_tables::install_table(SMBIOS3_TABLE_GUID, at as *mut c_void);
    if status.is_error() {
        warn!("smbios", "the tables were not offered"; status = Hex(status.as_usize()));
        return;
    }
    info!("smbios", "tables ready"; entry = Hex(at as u64), bytes = size, serial = core::str::from_utf8(&serial).unwrap_or(""));
}

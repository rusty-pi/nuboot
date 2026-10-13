//! ACPI tables, offered next to the device tree.
//!
//! An operating system that boots with `acpi=on` finds the RSDP in the
//! configuration tables and describes the board from them; one that does not
//! asks for the device tree as before. The TPM on the VPU is a CRB device in
//! the tables, which the operating system's own TPM driver takes without a
//! module of this firmware's, and the USB controller is a platform xHCI
//! device, which its generic driver takes without one for the PCIe root
//! complex it sits behind.

mod aml;
mod tables;

use core::ffi::c_void;

use r_efi::efi;

use crate::util::Hex;
use crate::{fdt, info, mem, tables as efi_tables, warn};

/// `EFI_ACPI_20_TABLE_GUID`.
const ACPI_20_TABLE_GUID: efi::Guid =
    efi::Guid::from_fields(0x8868e871, 0xe4f1, 0x11d3, 0xbc, 0x22, &[0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81]);

const CRB_NODE: &[u8] = b"tpm-crb@";
const ETHERNET_NODE: &[&[u8]] = &[b"", b"scb", b"ethernet@7d580000"];

const CORES: u32 = 4;

/// Offer the tables. `xhci` is where the USB controller's registers are, if
/// the board has one.
pub fn init(tree: &fdt::Fdt, xhci: Option<u64>) {
    let machine = tables::Machine {
        tpm: tree.reserved_base(CRB_NODE),
        ethernet: tree.bytes(ETHERNET_NODE, b"local-mac-address"),
        xhci,
        cores: CORES,
    };
    let size = tables::assemble(&machine, 0).bytes.len();
    let Ok(at) = mem::pool_alloc(efi::ACPI_RECLAIM_MEMORY, size) else {
        warn!("acpi", "no memory for the tables"; bytes = size);
        return;
    };
    let block = tables::assemble(&machine, at as u64);
    unsafe { core::ptr::copy_nonoverlapping(block.bytes.as_ptr(), at, size) };
    let rsdp = at as u64 + block.rsdp as u64;
    efi_tables::install_table(ACPI_20_TABLE_GUID, rsdp as *mut c_void);
    info!("acpi", "tables ready"; rsdp = Hex(rsdp), bytes = size, crb = Hex(machine.tpm.unwrap_or(0)), xhci = Hex(machine.xhci.unwrap_or(0)), cores = machine.cores);
}

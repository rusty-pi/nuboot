//! After `ExitBootServices`, the properties table offers `ResetSystem` and a
//! shutdown through it resets the board to the bootloader's halt.

#![no_std]
#![no_main]

use core::ptr::null_mut;

use r_efi::efi::{self, Guid, Handle, Status, SystemTable};
use runtime_efi::{check, exit_boot_services, say};

const RT_PROPERTIES: Guid = Guid::from_fields(0xeb66918a, 0x7eef, 0x402a, 0x84, 0x2e, &[0x93, 0x1d, 0x21, 0xc3, 0x8a, 0xe9]);
const RESET_SYSTEM: u32 = 0x400;

fn supported_services(system_table: *mut SystemTable) -> u32 {
    let tables = unsafe { core::slice::from_raw_parts((*system_table).configuration_table, (*system_table).number_of_table_entries) };
    match tables.iter().find(|t| t.vendor_guid == RT_PROPERTIES) {
        Some(table) => unsafe { *(table.vendor_table as *const u32).add(1) },
        None => 0,
    }
}

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(image: Handle, system_table: *mut SystemTable) -> Status {
    let supported = supported_services(system_table);
    let rt = exit_boot_services(image, system_table);
    runtime_efi::settle();
    check("the properties table offers ResetSystem", supported & RESET_SYSTEM != 0);
    say("runtime test: shutting down\r\n");
    unsafe { ((*rt).reset_system)(efi::RESET_SHUTDOWN, Status::SUCCESS, 0, null_mut()) };
    say("runtime test: ResetSystem returned\r\n");
    runtime_efi::hang()
}

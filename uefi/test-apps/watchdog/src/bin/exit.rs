//! Exits boot services as an operating system loader does, then stops.

#![no_std]
#![no_main]

use core::mem::size_of;

use r_efi::efi::{Handle, MemoryDescriptor, Status, SystemTable};
use watchdog_efi::{hang, say};

static mut MAP: [u8; 16384] = [0; 16384];

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(image: Handle, system_table: *mut SystemTable) -> Status {
    say(system_table, "watchdog test: exiting boot services\r\n");
    let bs = unsafe { (*system_table).boot_services };
    for _ in 0..4 {
        let mut size = core::mem::size_of_val(unsafe { &*(&raw const MAP) });
        let (mut key, mut desc_size, mut version) = (0usize, size_of::<MemoryDescriptor>(), 0u32);
        let status = unsafe {
            ((*bs).get_memory_map)(
                &mut size,
                (&raw mut MAP).cast(),
                &mut key,
                &mut desc_size,
                &mut version,
            )
        };
        if status.is_error() {
            continue;
        }
        if !unsafe { ((*bs).exit_boot_services)(image, key) }.is_error() {
            hang()
        }
    }
    say(system_table, "watchdog test: ExitBootServices failed\r\n");
    hang()
}

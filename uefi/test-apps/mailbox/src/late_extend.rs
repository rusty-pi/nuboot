//! Exits boot services, then tries to extend the boot measurement: the
//! firmware closed it as boot services went.

#![no_std]
#![no_main]

use core::mem::size_of;

use r_efi::efi::{Handle, MemoryDescriptor, Status, SystemTable};

#[path = "boot_key_common.rs"]
mod common;
use common::{call, page_below_1gib, say, TAG_EXTEND_BOOT_MEASUREMENT};

static mut MAP: [u8; 16384] = [0; 16384];

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(image: Handle, system_table: *mut SystemTable) -> Status {
    say(system_table, "late extend test: exiting boot services\r\n");
    let Some(buf) = page_below_1gib(system_table) else {
        return Status::OUT_OF_RESOURCES;
    };
    let bs = unsafe { (*system_table).boot_services };
    for _ in 0..4 {
        let mut size = core::mem::size_of_val(unsafe { &*(&raw const MAP) });
        let (mut key, mut desc_size, mut version) = (0usize, size_of::<MemoryDescriptor>(), 0u32);
        let status = unsafe {
            ((*bs).get_memory_map)(&mut size, (&raw mut MAP).cast(), &mut key, &mut desc_size, &mut version)
        };
        if status.is_error() {
            continue;
        }
        if !unsafe { ((*bs).exit_boot_services)(image, key) }.is_error() {
            let mut extend = [0x5a5a_5a5a; 9];
            extend[0] = 7;
            call(buf, TAG_EXTEND_BOOT_MEASUREMENT, &extend);
            loop {
                core::hint::spin_loop();
            }
        }
    }
    Status::ABORTED
}

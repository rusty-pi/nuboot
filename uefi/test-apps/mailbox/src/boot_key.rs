//! Asks the firmware over the property mailbox for the boot key, then tries
//! to extend the boot measurement and to ask for the key again: the key goes
//! once, and nothing is measured after it.

#![no_std]
#![no_main]

use r_efi::efi::{Handle, Status, SystemTable};

#[path = "boot_key_common.rs"]
mod common;
use common::{call, hex, page_below_1gib, say, TAG_EXTEND_BOOT_MEASUREMENT, TAG_GET_BOOT_KEY};

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(_image: Handle, system_table: *mut SystemTable) -> Status {
    say(system_table, "boot key test: asking\r\n");
    let Some(buf) = page_below_1gib(system_table) else {
        say(system_table, "boot key test: no page below 1 GiB\r\n");
        return Status::OUT_OF_RESOURCES;
    };
    match call(buf, TAG_GET_BOOT_KEY, &[0; 8]) {
        Some(key) => {
            say(system_table, "boot key test: first answer ");
            hex(system_table, &key);
            say(system_table, "\r\n");
        }
        None => say(system_table, "boot key test: first request not answered\r\n"),
    }
    match call(buf, TAG_EXTEND_BOOT_MEASUREMENT, &[0x5a5a_5a5a; 8]) {
        Some(_) => say(system_table, "boot key test: extend after the key answered\r\n"),
        None => say(system_table, "boot key test: extend after the key not answered\r\n"),
    }
    match call(buf, TAG_GET_BOOT_KEY, &[0; 8]) {
        Some(_) => say(system_table, "boot key test: second request answered\r\n"),
        None => say(system_table, "boot key test: second request not answered\r\n"),
    }
    Status::SUCCESS
}

//! Sets and reads the reboot flags over the property mailbox, as Linux's
//! `reboot '0 tryboot'` does, and says what came back.

#![no_std]
#![no_main]

use r_efi::efi::{Handle, Status, SystemTable};

mod common;

const TAG_GET_REBOOT_FLAGS: u32 = 0x0003_0064;
const TAG_SET_REBOOT_FLAGS: u32 = 0x0003_8064;

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(_image: Handle, system_table: *mut SystemTable) -> Status {
    let Some(buf) = common::page_below_1gib(system_table) else {
        common::say(system_table, "reboot flags test: no page below 1 GiB\r\n");
        return Status::OUT_OF_RESOURCES;
    };
    let flags = || common::call(buf, TAG_GET_REBOOT_FLAGS, &[0]).map(|v| v[0]);
    common::say(system_table, if flags() == Some(0) { "reboot flags test: none set at first\r\n" } else { "reboot flags test: flags set at first\r\n" });
    common::call(buf, TAG_SET_REBOOT_FLAGS, &[1]);
    common::say(system_table, if flags() == Some(1) { "reboot flags test: tryboot requested\r\n" } else { "reboot flags test: tryboot not requested\r\n" });
    common::call(buf, TAG_SET_REBOOT_FLAGS, &[0]);
    common::say(system_table, if flags() == Some(0) { "reboot flags test: request taken back\r\n" } else { "reboot flags test: request not taken back\r\n" });
    common::call(buf, TAG_SET_REBOOT_FLAGS, &[1]);
    common::say(system_table, "reboot flags test: done\r\n");
    Status::SUCCESS
}

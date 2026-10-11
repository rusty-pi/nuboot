//! An image only a certificate enrolled in `db` at run time signs.

#![no_std]
#![no_main]

use r_efi::efi::{Char16, Handle, Status, SystemTable};

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(_image: Handle, system_table: *mut SystemTable) -> Status {
    let mut buf = [0 as Char16; 40];
    for (i, b) in "store test: enrolled image runs\r\n".bytes().enumerate() {
        buf[i] = b as Char16;
    }
    unsafe {
        let con_out = (*system_table).con_out;
        ((*con_out).output_string)(con_out, buf.as_mut_ptr());
    }
    Status::SUCCESS
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

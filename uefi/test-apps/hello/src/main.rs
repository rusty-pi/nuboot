//! The EFI application the scenarios boot to see the firmware's services
//! work: it prints what it finds through them, one line each, and returns.

#![no_std]
#![no_main]

use core::ffi::c_void;
use core::ptr::null_mut;

use r_efi::efi::{self, Char16, Guid, Handle, Status, SystemTable};
use r_efi::protocols::{file, loaded_image, rng, simple_file_system};

static mut ST: *mut SystemTable = null_mut();

fn say(text: &str) {
    let mut buf = [0 as Char16; 160];
    for (i, b) in text.bytes().take(buf.len() - 1).enumerate() {
        buf[i] = b as Char16;
    }
    unsafe {
        let con_out = (*ST).con_out;
        ((*con_out).output_string)(con_out, buf.as_mut_ptr());
    }
}

fn check(what: &str, ok: bool) {
    say("hello test: ");
    say(what);
    say(if ok { ": ok\r\n" } else { ": FAILED\r\n" });
}

fn protocol<T>(handle: Handle, guid: &Guid) -> Option<*mut T> {
    let bs = unsafe { (*ST).boot_services };
    let mut p: *mut c_void = null_mut();
    let s = unsafe { ((*bs).handle_protocol)(handle, guid as *const _ as *mut _, &mut p) };
    (!s.is_error() && !p.is_null()).then_some(p as *mut T)
}

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(image: Handle, system_table: *mut SystemTable) -> Status {
    unsafe { ST = system_table };
    let bs = unsafe { (*system_table).boot_services };
    let rt = unsafe { (*system_table).runtime_services };
    say("hello test: started\r\n");

    let mut p: *mut c_void = null_mut();
    let pool = unsafe { ((*bs).allocate_pool)(efi::LOADER_DATA, 1000, &mut p) };
    check("AllocatePool", !pool.is_error() && unsafe { ((*bs).free_pool)(p) } == Status::SUCCESS);

    let mut size = 0usize;
    let (mut key, mut desc, mut ver) = (0usize, 0usize, 0u32);
    let s = unsafe { ((*bs).get_memory_map)(&mut size, null_mut(), &mut key, &mut desc, &mut ver) };
    check("GetMemoryMap", s == Status::BUFFER_TOO_SMALL && size > 0 && desc >= 40);

    let mut r: *mut c_void = null_mut();
    let s = unsafe { ((*bs).locate_protocol)(&rng::PROTOCOL_GUID as *const _ as *mut _, null_mut(), &mut r) };
    let mut bytes = [0u8; 16];
    let ok = !s.is_error() && {
        let r = r as *mut rng::Protocol;
        !unsafe { ((*r).get_rng)(r, null_mut(), bytes.len(), bytes.as_mut_ptr()) }.is_error()
    };
    check("EFI_RNG_PROTOCOL", ok && bytes.iter().any(|&b| b != 0));

    let mut name = [b'S' as u16, b'e' as u16, b'c' as u16, b'u' as u16, b'r' as u16, b'e' as u16, b'B' as u16,
        b'o' as u16, b'o' as u16, b't' as u16, 0];
    let global = Guid::from_fields(0x8be4df61, 0x93ca, 0x11d2, 0xaa, 0x0d, &[0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c]);
    let (mut value, mut len) = (0u8, 1usize);
    let s = unsafe {
        ((*rt).get_variable)(name.as_mut_ptr(), &global as *const _ as *mut _, null_mut(), &mut len,
            &mut value as *mut u8 as *mut c_void)
    };
    check("GetVariable SecureBoot", !s.is_error() && len == 1);
    say(if value == 1 { "hello test: Secure Boot is on\r\n" } else { "hello test: Secure Boot is off\r\n" });

    let read_self = || -> Option<u64> {
        let li = protocol::<loaded_image::Protocol>(image, &loaded_image::PROTOCOL_GUID)?;
        let fs = protocol::<simple_file_system::Protocol>(unsafe { (*li).device_handle }, &simple_file_system::PROTOCOL_GUID)?;
        let mut root: *mut file::Protocol = null_mut();
        if unsafe { ((*fs).open_volume)(fs, &mut root) }.is_error() {
            return None;
        }
        let mut path = [0u16; 32];
        for (i, b) in "\\EFI\\BOOT\\BOOTAA64.EFI".bytes().enumerate() {
            path[i] = b as u16;
        }
        let mut f: *mut file::Protocol = null_mut();
        if unsafe { ((*root).open)(root, &mut f, path.as_mut_ptr(), file::MODE_READ, 0) }.is_error() {
            return None;
        }
        let mut info = [0u64; 64];
        let mut n = core::mem::size_of_val(&info);
        let s = unsafe { ((*f).get_info)(f, &file::INFO_ID as *const _ as *mut _, &mut n, info.as_mut_ptr() as *mut c_void) };
        unsafe { ((*f).close)(f) };
        unsafe { ((*root).close)(root) };
        (!s.is_error()).then_some(info[1])
    };
    check("reading this image's own file", read_self().is_some_and(|size| size > 0));

    say("hello test: done\r\n");
    Status::SUCCESS
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

//! Enrols a certificate in `db` with an update signed by a key in `KEK`,
//! resets, and loads an image only that certificate signs. The first boot
//! cannot load it; the next one, which finds `db` in the flash store, can.

#![no_std]
#![no_main]

use core::ffi::c_void;
use core::ptr::null_mut;

use r_efi::efi::{self, Char16, Guid, Handle, Status, SystemTable};
use r_efi::protocols::{file, loaded_image, simple_file_system};

static mut ST: *mut SystemTable = null_mut();

const SECURITY_DB: Guid = Guid::from_fields(0xd719b2cb, 0x3d3a, 0x4596, 0xa3, 0xbc, &[0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f]);
/// Non-volatile, boot services, runtime, time-based authenticated, append.
const ATTRIBUTES: u32 = 0x1 | 0x2 | 0x4 | 0x20 | 0x40;

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

fn protocol<T>(handle: Handle, guid: &Guid) -> Option<*mut T> {
    let bs = unsafe { (*ST).boot_services };
    let mut p: *mut c_void = null_mut();
    let s = unsafe { ((*bs).handle_protocol)(handle, guid as *const _ as *mut _, &mut p) };
    (!s.is_error() && !p.is_null()).then_some(p as *mut T)
}

/// The file at `path` on this image's volume, in pool memory.
fn read(image: Handle, path: &str) -> Option<(*mut u8, usize)> {
    let li = protocol::<loaded_image::Protocol>(image, &loaded_image::PROTOCOL_GUID)?;
    let fs = protocol::<simple_file_system::Protocol>(unsafe { (*li).device_handle }, &simple_file_system::PROTOCOL_GUID)?;
    let mut root: *mut file::Protocol = null_mut();
    if unsafe { ((*fs).open_volume)(fs, &mut root) }.is_error() {
        return None;
    }
    let mut name = [0u16; 32];
    for (i, b) in path.bytes().enumerate() {
        name[i] = b as u16;
    }
    let mut f: *mut file::Protocol = null_mut();
    if unsafe { ((*root).open)(root, &mut f, name.as_mut_ptr(), file::MODE_READ, 0) }.is_error() {
        return None;
    }
    let mut info = [0u64; 64];
    let mut n = core::mem::size_of_val(&info);
    unsafe { ((*f).get_info)(f, &file::INFO_ID as *const _ as *mut _, &mut n, info.as_mut_ptr() as *mut c_void) };
    let mut size = info[1] as usize;
    let mut buf: *mut c_void = null_mut();
    let bs = unsafe { (*ST).boot_services };
    unsafe { ((*bs).allocate_pool)(efi::LOADER_DATA, size, &mut buf) };
    let s = unsafe { ((*f).read)(f, &mut size, buf) };
    unsafe { ((*f).close)(f) };
    unsafe { ((*root).close)(root) };
    (!s.is_error()).then_some((buf as *mut u8, size))
}

fn load(image: Handle, buf: *mut u8, size: usize) -> (Status, Handle) {
    let bs = unsafe { (*ST).boot_services };
    let mut handle: Handle = null_mut();
    let s = unsafe { ((*bs).load_image)(efi::Boolean::FALSE, image, null_mut(), buf as *mut c_void, size, &mut handle) };
    (s, handle)
}

fn set_db(auth: *mut u8, size: usize) -> Status {
    let rt = unsafe { (*ST).runtime_services };
    let mut name = [b'd' as u16, b'b' as u16, 0];
    unsafe {
        ((*rt).set_variable)(name.as_mut_ptr(), &SECURITY_DB as *const _ as *mut _, ATTRIBUTES, size, auth as *mut c_void)
    }
}

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(image: Handle, system_table: *mut SystemTable) -> Status {
    unsafe { ST = system_table };
    let Some((enrolled, enrolled_size)) = read(image, "\\enrolled.efi") else {
        say("store test: no enrolled.efi\r\n");
        return Status::NOT_FOUND;
    };
    let (status, handle) = load(image, enrolled, enrolled_size);
    if !status.is_error() {
        say("store test: enrolled image loaded\r\n");
        let bs = unsafe { (*ST).boot_services };
        let mut exit = 0usize;
        unsafe { ((*bs).start_image)(handle, &mut exit, null_mut()) };
        say("store test: done\r\n");
        return Status::SUCCESS;
    }
    say(if status == Status::SECURITY_VIOLATION {
        "store test: enrolled image refused\r\n"
    } else {
        "store test: enrolled image failed to load\r\n"
    });

    if let Some((bad, size)) = read(image, "\\db-bad.auth") {
        let s = set_db(bad, size);
        say(if s == Status::SECURITY_VIOLATION {
            "store test: update signed by a stranger refused\r\n"
        } else {
            "store test: update signed by a stranger NOT refused\r\n"
        });
    }
    let Some((auth, size)) = read(image, "\\db-x.auth") else {
        say("store test: no db-x.auth\r\n");
        return Status::NOT_FOUND;
    };
    let s = set_db(auth, size);
    if s.is_error() {
        say("store test: update refused\r\n");
        return s;
    }
    say("store test: update accepted, resetting\r\n");
    let rt = unsafe { (*system_table).runtime_services };
    unsafe { ((*rt).reset_system)(efi::RESET_COLD, Status::SUCCESS, 0, null_mut()) };
    Status::SUCCESS
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

//! The boot counting systemd-boot does through `EFI_FILE_PROTOCOL.SetInfo`:
//! the first boot renames the counter of boot entries' files and checks what
//! the firmware accepts and refuses, then resets; the second boot checks the
//! directory the medium holds.

#![no_std]
#![no_main]

use core::ffi::c_void;
use core::ptr::null_mut;

use r_efi::efi::{self, Char16, Guid, Handle, Status, SystemTable};
use r_efi::protocols::{file, loaded_image, simple_file_system};

const LINUX: &str = "\\EFI\\Linux";
const ENTRIES: &str = "\\loader\\entries";
const SIZE: usize = 5000;
const READ_ONLY: u64 = 1;

struct Test {
    table: *mut SystemTable,
    root: *mut file::Protocol,
    failed: bool,
}

fn say(table: *mut SystemTable, text: &str) {
    let mut buf = [0 as Char16; 160];
    for (i, b) in text.bytes().take(buf.len() - 1).enumerate() {
        buf[i] = b as Char16;
    }
    unsafe {
        let con_out = (*table).con_out;
        ((*con_out).output_string)(con_out, buf.as_mut_ptr());
    }
}

impl Test {
    fn check(&mut self, what: &str, ok: bool) {
        say(self.table, "bootcount test: ");
        say(self.table, what);
        say(self.table, if ok { " ok\r\n" } else { " FAILED\r\n" });
        self.failed |= !ok;
    }

    fn open(&self, path: &str, mode: u64) -> Result<*mut file::Protocol, Status> {
        let mut wide = [0 as Char16; 128];
        for (i, b) in path.bytes().enumerate() {
            wide[i] = b as Char16;
        }
        let mut f = null_mut();
        let status = unsafe { ((*self.root).open)(self.root, &mut f, wide.as_mut_ptr(), mode, 0) };
        if status.is_error() { Err(status) } else { Ok(f) }
    }

    fn entries(&self, dir: &str) -> Entries {
        Entries { dir: self.open(dir, file::MODE_READ).unwrap_or(null_mut()) }
    }

    fn has(&self, dir: &str, name: &str) -> bool {
        let mut found = false;
        self.entries(dir).each(|n| found |= same(n, name));
        found
    }

    fn count_prefix(&self, dir: &str, prefix: &str) -> usize {
        let mut count = 0;
        self.entries(dir).each(|n| count += n.starts_with_ascii(prefix) as usize);
        count
    }
}

trait Prefix {
    fn starts_with_ascii(&self, prefix: &str) -> bool;
}

impl Prefix for &[u16] {
    fn starts_with_ascii(&self, prefix: &str) -> bool {
        prefix.len() <= self.len() && prefix.bytes().zip(self.iter()).all(|(b, &c)| b as u16 == c)
    }
}

fn same(name: &[u16], text: &str) -> bool {
    name.len() == text.len() && name.iter().zip(text.bytes()).all(|(&c, b)| c == b as u16)
}

struct Entries {
    dir: *mut file::Protocol,
}

impl Entries {
    fn each(&self, mut f: impl FnMut(&[u16])) {
        if self.dir.is_null() {
            return;
        }
        loop {
            let mut buf = [0u64; 256];
            let mut size = core::mem::size_of_val(&buf);
            let status = unsafe { ((*self.dir).read)(self.dir, &mut size, buf.as_mut_ptr() as *mut c_void) };
            if status.is_error() || size == 0 {
                break;
            }
            f(name_of(&buf));
        }
        unsafe { ((*self.dir).close)(self.dir) };
    }
}

fn name_of(buf: &[u64; 256]) -> &[u16] {
    let header = core::mem::size_of::<file::Info>();
    let name = unsafe { (buf.as_ptr() as *const u8).add(header) as *const u16 };
    let mut len = 0;
    while unsafe { name.add(len).read_unaligned() } != 0 {
        len += 1;
    }
    unsafe { core::slice::from_raw_parts(name, len) }
}

fn info_of(f: *mut file::Protocol, buf: &mut [u64; 256]) -> Status {
    let mut size = core::mem::size_of_val(buf);
    let mut ty = file::INFO_ID;
    unsafe { ((*f).get_info)(f, &mut ty, &mut size, buf.as_mut_ptr() as *mut c_void) }
}

enum Change {
    Nothing,
    Size,
    Attribute,
    OldSize,
}

fn rename(f: *mut file::Protocol, new: &str, change: Change) -> Status {
    let mut buf = [0u64; 256];
    let status = info_of(f, &mut buf);
    if status.is_error() {
        return status;
    }
    let header = core::mem::size_of::<file::Info>();
    let info = buf.as_mut_ptr() as *mut file::Info;
    unsafe {
        let old_size = (*info).size as usize;
        match change {
            Change::Nothing | Change::OldSize => {}
            Change::Size => (*info).file_size += 1,
            Change::Attribute => (*info).attribute |= READ_ONLY,
        }
        let name = (buf.as_mut_ptr() as *mut u8).add(header) as *mut u16;
        for (i, b) in new.bytes().enumerate() {
            name.add(i).write_unaligned(b as u16);
        }
        name.add(new.len()).write_unaligned(0);
        (*info).size = (header + (new.len() + 1) * 2) as u64;
        let mut ty = file::INFO_ID;
        let size = if matches!(change, Change::OldSize) { old_size } else { (*info).size as usize };
        ((*f).set_info)(f, &mut ty, size, buf.as_mut_ptr() as *mut c_void)
    }
}

fn pattern(i: usize) -> u8 {
    (i * 7 + 3) as u8
}

fn content_ok(f: *mut file::Protocol) -> bool {
    let mut data = [0u8; SIZE + 64];
    let mut size = data.len();
    unsafe {
        if ((*f).set_position)(f, 0).is_error() || ((*f).read)(f, &mut size, data.as_mut_ptr() as *mut c_void).is_error() {
            return false;
        }
    }
    size == SIZE && data[..SIZE].iter().enumerate().all(|(i, &b)| b == pattern(i))
}

fn name_is(f: *mut file::Protocol, text: &str) -> bool {
    let mut buf = [0u64; 256];
    !info_of(f, &mut buf).is_error() && same(name_of(&buf), text)
}

fn refused(status: Status) -> bool {
    status == Status::WRITE_PROTECTED || status == Status::ACCESS_DENIED
}

fn first_boot(t: &mut Test) {
    let Ok(f) = t.open("\\EFI\\Linux\\test_1+3-0.efi", file::MODE_READ | file::MODE_WRITE) else {
        t.check("the entry opens for writing", false);
        return;
    };
    t.check("the entry opens for writing", true);
    t.check("the entry reads before the rename", content_ok(f));

    t.check("the counter is renamed to +2-1", rename(f, "test_1+2-1.efi", Change::Nothing) == Status::SUCCESS);
    t.check("the handle reports the new name", name_is(f, "test_1+2-1.efi"));
    t.check("the handle still reads the same content", content_ok(f));
    t.check("the directory lists the new name", t.has(LINUX, "test_1+2-1.efi"));
    t.check("the directory no longer lists the old name", !t.has(LINUX, "test_1+3-0.efi"));
    t.check("the directory holds one entry of the name", t.count_prefix(LINUX, "test_1+") == 2);
    t.check("the old path is gone", t.open("\\EFI\\Linux\\test_1+3-0.efi", file::MODE_READ).is_err());
    match t.open("\\EFI\\Linux\\test_1+2-1.efi", file::MODE_READ) {
        Ok(g) => {
            t.check("the new path has the same content", content_ok(g));
            unsafe { ((*g).close)(g) };
        }
        Err(_) => t.check("the new path has the same content", false),
    }
    t.check("flush succeeds", unsafe { ((*f).flush)(f) } == Status::SUCCESS);

    t.check("the counter is renamed again to +1-2", rename(f, "test_1+1-2.efi", Change::Nothing) == Status::SUCCESS);
    t.check("the handle reports the second name", name_is(f, "test_1+1-2.efi"));
    t.check("the handle reads after the second rename", content_ok(f));
    t.check("the directory lists the second name only", t.has(LINUX, "test_1+1-2.efi") && !t.has(LINUX, "test_1+2-1.efi"));

    t.check("the same name is a no-op", rename(f, "test_1+1-2.efi", Change::Nothing) == Status::SUCCESS);
    t.check("another name is refused", refused(rename(f, "other.efi", Change::Nothing)));
    t.check("a name that exists is refused", rename(f, "test_1+0-3.efi", Change::Nothing) == Status::ACCESS_DENIED);
    t.check("a counter that goes back is refused", refused(rename(f, "test_1+2-1.efi", Change::Nothing)));
    t.check("a counter that goes back in the tries done is refused", refused(rename(f, "test_1+1-1.efi", Change::Nothing)));
    t.check("another stem is refused", refused(rename(f, "test_2+1-2.efi", Change::Nothing)));
    t.check("another extension is refused", refused(rename(f, "test_1+0-3.EFX", Change::Nothing)));
    t.check("a name in another directory is refused", refused(rename(f, "..\\test_1+0-3.efi", Change::Nothing)));
    t.check("an absolute name is refused", refused(rename(f, "\\test_1+0-3.efi", Change::Nothing)));
    t.check("a size change is refused", refused(rename(f, "test_1+1-3.efi", Change::Size)));
    t.check("a size change with the same name is refused", refused(rename(f, "test_1+1-2.efi", Change::Size)));
    t.check("an attribute change is refused", refused(rename(f, "test_1+1-3.efi", Change::Attribute)));
    let mut other = Guid::from_fields(0x09576e93, 0x6d3f, 0x11d2, 0x8e, 0x39, &[0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b]);
    let mut buf = [0u64; 256];
    let status = unsafe { ((*f).set_info)(f, &mut other, 64, buf.as_mut_ptr() as *mut c_void) };
    t.check("another information type is refused", refused(status));
    t.check("a short buffer is refused", unsafe {
        let mut ty = file::INFO_ID;
        ((*f).set_info)(f, &mut ty, 8, buf.as_mut_ptr() as *mut c_void) != Status::SUCCESS
    });
    t.check("the refusals left the name", name_is(f, "test_1+1-2.efi") && t.has(LINUX, "test_1+1-2.efi"));
    t.check("the refusals left the content", content_ok(f));
    t.check("the file still has the size", {
        let mut buf = [0u64; 256];
        info_of(f, &mut buf);
        unsafe { (*(buf.as_ptr() as *const file::Info)).file_size == SIZE as u64 }
    });
    unsafe { ((*f).close)(f) };

    match t.open("\\EFI\\Linux\\test_1+1-2.efi", file::MODE_READ) {
        Ok(g) => {
            t.check("a handle opened read-only is refused", refused(rename(g, "test_1+0-3.efi", Change::Nothing)));
            unsafe { ((*g).close)(g) };
        }
        Err(_) => t.check("a handle opened read-only is refused", false),
    }
    t.check("a counterless entry cannot get a counter", match t.open("\\EFI\\Linux\\plain.efi", file::MODE_READ | file::MODE_WRITE) {
        Ok(g) => {
            let status = rename(g, "plain+3.efi", Change::Nothing);
            unsafe { ((*g).close)(g) };
            refused(status) && t.has(LINUX, "plain.efi")
        }
        Err(_) => false,
    });
    t.check("a file outside the entry directories does not open for writing",
        t.open("\\data\\entry+3-0.efi", file::MODE_READ | file::MODE_WRITE) == Err(Status::WRITE_PROTECTED));
    t.check("a file outside the entry directories is refused", match t.open("\\data\\entry+3-0.efi", file::MODE_READ) {
        Ok(g) => {
            let status = rename(g, "entry+2-1.efi", Change::Nothing);
            unsafe { ((*g).close)(g) };
            refused(status) && t.has("\\data", "entry+3-0.efi")
        }
        Err(_) => false,
    });
    t.check("a directory does not open for writing", t.open(LINUX, file::MODE_READ | file::MODE_WRITE) == Err(Status::WRITE_PROTECTED));
    t.check("a file does not open for creation",
        t.open("\\EFI\\Linux\\plain.efi", file::MODE_READ | file::MODE_WRITE | file::MODE_CREATE) == Err(Status::WRITE_PROTECTED));

    match t.open("\\loader\\entries\\type1_1+3.conf", file::MODE_READ | file::MODE_WRITE) {
        Ok(g) => {
            t.check("a type 1 entry is renamed to a longer name in a buffer sized for the old one", rename(g, "type1_1+2-1.conf", Change::OldSize) == Status::SUCCESS);
            t.check("the type 1 entry has the new name", name_is(g, "type1_1+2-1.conf") && t.has(ENTRIES, "type1_1+2-1.conf"));
            unsafe { ((*g).close)(g) };
        }
        Err(_) => t.check("a type 1 entry is renamed to a longer name in a buffer sized for the old one", false),
    }
}

fn second_boot(t: &mut Test) {
    t.check("the medium lists the last name", t.has(LINUX, "test_1+1-2.efi"));
    t.check("the medium does not list the earlier names",
        !t.has(LINUX, "test_1+3-0.efi") && !t.has(LINUX, "test_1+2-1.efi"));
    t.check("the medium lists the entry that was not renamed", t.has(LINUX, "test_1+0-3.efi") && t.has(LINUX, "plain.efi"));
    t.check("the medium lists the type 1 entry's new name", t.has(ENTRIES, "type1_1+2-1.conf") && !t.has(ENTRIES, "type1_1+3.conf"));
    t.check("the file outside is as it was", t.has("\\data", "entry+3-0.efi"));
    match t.open("\\EFI\\Linux\\test_1+1-2.efi", file::MODE_READ) {
        Ok(f) => {
            t.check("the renamed file has its content", content_ok(f));
            t.check("the renamed file reports its name", name_is(f, "test_1+1-2.efi"));
            unsafe { ((*f).close)(f) };
        }
        Err(_) => t.check("the renamed file has its content", false),
    }
    say(t.table, "bootcount test: done\r\n");
}

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(image: Handle, table: *mut SystemTable) -> Status {
    let bs = unsafe { (*table).boot_services };
    let mut loaded: *mut c_void = null_mut();
    let mut loaded_guid = loaded_image::PROTOCOL_GUID;
    let mut fs: *mut c_void = null_mut();
    let mut fs_guid = simple_file_system::PROTOCOL_GUID;
    let mut root = null_mut();
    unsafe {
        if ((*bs).handle_protocol)(image, &mut loaded_guid, &mut loaded).is_error() {
            return Status::LOAD_ERROR;
        }
        let device = (*(loaded as *mut loaded_image::Protocol)).device_handle;
        if ((*bs).handle_protocol)(device, &mut fs_guid, &mut fs).is_error() {
            return Status::LOAD_ERROR;
        }
        let fs = fs as *mut simple_file_system::Protocol;
        if ((*fs).open_volume)(fs, &mut root).is_error() {
            return Status::LOAD_ERROR;
        }
    }
    let mut t = Test { table, root, failed: false };
    if t.has(LINUX, "test_1+3-0.efi") {
        first_boot(&mut t);
        if t.failed {
            say(table, "bootcount test: FAILED\r\n");
            return Status::ABORTED;
        }
        say(table, "bootcount test: resetting\r\n");
        unsafe {
            let rt = (*table).runtime_services;
            ((*rt).reset_system)(efi::RESET_COLD, Status::SUCCESS, 0, null_mut());
        }
    } else {
        second_boot(&mut t);
    }
    Status::SUCCESS
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

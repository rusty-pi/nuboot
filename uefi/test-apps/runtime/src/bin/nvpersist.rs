//! The TPM's NV indices outlast a reset: the first boot defines three, writes
//! one more after `ExitBootServices` and undefines another, then resets; the
//! second checks what the first left. The TPM is reached over the property
//! mailbox, which is how a driver that has the board answers for itself.

#![no_std]
#![no_main]

use core::ptr::{read_volatile, write_volatile};

use r_efi::efi::{self, Handle, Status, SystemTable};
use runtime_efi::{check, exit_boot_services, say, settle};

const MAIL0_READ: usize = 0xfe00_b880;
const MAIL0_STATUS: usize = 0xfe00_b898;
const MAIL1_WRITE: usize = 0xfe00_b8a0;
const MAIL1_STATUS: usize = 0xfe00_b8b8;
const TAG_TPM2_COMMAND: u32 = 0x0003_00a3;
const ROOM_WORDS: usize = 48;

const RH_OWNER: u32 = 0x4000_0001;
const CC_NV_UNDEFINE_SPACE: u32 = 0x122;
const CC_NV_DEFINE_SPACE: u32 = 0x12a;
const CC_NV_WRITE: u32 = 0x137;
const CC_NV_READ: u32 = 0x14e;
const CC_NV_READ_PUBLIC: u32 = 0x169;
const AUTHWRITE: u32 = 1 << 2;
const AUTHREAD: u32 = 1 << 18;

const KEPT_AT_EXIT: u32 = 0x0150_0001;
const WRITTEN_BY_OS: u32 = 0x0150_0002;
const REMOVED_BY_OS: u32 = 0x0150_0003;
const AUTH: &[u8] = b"nv-pw";

static mut MESSAGE: *mut u32 = core::ptr::null_mut();

fn flush(at: usize, len: usize) {
    for line in (at & !63..at + len).step_by(64) {
        unsafe { core::arch::asm!("dc civac, {}", in(reg) line) };
    }
    unsafe { core::arch::asm!("dsb sy") };
}

struct Response {
    bytes: [u8; 4 * ROOM_WORDS],
}

impl Response {
    fn code(&self) -> u32 {
        u32::from_be_bytes([self.bytes[6], self.bytes[7], self.bytes[8], self.bytes[9]])
    }
}

/// Send the TPM a command.
fn tpm(command: &[u8]) -> Response {
    let m = unsafe { MESSAGE };
    let words = ROOM_WORDS;
    unsafe {
        for i in 0..8 + words {
            write_volatile(m.add(i), 0);
        }
        write_volatile(m, (4 * (5 + words + 1)) as u32);
        write_volatile(m.add(2), TAG_TPM2_COMMAND);
        write_volatile(m.add(3), (4 * words) as u32);
        write_volatile(m.add(4), command.len() as u32);
        for (i, byte) in command.iter().enumerate() {
            let word = m.add(5 + i / 4);
            write_volatile(word, read_volatile(word) | (*byte as u32) << (8 * (i % 4)));
        }
    }
    flush(m as usize, 4 * (8 + words));
    let reply = (0xc000_0000 | m as u32) | 8;
    unsafe {
        while read_volatile(MAIL1_STATUS as *const u32) & (1 << 31) != 0 {}
        write_volatile(MAIL1_WRITE as *mut u32, reply);
        loop {
            while read_volatile(MAIL0_STATUS as *const u32) & (1 << 30) != 0 {}
            if read_volatile(MAIL0_READ as *const u32) == reply {
                break;
            }
        }
    }
    flush(m as usize, 4 * (8 + words));
    let mut out = Response { bytes: [0; 4 * ROOM_WORDS] };
    for (i, byte) in out.bytes.iter_mut().enumerate() {
        *byte = (unsafe { read_volatile(m.add(5 + i / 4)) } >> (8 * (i % 4))) as u8;
    }
    out
}

struct Command {
    bytes: [u8; 4 * ROOM_WORDS],
    len: usize,
}

impl Command {
    fn new(tag: u16, code: u32) -> Command {
        let mut c = Command { bytes: [0; 4 * ROOM_WORDS], len: 0 };
        c.put(&tag.to_be_bytes()).put(&[0; 4]).put(&code.to_be_bytes());
        c
    }
    fn put(&mut self, b: &[u8]) -> &mut Self {
        self.bytes[self.len..self.len + b.len()].copy_from_slice(b);
        self.len += b.len();
        self
    }
    fn sized(&mut self, b: &[u8]) -> &mut Self {
        self.put(&(b.len() as u16).to_be_bytes()).put(b)
    }
    fn password(&mut self, password: &[u8]) -> &mut Self {
        self.put(&(9 + password.len() as u32).to_be_bytes()).put(&0x4000_0009u32.to_be_bytes()).put(&[0, 0, 0]).sized(password)
    }
    fn send(&mut self) -> Response {
        let len = self.len as u32;
        self.bytes[2..6].copy_from_slice(&len.to_be_bytes());
        tpm(&self.bytes[..self.len])
    }
}

fn define(index: u32) -> u32 {
    let mut public = [0u8; 20];
    public[..4].copy_from_slice(&index.to_be_bytes());
    public[4..6].copy_from_slice(&0x000bu16.to_be_bytes());
    public[6..10].copy_from_slice(&(AUTHWRITE | AUTHREAD).to_be_bytes());
    public[12..14].copy_from_slice(&16u16.to_be_bytes());
    Command::new(0x8002, CC_NV_DEFINE_SPACE).put(&RH_OWNER.to_be_bytes()).password(&[]).sized(AUTH).sized(&public[..14]).send().code()
}

fn write(index: u32, data: &[u8]) -> u32 {
    Command::new(0x8002, CC_NV_WRITE).put(&index.to_be_bytes()).put(&index.to_be_bytes()).password(AUTH).sized(data).put(&[0, 0]).send().code()
}

fn undefine(index: u32) -> u32 {
    Command::new(0x8002, CC_NV_UNDEFINE_SPACE).put(&RH_OWNER.to_be_bytes()).put(&index.to_be_bytes()).password(&[]).send().code()
}

fn exists(index: u32) -> bool {
    Command::new(0x8001, CC_NV_READ_PUBLIC).put(&index.to_be_bytes()).send().code() == 0
}

/// The first `N` bytes of an index, or none if it cannot be read.
fn read<const N: usize>(index: u32) -> Option<[u8; N]> {
    let response = Command::new(0x8002, CC_NV_READ)
        .put(&index.to_be_bytes())
        .put(&index.to_be_bytes())
        .password(AUTH)
        .put(&(N as u16).to_be_bytes())
        .put(&[0, 0])
        .send();
    if response.code() != 0 {
        return None;
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&response.bytes[16..16 + N]);
    Some(out)
}

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(image: Handle, system_table: *mut SystemTable) -> Status {
    let mut at: u64 = 0x2fff_ffff;
    let bs = unsafe { (*system_table).boot_services };
    if unsafe { ((*bs).allocate_pages)(efi::ALLOCATE_MAX_ADDRESS, efi::LOADER_DATA, 1, &mut at) } != Status::SUCCESS {
        say("nv persist test: no page below 1 GiB\r\n");
        runtime_efi::hang()
    }
    unsafe { MESSAGE = at as *mut u32 };

    if !exists(KEPT_AT_EXIT) {
        say("nv persist test: first boot\r\n");
        check("an index is defined", define(KEPT_AT_EXIT) == 0 && define(WRITTEN_BY_OS) == 0 && define(REMOVED_BY_OS) == 0);
        check("and written", write(KEPT_AT_EXIT, b"before the exit") == 0 && write(WRITTEN_BY_OS, b"first") == 0 && write(REMOVED_BY_OS, b"doomed") == 0);
        let rt = exit_boot_services(image, system_table);
        settle();
        check("an index is written after ExitBootServices", write(WRITTEN_BY_OS, b"after the exit") == 0);
        check("and another undefined", undefine(REMOVED_BY_OS) == 0);
        say("nv persist test: resetting\r\n");
        unsafe { ((*rt).reset_system)(efi::RESET_COLD, Status::SUCCESS, 0, core::ptr::null_mut()) };
        runtime_efi::hang()
    }

    say("nv persist test: second boot\r\n");
    check("an index written before ExitBootServices is back", read::<15>(KEPT_AT_EXIT) == Some(*b"before the exit"));
    check("an index written after it is back with the later write", read::<14>(WRITTEN_BY_OS) == Some(*b"after the exit"));
    check("an index undefined after it is gone", !exists(REMOVED_BY_OS));
    check("an index is read with its authorization value", read::<1>(KEPT_AT_EXIT).is_some());
    say("nv persist test: done\r\n");
    Status::SUCCESS
}

//! EFI applications the runtime-services scenarios boot: each exits boot
//! services as an operating system loader does, then calls what the firmware
//! leaves the OS, saying what it finds on the serial port (the console is
//! gone by then).

#![no_std]

use core::mem::size_of;

use r_efi::efi::{self, Handle, MemoryDescriptor, SystemTable};

const UART0: usize = 0xFE20_1000;
const FR: usize = 0x18;
const TXFF: u32 = 1 << 5;

pub fn say(text: &str) {
    for b in text.bytes() {
        unsafe {
            while core::ptr::read_volatile((UART0 + FR) as *const u32) & TXFF != 0 {}
            core::ptr::write_volatile(UART0 as *mut u32, b as u32);
        }
    }
}

pub fn say_hex(value: u64) {
    say("0x");
    for shift in (0..16).rev() {
        let digit = ((value >> (4 * shift)) & 0xf) as u8;
        let mut buf = [0u8; 1];
        buf[0] = if digit < 10 { b'0' + digit } else { b'a' + digit - 10 };
        say(core::str::from_utf8(&buf).unwrap_or("?"));
    }
}

pub fn hang() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    say("runtime test: panic\r\n");
    hang()
}

static mut MAP: [u8; 16384] = [0; 16384];

/// Exit boot services, and give back the runtime services table.
pub fn exit_boot_services(image: Handle, system_table: *mut SystemTable) -> *mut efi::RuntimeServices {
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
            return unsafe { (*system_table).runtime_services };
        }
    }
    say("runtime test: ExitBootServices failed\r\n");
    hang()
}

pub fn check(name: &str, ok: bool) {
    say("runtime test: ");
    say(name);
    say(if ok { " ok\r\n" } else { " FAILED\r\n" });
}

/// A NUL-terminated UCS-2 name in `buf`.
pub fn name<const N: usize>(text: &str, buf: &mut [u16; N]) -> *mut u16 {
    for (i, b) in text.bytes().enumerate() {
        buf[i] = b as u16;
    }
    buf.as_mut_ptr()
}

/// Wait for the VPU firmware to finish logging what `ExitBootServices` set
/// off, so its lines do not run into ours.
pub fn settle() {
    let (start, freq): (u64, u64);
    unsafe {
        core::arch::asm!("mrs {0}, CNTPCT_EL0", out(reg) start);
        core::arch::asm!("mrs {0}, CNTFRQ_EL0", out(reg) freq);
    }
    loop {
        let now: u64;
        unsafe { core::arch::asm!("isb", "mrs {0}, CNTPCT_EL0", out(reg) now) };
        if now - start > freq / 2 {
            return;
        }
    }
}

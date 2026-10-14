//! Can the ARM reach the OTP block (0x7E20_F000, seen at 0xFE20_F000) the way
//! the VPU does? First reads the block's registers and row 17 (the boot mode,
//! not secret) from EL0 and from EL1, then, from EL2 and in this order, says
//! what it is about to do before each step so that a hang names the step: the
//! block's control registers (values), the data and key registers (zero or
//! not), then the VPU's own read sequence for row 17 and for row 56, the first
//! of the device private key (zero or not, never the value).

#![no_std]
#![no_main]

use core::ptr::{read_volatile, write_volatile};

use r_efi::efi::{Handle, Status, SystemTable};

const UART0: usize = 0xFE20_1000;
const FR: usize = 0x18;
const TXFF: u32 = 1 << 5;

fn say(text: &str) {
    for b in text.bytes() {
        unsafe {
            while read_volatile((UART0 + FR) as *const u32) & TXFF != 0 {}
            write_volatile(UART0 as *mut u32, b as u32);
        }
    }
}

fn hex(value: u32) {
    say("0x");
    for shift in (0..8).rev() {
        let digit = ((value >> (4 * shift)) & 0xf) as u8;
        let b = [if digit < 10 { b'0' + digit } else { b'a' + digit - 10 }];
        say(core::str::from_utf8(&b).unwrap_or("?"));
    }
}

fn counter() -> u64 {
    let now: u64;
    unsafe { core::arch::asm!("isb", "mrs {0}, CNTPCT_EL0", out(reg) now) };
    now
}

fn delay_us(us: u64) {
    let freq: u64;
    unsafe { core::arch::asm!("mrs {0}, CNTFRQ_EL0", out(reg) freq) };
    let start = counter();
    while counter() - start < freq * us / 1_000_000 {}
}

const BASE: usize = 0xFE20_F000;
const CLKMUX: usize = BASE + 0x04;
const PARAM_A: usize = BASE + 0x08;
const PARAM_B: usize = BASE + 0x0c;
const STATUS: usize = BASE + 0x10;
const DATA: usize = BASE + 0x18;
const KEY: usize = BASE + 0x1c;

fn read(at: usize) -> u32 {
    unsafe { read_volatile(at as *const u32) }
}

fn write(at: usize, value: u32) {
    unsafe { write_volatile(at as *mut u32, value) }
}

/// The VPU's sequence for one row (`src/otp.rs`), byte for byte.
fn row(n: u32) -> Option<u32> {
    write(CLKMUX, 3);
    delay_us(10);
    write(PARAM_B, 0);
    write(PARAM_A, 0);
    delay_us(10);
    write(CLKMUX, 2);
    delay_us(10);
    write(KEY, n);
    write(PARAM_B, 0);
    write(PARAM_A, 0);
    write(PARAM_A, read(PARAM_A) | 1);
    let mut fell = false;
    let mut rose = false;
    let start = counter();
    let freq: u64;
    unsafe { core::arch::asm!("mrs {0}, CNTFRQ_EL0", out(reg) freq) };
    while counter() - start < freq / 1000 {
        if read(STATUS) & 2 == 0 {
            fell = true;
            break;
        }
    }
    let start = counter();
    while counter() - start < freq / 1000 {
        if read(STATUS) & 2 != 0 {
            rose = true;
            break;
        }
    }
    write(PARAM_B, 0);
    write(PARAM_A, 0);
    let value = read(DATA);
    write(PARAM_B, 0);
    write(PARAM_A, 0);
    write(CLKMUX, 0);
    (fell && rose).then_some(value)
}


core::arch::global_asm!(
    r#"
    .macro spin n
    movz x6, #\n
1:  subs x6, x6, #1
    b.ne 1b
    .endm

    .section .text.level, "ax"
    .balign 2048
level_vectors:
    .rept 16
    .balign 128
    b level_trap
    .endr

level_trap:
    mrs x0, esr_el2
    mov sp, x19
    msr vbar_el2, x20
    msr hcr_el2, x21
    isb
    ldp x21, x22, [sp, #16]
    ldp x23, x24, [sp, #32]
    ldp x25, x26, [sp, #48]
    ldp x27, x28, [sp, #64]
    ldp x29, x30, [sp, #80]
    ldp x19, x20, [sp], #96
    ret

    .global level_run
level_run:
    stp x19, x20, [sp, #-96]!
    stp x21, x22, [sp, #16]
    stp x23, x24, [sp, #32]
    stp x25, x26, [sp, #48]
    stp x27, x28, [sp, #64]
    stp x29, x30, [sp, #80]
    mov x19, sp
    mrs x20, vbar_el2
    mrs x21, hcr_el2
    adr x3, level_vectors
    msr vbar_el2, x3
    movz x4, #0x8000, lsl #16
    mov x5, #0x3c5
    cbnz x2, 1f
    orr x4, x4, #0x08000000
    mov x5, #0x3c0
1:  msr hcr_el2, x4
    msr spsr_el2, x5
    msr elr_el2, x0
    mov x0, x1
    isb
    eret

    .global level_payload
level_payload:
    movz x1, #0xFE20, lsl #16
    movk x1, #0xF000
    ldr w2, [x1, #0x00]
    str w2, [x0, #0x00]
    ldr w2, [x1, #0x04]
    str w2, [x0, #0x04]
    ldr w2, [x1, #0x08]
    str w2, [x0, #0x08]
    ldr w2, [x1, #0x0c]
    str w2, [x0, #0x0c]
    ldr w2, [x1, #0x10]
    str w2, [x0, #0x10]
    ldr w2, [x1, #0x14]
    str w2, [x0, #0x14]
    mov w3, #3
    str w3, [x1, #0x04]
    spin 3000
    str wzr, [x1, #0x0c]
    str wzr, [x1, #0x08]
    spin 3000
    mov w3, #2
    str w3, [x1, #0x04]
    spin 3000
    mov w3, #17
    str w3, [x1, #0x1c]
    str wzr, [x1, #0x0c]
    str wzr, [x1, #0x08]
    ldr w3, [x1, #0x08]
    orr w3, w3, #1
    str w3, [x1, #0x08]
    movz x6, #0xffff
2:  ldr w3, [x1, #0x10]
    tbz w3, #1, 3f
    subs x6, x6, #1
    b.ne 2b
3:  movz x6, #0xffff
4:  ldr w3, [x1, #0x10]
    tbnz w3, #1, 5f
    subs x6, x6, #1
    b.ne 4b
5:  str wzr, [x1, #0x0c]
    str wzr, [x1, #0x08]
    ldr w3, [x1, #0x18]
    str w3, [x0, #0x18]
    str wzr, [x1, #0x0c]
    str wzr, [x1, #0x08]
    str wzr, [x1, #0x04]
    hvc #0
    "#
);

unsafe extern "C" {
    fn level_run(entry: usize, buffer: *mut u32, el1: u64) -> u64;
    fn level_payload();
}

#[repr(align(64))]
struct Buffer([u32; 16]);

static mut LEVEL_BUFFER: Buffer = Buffer([0; 16]);

fn flush(at: usize, len: usize) {
    let mut line = at & !63;
    while line < at + len {
        unsafe { core::arch::asm!("dc civac, {0}", in(reg) line) };
        line += 64;
    }
    unsafe { core::arch::asm!("dsb sy", "isb") };
}

/// Reads the block's registers and row 17 from EL0 (`el1` false) or EL1, with
/// the MMU of that level off, and says what came back.
fn at_level(el1: bool) {
    let buffer = &raw mut LEVEL_BUFFER as *mut u32;
    unsafe { core::ptr::write_bytes(buffer, 0, 16) };
    flush(buffer as usize, 64);
    flush(level_payload as usize, 512);
    unsafe { core::arch::asm!("ic ialluis", "dsb sy", "isb") };
    say(if el1 { "otp probe: reading from EL1\r\n" } else { "otp probe: reading from EL0\r\n" });
    let esr = unsafe { level_run(level_payload as usize, buffer, el1 as u64) };
    flush(buffer as usize, 64);
    say("otp probe: back, esr_el2 = ");
    hex(esr as u32);
    say("\r\n");
    for (name, i) in [("0x00", 0), ("CLKMUX", 1), ("PARAM_A", 2), ("PARAM_B", 3), ("STATUS", 4), ("0x14", 5)] {
        say("otp probe: ");
        say(if el1 { "EL1 " } else { "EL0 " });
        say(name);
        say(" = ");
        hex(unsafe { read_volatile(buffer.add(i)) });
        say("\r\n");
    }
    say("otp probe: ");
    say(if el1 { "EL1 " } else { "EL0 " });
    say("row 17 = ");
    hex(unsafe { read_volatile(buffer.add(6)) });
    say("\r\n");
}

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(_image: Handle, _system_table: *mut SystemTable) -> Status {
    say("otp probe: start\r\n");
    let (el, hcr): (u64, u64);
    unsafe { core::arch::asm!("mrs {0}, CurrentEL", "mrs {1}, hcr_el2", out(reg) el, out(reg) hcr) };
    say("otp probe: CurrentEL = ");
    hex(el as u32);
    say(", HCR_EL2 = ");
    hex(hcr as u32);
    say("\r\n");
    at_level(false);
    at_level(true);
    for (name, at) in [("CLKMUX", CLKMUX), ("PARAM_A", PARAM_A), ("PARAM_B", PARAM_B), ("STATUS", STATUS)] {
        say("otp probe: reading ");
        say(name);
        say("\r\n");
        let v = read(at);
        say("otp probe: ");
        say(name);
        say(" = ");
        hex(v);
        say("\r\n");
    }
    for (name, at) in [("0x00", BASE), ("0x14", BASE + 0x14), ("DATA", DATA), ("KEY", KEY)] {
        say("otp probe: reading ");
        say(name);
        say("\r\n");
        let v = read(at);
        say("otp probe: ");
        say(name);
        say(if v == 0 { " is zero\r\n" } else { " is not zero\r\n" });
    }
    let mut seen = [None; 5];
    for (i, n) in [17u32, 30, 56, 57, 17].into_iter().enumerate() {
        say("otp probe: reading row ");
        hex(n);
        say(" the way the VPU does\r\n");
        seen[i] = row(n);
        match (n, seen[i]) {
            (17 | 30, Some(v)) => {
                say("otp probe: row ");
                hex(n);
                say(" = ");
                hex(v);
                say("\r\n");
            }
            (_, Some(v)) => {
                say("otp probe: row ");
                hex(n);
                say(if v == 0 { " is zero\r\n" } else { " is not zero\r\n" });
            }
            (_, None) => say("otp probe: the block did not answer the command\r\n"),
        }
    }
    if let (Some(a), Some(b), Some(c), Some(d)) = (seen[0], seen[1], seen[2], seen[3]) {
        say(if c != a && c != b { "otp probe: row 56 differs from rows 17 and 30\r\n" } else { "otp probe: row 56 equals row 17 or 30\r\n" });
        say(if c != d { "otp probe: row 56 differs from row 57\r\n" } else { "otp probe: row 56 equals row 57\r\n" });
    }
    say("otp probe: done\r\n");
    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    say("otp probe: panic\r\n");
    loop {}
}

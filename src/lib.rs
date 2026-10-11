//! Bare-metal Rust on the VideoCore IV VPU: startup, the console log, panic
//! handling, and the runtime and drivers the firmware in `src/bin/` is built
//! from.

#![no_std]
#![feature(asm_experimental_arch)]

use core::panic::PanicInfo;
use core::ptr::{addr_of, addr_of_mut, read_volatile, write_volatile};

pub mod aes;
pub mod arm;
pub mod board;
pub mod cache;
pub mod cm;
pub mod console;
pub mod critical;
pub mod eeprom;
pub mod elf;
pub mod fdt;
pub mod gpio;
pub mod handover;
pub mod i2c;
pub mod idle;
pub mod kdf;
pub mod keystore;
pub mod log;
pub mod lz4;
pub mod measure;
pub mod lzss;
pub mod mailbox;
pub mod mmio;
pub mod otp;
pub mod p256;
pub mod pcie;
pub mod pmic;
pub mod rng;
pub mod rsa;
pub mod sched;
pub mod sdram;
pub mod sha256;
pub mod spi_flash;
pub mod stack;
pub mod stc;
pub mod sync;
pub mod timer;
pub mod tpm2;
pub mod usb;
pub mod vl805;
pub mod watchdog;

// Both VPU cores come out of reset at the same place; bit 16 of `version` is
// the core number. Core 1 parks.
//
// Before it parks it clears its own interrupt controller's eight priority words
// and its vector base: whatever stage ran before this one may have left a source
// enabled in core 1's bank and a vector base pointing at code this image has
// since overwritten, and core 1 would wake out of `sleep` and jump into it. With
// every priority field at zero nothing can be delivered, so it cannot vector
// whether or not interrupts are enabled -- which is why this clears the enables
// rather than executing `di`: a wake through `IC1_WAKEUP` has to keep working if
// core 1 is ever given work.
core::arch::global_asm!(
    ".pushsection .text.start, \"ax\"",
    ".globl _start",
    "_start:",
    "    version r0",
    "    btest r0, #16",
    "    bne 2f",
    "    mov.l sp, #__stack_top",
    "    bl rust_start",
    "3:  b 3b",
    "2:  mov r1, #0",
    "    mov r0, #0x7e002810",
    "    st r1, (r0)",
    "    mov r0, #0x7e002814",
    "    st r1, (r0)",
    "    mov r0, #0x7e002818",
    "    st r1, (r0)",
    "    mov r0, #0x7e00281c",
    "    st r1, (r0)",
    "    mov r0, #0x7e002820",
    "    st r1, (r0)",
    "    mov r0, #0x7e002824",
    "    st r1, (r0)",
    "    mov r0, #0x7e002828",
    "    st r1, (r0)",
    "    mov r0, #0x7e00282c",
    "    st r1, (r0)",
    "    mov r0, #0x7e002830",
    "    st r1, (r0)",
    "4:  sleep",
    "    b 4b",
    ".popsection",
);

unsafe extern "C" {
    static mut __bss_start: u8;
    static mut __bss_end: u8;
    static mut __data_start: u8;
    static mut __data_end: u8;
    /// Where the linker put `.data`'s initial values; the same as
    /// `__data_start` unless the image runs from ROM.
    static __data_load: u8;
}

unsafe extern "Rust" {
    /// Each image's entry point, `#[unsafe(no_mangle)] fn firmware_main() -> !`.
    safe fn firmware_main() -> !;
}

#[unsafe(no_mangle)]
extern "C" fn rust_start() -> ! {
    unsafe {
        let mut src = addr_of!(__data_load);
        let mut dst = addr_of_mut!(__data_start);
        let end = addr_of_mut!(__data_end);
        if src != dst.cast_const() {
            while dst < end {
                write_volatile(dst, read_volatile(src));
                src = src.add(1);
                dst = dst.add(1);
            }
        }

        let mut p = addr_of_mut!(__bss_start);
        let end = addr_of_mut!(__bss_end);
        while p < end {
            write_volatile(p, 0);
            p = p.add(1);
        }
    }
    firmware_main()
}

pub fn halt() -> ! {
    loop {
        unsafe { core::arch::asm!("sleep") };
    }
}

/// `core` calls `abort` from a handful of cold paths -- `slice_error_fail_rt`
/// is the one the images reach. At `opt-level = "s"` `--gc-sections` drops
/// them and the symbol is never needed; at any higher level they survive and
/// the link fails without this.
#[unsafe(no_mangle)]
extern "C" fn abort() -> ! {
    halt()
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // Nothing else may switch in or interrupt from here: the line goes out
    // whole, and it is the last thing the core does. The place as well as the
    // message: on a board with nothing but a serial line, this is the whole of
    // the diagnosis.
    critical::disable();
    idle::disable_all();
    match info.location() {
        Some(at) => log::panic_record(format_args!("{}", info.message()), at.file(), at.line()),
        None => log::panic_record(format_args!("{}", info.message()), "?", 0),
    }
    console::drain();
    halt()
}

//! The image the VPU firmware starts the ARM cores in, at ARM physical 0: an
//! armstub (`armstub.rs`), then a decompressor that unpacks the UEFI payload
//! to the address the payload is linked at and jumps to it with the device
//! tree.
//!
//! The payload is coded with xz's ARM64 filter and LZMA, which takes it to
//! about a third of its size; the EEPROM has no room for it otherwise.
//!
//! The decompressor builds a 1 GiB-block identity map so the decoder runs
//! with the caches on, and turns the MMU back off before the jump: the
//! payload expects to be entered as an armstub enters an image.

#![no_std]
#![no_main]

mod armstub;
mod lzma;

use core::arch::global_asm;
use core::panic::PanicInfo;

include!(concat!(env!("OUT_DIR"), "/payload.rs"));

const UART0_DR: usize = 0xFE20_1000;
const UART0_FR: usize = 0xFE20_1018;

global_asm!(
    r#"
.section .text.decompress, "ax"
.global decompress
decompress:
    mov x19, x0

    // Attr0 device-nGnRnE, Attr1 normal write-back.
    mov x1, #0xFF00
    msr MAIR_EL2, x1
    // T0SZ=16, IRGN0/ORGN0 write-back, inner shareable, 4K granule, 44-bit PA.
    mov x1, #0x3510
    movk x1, #0x8084, lsl #16
    msr TCR_EL2, x1

    adrp x10, _pt_l0
    add x10, x10, :lo12:_pt_l0
    adrp x11, _pt_l1
    add x11, x11, :lo12:_pt_l1
    mov x2, x10
    mov x3, #(2 * 512)
1:  str xzr, [x2], #8
    subs x3, x3, #1
    b.ne 1b
    orr x1, x11, #3
    str x1, [x10]
    // L1[0..2]: normal RAM. L1[3]: device, the peripheral window and below.
    mov x1, #0x705
    str x1, [x11]
    orr x1, x1, #0x40000000
    str x1, [x11, #8]
    mov x1, #0x705
    orr x1, x1, #0x80000000
    str x1, [x11, #16]
    mov x1, #0x641
    orr x1, x1, #0xC0000000
    str x1, [x11, #24]

    dsb sy
    msr TTBR0_EL2, x10
    tlbi alle2
    dsb sy
    isb
    mrs x1, SCTLR_EL2
    orr x1, x1, #(1 << 0)       // M
    orr x1, x1, #(1 << 2)       // C
    orr x1, x1, #(1 << 12)      // I
    bic x1, x1, #(1 << 1)       // no alignment checks
    bic x1, x1, #(1 << 19)      // no WXN
    msr SCTLR_EL2, x1
    isb

    adrp x1, _stack_top
    add x1, x1, :lo12:_stack_top
    mov sp, x1
    adrp x1, _bss_start
    add x1, x1, :lo12:_bss_start
    adrp x2, _bss_end
    add x2, x2, :lo12:_bss_end
2:  cmp x1, x2
    b.hs 3f
    stp xzr, xzr, [x1], #16
    b 2b
3:
    mov x0, x19
    bl stub_main                // x0 = where the payload is, x1 = its size

    // Write the payload out to memory, as the MMU and caches go off.
    mrs x3, CTR_EL0
    ubfx x3, x3, #16, #4
    mov x4, #4
    lsl x4, x4, x3              // D-cache line size
    sub x5, x4, #1
    bic x2, x0, x5
    add x1, x0, x1
4:  dc cvac, x2
    add x2, x2, x4
    cmp x2, x1
    b.lo 4b
    dsb sy

    mrs x1, SCTLR_EL2
    bic x1, x1, #(1 << 0)
    bic x1, x1, #(1 << 2)
    bic x1, x1, #(1 << 12)
    msr SCTLR_EL2, x1
    isb
    ic iallu
    tlbi alle2
    dsb sy
    isb

    mov x2, x0
    mov x0, x19
    mov x1, xzr
    mov x3, xzr
    br x2
"#
);

fn puts(s: &str) {
    for b in s.bytes() {
        unsafe {
            while core::ptr::read_volatile(UART0_FR as *const u32) & (1 << 5) != 0 {}
            core::ptr::write_volatile(UART0_DR as *mut u32, b as u32);
        }
    }
}

fn halt(why: &str) -> ! {
    puts("pi4-uefi-stub: ");
    puts(why);
    puts("\r\n");
    loop {
        unsafe { core::arch::asm!("wfe") };
    }
}

/// Returned in `x0` and `x1`.
#[repr(C)]
struct Payload {
    base: usize,
    len: usize,
}

#[unsafe(no_mangle)]
extern "C" fn stub_main(tree: usize) -> Payload {
    if (PAYLOAD_BASE..PAYLOAD_END).contains(&tree) {
        halt("the device tree is where the payload goes");
    }
    let out = unsafe { core::slice::from_raw_parts_mut(PAYLOAD_BASE as *mut u8, PAYLOAD_LEN) };
    if lzma::decode(PAYLOAD_LZMA, PAYLOAD_PROPS, out).is_err() {
        halt("the payload does not decompress");
    }
    lzma::unfilter_arm64(out);
    Payload { base: PAYLOAD_BASE, len: PAYLOAD_LEN }
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    halt("panic")
}

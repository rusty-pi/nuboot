//! The first instructions: the armstub enters here at EL2 with the MMU and
//! caches off and x0 holding the device tree. Build an identity map, turn the
//! MMU on, set up a stack and go to `pi4_main`.
//!
//! The image starts with an arm64 `Image` header (Linux's
//! `Documentation/arch/arm64/booting.rst`), so a loader that reads it places
//! the image 2 MiB-aligned at `0x200000`, the address it is linked at,
//! instead of at the legacy `0x80000`.
//!
//! The map, in blocks:
//!
//! | range | attributes |
//! |---|---|
//! | `0x0000_0000..0xFC00_0000` | normal, write-back (low RAM) |
//! | `0xFC00_0000..0x1_0000_0000` | device (the peripheral window) |
//! | `0x1_0000_0000..0x2_0000_0000` | normal (RAM above 4 GiB on 4/8 GiB boards) |
//! | `0x2_0000_0000..` | device (PCIe outbound windows) |

use core::arch::global_asm;

global_asm!(
    r#"
.section .text.entry, "ax"
.global _start
_start:
    b 0f                        // code0
    .word 0                     // code1
    .quad 0                     // text_offset
    .quad _image_size           // image_size: everything up to the end of the deferred buffer
    .quad 2                     // flags: little-endian, 4 KiB pages, 2 MiB-aligned base
    .quad 0, 0, 0               // res2..res4
    .ascii "ARM\x64"            // magic
    .word 0                     // res5
0:
    mov x19, x0

    adrp x1, exception_vectors
    add x1, x1, :lo12:exception_vectors
    msr VBAR_EL2, x1
    isb

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
    adrp x12, _pt_l2
    add x12, x12, :lo12:_pt_l2

    // Zero the three tables.
    mov x2, x10
    mov x3, #(3 * 512)
1:  str xzr, [x2], #8
    subs x3, x3, #1
    b.ne 1b

    // L0[0] -> L1.
    orr x1, x11, #3
    str x1, [x10]

    mov x5, xzr                 // physical address
    mov x6, #0x40000000         // 1 GiB
    mov x2, x11

    // L1[0..2]: normal.
    mov x3, #3
2:  mov x4, #0x705
    orr x4, x4, x5
    str x4, [x2], #8
    add x5, x5, x6
    subs x3, x3, #1
    b.ne 2b

    // L1[3] -> L2: 480 normal 2 MiB blocks, then 32 device ones.
    orr x1, x12, #3
    str x1, [x2], #8
    mov x7, x12
    mov x8, x5
    mov x9, #0x200000
    mov x3, #480
3:  mov x4, #0x705
    orr x4, x4, x8
    str x4, [x7], #8
    add x8, x8, x9
    subs x3, x3, #1
    b.ne 3b
    mov x3, #32
4:  mov x4, #0x641
    orr x4, x4, x8
    str x4, [x7], #8
    add x8, x8, x9
    subs x3, x3, #1
    b.ne 4b
    add x5, x5, x6

    // L1[4..7]: normal.
    mov x3, #4
5:  mov x4, #0x705
    orr x4, x4, x5
    str x4, [x2], #8
    add x5, x5, x6
    subs x3, x3, #1
    b.ne 5b

    // L1[8..511]: device.
    mov x3, #504
6:  mov x4, #0x641
    orr x4, x4, x5
    str x4, [x2], #8
    add x5, x5, x6
    subs x3, x3, #1
    b.ne 6b

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
7:  cmp x1, x2
    b.hs 8f
    stp xzr, xzr, [x1], #16
    b 7b
8:
    mov x0, x19
    bl pi4_main
9:  wfe
    b 9b
"#
);

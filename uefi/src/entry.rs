//! The first instructions: the stub enters here at EL2 with the MMU and caches
//! off and x0 holding the device tree, as the armstub left them. Build an
//! identity map, turn the MMU on, set up a stack and go to `pi4_main`.
//!
//! The map:
//!
//! | range | attributes |
//! |---|---|
//! | `0x0000_0000..0x0020_0000` | normal, write-back |
//! | `0x0020_0000..0x0040_0000` | normal, non-cacheable: [`crate::dma`]'s arena |
//! | `0x0040_0000..0xFC00_0000` | normal, write-back (low RAM) |
//! | `0xFC00_0000..0x1_0000_0000` | device (the peripheral window) |
//! | `0x1_0000_0000..0x2_0000_0000` | normal (RAM above 4 GiB on 4/8 GiB boards) |
//! | `0x2_0000_0000..` | device (PCIe outbound windows) |
//!
//! The exception vectors catch whatever goes wrong at EL2, in this firmware
//! or in an EFI application, and report it before stopping.

use core::arch::global_asm;

global_asm!(
    r#"
.section .text.entry, "ax"
.global _start
_start:
    mov x19, x0

    adrp x1, exception_vectors
    add x1, x1, :lo12:exception_vectors
    msr VBAR_EL2, x1
    isb

    // Attr0 device-nGnRnE, Attr1 normal write-back, Attr2 normal non-cacheable.
    mov x1, #0xFF00
    movk x1, #0x44, lsl #16
    msr MAIR_EL2, x1
    // T0SZ=16, IRGN0/ORGN0 write-back, inner shareable, 4K granule, 44-bit PA.
    mov x1, #0x3510
    movk x1, #0x8084, lsl #16
    msr TCR_EL2, x1

    adrp x10, _pt_l0
    add x10, x10, :lo12:_pt_l0
    adrp x11, _pt_l1
    add x11, x11, :lo12:_pt_l1
    adrp x12, _pt_l2_low
    add x12, x12, :lo12:_pt_l2_low
    adrp x13, _pt_l2_high
    add x13, x13, :lo12:_pt_l2_high

    // Zero the four tables.
    mov x2, x10
    mov x3, #(4 * 512)
1:  str xzr, [x2], #8
    subs x3, x3, #1
    b.ne 1b

    // L0[0] -> L1.
    orr x1, x11, #3
    str x1, [x10]

    mov x6, #0x200000           // 2 MiB
    mov x9, #0x40000000         // 1 GiB

    // L1[0] -> the low L2: normal 2 MiB blocks, the second non-cacheable.
    orr x1, x12, #3
    str x1, [x11]
    mov x5, xzr
    mov x7, x12
    mov x3, #512
2:  mov x4, #0x705
    cmp x5, x6
    b.ne 3f
    mov x4, #0x709
3:  orr x4, x4, x5
    str x4, [x7], #8
    add x5, x5, x6
    subs x3, x3, #1
    b.ne 2b

    // L1[1..2]: normal.
    mov x4, #0x705
    orr x4, x4, x5
    str x4, [x11, #8]
    add x5, x5, x9
    mov x4, #0x705
    orr x4, x4, x5
    str x4, [x11, #16]
    add x5, x5, x9

    // L1[3] -> the high L2: 480 normal 2 MiB blocks, then 32 device ones.
    orr x1, x13, #3
    str x1, [x11, #24]
    mov x7, x13
    mov x3, #480
4:  mov x4, #0x705
    orr x4, x4, x5
    str x4, [x7], #8
    add x5, x5, x6
    subs x3, x3, #1
    b.ne 4b
    mov x3, #32
5:  mov x4, #0x641
    orr x4, x4, x5
    str x4, [x7], #8
    add x5, x5, x6
    subs x3, x3, #1
    b.ne 5b

    // L1[4..7]: normal. L1[8..511]: device.
    add x2, x11, #32
    mov x3, #4
6:  mov x4, #0x705
    orr x4, x4, x5
    str x4, [x2], #8
    add x5, x5, x9
    subs x3, x3, #1
    b.ne 6b
    mov x3, #504
7:  mov x4, #0x641
    orr x4, x4, x5
    str x4, [x2], #8
    add x5, x5, x9
    subs x3, x3, #1
    b.ne 7b

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
8:  cmp x1, x2
    b.hs 9f
    stp xzr, xzr, [x1], #16
    b 8b
9:
    mov x0, x19
    bl pi4_main
10: wfe
    b 10b

// Sixteen entries of 0x80 bytes. Each one saves x0..x3 and lr, puts which
// entry it is in x0 and goes to `exception`, which does not return.
.macro vector n
    .balign 0x80
    stp x0, x1, [sp, #-48]!
    stp x2, x3, [sp, #16]
    str x30, [sp, #32]
    mov x0, #\n
    mov x1, sp
    b exception
.endm

// An interrupt at EL2 on SP_EL2, which is where the firmware and everything it
// starts run: keep what the code it interrupted can have in registers (the
// caller-saved ones, which `pi4_irq` may use), call it, and go back.
.macro irq_vector
    .balign 0x80
    sub sp, sp, #(16 * 10 + 16 * 24)
    stp x0, x1, [sp, #0]
    stp x2, x3, [sp, #16]
    stp x4, x5, [sp, #32]
    stp x6, x7, [sp, #48]
    stp x8, x9, [sp, #64]
    stp x10, x11, [sp, #80]
    stp x12, x13, [sp, #96]
    stp x14, x15, [sp, #112]
    stp x16, x17, [sp, #128]
    stp x18, x30, [sp, #144]
    b irq_save_vectors
.endm

.section .text.irq, "ax"
irq_save_vectors:
    stp q0, q1, [sp, #160]
    stp q2, q3, [sp, #192]
    stp q4, q5, [sp, #224]
    stp q6, q7, [sp, #256]
    stp q16, q17, [sp, #288]
    stp q18, q19, [sp, #320]
    stp q20, q21, [sp, #352]
    stp q22, q23, [sp, #384]
    stp q24, q25, [sp, #416]
    stp q26, q27, [sp, #448]
    stp q28, q29, [sp, #480]
    stp q30, q31, [sp, #512]
    bl pi4_irq
    ldp q0, q1, [sp, #160]
    ldp q2, q3, [sp, #192]
    ldp q4, q5, [sp, #224]
    ldp q6, q7, [sp, #256]
    ldp q16, q17, [sp, #288]
    ldp q18, q19, [sp, #320]
    ldp q20, q21, [sp, #352]
    ldp q22, q23, [sp, #384]
    ldp q24, q25, [sp, #416]
    ldp q26, q27, [sp, #448]
    ldp q28, q29, [sp, #480]
    ldp q30, q31, [sp, #512]
    ldp x0, x1, [sp, #0]
    ldp x2, x3, [sp, #16]
    ldp x4, x5, [sp, #32]
    ldp x6, x7, [sp, #48]
    ldp x8, x9, [sp, #64]
    ldp x10, x11, [sp, #80]
    ldp x12, x13, [sp, #96]
    ldp x14, x15, [sp, #112]
    ldp x16, x17, [sp, #128]
    ldp x18, x30, [sp, #144]
    add sp, sp, #(16 * 10 + 16 * 24)
    eret

.section .vectors, "ax"
.balign 2048
.global exception_vectors
exception_vectors:
    vector 0
    vector 1
    vector 2
    vector 3
    vector 4
    irq_vector
    vector 6
    vector 7
    vector 8
    vector 9
    vector 10
    vector 11
    vector 12
    vector 13
    vector 14
    vector 15
"#
);

/// Every exception at EL2 but the timer interrupt ([`crate::watchdog`]) is a
/// fault here.
#[unsafe(no_mangle)]
extern "C" fn exception(entry: u64, _saved: *const u64) -> ! {
    let (esr, elr, far): (u64, u64, u64);
    unsafe {
        core::arch::asm!(
            "mrs {0}, ESR_EL2", "mrs {1}, ELR_EL2", "mrs {2}, FAR_EL2",
            out(reg) esr, out(reg) elr, out(reg) far,
        );
    }
    crate::error!("uefi", "unexpected exception, stopping";
        vector = entry, esr = crate::util::Hex(esr), elr = crate::util::Hex(elr),
        far = crate::util::Hex(far), image = crate::image::describe(elr));
    crate::util::halt()
}

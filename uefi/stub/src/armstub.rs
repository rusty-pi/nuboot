//! The first instructions: all four cores come out of reset at ARM physical 0
//! in EL3 with interrupts masked, which is where the VPU firmware puts this
//! image.
//!
//! Each core sets up what an armstub does on this board (the shape of
//! Raspberry Pi's `armstub8.S`, built for BCM2711 with the GIC): the ARM local
//! timer, the L2 cache latency, the generic timer, EL3's controls, SMP mode
//! and the GIC's per-core view, then drops to non-secure EL2. There the
//! primary core goes on to decompress the payload with `x0` = the device tree
//! the VPU firmware wrote at `0xf8`; the others wait on the spin table the
//! device tree points at (`cpu-release-addr = <0 0xd8>` ... `<0 0xf0>`), and
//! on the mailboxes the ACPI tables point at (the parking protocol).

use core::arch::global_asm;

global_asm!(
    r#"
.section .text.entry, "ax"
.global _start

.equ LOCAL_CONTROL, 0xff800000
.equ LOCAL_PRESCALER, 0x8
.equ GICD, 0xff841000
.equ GICC_OFFSET, 0x1000
.equ GICD_CTLR, 0x0
.equ GICD_IGROUPR, 0x80
.equ GICD_ISENABLER0, 0x100
.equ GICC_CTLR, 0x0
.equ GICC_PMR, 0x4
.equ GICC_IAR, 0xc
.equ GICC_EOIR, 0x10
// Physical IRQs routed to EL2.
.equ HCR_EL2_IMO, 0x10
// Eight group registers: 256 interrupts.
.equ IGROUPR_BYTES, (8 * 4)

// L2 read and write latency 3.
.equ L2CTLR_LATENCY, 0x22
.equ OSC_HZ, 54000000
// FP and SIMD not trapped.
.equ CPTR_EL3_VAL, 0x33ff
// RW, HCE, SMD, the two RES1 bits and NS: a non-secure AArch64 EL2 with HVC
// and no SMC.
.equ SCR_EL3_VAL, 0x5b1
// Lower levels may use the implementation defined registers (CPUACTLR,
// CPUECTLR, L2CTLR, L2ECTLR, L2ACTLR).
.equ ACTLR_EL3_VAL, 0x73
.equ CPUECTLR_SMPEN, 0x40
// Little-endian, MMU and caches off; the set bits are RES1.
.equ SCTLR_EL2_VAL, 0x30c50830
// EL2h with DAIF masked.
.equ SPSR_EL3_VAL, 0x3c9

_start:
    ldr x0, =LOCAL_CONTROL
    str wzr, [x0]
    mov w1, #0x80000000
    str w1, [x0, #LOCAL_PRESCALER]

    mrs x0, s3_1_c11_c0_2       // L2CTLR_EL1
    mov x1, #L2CTLR_LATENCY
    orr x0, x0, x1
    msr s3_1_c11_c0_2, x0

    ldr x0, =OSC_HZ
    msr cntfrq_el0, x0
    msr cntvoff_el2, xzr

    mov x0, #CPTR_EL3_VAL
    msr cptr_el3, x0
    mov x0, #SCR_EL3_VAL
    msr scr_el3, x0
    mov x0, #ACTLR_EL3_VAL
    msr actlr_el3, x0
    mov x0, #CPUECTLR_SMPEN
    msr s3_1_c15_c2_1, x0       // CPUECTLR_EL1

    bl setup_gic

    ldr x0, =SCTLR_EL2_VAL
    msr sctlr_el2, x0
    mov x0, #SPSR_EL3_VAL
    msr spsr_el3, x0
    adr x0, in_el2
    msr elr_el3, x0
    eret

in_el2:
    mrs x6, mpidr_el1
    and x6, x6, #0x3
    cbz x6, primary
    b secondary

primary:
    ldr w0, dtb_ptr32
    b decompress

    .ltorg

    // The spin table the operating system releases the secondary cores
    // through.
    .org 0xd8
spin_table:
    .quad 0, 0, 0
    // The last core's entry.
    .org 0xf0
    .quad 0

    // Written by the VPU firmware: where the device tree is.
    .org 0xf8
dtb_ptr32:
    .word 0
    // Written by the UEFI firmware, read by the VPU firmware: the boot
    // watchdog requests (`uefi/src/main.rs`).
watchdog_word:
    .word 0

    .org 0x100
// Every core: all interrupts in group 1, the software interrupts enabled, the
// CPU interface enabled and nothing masked by priority. The group and enable
// registers of the private interrupts and the CPU interface are banked per
// core. Only the secondary cores write the distributor's control word.
setup_gic:
    mrs x0, mpidr_el1
    ldr x2, =GICD
    tst x0, #0x3
    b.eq 1f
    mov w0, #3
    str w0, [x2, #GICD_CTLR]
1:  mov w0, #0xffff
    str w0, [x2, #GICD_ISENABLER0]
    add x1, x2, #GICC_OFFSET
    mov w0, #0x1e7
    str w0, [x1, #GICC_CTLR]
    mov w0, #0xff
    str w0, [x1, #GICC_PMR]
    add x2, x2, #GICD_IGROUPR
    mov x0, #IGROUPR_BYTES
    mov w1, #~0
2:  subs x0, x0, #4
    str w1, [x2, x0]
    b.ne 2b
    ret

    .ltorg

    // A core that is not the primary waits here for the operating system to
    // start it, through the spin table of the device tree or the mailbox of
    // the ACPI tables (the parking protocol), which wakes it with a software
    // interrupt. A core in `wfe` wakes for an interrupt it takes, so this one
    // is routed to EL2 and unmasked while the core waits, and its vector (the
    // current level's, at 0x280) sends the core back to look.
    .org 0x200
    b .

    .org 0x280
irq:
    ldr x16, =GICD
    add x16, x16, #GICC_OFFSET
    ldr w17, [x16, #GICC_IAR]
    and w15, w17, #0x3ff
    cmp w15, #1020
    b.hs 1f
    str w17, [x16, #GICC_EOIR]
1:  adr x16, poll
    msr elr_el2, x16
    eret

    .ltorg

    .org 0x300
secondary:
    adr x5, spin_table
    mov x0, #HCR_EL2_IMO
    msr hcr_el2, x0
    msr vbar_el2, xzr
    isb
poll:
    msr daifset, #2
    ldr x4, [x5, x6, lsl #3]
    cbnz x4, enter
    adr x8, parking_mailboxes
    add x8, x8, x6, lsl #4
    ldr w9, [x8]
    cmp w9, w6
    b.ne wait
    ldr x4, [x8, #8]
    cbz x4, wait
    str xzr, [x8, #8]
    mov w9, #-1
    str w9, [x8]
    dsb sy
enter:
    msr hcr_el2, xzr
    isb
    mov x0, #0
    mov x1, #0
    mov x2, #0
    mov x3, #0
    br x4
wait:
    msr daifclr, #2
    wfe
    b poll

    .ltorg

    // One mailbox for each core: the number the operating system writes
    // (all ones until it does), then the entry point.
    .org 0x800
parking_mailboxes:
    .rept 4
    .word 0xffffffff, 0
    .quad 0
    .endr
"#
);

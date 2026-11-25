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
//! device tree points at (`cpu-release-addr = <0 0xd8>` ... `<0 0xf0>`), on
//! the mailboxes of the ACPI parking protocol, and on a PSCI `CPU_ON`.
//!
//! EL3 stays as the PSCI implementation the ACPI tables name: an SMC from the
//! operating system comes back here for the version, the cores' power state,
//! reset and power off.

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
// RW, HCE, the two RES1 bits and NS: a non-secure AArch64 EL2 with HVC, and
// SMC for the PSCI calls.
.equ SCR_EL3_VAL, 0x531
.equ PM, 0xfe100000
.equ PM_RSTC, 0x1c
.equ PM_RSTS, 0x20
.equ PM_WDOG, 0x24
.equ PM_PASSWORD, 0x5a000000
.equ PM_RSTS_HALT, 0x555
.equ PSCI_BASE, 0x84000000
// PSCI_VERSION, CPU_OFF, CPU_ON, AFFINITY_INFO, MIGRATE_INFO_TYPE, SYSTEM_OFF,
// SYSTEM_RESET and PSCI_FEATURES, by function number.
.equ PSCI_FUNCTIONS, 0x75d
.equ PSCI_ON, 0
.equ PSCI_OFF, 1
.equ PSCI_ON_PENDING, 2
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
1:  mov x1, #0x800
    msr vbar_el3, x1
    and x0, x0, #0x3
    adr x1, psci_stacks
    add x1, x1, x0, lsl #5
    add sp, x1, #32
    mov w0, #0xffff
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
    adr x8, psci_entries
    add x8, x8, x6, lsl #4
    ldr x4, [x8]
    cbz x4, 1f
    ldr x0, [x8, #8]
    str xzr, [x8]
    adr x8, psci_states
    str wzr, [x8, x6, lsl #2]
    msr hcr_el2, xzr
    isb
    mov x1, #0
    mov x2, #0
    mov x3, #0
    br x4
1:
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

    // PSCI, for an operating system that starts the cores with it: each
    // core's state, the entry point and context a CPU_ON left for it, and
    // its stack in EL3. The mailboxes and these are where EL3's own vectors
    // would be, which nothing here takes.
psci_states:
    .word PSCI_ON, PSCI_OFF, PSCI_OFF, PSCI_OFF
psci_entries:
    .rept 4
    .quad 0, 0
    .endr
psci_stacks:
    .rept 4
    .quad 0, 0, 0, 0
    .endr

    // EL3's vector for a call from a lower level: the SMC of a PSCI call,
    // with the function in w0. A 64-bit function is taken as its 32-bit one.
    .org 0xc00
smc:
    stp x9, x10, [sp, #-16]!
    and w9, w0, #0xbfffffff
    mov w10, #PSCI_BASE
    sub w9, w9, w10
    cbz w9, psci_version
    cmp w9, #2
    b.eq psci_cpu_off
    cmp w9, #3
    b.eq psci_cpu_on
    cmp w9, #4
    b.eq psci_affinity_info
    cmp w9, #6
    b.eq psci_migrate_info_type
    cmp w9, #8
    b.eq psci_system_off
    cmp w9, #9
    b.eq psci_system_reset
    cmp w9, #10
    b.eq psci_features
psci_not_supported:
    mov x0, #-1
psci_return:
    ldp x9, x10, [sp], #16
    eret
psci_invalid:
    mov x0, #-2
    b psci_return
psci_version:
    mov x0, #0x10000
    b psci_return
psci_migrate_info_type:
    mov x0, #2
    b psci_return
psci_features:
    and w9, w1, #0xbfffffff
    mov w10, #PSCI_BASE
    sub w9, w9, w10
    cmp w9, #10
    b.hi psci_not_supported
    mov w10, #PSCI_FUNCTIONS
    lsr w10, w10, w9
    tbz w10, #0, psci_not_supported
    mov x0, #0
    b psci_return
psci_affinity_info:
    tst x1, #~3
    b.ne psci_invalid
    adr x10, psci_states
    ldr w0, [x10, x1, lsl #2]
    b psci_return
psci_cpu_on:
    tst x1, #~3
    b.ne psci_invalid
    adr x10, psci_states
    ldr w9, [x10, x1, lsl #2]
    cmp w9, #PSCI_OFF
    b.ne 1f
    mov w9, #PSCI_ON_PENDING
    str w9, [x10, x1, lsl #2]
    adr x10, psci_entries
    add x10, x10, x1, lsl #4
    str x3, [x10, #8]
    str x2, [x10]
    dsb sy
    sev
    mov x0, #0
    b psci_return
    // ALREADY_ON, or ON_PENDING.
1:  cmp w9, #PSCI_ON
    mov x0, #-4
    mov x9, #-5
    csel x0, x0, x9, eq
    b psci_return
psci_cpu_off:
    mrs x6, mpidr_el1
    and x6, x6, #0x3
    adr x10, psci_states
    mov w9, #PSCI_OFF
    str w9, [x10, x6, lsl #2]
    add sp, sp, #16
    ldr x9, =SCTLR_EL2_VAL
    msr sctlr_el2, x9
    mov x9, #SPSR_EL3_VAL
    msr spsr_el3, x9
    adr x9, secondary
    msr elr_el3, x9
    eret
    // The dog resets the board within its count, as the runtime services'
    // ResetSystem has it: ten ticks, or a second and the halt mark for a
    // power off. The VPU may reload the dog, and the count is asked for again
    // when it has.
psci_system_off:
    ldr x9, =PM
    ldr w10, [x9, #PM_RSTS]
    and w10, w10, #0xfffff000
    ldr w0, =(PM_PASSWORD | PM_RSTS_HALT)
    orr w10, w10, w0
    str w10, [x9, #PM_RSTS]
    mov w10, #0x10000
    b 1f
psci_system_reset:
    ldr x9, =PM
    mov w10, #10
1:  lsl w1, w10, #2
    ldr w0, =PM_PASSWORD
    orr w10, w10, w0
    str w10, [x9, #PM_WDOG]
    ldr w2, [x9, #PM_RSTC]
    and w2, w2, #0xffffffcf
    orr w2, w2, #0x20
    orr w2, w2, w0
    str w2, [x9, #PM_RSTC]
2:  ldr w2, [x9, #PM_WDOG]
    and w2, w2, #0xfffff
    cmp w2, w1
    b.ls 2b
    str w10, [x9, #PM_WDOG]
    b 2b

    .ltorg
    .org 0x1000
"#
);

/* CrabEFI on the Raspberry Pi 4. The stub in stub/ decompresses it here and
 * enters it with x0 = the device tree. */
OUTPUT_FORMAT("elf64-littleaarch64")
OUTPUT_ARCH(aarch64)
ENTRY(_start)

LOAD_BASE = 0x1000000;

PHDRS {
    code PT_LOAD FLAGS(5);
    rodata PT_LOAD FLAGS(4);
    data PT_LOAD FLAGS(6);
    defer PT_NULL FLAGS(0);
}

SECTIONS {
    . = LOAD_BASE;
    __boot_code_start = .;
    .text : {
        KEEP(*(.text.entry))
        *(.text .text.*)
    } :code
    .vectors : ALIGN(2048) {
        KEEP(*(.vectors))
    } :code
    __boot_code_end = .;

    __boot_data_start = ALIGN(4096);
    .rodata : ALIGN(4096) {
        *(.rodata .rodata.*)
    } :rodata
    .got : ALIGN(8) { *(.got .got.*) } :rodata
    .data : ALIGN(4096) {
        *(.data .data.*)
    } :data
    .bss : ALIGN(4096) {
        _bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(16);
        _bss_end = .;
    } :data
    .stack (NOLOAD) : ALIGN(4096) {
        _stack_bottom = .;
        . += 0x40000;
        _stack_top = .;
    } :data
    .exc_stack (NOLOAD) : ALIGN(4096) {
        _exc_stack_bottom = .;
        . += 0x4000;
        _exc_stack_top = .;
    } :data
    __boot_data_end = ALIGN(4096);
    _end = .;

    /* Outside the boot data range: CrabEFI reserves the live page tables on
     * their own, and a second reservation over them would fail. */
    .page_tables (NOLOAD) : ALIGN(4096) {
        _pt_l0 = .;
        . += 4096;
        _pt_l1 = .;
        . += 4096;
        _pt_l2 = .;
        . += 4096;
    } :data

    /* Runtime variable staging: kept across a warm reset, outside the image. */
    .deferred_buffer (NOLOAD) : ALIGN(4096) {
        _deferred_buffer_start = .;
        . += 128K;
        _deferred_buffer_end = .;
    } :defer

    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) *(.debug*) }
}

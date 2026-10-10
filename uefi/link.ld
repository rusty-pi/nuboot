/* The UEFI firmware. The stub in stub/ decompresses it here and enters it
 * with x0 = the device tree. */
OUTPUT_FORMAT("elf64-littleaarch64")
OUTPUT_ARCH(aarch64)
ENTRY(_start)

LOAD_BASE = 0x1000000;

PHDRS {
    code PT_LOAD FLAGS(5);
    rodata PT_LOAD FLAGS(4);
    data PT_LOAD FLAGS(6);
}

SECTIONS {
    . = LOAD_BASE;
    _image_start = .;
    .text : {
        KEEP(*(.text.entry))
        *(.text .text.*)
    } :code
    .vectors : ALIGN(2048) {
        KEEP(*(.vectors))
    } :code

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
    /* The page tables: L0, L1, and an L2 each for the first gigabyte and the
     * fourth. */
    .page_tables (NOLOAD) : ALIGN(4096) {
        _pt_l0 = .;
        . += 4096;
        _pt_l1 = .;
        . += 4096;
        _pt_l2_low = .;
        . += 4096;
        _pt_l2_high = .;
        . += 4096;
    } :data
    /* EFI applications run on this stack too. */
    .stack (NOLOAD) : ALIGN(4096) {
        _stack_bottom = .;
        . += 0x100000;
        _stack_top = .;
    } :data
    . = ALIGN(4096);
    _end = .;

    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) *(.debug*) }
}

/* The armstub and decompressor, at ARM physical 0, where the cores start. */
OUTPUT_FORMAT("elf64-littleaarch64")
OUTPUT_ARCH(aarch64)
ENTRY(_start)

SECTIONS {
    . = 0;
    .text : {
        KEEP(*(.text.entry))
        KEEP(*(.text.decompress))
        *(.text .text.*)
    }
    .rodata : ALIGN(16) {
        *(.rodata .rodata.*)
    }
    .data : ALIGN(16) {
        *(.data .data.*)
    }
    _image_end = .;
    .bss (NOLOAD) : ALIGN(4096) {
        _bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(16);
        _bss_end = .;
    }
    .page_tables (NOLOAD) : ALIGN(4096) {
        _pt_l0 = .;
        . += 4096;
        _pt_l1 = .;
        . += 4096;
    }
    .stack (NOLOAD) : ALIGN(4096) {
        . += 0x10000;
        _stack_top = .;
    }
    _end = .;

    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) *(.debug*) }
}

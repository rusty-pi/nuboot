/* bootcode: the boot ROM stages it into L2-as-SRAM at 0x80000000 and enters
   it at +0x200; the first 0x200 bytes are the (zeroed) image header. SDRAM is
   not up yet, so the buffers for the SDRAM firmware, the stack and bss stay
   in the same 128 KiB. */

ENTRY(_start)
EXTERN(_start)

MEMORY
{
  sram (rwx) : ORIGIN = 0x80000000, LENGTH = 128K
}

SECTIONS
{
  .header : {
    LONG(0)
    . = 0x200;
  } > sram

  .text : {
    KEEP(*(.text.start))
    *(.text .text.*)
  } > sram

  .rodata : ALIGN(4) {
    *(.rodata .rodata.*)
  } > sram

  .data : ALIGN(4) {
    __data_start = .;
    *(.data .data.*)
    . = ALIGN(4);
    __data_end = .;
  } > sram
  __data_load = LOADADDR(.data);

  .bss (NOLOAD) : ALIGN(4) {
    __bss_start = .;
    *(.bss .bss.* COMMON)
    . = ALIGN(4);
    __bss_end = .;
  } > sram

  /* One memsysNN.bin at a time, below the MCB. */
  .memsys (NOLOAD) : ALIGN(32) {
    *(.memsys)
  } > sram

  /* mcb.bin goes where the stock bootcode keeps it. */
  .mcb 0x80015ff0 (NOLOAD) : {
    *(.mcb)
  } > sram

  __stack_bottom = ALIGN(ADDR(.mcb) + SIZEOF(.mcb), 32);
  __stack_top = ORIGIN(sram) + LENGTH(sram);

  ASSERT(ADDR(.memsys) + SIZEOF(.memsys) <= ADDR(.mcb), "bootcode runs into the MCB buffer")
  ASSERT(__stack_bottom + 16K <= __stack_top, "bootcode leaves under 16 KiB of stack in L2")

  /DISCARD/ : {
    *(.comment .note.* .eh_frame .eh_frame_hdr)
  }
}

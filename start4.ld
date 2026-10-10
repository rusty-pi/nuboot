/* The VPU image the EEPROM bootloader loads from the boot medium as
   `start4.elf`, linked in the cached alias (0x3ec00200) of the DRAM the stock
   image takes on a 1 GiB VPU top. The uncached alias costs ~116 ns per load
   against ~10 ns for this one.

   The bootloader flushes every cache before it enters the image, so what it
   loaded is in memory. */

ENTRY(_start)
EXTERN(_start)

MEMORY
{
  sdram (rwx) : ORIGIN = 0x3ec00200, LENGTH = 16M - 0x200
}

SECTIONS
{
  .text : {
    KEEP(*(.text.start))
    *(.text .text.*)
  } > sdram

  .rodata : ALIGN(4) {
    *(.rodata .rodata.*)
    KEEP(*(.build_id))
  } > sdram

  /* The EEPROM bootloader looks these two up by name, as in the stock
     start4.elf: without them it refuses the image ("not compatible"). */
  .text.bootloader_state : ALIGN(16) {
    KEEP(*(.bootloader_state))
  } > sdram
  .text.firmware_rev : ALIGN(16) {
    KEEP(*(.firmware_rev))
  } > sdram

  .data : ALIGN(4) {
    __data_start = .;
    *(.data .data.*)
    . = ALIGN(4);
    __data_end = .;
  } > sdram
  __data_load = LOADADDR(.data);

  .bss (NOLOAD) : ALIGN(4) {
    __bss_start = .;
    *(.bss .bss.* COMMON)
    . = ALIGN(4);
    __bss_end = .;
  } > sdram

  . = ALIGN(16);
  __stack_bottom = .;
  . += 64K;
  __stack_top = .;

  /DISCARD/ : {
    *(.comment .note.* .eh_frame .eh_frame_hdr)
  }
}

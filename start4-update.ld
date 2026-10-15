/* The same firmware linked for the update slot, 2 MiB above the image the
   bootloader loads (start4.ld), which stays where it is: the firmware the
   bootloader started copies a signed bundle of this image here and enters it
   (src/update.rs). It is a flat binary, not loaded by the bootloader. */

ENTRY(_start)
EXTERN(_start)

MEMORY
{
  sdram (rwx) : ORIGIN = 0x3ee00200, LENGTH = 14M - 0x200
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

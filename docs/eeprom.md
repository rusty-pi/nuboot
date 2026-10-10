# EEPROM image

`out/pieeprom.bin` is the whole firmware: the 512 KiB the board's SPI EEPROM
holds, with no stock bootloader and no stock `start4.elf` in it. The boot
medium carries only the operating system.

## Layout

The image is a chain of sections, each a big-endian `magic, length` header
on an 8-byte boundary, as the boot ROM and the stock tools expect.

| section | from | size |
|---|---|---|
| bootcode (`0x55aaf00f`) | `src/bin/bootcode.rs` | 42 KB |
| `memsys00.bin` .. `memsys08.bin`, `mcb.bin` (`0x55aaf44f`) | the stock image, unchanged | 102 KB |
| `start4.elf` (`0x55aaf11f`) | `src/bin/start4.rs`, with `pi4-uefi.bin` and the device tree in it | 235 KB |
| free | | 145 KB |

`memsys00.bin` to `memsys08.bin` are the nine passes of the LPDDR4 training
firmware and `mcb.bin` the table of SDRAM parts and their timings. They are
Raspberry Pi's, and `scripts/build.sh` takes them out of the stock
`pieeprom-2026-08-04.bin` it downloads (pinned by URL and SHA-256);
`scripts/mkeeprom.py` puts the image together.

`start4.elf` is stored with its section headers and debug information taken
off.

## Boot

1. The boot ROM loads the bootcode section into the L2 at `0x8000_0000`,
   which serves as SRAM, and enters it at `+0x200`.
2. The bootcode programs the PL011 and logs the board, starts PLLs and the
   peripheral clocks, raises the SPI flash's clock, and brings up the SDRAM
   with the training firmware, one pass at a time in the same 128 KiB.
3. It reads `start4.elf` out of the EEPROM into SDRAM, copies its loadable
   segment to where it is linked (`0x3EC0_0000`, through the uncached alias),
   leaves the handover block at `0xC004_0000` (the version, the SDRAM size and
   the boot medium `eeprom`), and enters it through the cache flush stub.
4. `start4.elf` starts the ARM in UEFI ([uefi.md](uefi.md)).

## Running it in pimu

```bash
pimu boot --scenario scenarios/uefi-hello.yaml   # an EFI application
pimu boot --scenario scenarios/uefi-grub.yaml    # Ubuntu's signed GRUB
pimu boot --eeprom out/pieeprom.bin --sd boot/   # a directory as the SD card
```

## Known limitations

- The bootcode's HMAC is left zero, so a board's boot ROM refuses the image:
  it runs in pimu only.
- No GPIO expander or PMIC set-up: the SD card is not power-cycled and the
  activity and power LEDs stay as they come up. A Pi 4B rev 1.4, whose
  bootloader programs its PMIC, is not supported.
- No VL805 firmware and no PCIe, so no USB.
- No boot watchdog is armed.
- `SDRAM_BANKLOW` is the stock default, 3.
- Nothing sets the ARM's clock.
- `start4.elf` is stored uncompressed and without a checksum.

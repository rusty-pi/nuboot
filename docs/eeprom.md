# EEPROM image

`out/pieeprom.bin` is the whole firmware: the 512 KiB the board's SPI EEPROM
holds, with no stock bootloader and no stock `start4.elf` in it. The boot
medium carries only the operating system.

## Layout

The image is a chain of sections, each a big-endian `magic, length` header
on an 8-byte boundary, as the boot ROM and the stock tools expect.

| section | from | size |
|---|---|---|
| bootcode (`0x55aaf00f`) | `src/bin/bootcode.rs` | 45 KB |
| `memsys00.bin` .. `memsys08.bin`, `mcb.bin` (`0x55aaf44f`) | the stock image, unchanged | 103 KB |
| `vl805hub.bin`, `vl805mcu.bin` (`0x55aaf33f`) | the stock image, unchanged | 67 KB |
| `start4.elf` (`0x55aaf11f`) | `src/bin/start4.rs`, with `pi4-uefi.bin` and the device tree in it | 156 KB |
| free | | 153 KB |

`memsys00.bin` to `memsys08.bin` are the nine passes of the LPDDR4 training
firmware and `mcb.bin` the table of SDRAM parts and their timings.
`vl805hub.bin` and `vl805mcu.bin` are the VL805 USB controller's firmware, which
every board but a 4B before rev 1.4 has to be given by the host. They are all
Raspberry Pi's, and `scripts/build.sh` takes them out of the stock
`pieeprom-2026-08-04.bin` it downloads (pinned by URL and SHA-256);
`scripts/mkeeprom.py` puts the image together.

`start4.elf` is stored with its section headers and debug information taken
off.

## Boot

1. The boot ROM loads the bootcode section into the L2 at `0x8000_0000`,
   which serves as SRAM, and enters it at `+0x200`.
2. The bootcode programs the PL011, logs the board, arms the boot watchdog
   ([Boot watchdog](#boot-watchdog)), turns the SD card's
   power off through the GPIO expander, sets up the 0x1D PMIC on a board whose
   core rail is on a second PMIC (a 4B rev 1.4, a Pi 400, a CM4), starts PLLs
   and the peripheral clocks, raises the SPI flash's clock, and brings up the
   SDRAM with the training firmware, one pass at a time in the same 128 KiB.
   Then it powers the card again at 3.3 V signalling.
3. It reads `start4.elf` out of the EEPROM into SDRAM, copies its loadable
   segment to where it is linked (`0x3EC0_0000`, through the uncached alias),
   leaves the handover block at `0xC004_0000` (the version, the SDRAM size and
   the boot medium `eeprom`), and enters it through the cache flush stub.
4. `start4.elf` brings up the PCIe link, gives the VL805 its firmware on a
   board that needs it, and puts the controller's registers in the outbound
   window at `0x6_0200_0000`.
5. It starts the ARM in UEFI ([uefi.md](uefi.md)).

## Boot watchdog

Every boot runs under the board's watchdog, with no setting to turn it off,
until the operating system's own driver for it (Linux's `bcm2835_wdt`) takes
it over. A hang anywhere before that resets the board.

| from | until | span |
|---|---|---|
| the first stage's start | the ARM is started | 30 s |
| the ARM is started | `ExitBootServices` | 300 s; a `SetWatchdogTimer` call starts a new span of the seconds it asks for, or of 300 s when it asks for none |
| `ExitBootServices` | the operating system's driver beats the dog | 120 s |

The dog itself counts at most 16 s, so `start4.elf` reloads it once a second
from its monitor thread while a span lasts. When the span is over it stops,
and the board resets up to 16 s later unless the operating system is beating
the dog by then. UEFI tells `start4.elf` about `SetWatchdogTimer` and
`ExitBootServices` through the word at ARM physical `0xfc`, in the
armstub's page.

## Running it in pimu

```bash
pimu boot --scenario scenarios/uefi-hello.yaml   # a signed EFI application
pimu boot --scenario scenarios/shim-grub.yaml    # Ubuntu's signed shim and GRUB
pimu boot --scenario scenarios/secure-boot-refused.yaml  # an image not signed by a key in db
pimu boot --scenario scenarios/rev14-hello.yaml  # an EFI application on a 4B rev 1.4
pimu boot --scenario scenarios/usb-hello.yaml    # an EFI application off a USB drive
pimu boot --scenario scenarios/xhci-reset.yaml   # NOTIFY_XHCI_RESET over the property mailbox
pimu boot --scenario scenarios/watchdog-hang.yaml  # a hang in UEFI resets the board
pimu boot --scenario scenarios/watchdog-exit.yaml  # ExitBootServices hands the dog to the OS
pimu boot --eeprom out/pieeprom.bin --sd boot/   # a directory as the SD card
```

The scenarios that run the test applications boot `out/pieeprom-test.bin`
(`scripts/build.sh --test-keys`), whose UEFI firmware also trusts the key
they are signed with ([uefi.md](uefi.md#secure-boot)).

## Known limitations

- The bootcode's HMAC is left zero, so a board's boot ROM refuses the image:
  it runs in pimu only.
- The property mailbox answers `NOTIFY_XHCI_RESET` (reload the VL805's
  firmware after the OS has reset the PCIe link) and no other tag.
- `SDRAM_BANKLOW` is the stock default, 3.
- Nothing sets the ARM's clock.
- `start4.elf` is stored uncompressed and without a checksum.

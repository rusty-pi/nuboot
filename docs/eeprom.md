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
| `start4.elf` (`0x55aaf44f`) | `src/bin/start4.rs`, with `pi4-uefi.bin` and the device tree in it, as an LZ4 frame | 188 KB |
| free | | 55 KB |
| variable store | the UEFI variable log, two banks of 32 KiB from `0x70000` ([uefi.md](uefi.md#the-variable-store)) | 64 KiB |

`memsys00.bin` to `memsys08.bin` are the nine passes of the LPDDR4 training
firmware and `mcb.bin` the table of SDRAM parts and their timings.
`vl805hub.bin` and `vl805mcu.bin` are the VL805 USB controller's firmware, which
every board but a 4B before rev 1.4 has to be given by the host. They are all
Raspberry Pi's, and `scripts/build.sh` takes them out of the stock
`pieeprom-2026-08-04.bin` it downloads (pinned by URL and SHA-256);
`scripts/mkeeprom.py` puts the image together.

`start4.elf` is stored with its section headers and debug information taken
off, packed as an LZ4 frame with the SHA-256 of what it unpacks to after it, as
the stock image packs its own sections; the bootcode checks the digest before it
runs it.

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
| the first stage's start | the ARM is started | 30 s, beaten by the VPU |
| the ARM is started | `ExitBootServices` | 300 s, beaten by UEFI; a `SetWatchdogTimer` call starts a new span of the seconds it asks for, or of 300 s when it asks for none |
| `ExitBootServices` | the operating system's driver beats the dog | 120 s, beaten by the VPU |

The dog itself counts at most 16 s. When the ARM starts, `start4.elf` gives the
dog to it with a full reload, and UEFI reloads it from then on from the
hypervisor timer's interrupt every half second, while the span lasts. An
ARM that has stopped (a fault, a hang with interrupts masked, a core that never
ran) stops beating, and the board resets up to 16 s later whatever span was
asked for; one that is running but never returns from a payload is reset when
the span ends. At `ExitBootServices` UEFI stops the interrupt and tells
`start4.elf`, through the word at ARM physical `0xfc` in the armstub's page,
which takes the dog back and beats it for 120 s, the time a kernel has to load
`bcm2835_wdt`, a module in most distributions' kernels, and have it find the
dog running. The VPU stops reloading as soon as the dog has less than 8 s left
at a reload, which is the operating system having armed it with a timeout of its
own.

The timer is the EL2 hypervisor timer (`CNTHP`, GIC interrupt 26), routed to EL2
until `ExitBootServices`: a payload that uses either takes the beat from UEFI.
A reset with a short count (Linux's `reboot`) within the 120 s after
`ExitBootServices` is delayed if one of the VPU's reloads lands in the 160 µs
before it fires, which is rare.

## Running it in pimu

```bash
pimu boot --scenario scenarios/uefi-hello.yaml   # a signed EFI application
pimu boot --scenario scenarios/shim-grub.yaml    # Ubuntu's signed shim and GRUB
pimu boot --scenario scenarios/secure-boot-refused.yaml  # an image not signed by a key in db
pimu boot --scenario scenarios/rev14-hello.yaml  # an EFI application on a 4B rev 1.4
pimu boot --scenario scenarios/usb-hello.yaml    # an EFI application off a USB drive
pimu boot --scenario scenarios/xhci-reset.yaml   # NOTIFY_XHCI_RESET over the property mailbox
pimu boot --scenario scenarios/boot-key.yaml     # the boot key bound to PCR 4, once
pimu boot --scenario scenarios/boot-key-unbound.yaml    # bound to PCR 7
pimu boot --scenario scenarios/tpm2-commands.yaml  # TPM 2.0 commands on the VPU
pimu boot --scenario scenarios/watchdog-hang.yaml  # a hang in UEFI resets the board
pimu boot --scenario scenarios/watchdog-exit.yaml  # ExitBootServices hands the dog to the OS
pimu boot --eeprom out/pieeprom.bin --sd boot/   # a directory as the SD card
```

The scenarios that run the test applications boot `out/pieeprom-test.bin`
(`scripts/build.sh --test-keys`), whose UEFI firmware also trusts the key
they are signed with ([uefi.md](uefi.md#secure-boot)).

## Updating from the OS

A flash layout with the image's two regions writes the firmware and leaves the
variable store as it is:

```bash
printf '000000:06ffff firmware\n070000:07ffff store\n' > layout.txt
flashrom -p linux_spi:dev=/dev/spidev0.0,spispeed=16000 -l layout.txt -i firmware -w pieeprom.bin
```

A whole-image write clears the store.

## Known limitations

- A board whose secure boot is programmed (OTP boot mode row `0x0000C8B0`:
  bit 14 set and the development key revoked) accepts only a bootcode with an
  RSA signature from a key in its boot ROM, which only Raspberry Pi holds.
  This image carries an HMAC instead, so such a board does not boot it. The
  check is the boot ROM's code run in pimu with those fuses; no board with
  secure boot programmed has run it.
- The bootcode's HMAC is left zero, so a board's boot ROM refuses the image:
  it runs in pimu only.
- The property mailbox answers `NOTIFY_XHCI_RESET` (reload the VL805's
  firmware after the OS has reset the PCIe link), the TPM 2.0 on the VPU (tag
  `0x000300a3` carries a command, `0x000300a1` extends a PCR) and the
  one-time boot key (tag `0x000300a0`) and variable store key (`0x000300a5`),
  and no other tag. None returns a fuse.
- `SDRAM_BANKLOW` is the stock default, 3.
- Nothing sets the ARM's clock.

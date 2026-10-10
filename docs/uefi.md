# UEFI

The operating system is started through UEFI. The implementation is
[CrabEFI](https://github.com/ArthurHeymans/CrabEFI), a UEFI in Rust, built as
an AArch64 payload in `uefi/` with a Raspberry Pi 4 platform layer around it.
`start4.elf` carries `pi4-uefi.bin` and the board's device tree, and starts
the ARM in them:

1. It puts `pi4-uefi.bin` at ARM physical 0, where the cores come out of
   reset, and the device tree at `0xF0_0000` with `/memory@0` filled in from
   the board's SDRAM. The ARM gets everything below `0x3EC0_0000`, where the
   VPU firmware's own memory starts, and all the memory above 1 GiB.
2. `pi4-uefi.bin` (`uefi/stub/`) starts with an armstub: each core sets up
   the local timer, the generic timer, the GIC and EL3's controls, and drops
   to non-secure EL2. The secondary cores wait on the spin table at `0xd8`
   that the device tree names.
3. The primary core decompresses the payload, coded with xz's ARM64 filter
   and LZMA, to `0x100_0000` and enters it with `x0` holding the device tree.

## What the platform layer provides

| | |
|---|---|
| Entry | An identity map (RAM normal write-back, `0xFC00_0000..0x1_0000_0000` and everything above 8 GiB device), stack, BSS |
| Memory map | `/memory` from the device tree, less `/memreserve/`, `/reserved-memory`, the spin-table page at 0 and the tree itself |
| Console | PL011 at `0xFE20_1000` |
| Storage | The SD card on EMMC2 (`0xFE34_0000`), through CrabEFI's MMIO SDHCI driver |
| USB | The VL805's xHCI, through CrabEFI's driver: drives and keyboards, on the root ports and behind a hub. The PCIe root complex's configuration space and outbound window are the platform's (`patches/crabefi/0004-*`); `start4.elf` has already brought the link up and given the VL805 its firmware |
| `EFI_RNG_PROTOCOL` | RNG200's FIFO |
| `ResetSystem` | The power manager's watchdog (`PM_RSTC`/`PM_WDOG`), halt through `PM_RSTS` |
| `SetWatchdogTimer`, `ExitBootServices` | Handed to `start4.elf`, which has the boot watchdog ([eeprom.md](eeprom.md#boot-watchdog); `patches/crabefi/0003-*`) |
| Device tree | Passed on to the OS as the `EFI_DTB_TABLE` configuration table |

The boot manager looks for `\EFI\BOOT\BOOTAA64.EFI` on any FAT partition of
the card and of any USB drive, so a distribution image with an ESP boots
through shim and GRUB.

Left out of the build: CrabEFI's AHCI, NVMe and EHCI/OHCI drivers, booting a
kernel straight from a BLS or `grub.cfg` entry, El Torito, and log records
below warnings (`patches/crabefi/0002-*` adds the features that drop them).

## Building

```bash
scripts/build-uefi.sh                         # out/pi4-uefi.bin, and the bare payload as out/pi4-uefi-payload.bin
scripts/build-uefi.sh --features secure-boot  # with image verification and authenticated variables
scripts/build-uefi.sh --test-apps             # also out/hello.efi and out/grubaa64.efi
```

`scripts/fetch-crabefi.sh` (run by `build-uefi.sh`) checks CrabEFI out into
`third_party/crabefi` at the revision it pins and applies `patches/crabefi/`.
`uefi/rust-toolchain.toml` pins the nightly CrabEFI needs. The build also needs
`xz`.

## Size

`pi4-uefi.bin` goes into the EEPROM inside `start4.elf`
([eeprom.md](eeprom.md)). The EEPROM is 512 KiB, of which the first stage and
the SDRAM training firmware take about 148 KB, the VL805's firmware 67 KB,
`start4.elf` with the default build and the device tree 287 KB, and 22 KB is
free.

| build | payload | `pi4-uefi.bin` |
|---|---|---|
| default | 609 KB | 186 KB |
| `--features secure-boot` | 708 KB | 233 KB |

## Running it in pimu

`out/pieeprom.bin` carries the default build. After `scripts/build-uefi.sh
--test-apps` and `scripts/build.sh`:

```bash
pimu boot --scenario scenarios/uefi-hello.yaml   # an EFI application
pimu boot --scenario scenarios/uefi-grub.yaml    # Ubuntu's signed GRUB reads its grub.cfg
pimu boot --scenario scenarios/usb-hello.yaml    # an EFI application off a USB drive
```

## Known limitations

- `pi4-uefi.bin` is linked at 0 and the payload at `0x100_0000`; neither is
  relocatable.
- The device tree is Raspberry Pi's for the Pi 4B whatever the board, with
  nothing filled in but `/memory@0`.
- Nothing sets the ARM's clock.
- After `ExitBootServices` the runtime `ResetSystem` is declared as PSCI over
  SMC, which nothing on this board answers; Linux resets through
  `bcm2835-wdt`.
- UEFI variables are volatile: no variable store is wired up.
- Secure Boot builds, but no keys are enrolled, so nothing is enforced.
- No NVMe and no network boot.
- CrabEFI gives each empty xHCI root port 400 ms to show a connection, since
  a SuperSpeed port reads empty until its link has trained
  (`patches/crabefi/0005-*`).
- Only warnings and errors are logged.
- CrabEFI's boot menu counts down 5 seconds before it boots; the scenarios
  press Enter at the prompt.
- `patches/crabefi/0001-*` lets the platform supply the RNG. Without it
  CrabEFI probes for an SMCCC TRNG with `smc`, an undefined instruction on
  this board, where nothing stays at EL3 and the armstub sets
  `SCR_EL3.SMD`.

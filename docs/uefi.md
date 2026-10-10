# UEFI

The operating system is started through UEFI. The implementation is
[CrabEFI](https://github.com/ArthurHeymans/CrabEFI), a UEFI in Rust, built as
an AArch64 payload in `uefi/` with a Raspberry Pi 4 platform layer around it.
The VPU firmware releases the ARM cores into `pi4-uefi.bin` at `0x200000`, at
EL2 with `x0` holding the device tree. That image is a stub (`uefi/stub/`)
with the payload inside it, coded with xz's ARM64 filter and LZMA; the stub
decompresses the payload to `0x1000000` and enters it the same way.

Until the VPU firmware in this tree starts a payload itself, the stock
`start4.elf` starts it, named as the kernel in `config.txt`; the scenarios in
`uefi/scenarios/` boot it that way.

## What the platform layer provides

| | |
|---|---|
| Entry | An identity map (RAM normal write-back, `0xFC00_0000..0x1_0000_0000` and everything above 8 GiB device), stack, BSS |
| Memory map | `/memory` from the device tree, less `/memreserve/`, `/reserved-memory`, the spin-table page at 0 and the tree itself |
| Console | PL011 at `0xFE20_1000` |
| Storage | The SD card on EMMC2 (`0xFE34_0000`), through CrabEFI's MMIO SDHCI driver |
| `EFI_RNG_PROTOCOL` | RNG200's FIFO |
| `ResetSystem` | The power manager's watchdog (`PM_RSTC`/`PM_WDOG`), halt through `PM_RSTS` |
| Device tree | Passed on to the OS as the `EFI_DTB_TABLE` configuration table |

The boot manager looks for `\EFI\BOOT\BOOTAA64.EFI` on any FAT partition of
the card, so a distribution image with an ESP boots through shim and GRUB.

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

`pi4-uefi.bin` is what goes into the EEPROM, next to this tree's VPU firmware
in place of the stock bootloader and `start4.elf`. The EEPROM is 512 KiB. Of
that, about 235 KB goes to what the image carries besides the firmware: the
first-stage bootcode (about 62 KB), the DRAM set-up blobs (102 KB as the stock
image compresses them) and the VL805 firmware (68 KB). That leaves about
290 KB for the VPU firmware and `pi4-uefi.bin` together.

| build | payload | `pi4-uefi.bin` |
|---|---|---|
| default | 536 KB | 154 KB |
| `--features secure-boot` | 639 KB | 202 KB |
| `--features secure-boot,xhci` | 708 KB | 232 KB |

## Running it in pimu

```bash
scripts/build-uefi.sh --test-apps
pimu boot --scenario uefi/scenarios/hello.yaml   # an EFI application
pimu boot --scenario uefi/scenarios/grub.yaml    # Ubuntu's signed GRUB reads its grub.cfg
```

## Known limitations

- The stub is linked at `0x200000`, with an arm64 `Image` header so the
  loader places it there, and the payload at `0x1000000`; neither is
  relocatable.
- After `ExitBootServices` the runtime `ResetSystem` is declared as PSCI over
  SMC, which nothing on this board answers; Linux resets through
  `bcm2835-wdt`.
- UEFI variables are volatile: no variable store is wired up.
- Secure Boot builds, but no keys are enrolled, so nothing is enforced.
- No PCIe, so no USB (the VL805), no NVMe and no network boot.
- Only warnings and errors are logged.
- CrabEFI's boot menu counts down 5 seconds before it boots; the scenarios
  press Enter at the prompt.
- `patches/crabefi/0001-*` lets the platform supply the RNG. Without it
  CrabEFI probes for an SMCCC TRNG with `smc`, an undefined instruction on
  this board, where nothing runs at EL3 and `SCR_EL3.SMD` is set.

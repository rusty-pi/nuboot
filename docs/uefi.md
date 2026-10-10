# UEFI

The operating system is started through UEFI. The implementation is
[CrabEFI](https://github.com/ArthurHeymans/CrabEFI), a UEFI in Rust, built as
an AArch64 payload in `uefi/` with a Raspberry Pi 4 platform layer around it.
The VPU firmware releases the ARM cores into it at EL2 with `x0` holding the
device tree.

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

## Building

```bash
scripts/build-uefi.sh                         # out/pi4-uefi.bin
scripts/build-uefi.sh --features secure-boot  # with image verification and authenticated variables
scripts/build-uefi.sh --test-apps             # also out/hello.efi and out/grubaa64.efi
```

`scripts/fetch-crabefi.sh` (run by `build-uefi.sh`) checks CrabEFI out into
`third_party/crabefi` at the revision it pins and applies `patches/crabefi/`.
`uefi/rust-toolchain.toml` pins the nightly CrabEFI needs.

## Size

`pi4-uefi.bin` as a flat image:

| build | raw | gzip -9 | xz -9e |
|---|---|---|---|
| default | 794 KB | 342 KB | 272 KB |
| `--features secure-boot` | 921 KB | 419 KB | 332 KB |

## Running it in pimu

```bash
scripts/build-uefi.sh --test-apps
pimu boot --scenario uefi/scenarios/hello.yaml   # an EFI application
pimu boot --scenario uefi/scenarios/grub.yaml    # Ubuntu's signed GRUB reads its grub.cfg
```

## Known limitations

- The payload is linked at `0x200000` and carries an arm64 `Image` header
  so the loader places it there; it is not relocatable.
- After `ExitBootServices` the runtime `ResetSystem` is declared as PSCI over
  SMC, which nothing on this board answers; Linux resets through
  `bcm2835-wdt`.
- UEFI variables are volatile: no variable store is wired up.
- Secure Boot builds, but no keys are enrolled, so nothing is enforced.
- No USB (the VL805 behind PCIe) and no network boot.
- CrabEFI's boot menu counts down 5 seconds before it boots; the scenarios
  press Enter at the prompt.
- `patches/crabefi/0001-*` lets the platform supply the RNG. Without it
  CrabEFI probes for an SMCCC TRNG with `smc`, an undefined instruction on
  this board, where nothing runs at EL3 and `SCR_EL3.SMD` is set.

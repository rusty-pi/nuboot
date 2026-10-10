# UEFI

The operating system is started through UEFI. `uefi/` is a UEFI firmware of
its own, written in Rust for this board and nothing else: the boot services
and the protocols a distribution's shim, GRUB and Linux's EFI stub use, with
Secure Boot always on. `start4.elf` carries it, as `pi4-uefi.bin`, and the
board's device tree, and starts the ARM in them:

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
4. The payload sets up an identity map, builds the memory map from the
   device tree, finds the SD card and any USB drive, and boots
   `\EFI\BOOT\BOOTAA64.EFI` off the first FAT partition that has one.

The UEFI firmware logs through `src/log.rs` like the rest of the firmware,
on the same console and the same system-timer clock, so its records carry on
from `start4.elf`'s:

```text
   0.559890 INFO  uefi     UEFI firmware started  commit=1a2b3c4 tree=0xf00000
   0.567376 INFO  mem      memory map ready  ram_mib=8108 free_mib=8104 regions=10
   0.574586 INFO  secboot  Secure Boot enforced  db=2 dbx=26
   0.961838 INFO  sd       card ready  mib=258 kind=SDHC/SDXC
   0.961845 INFO  disk     disk found  name=sd mib=258 partitions=1 path=VenHw/SD(0)
   1.661885 INFO  usb      USB ready  devices=1 registers=0x602000000
   1.685224 INFO  secboot  image verified  signer="Microsoft Windows UEFI Driver Publisher" db="Microsoft Corporation UEFI CA 2011" path=VenHw/SD(0)/HD(1)\EFI\BOOT\BOOTAA64.EFI
   1.698267 INFO  boot     booting  path=VenHw/SD(0)/HD(1)\EFI\BOOT\BOOTAA64.EFI
```

## What it provides

| | |
|---|---|
| Memory | An identity map: RAM below `0xFC00_0000` and from 4 to 8 GiB normal write-back, the 2 MiB at `0x20_0000` non-cacheable for DMA, the rest device. The memory map is `/memory` from the device tree, less `/memreserve/`, `/reserved-memory`, the armstub's page at 0, the tree and the firmware itself |
| Boot services | Memory, pools, events and timers (polled; there are no interrupts), protocol handlers, `LoadImage`/`StartImage`/`Exit` for PE32+ AArch64 images, `ExitBootServices` |
| Runtime services | `GetVariable` and the rest while boot services last. After `ExitBootServices` every runtime service returns `EFI_UNSUPPORTED`, and the `EFI_RT_PROPERTIES_TABLE` says so; Linux resets through `bcm2835-wdt` |
| Console | `SimpleTextOutput` and `SimpleTextInput` on the PL011 at `0xFE20_1000`, with VT100 keys |
| Storage | The SD card on EMMC2 (`0xFE34_0000`), and USB drives (bulk-only mass storage) on the VL805's root ports or behind a hub. `BlockIo`, `DiskIo`, MBR and GPT partitions, and a read-only FAT12/16/32 `SimpleFileSystem` |
| USB | The VL805's xHCI behind the PCIe root complex, which `start4.elf` has brought up and given its firmware |
| `EFI_RNG_PROTOCOL` | RNG200's FIFO, raw |
| `ResetSystem` | The power manager's watchdog (`PM_RSTC`/`PM_WDOG`), halt through `PM_RSTS` |
| `SetWatchdogTimer`, `ExitBootServices` | Handed to `start4.elf`, which has the boot watchdog ([eeprom.md](eeprom.md#boot-watchdog)) |
| Device tree | Passed on to the OS as the `EFI_DTB_TABLE` configuration table |
| Variables | Held in RAM for the boot |

The SD card is tried before USB.

## Secure Boot

Secure Boot is always on. `LoadImage` runs an image only when an
Authenticode signature on it chains to a certificate in `db` and its hash is
not in `dbx`; otherwise it refuses it with `EFI_SECURITY_VIOLATION` and logs
why:

```text
   1.661962 WARN  secboot  image refused  reason="not signed by a key in db" path=VenHw/SD(0)/HD(1)\EFI\BOOT\BOOTAA64.EFI
```

The keys are built in from `uefi/keys/`:

| variable | holds |
|---|---|
| `db` | Microsoft Corporation UEFI CA 2011 and Microsoft UEFI CA 2023, which sign shim for the distributions |
| `dbx` | The AArch64 image hashes in Microsoft's revocation list (`dbx-aarch64.txt`, from [microsoft/secureboot_objects](https://github.com/microsoft/secureboot_objects)) |
| `SecureBoot`, `SetupMode`, `AuditMode`, `DeployedMode` | 1, 0, 0, 1 |

None of them can be written. A distribution boots through its shim, which
checks GRUB and the kernel against its own keys and the MOK list; shim's
SBAT revocations apply as they do on any other machine.

Signatures are checked with SHA-256 and RSA keys up to 4096 bits, as the UEFI
CAs and the distributions' signers use.

### The test build

`scripts/build.sh --test-keys` (the `test-keys` cargo feature) builds
`out/pieeprom-test.bin`, whose UEFI firmware also has a test key in `db`: a
self-signed certificate `scripts/build-uefi.sh` generates in
`out/test-keys/` on first use, which is never committed.
`scripts/build-uefi.sh --test-apps` signs the scenarios' EFI applications
with it. The test build logs a warning at every boot; it is not for a real
board.

## Building

```bash
scripts/build-uefi.sh               # out/pi4-uefi.bin, and the bare payload as out/pi4-uefi-payload.bin
scripts/build-uefi.sh --test-keys   # out/pi4-uefi-test.bin, which also trusts the test key
scripts/build-uefi.sh --test-apps   # also the EFI applications the scenarios run, signed with the test key,
                                    # and Ubuntu's signed shim and GRUB as out/shimaa64.efi and out/grubaa64.efi
```

`cargo build` in the repository runs `scripts/build-uefi.sh` itself.
`uefi/rust-toolchain.toml` pins the nightly the firmware builds with. The
build also needs `xz` and `openssl`, and `--test-apps` needs `sbsign`
(sbsigntool).

## Size

`pi4-uefi.bin` goes into the EEPROM inside `start4.elf`
([eeprom.md](eeprom.md)).

| build | payload | `pi4-uefi.bin` |
|---|---|---|
| default | 119 KB | 55 KB |

## Running it in pimu

After `scripts/build-uefi.sh --test-apps`, `scripts/build.sh` and
`scripts/build.sh --test-keys`:

```bash
pimu boot --scenario scenarios/uefi-hello.yaml           # a signed EFI application off the SD card
pimu boot --scenario scenarios/usb-hello.yaml            # the same off a USB drive
pimu boot --scenario scenarios/shim-grub.yaml            # Ubuntu's shim checks and starts GRUB, which reads grub.cfg
pimu boot --scenario scenarios/secure-boot-refused.yaml  # an image not signed by a key in db is refused
```

## Known limitations

- `pi4-uefi.bin` is linked at 0 and the payload at `0x100_0000`; neither is
  relocatable.
- The device tree is Raspberry Pi's for the Pi 4B whatever the board, with
  nothing filled in but `/memory@0`.
- Nothing sets the ARM's clock.
- Variables are volatile: there is no variable store, so boot entries and the
  MOK list last only for the boot, and the boot is always the removable-media
  path.
- The Secure Boot keys are built in; there is no `PK` or `KEK`, and an owner
  cannot enrol keys of their own.
- `dbx` holds image hashes only, no certificates.
- Storage is read-only to EFI applications.
- No NVMe, no network boot, no USB keyboards.
- The xHCI driver gives each empty root port 400 ms to show a connection,
  since a SuperSpeed port reads empty until its link has trained.

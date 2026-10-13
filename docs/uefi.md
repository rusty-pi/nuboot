# UEFI

The operating system is started through UEFI. `uefi/` is a UEFI firmware of
its own, written in Rust for this board and nothing else: the boot services
and the protocols a distribution's shim, GRUB and Linux's EFI stub use, with
Secure Boot always on. `start4.elf` carries it, as `pi4-uefi.bin`, and the
board's device tree, and starts the ARM in them:

1. It puts `pi4-uefi.bin` at ARM physical 0, where the cores come out of
   reset, and the device tree at `0xF0_0000` with `/memory@0` filled in from
   the board's SDRAM, a `vpu-tpm` node ([os-image.md](os-image.md)) and the
   reserved page of the TPM's command response buffer ([tpm2.md](tpm2.md#the-command-response-buffer)),
   and the Ethernet controller's `local-mac-address`: `02:` and five bytes of a hash of
   the board's serial number, the same at every boot, and the board's `serial-number` and
   revision code in the root. The ARM gets everything below `0x3EC0_0000`, where the
   VPU firmware's own memory starts, and all the memory above 1 GiB.
2. `pi4-uefi.bin` (`uefi/stub/`) starts with an armstub: each core sets up
   the local timer, the generic timer, the GIC and EL3's controls, and drops
   to non-secure EL2. The secondary cores wait on the spin table at `0xd8`
   that the device tree names, and on the mailboxes at `0x800` that the ACPI
   tables name.
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
   0.574586 INFO  secboot  Secure Boot enforced  db=3 dbx=26
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
| Runtime services | `GetVariable`, `GetNextVariableName`, `SetVariable`, `QueryVariableInfo` and `ResetSystem` after `ExitBootServices`. The firmware image is typed as runtime services code and data, the variables are a 128 KiB table in it, and the mailbox's page and the power manager's are typed as memory-mapped I/O for the OS to map. The OS reads the variables the firmware holds with runtime access and creates or changes others, and the writes outlast a reset ([below](#variables-the-os-writes)). `PK` and the Secure Boot state refuse writes. `ResetSystem` writes the power manager's registers: every kind but a shutdown resets the board, and a shutdown resets it to the bootloader's halt. The `EFI_RT_PROPERTIES_TABLE` lists only these five, so `SetVirtualAddressMap` is not offered and the OS maps the runtime regions where they are. Every other runtime service returns `EFI_UNSUPPORTED` |
| Console | `SimpleTextOutput` and `SimpleTextInput` on the PL011 at `0xFE20_1000`, with VT100 keys |
| Storage | The SD card on EMMC2 (`0xFE34_0000`), and USB drives (bulk-only mass storage) on the VL805's root ports or behind a hub. `BlockIo`, `DiskIo`, MBR and GPT partitions, and a read-only FAT12/16/32 `SimpleFileSystem` |
| USB | The VL805's xHCI behind the PCIe root complex, which `start4.elf` has brought up and given its firmware |
| `EFI_RNG_PROTOCOL` | RNG200's FIFO, raw |
| `ResetSystem` | The power manager's watchdog (`PM_RSTC`/`PM_WDOG`), halt through `PM_RSTS`: partition 63, which the EEPROM bootloader halts at (and powers off at when its `POWER_OFF_ON_HALT` is set). The same after `ExitBootServices`, which is how Linux resets and powers off in both modes |
| `SetWatchdogTimer`, `ExitBootServices` | UEFI beats the board's watchdog from the hypervisor timer's interrupt and hands it back to `start4.elf` at `ExitBootServices` ([boot.md](boot.md#boot-watchdog)) |
| ESRT | One system firmware resource, the firmware itself, in the `EFI_SYSTEM_RESOURCE_TABLE`, with the commit's time as its version. `OsIndicationsSupported` offers file capsule delivery, and `OsIndications` takes the OS's write |
| Device tree | Passed on to the OS as the `EFI_DTB_TABLE` configuration table. Besides the stock tree's content it has the memory, the network address, the TPM, and the board's identity: `serial-number` and `rusty-pi,board-revision` in the root |
| SMBIOS | Version 3.1.1, as the `EFI_SMBIOS3_TABLE` configuration table, whichever way the OS describes the board: the firmware (its vendor, the commit and its date), the system (maker, the device tree's `model`, the revision code, the serial number and a UUID made from it), the board and its enclosure, the processor and the memory. `/sys/class/dmi/id`, `dmidecode`, `hostnamectl` and fwupd's hardware IDs read them, and an OS on the ACPI tables has no device tree to get the model and serial number from |
| ACPI | The tables of the [next section](#acpi), as the `EFI_ACPI_20_TABLE_GUID` configuration table |
| Variables | Held in RAM, with the non-volatile ones also in the flash store ([below](#the-variable-store)) |

The SD card is tried before USB.

## ACPI

The firmware also offers ACPI tables: the RSDP is the
`EFI_ACPI_20_TABLE_GUID` configuration table, and the tables are built at every
boot from the board and the VPU's own state. A kernel that is given both them
and the device tree uses the device tree, and uses the tables when its command
line says `acpi=on` or when the device tree it is given has nothing in it. With
them the OS finds the TPM on the VPU through its own driver, with no module
([os-image.md](os-image.md#with-the-acpi-tables)).

| table | holds |
|---|---|
| FADT | Hardware-reduced ACPI 6.3, with no PSCI: the cores start through the parking protocol |
| MADT | The four cores, each with the interrupt of its performance monitor (`perf` works), and the GIC-400 |
| GTDT | The generic timers |
| SPCR | The PL011 on GPIO 14 and 15 as the console, at 115200 baud |
| PPTT | Each core's caches (48 KiB for instructions, 32 KiB for data) and the 1 MiB they share |
| IORT | How much memory the USB controller reaches: the lower 2 GiB |
| TPM2 | The TPM on the VPU, as a command response buffer device with the ACPI start method ([tpm2.md](tpm2.md#the-command-response-buffer)) |
| DSDT | The devices below |

The DSDT has a device for each of:

| device | `_HID` | what takes it |
|---|---|---|
| each core | `ACPI0007` | the kernel's processor driver |
| the console | `ARMH0011` | the PL011 driver |
| the TPM | `MSFT0101` | `tpm_crb`; its start method writes the doorbell to the mailbox |
| the power manager | `PRP0001`, with the `compatible` of the device tree's node | `bcm2835-pm`: the watchdog the boot watchdog is handed to ([boot.md](boot.md#boot-watchdog)) |
| the random number generator | `PRP0001`, with the `compatible` of the device tree's node | `iproc-rng200` |
| the temperature sensor | a thermal zone, `_TMP` reading the sensor's register and `_CRT` giving 85 °C, the SoC's rating, since nothing here slows the cores down before then | the kernel's ACPI thermal driver (`acpitz`); the VPU starts the sensor's clock, which the zone and the device tree's thermal driver both need |
| the SD host | `BRCME88C` | `sdhci-iproc`, with the card at 3.3 V and no DMA, as this firmware's own driver runs it |
| the network interface | `BCM6E4E` | `genet`, with the address the device tree gives it |
| the USB controller | `PNP0D10`, in a container device (`ACPI0004`) that says what it reaches | the kernel's generic xHCI driver (`xhci-plat-hcd`) |

The secondary cores wait in the armstub on the spin table the device tree names
and on a mailbox for each core, the ACPI parking protocol's: the OS writes the
core's number and an entry point there and sends software interrupt 0, which
wakes the core, and the core takes the entry point.

The USB controller, the VL805 behind the PCIe root complex, is a platform
xHCI device: UEFI has brought the link up, given the controller its firmware
and put its registers in the root complex's window, and the tables name that
address and the interrupt line the root complex raises for it, so the OS needs
no driver for the root complex. The controller reaches the lower 2 GiB of
memory, from the container's `_DMA` and from the IORT, which the kernel reads
early enough to keep the memory a driver asks for in reach and to copy
transfers through a buffer below it for the rest. UEFI turns off the
controller's MSI as the OS takes over, because a function with MSI enabled does
not raise its interrupt line, which is all an OS on the tables has.

Reset and power off are not in the tables: the kernel takes them from the runtime services' `ResetSystem`.

What the device tree has and the tables leave out is what the kernel's driver
reads from the device tree only, or what the board does not offer under either
description:

- the GPIO controller, I2C, SPI and PWM: the drivers are device tree only, and
  HATs are out of scope;
- the PCIe root complex, whose configuration space is not ECAM: the USB
  controller behind it is described as a device of its own, so `lspci` lists
  nothing, and a CM4's PCIe slot has no driver on the tables;
- Wi-Fi and Bluetooth: the chip's power switches are lines of the GPIO
  expander, which Raspberry Pi's VPU firmware serves over the mailbox and this
  firmware does not;
- CPU frequency scaling, which Linux does through the VPU's clock services over
  the same mailbox: the ARM runs at the one rate this firmware sets, 600 MHz;
- the display, camera and audio.

`scripts/test-acpi.sh` builds the table code for the host (`tools/acpi-check`)
and checks the tables' links and checksums, then disassembles each with the
ACPICA tools' `iasl` and compiles the DSDT again to the same bytes.
`scenarios/linux-acpi.yaml` boots Debian's arm64 kernel on them in pimu.

## Secure Boot

Secure Boot is always on. `LoadImage` runs an image only when an
Authenticode signature on it chains to a certificate in `db` and its hash is
not in `dbx`; otherwise it refuses it with `EFI_SECURITY_VIOLATION` and logs
why:

```text
   1.661962 WARN  secboot  image refused  reason="not signed by a key in db" path=VenHw/SD(0)/HD(1)\EFI\BOOT\BOOTAA64.EFI
```

The keys are built in, from `uefi/keys/` and `keys/` ([Keys](#keys)):

| variable | holds |
|---|---|
| `PK` | The platform key, `keys/pk` |
| `KEK` | `keys/kek` |
| `db` | This firmware's signing key, `keys/db`, and Microsoft Corporation UEFI CA 2011 and Microsoft UEFI CA 2023, which sign shim for the distributions |
| `dbx` | The AArch64 image hashes in Microsoft's revocation list (`dbx-aarch64.txt`, from [microsoft/secureboot_objects](https://github.com/microsoft/secureboot_objects)) |
| `SecureBoot`, `SetupMode`, `AuditMode`, `DeployedMode` | 1, 0, 0, 1 |

`PK` and the state variables cannot be written, and `KEK`, `db` and `dbx`
change only through signed updates ([Updating the keys](#updating-the-keys)). A distribution boots through its shim, which
checks GRUB and the kernel against its own keys and the MOK list; shim's
SBAT revocations apply as they do on any other machine.

The firmware measures what it verifies and offers `EFI_TCG2_PROTOCOL` to the
loaders that follow: the Secure Boot configuration, each image's hash and the
certificate that verified it go to the PCRs of the TPM on the VPU
([tpm2.md](tpm2.md)).

Signatures are checked with SHA-256 and RSA keys up to 4096 bits, as the UEFI
CAs and the distributions' signers use.

### Keys

`scripts/genkeys.sh` generates `keys/pk`, `keys/kek` and `keys/db` (a `.key`,
a `.crt` and the `.der` the firmware embeds) for any that is missing, and
`scripts/build-uefi.sh` runs it. `keys/` is never committed. The platform key
is built in and cannot be replaced, so it is valid for 50 years. A build
that has the certificates but not the keys, such as CI, names them in
`PI4_PK_CERT`, `PI4_KEK_CERT` and `PI4_DB_CERT` (DER files) instead. Sign
what the firmware boots with `keys/db.key` and `keys/db.crt`, for example
`sbsign --key keys/db.key --cert keys/db.crt`.

### Updating the keys

`PK` cannot be written. `KEK`, `db` and `dbx` take time-based authenticated
writes, the way `efi-updatevar` and `sign-efi-sig-list` make them: `KEK` is
signed by the key in `PK`, `db` and `dbx` by that key or one in `KEK`, with a
timestamp later than the variable's last, and the value an `EFI_SIGNATURE_LIST`
of X.509 certificates or SHA-256 hashes. A write without a signature gets
`EFI_SECURITY_VIOLATION`. `scripts/mkauth.py` builds one:

```bash
scripts/mkauth.py keys/kek.key keys/kek.crt db customer.crt db-customer.auth
```

An accepted write takes effect for the next `LoadImage` and is kept in the
flash store.

### The variable store

Non-volatile variables are kept in the flash after the stock bootloader's
sections ([boot.md](boot.md#what-the-eeprom-holds-besides-the-bootloader)), a
log in two banks of 20 KiB from `0x74000`, and come back at the next boot.

- `KEK`, `db` and `dbx` are stored as the signed writes that made them. Every
  boot starts from the built-in keys and checks each stored write again against
  the keys as they were when it was made.
- Every other non-volatile variable (boot entries, shim's MOK list) is stored
  with a signature, the device private key's ECDSA P-256 signature
  ([keystore.md](keystore.md#the-firmware-cryptography-service)) over its
  attributes, name, value and a counter. A record whose signature does not verify, or
  whose counter is not above the one before it, is ignored. A variable is
  at most 16 KiB.
- A record is intact when its framing and SHA-256 are. One that is not, such as
  a write a power loss cut short, is stepped over to the next intact one, and
  the store moves to the other bank without it at that boot.
- A bank more than half full at boot is replaced by the other, started with
  the records the variables still need, when that frees room: the VPU only
  appends once UEFI is gone, and the OS's writes fail while the bank is full.
  What the boot refused goes with what the writes replaced: a write signed by
  keys the board does not hold, and a variable that is not the OS's. A board
  with no device private key keeps its bank, since it read none of the plain
  records.

The OS can write the flash, and can drop records, but not make one: the
device key signs for it only through the VPU's runtime tag, in a signature
domain UEFI accepts for a variable of the OS's own and nothing else (below).
UEFI forbids the device key to sign and to HMAC at `ExitBootServices`, and
stops the boot when the VPU does not say it is locked. Dropping the
newest record of a variable returns it to its previous value. Where the flash
does not answer, or no device private key is fused, there is no signature and a
variable other than `KEK`, `db` and `dbx` lasts until reset. Writing a whole new
`pieeprom.bin` clears the store.

### Variables the OS writes

After `ExitBootServices` the runtime services keep a write the OS makes in
their table, and tell the VPU over the mailbox, on a channel of their own
(7) that the OS's mailbox driver does not listen on, so that nothing is posted
back to disturb it: the VPU answers in the message's own buffer.

- A non-volatile variable no signature guards is signed by the VPU with the
  device key and appended to the flash store, with the sequence number the next
  record needs. The VPU signs, in a domain of its own, only a write or a
  deletion with the attributes non-volatile, boot services and runtime, a name
  without a NUL and at most 16 KiB of value: what the OS asks it to sign is the
  OS's word. At the next boot UEFI takes such a record only for a variable the
  OS owns, one that the table holds with those attributes, or none. A
  `SecureBoot`, `PK` or other variable the firmware keeps, or one the boot
  chain keeps from the OS (non-volatile without runtime access, such as shim's
  MOK lists and the update records), is left as it is. A board with no device
  key keeps the write in the table until reset.
- A write of `KEK`, `db` or `dbx` is a signed update (what `efi-updatevar` and
  fwupd's `uefi-db`, `uefi-dbx` and `uefi-kek` plugins write). The runtime
  services cannot check the signature, so they append the record as it is, and
  UEFI checks it against `PK` and the `KEK`s at the next boot like every stored
  write. The table keeps the old value until then; the update takes effect at
  the restart fwupd asks for.
- A write the VPU does not take, such as one into a bank that is full until
  UEFI compacts it at the next boot, returns `EFI_OUT_OF_RESOURCES` or
  `EFI_DEVICE_ERROR`, and the variable lasts until reset. A non-volatile variable
  has the attributes non-volatile, boot services and runtime access, and at most
  16 KiB, or the write is refused.

### The test build

`scripts/build.sh --test-keys` (the `test-keys` cargo feature) builds
`out/start4-test.elf`, whose UEFI firmware also has a test key in `db`: a
self-signed certificate `scripts/build-uefi.sh` generates in
`out/test-keys/` on first use, which is never committed.
`scripts/build-uefi.sh --test-apps` signs the scenarios' EFI applications
with it. The test build logs a warning at every boot; it is not for a real
board.

## Firmware capsules

The firmware and the EEPROM bootloader are the two resources in the ESRT, and fwupd's `uefi-capsule`
plugin updates it by putting a capsule in `\EFI\UpdateCapsule` on the EFI
system partition. At every boot, before the boot option runs, each `.cap` file
there is checked:

1. The header's GUID is the firmware's ESRT class, and the sizes fit the file.
2. A `WIN_CERTIFICATE_UEFI_GUID` holds a detached PKCS #7 signature over the
   image after it. The signer has to chain to a `db` entry that is not
   Microsoft's, whose CAs sign for anyone, and the image's SHA-256 must not
   be in `dbx`.
3. The image is `P4FW`, a little-endian `u32` version, the length of
   `boot.sig` as one, `boot.sig`, and `boot.img` ([boot.md](boot.md#signed-boot)).
   `boot.sig` names the SHA-256 of that `boot.img`.
4. The version is newer than the running firmware's.

A capsule that fails sets the ESRT's last attempt version and status
(`4` invalid format, `5` authentication error, `3` incorrect version, `2`
image too large) and is logged with the reason. `scripts/mkcapsule.py` builds
one.

A capsule that passes is staged as a tryboot, when the board has a device key
and the flash store answers, so that the update can be recorded. The update
takes three boots:

1. The firmware that finds the capsule writes `tryboot.img` and `tryboot.sig`
   next to `boot.img` and `boot.sig` on the file system that has them, reads
   them back, removes the capsule, records the update as pending in a signed
   variable the OS cannot see, and resets with the bootloader's tryboot request
   set (bit 1 of `PM_RSTS`).
2. The bootloader checks `tryboot.sig` against the EEPROM's key and starts the
   new firmware out of `tryboot.img`. That firmware finds the record, reports
   success in the ESRT, and records the update as proven when it reaches
   `ExitBootServices`. The request is one-shot: a boot that fails before then
   is followed by one from `boot.img`.
3. The firmware that starts from `boot.img` finds the update proven, checks
   that the pair belongs together, and makes `tryboot.img` and `tryboot.sig` the
   `boot.img` and `boot.sig` in one directory update, and resets into the new
   firmware. Finding it unproven, it removes `tryboot.img` and `tryboot.sig` and
   reports failure in the ESRT.

A capsule for the EEPROM bootloader carries, in its `boot.img`, a `pieeprom.upd`
and a `pieeprom.sig`, which the stock bootloader writes to the EEPROM when it
boots them, if the time in `pieeprom.sig` is later than its own. The capsule's
version is that time. It is staged like a firmware update's, with one more step
and a different end:

- The bootloader's update writes the whole flash, so the variable store, the
  record of the update in it included, would be lost. The firmware copies the
  store to `STORE.BAK` on the file system before it resets, and reads the copy
  back to check it.
- The bootloader stamps the update's time into the last 8 bytes of the flash.
  The ESRT's version for the EEPROM is that time.
- When the firmware next starts with an empty store and a `STORE.BAK`, it puts
  the copy back and restarts. The record then says an update of the EEPROM was
  pending: the flash is as new as the capsule said, and the ESRT reports
  success, or it is not, and the ESRT reports failure. Either way the staged pair
  and the copy go.

The configuration, signature and public key the EEPROM holds are part of the
image the capsule's builder prepares (`rpi-eeprom-config`), so the update keeps
them.

The result stays in the flash store for the OS to read in the ESRT until the
next update.

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
([boot.md](boot.md)).

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
  nothing filled in but `/memory@0`, the TPM's node and the Ethernet address,
  which is not the one Raspberry Pi's firmware gives the board.
- The ACPI tables describe a Raspberry Pi 4B's devices whatever the board.
- Nothing sets the ARM's clock.
- Nothing reads `BootOrder`: the boot is always the removable-media path.
- `dbx` holds image hashes only; a certificate in it is ignored.
- Storage is read-only to EFI applications; the firmware writes only the files an update needs.
- A write the OS makes to a variable while a full bank of the store waits for
  UEFI to compact it lasts until reset.
- No NVMe, no network boot, no USB keyboards.
- The xHCI driver gives each empty root port 400 ms to show a connection,
  since a SuperSpeed port reads empty until its link has trained.

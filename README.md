# nuboot

nuboot is Raspberry Pi 4 firmware for headless servers, written in Rust: its own VPU
firmware (`start4.elf`) in place of Raspberry Pi's, started by Raspberry Pi's
EEPROM bootloader as it ships, built around a small
preemptive thread scheduler and with its own idea of what the firmware is
for:

- **Zero config.** No `config.txt`: the firmware takes what it needs from the
  board and the boot medium.
- **Headless only.** No display, camera or audio. A server needs a serial
  console, storage, the network and a watchdog.
- **A readable log.** Every line says when, how important, which subsystem and
  what, with the values as named fields.
- **UEFI with Secure Boot** as the way an operating system is started: a
  small UEFI of its own in `uefi/` that runs only images signed by a key in
  `db`, Microsoft's UEFI CAs by default, so a distribution's shim and GRUB
  boot as they are ([docs/uefi.md](docs/uefi.md)). The platform key is built in,
  and `KEK`, `db` and `dbx` change through updates that a `PK` or `KEK` key signs.
- **One file**: `start4.elf` carries the UEFI firmware and the board's device
  tree, so a board with secure boot programmed takes this firmware in a signed
  `boot.img` under Raspberry Pi's own bootloader ([docs/boot.md](docs/boot.md)).

- **Updates through fwupd.** The firmware and the EEPROM bootloader are ESRT
  resources. A board's owner signs `start4.elf` once, and a bundle that an
  update key signs then replaces the whole firmware, VPU and UEFI, with no
  signature by the owner; a capsule the owner signs is applied as a tryboot and
  committed once it has reached the OS ([docs/updates.md](docs/updates.md)).

- **Wake-on-LAN.** The VPU firmware stays up after the OS powers the board
  off, and a magic packet for the board's address boots it
  ([docs/boot.md](docs/boot.md#wake-on-lan)).

- **A stated security design**: what it defends, by what, and what it takes to
  break it ([docs/security.md](docs/security.md)).

Out of scope: HATs and IPv6. The operating system gets a device tree, and ACPI
tables when it asks for them or has no device tree ([docs/uefi.md](docs/uefi.md#acpi)).

> [!NOTE]
> This is an early firmware. On a Raspberry Pi 4B rev 1.5 (`d03115`) it starts
> the ARM in UEFI, which boots Debian's arm64 kernel off the SD card and runs an
> EFI application off a USB drive; the other boards are tested only in pimu
> ([Tested](#tested)).

## What it does

From the boot ROM to the threads that run for as long as the board is up:

1. Raspberry Pi's EEPROM bootloader brings up the SDRAM and starts
   `start4.elf` off the boot medium ([docs/boot.md](docs/boot.md)).
2. `start4.elf` programs the PL011 on GPIO 14/15 for 115200 8N1 itself, so the log is on
   the serial console with no setting anywhere.
3. Logs the firmware's commit, the board's model and revision code, the boot
   medium, the RAM size and the bootloader's version, and starts the SoC's
   temperature sensor, which the OS reads as a thermal zone.
4. Beats the boot watchdog the bootloader armed, or arms one, hands it to the ARM when it
   starts, and takes it back at `ExitBootServices` until the operating
   system's driver has it, so a hang anywhere in the boot, or an ARM that
   stops, resets the board ([docs/boot.md](docs/boot.md#boot-watchdog)).
5. Starts the ARM in the UEFI firmware it carries, with the board's device
   tree ([docs/uefi.md](docs/uefi.md)), once it has brought up the PCIe link
   and given the VL805 USB controller its firmware. UEFI finds the SD card and
   any USB drive and boots `\EFI\BOOT\BOOTAA64.EFI` from them.
   UEFI measures what it verifies into a TPM 2.0 on the VPU and offers
   `EFI_TCG2_PROTOCOL` over it ([docs/tpm2.md](docs/tpm2.md)); the payload can
   have a key from the device private key ([docs/keystore.md](docs/keystore.md)).
   The OS finds that TPM through the ACPI tables UEFI builds, with its own
   driver, or through the device tree and a module
   ([docs/os-image.md](docs/os-image.md)). UEFI describes the board in SMBIOS
   tables too.
6. Starts the scheduler: a service thread that answers the property mailbox
   (Linux's `NOTIFY_XHCI_RESET`, which has the VL805's firmware reloaded, and
   the TPM's commands and the boot key), and a monitor thread that reports each
   stack's high-water mark as it grows.

```text
   0.267088 INFO  boot     nuboot 1a2b3c4  board="Raspberry Pi 4 Model B" revision=d03115 pcb=1.5
   0.267218 INFO  boot     started by the EEPROM bootloader  medium=sd ram_mib=8192 bootloader=1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d
   0.267905 INFO  thermal  temperature sensor running  celsius=43.8
   0.583645 INFO  usb      VL805 xHCI controller up  bus=1 firmware=loaded registers=0x602000000
   0.595415 INFO  arm      ARM started in UEFI  image_bytes=54910 tree=0xf00000 tree_bytes=56443 memory_mib=8108
   0.595737 INFO  sched    threads running  threads=2 tick_us=1000
```

[docs/logging.md](docs/logging.md) describes the log format.

## Tested

✅ tested (in [pimu](https://github.com/rusty-pi/pimu), or on a board) · ❌ tried and does not work yet · ➖ not tried

| | pimu | Pi 4B | Pi 400 | CM4 |
|---|---|---|---|---|
| `start4.elf` started by the stock EEPROM bootloader from SD | ✅ | ➖ | ➖ | ➖ |
| `start4.elf` started by the stock EEPROM bootloader from the network (TFTP) | ➖ | ✅ | ➖ | ➖ |
| `start4.elf` started from a USB drive | ✅ | ➖ | ➖ | ➖ |
| Signed boot: `start4.elf` out of a `boot.img` the EEPROM's key signed, one signed by another key refused | ✅ | ➖ | ➖ | ➖ |
| Console log, board identity, threads | ✅ | ✅ | ➖ | ➖ |
| Boot watchdog: a hang in UEFI resets the board, `ExitBootServices` hands it to the OS | ✅ | ➖ | ➖ | ➖ |
| Pi 4B rev 1.4 (`d03114`) and rev 1.2 (`c03112`) | ✅ | ➖ | ➖ | ➖ |
| ARM started in UEFI: SD card, a signed EFI application | ✅ | ✅ | ➖ | ➖ |
| Secure Boot: Ubuntu's shim and GRUB run, an image not signed by a key in `db` is refused | ✅ | ➖ | ➖ | ➖ |
| USB: VL805 firmware from the EEPROM, an EFI application off a USB drive | ✅ | ✅ | ➖ | ➖ |
| Property mailbox: `NOTIFY_XHCI_RESET` reloads the VL805's firmware | ✅ | ✅ | ➖ | ➖ |
| TPM 2.0 on the VPU (PCRs, properties, random numbers) behind `EFI_TCG2_PROTOCOL`, shim measuring into it, firmware, board, EEPROM bootloader and configuration and VL805 firmware measured into PCRs 0 and 1, separators in PCRs 0-7 | ✅ | ➖ | ➖ | ➖ |
| systemd-boot and systemd-stub (a unified kernel image) measuring into the TPM | ✅ | ➖ | ➖ | ➖ |
| Firmware update capsules: one signed by a key in `db` with a newer version is verified; an older one, a changed one, one signed by another key and a file that is not a capsule are refused | ✅ | ✅ | ➖ | ➖ |
| Firmware update, the firmware's side: a capsule staged as `tryboot.img` with the bootloader's tryboot request, the updated firmware proven once it reaches the OS and committed as `boot.img`, or dropped when it does not | ✅ | ✅ | ➖ | ➖ |
| EEPROM update, the firmware's side: a capsule staged with the variable store saved, dropped when the bootloader did not update the EEPROM | ✅ | ✅ | ➖ | ➖ |
| EEPROM update the stock bootloader makes from the capsule's `pieeprom.upd`, with the variable store put back | ✅ | ➖ | ➖ | ➖ |
| The firmware cryptography service: the fused key signs and HMACs for UEFI, gives its public key, never itself, and is locked from the OS | ✅ | ✅ | ➖ | ➖ |
| Linux 6.12 (Debian's arm64 kernel in a signed unified kernel image, started by systemd-boot): its loader variables are there, Secure Boot reads as on and the kernel locks down, `efivarfs` and the ESRT read, `tools/tpm-vpu` (signed with a key in `db`) gives `/dev/tpm0` with the PCRs and the event log | ✅ | ✅ | ➖ | ➖ |
| Linux 6.12 as above: `bootctl status` (systemd 257) reads Secure Boot as enabled and the unified kernel image as measured | ✅ | ✅ | ➖ | ➖ |
| Linux 6.12 as above: a variable is written and is there after the OS resets the board, and its power off halts the board in the bootloader, both through the firmware's `ResetSystem` with no watchdog module loaded | ✅ | ✅ | ➖ | ➖ |
| Linux 6.12 as above: the SMBIOS tables name the board (`/sys/class/dmi/id`: maker, model, serial number, firmware, enclosure and a UUID), with the device tree and with the ACPI tables | ✅ | ✅ | ➖ | ➖ |
| Linux 6.12 as above: the temperature sensor reads as a thermal zone (`cpu-thermal` from the device tree, `acpitz` from the ACPI tables, with a critical trip), the hardware random number generator gives bytes and the cores' performance monitors register | ✅ | ✅ | ➖ | ➖ |
| Linux 6.12 as above, started with `acpi=on` and no module: the kernel's own `tpm_crb` takes the TPM (the PCRs, the event log), the four cores start, the SD card, the network interface and the USB controller with a stick on it are there, the variable survives the reset, and the power off halts the board | ✅ | ✅ | ➖ | ➖ |
| Linux 6.12 as above, given a device tree with nothing in it (a `.dtb` section in the unified kernel image) and no `acpi=on`: the kernel takes the ACPI tables by itself, and the TPM, the SD card, the network interface, the USB stick, the thermal zone, the SMBIOS tables and the power off are there | ✅ | ✅ | ➖ | ➖ |
| Raspberry Pi OS (its own kernel 6.12.93+rpt, in a unified kernel image signed with a key in `db`, using the device tree): root on the SD card at the stock firmware's 44 MB/s, the network interface, the four cores and the USB controller | ➖ | ✅ | ➖ | ➖ |
| The GPIO expander's two SD pins over the property mailbox, every other pin refused | ✅ | ✅ | ➖ | ➖ |
| Variables the OS writes through the runtime services, a signed `db` update among them, kept across a reset | ✅ | ✅ | ➖ | ➖ |
| The flash variable store has room for the OS's writes after a boot: a bank the OS filled with the variables it replaced is started afresh with what the variables still need, and the OS writes again | ✅ | ✅ | ➖ | ➖ |
| A shutdown through the runtime services, after `ExitBootServices`, ends in the bootloader's halt | ✅ | ➖ | ➖ | ➖ |
| A boot key from the fused private key, handed over once, nothing of it left in the VPU's memory | ✅ | ➖ | ➖ | ➖ |
| Update bundles: an update capsule's bundle is kept, left in RAM across a reset, checked against the update key and run in the update slot by the firmware the bootloader loaded, and proven at `ExitBootServices`; one no update key signed is refused | ✅ | ✅ | ➖ | ➖ |
| A kept update bundle is staged again at the next power-up and runs; one that does not reach the OS is tried three times, counted in its file name, and then dropped for the one that ran before it; one that does is blessed and the older ones are removed | ✅ | ✅ | ➖ | ➖ |
| Wake-on-LAN: the OS powers the board off, the VPU waits on the Ethernet port, a magic packet boots the board | ✅ | ✅ | ➖ | ➖ |

The Pi 4B column is a rev 1.5 (`d03115`).

## Building

With the VC4 toolchain installed ([docs/toolchain.md](docs/toolchain.md)), and
rustup, `xz`, `openssl` and `curl` for the UEFI firmware and device tree it carries
([docs/uefi.md](docs/uefi.md)), `cargo build` builds `start4.elf`, the UEFI
firmware included.

```bash
scripts/build.sh
```

gives `out/start4.elf`. It also needs `python3`, and downloads the stock EEPROM
image the scenarios boot. `scripts/build.sh --features color` colours the log
with ANSI escapes.

A release is an `X.Y.Z` tag on `main`: pushing it builds `start4.elf` in CI and
publishes it as that tag's GitHub release, with the tag's message as the notes
(`.claude/skills/release/SKILL.md` has the steps).

## Running it in pimu

[`scenarios/`](scenarios/) holds the boots CI checks: each names the EEPROM
image, the files of the boot medium and the lines the console has to print.
After `scripts/build-uefi.sh --test-apps` for the EFI applications the UEFI
scenarios put on the card, signed with a test key, and `scripts/build.sh` and
`scripts/build.sh --test-keys` for `start4.elf` and its test build, which
also trusts that key:

```bash
pimu boot --scenario scenarios/sd-boot.yaml
pimu boot --scenario scenarios/signed-boot.yaml
pimu boot --scenario scenarios/signed-boot-refused.yaml
pimu boot --scenario scenarios/uefi-hello.yaml
pimu boot --scenario scenarios/shim-grub.yaml
pimu boot --scenario scenarios/secure-boot-refused.yaml
pimu boot --scenario scenarios/rev14-hello.yaml
pimu boot --scenario scenarios/usb-hello.yaml
pimu boot --scenario scenarios/xhci-reset.yaml
pimu boot --scenario scenarios/boot-key.yaml
pimu boot --scenario scenarios/boot-key-unbound.yaml
pimu boot --scenario scenarios/boot-key-unbound-b.yaml
pimu boot --scenario scenarios/tpm2-commands.yaml
pimu boot --scenario scenarios/systemd-boot.yaml
pimu boot --scenario scenarios/watchdog-hang.yaml
pimu boot --scenario scenarios/watchdog-exit.yaml
pimu boot --scenario scenarios/watchdog-takeover.yaml
pimu boot --scenario scenarios/watchdog-stuck.yaml
pimu boot --scenario scenarios/watchdog-fault.yaml
```

`scripts/run-scenarios.sh` boots several by name, one a CPU at a time, as CI
does:

```bash
scripts/run-scenarios.sh uefi-hello persist crypto
```

To run it by hand, boot the image with a directory as the SD card:

```bash
pimu boot --eeprom out/stock-pieeprom.bin --sd boot/
```

## Source

| | |
|---|---|
| `src/firmware.rs`, `src/bin/` | The firmware: the boot, then the threads, linked where the bootloader loads it and for the update slot |
| `src/log.rs` | The structured log and its console rendering |
| `src/sched.rs`, `src/critical.rs`, `src/sync.rs`, `src/stack.rs` | Threads, critical sections, semaphores, queues and locks, stack guards |
| `src/idle.rs`, `src/timer.rs`, `src/stc.rs` | Interrupts, sleeping, the system timer |
| `src/watchdog.rs`, `src/handover.rs` | The boot watchdog, and the state the bootloader hands over |
| `src/tpm2.rs`, `src/keystore.rs`, `src/crypto.rs`, `src/rng.rs` | The TPM 2.0 on the VPU, its PCRs, the boot key derived from the device private key and the firmware cryptography service for it, the random number generator |
| `src/console.rs`, `src/cm.rs`, `src/otp.rs`, `src/board.rs` | The PL011, clock generators, OTP and the board's identity |
| `src/spi_flash.rs`, `src/eeprom.rs`, `src/elf.rs`, `src/cache.rs` | The EEPROM and its sections, loading the ARM's image |
| `src/pcie.rs`, `src/vl805.rs`, `src/usb.rs`, `src/lzss.rs` | The PCIe link, and the VL805 and its firmware |
| `src/wake.rs`, `src/genet.rs` | Waiting for a magic packet after the OS powers the board off, and the Ethernet MAC and PHY that wait on |
| `src/i2c.rs`, `src/expander.rs`, `src/pmic.rs` | The master the PMICs and the GPIO expander hang off, the power LED on the expander, and the SoC core rail's setpoint on the PMIC at `0x1E` |
| `src/mailbox.rs` | The property mailbox |
| `src/tpm_crb.rs` | The TPM's command response buffer, a page of the ARM's memory the VPU answers commands in |
| `src/arm.rs`, `src/fdt.rs` | Starting the ARM, and the device tree it gets |
| `src/update.rs` | Checking and running an update bundle that UEFI left in RAM |
| `scripts/mkcapsule.py` | Puts a signed `boot.img` and `boot.sig` in a firmware update capsule |
| `scripts/mkcab.py` | Puts a capsule in the cabinet `fwupdmgr install` takes ([docs/updates.md](docs/updates.md)) |
| `scripts/mkbootimg.py` | Puts `start4.elf` in a signed `boot.img` and `boot.sig` |
| `scripts/mkbundle.py` | Signs an update bundle with the update key ([docs/updates.md](docs/updates.md#updates-the-owner-does-not-sign)) |
| `uefi/` | The UEFI firmware, its Secure Boot keys and ACPI tables, and the armstub and decompressor the ARM starts in |

## Licence

MIT — see [`LICENSE`](LICENSE). This is an independent project, not
affiliated with, sanctioned by or endorsed by Raspberry Pi Ltd. or Broadcom.
"Raspberry Pi" is a trademark of Raspberry Pi Ltd., used here only to say
which hardware this runs on.

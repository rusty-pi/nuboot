# pi4-server-firmware

Raspberry Pi 4 firmware for headless servers, written in Rust: its own VPU
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
  boot as they are ([docs/uefi.md](docs/uefi.md)). Enrolling the owner's own
  keys in their place is not there yet.
- **One file**: `start4.elf` carries the UEFI firmware and the board's device
  tree, so a board with secure boot programmed takes this firmware in a signed
  `boot.img` under Raspberry Pi's own bootloader ([docs/boot.md](docs/boot.md)).

Out of scope: HATs, IPv6 and ACPI (the operating system gets a device tree).

> [!NOTE]
> This is the start of the firmware, not a usable one: it brings up the SDRAM,
> starts the ARM in UEFI and runs its threads, but has not booted an operating
> system yet, and it has run only in pimu.

## What it does

From the boot ROM to the threads that run for as long as the board is up:

1. Raspberry Pi's EEPROM bootloader brings up the SDRAM and starts
   `start4.elf` off the boot medium ([docs/boot.md](docs/boot.md)).
2. `start4.elf` programs the PL011 on GPIO 14/15 for 115200 8N1 itself, so the log is on
   the serial console with no setting anywhere.
3. Logs the firmware's commit, the board's model and revision code, the boot
   medium, the RAM size and the bootloader's version.
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
6. Starts the scheduler: a service thread that answers the property mailbox
   (Linux's `NOTIFY_XHCI_RESET`, which has the VL805's firmware reloaded, and
   the TPM's commands and the boot key), and a monitor thread that reports each
   stack's high-water mark as it grows.

```text
   0.267088 INFO  boot     pi4-server-firmware 1a2b3c4  board="Raspberry Pi 4 Model B" revision=d03115 pcb=1.5
   0.267218 INFO  boot     started by the EEPROM bootloader  medium=sd ram_mib=8192 bootloader=1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d
   0.583645 INFO  usb      VL805 xHCI controller up  bus=1 firmware=loaded registers=0x602000000
   0.595415 INFO  arm      ARM started in UEFI  image_bytes=54910 tree=0xf00000 tree_bytes=56443 memory_mib=8108
   0.595737 INFO  sched    threads running  threads=2 tick_us=1000
```

[docs/logging.md](docs/logging.md) describes the log format.

## Tested

✅ boots in [pimu](https://github.com/rusty-pi/pimu) · ➖ not tried

| | pimu | Pi 4B | Pi 400 | CM4 |
|---|---|---|---|---|
| `start4.elf` started by the stock EEPROM bootloader from SD | ✅ | ➖ | ➖ | ➖ |
| `start4.elf` started from a USB drive | ✅ | ➖ | ➖ | ➖ |
| Signed boot: `start4.elf` out of a `boot.img` the EEPROM's key signed, one signed by another key refused | ✅ | ➖ | ➖ | ➖ |
| Console log, board identity, threads | ✅ | ➖ | ➖ | ➖ |
| Boot watchdog: a hang in UEFI resets the board, `ExitBootServices` hands it to the OS | ✅ | ➖ | ➖ | ➖ |
| Pi 4B rev 1.4 (`d03114`) and rev 1.2 (`c03112`) | ✅ | ➖ | ➖ | ➖ |
| ARM started in UEFI: SD card, a signed EFI application | ✅ | ➖ | ➖ | ➖ |
| Secure Boot: Ubuntu's shim and GRUB run, an image not signed by a key in `db` is refused | ✅ | ➖ | ➖ | ➖ |
| USB: VL805 firmware from the EEPROM, an EFI application off a USB drive | ✅ | ➖ | ➖ | ➖ |
| Property mailbox: `NOTIFY_XHCI_RESET` reloads the VL805's firmware | ✅ | ➖ | ➖ | ➖ |
| TPM 2.0 on the VPU (PCRs, properties, random numbers) behind `EFI_TCG2_PROTOCOL`, shim measuring into it, firmware and board measured into PCRs 0 and 1 | ✅ | ➖ | ➖ | ➖ |
| systemd-boot and systemd-stub (a unified kernel image) measuring into the TPM | ✅ | ➖ | ➖ | ➖ |
| Firmware updates: a signed capsule on the card staged as `tryboot.img`, started under the bootloader's tryboot, committed once it reaches the OS and dropped when it does not | ✅ | ➖ | ➖ | ➖ |
| The firmware cryptography service: the fused key signs and HMACs for UEFI, gives its public key, never itself, and is locked from the OS | ✅ | ➖ | ➖ | ➖ |
| A boot key from the fused private key, handed over once, nothing of it left in the VPU's memory | ✅ | ➖ | ➖ | ➖ |

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

To run it by hand, boot the image with a directory as the SD card:

```bash
pimu boot --eeprom out/stock-pieeprom.bin --sd boot/
```

## Source

| | |
|---|---|
| `src/bin/start4.rs` | The firmware: the boot, then the threads |
| `src/log.rs` | The structured log and its console rendering |
| `src/sched.rs`, `src/critical.rs`, `src/sync.rs`, `src/stack.rs` | Threads, critical sections, semaphores, queues and locks, stack guards |
| `src/idle.rs`, `src/timer.rs`, `src/stc.rs` | Interrupts, sleeping, the system timer |
| `src/watchdog.rs`, `src/handover.rs` | The boot watchdog, and the state the bootloader hands over |
| `src/tpm2.rs`, `src/keystore.rs`, `src/crypto.rs`, `src/rng.rs` | The TPM 2.0 on the VPU, its PCRs, the boot key derived from the device private key and the firmware cryptography service for it, the random number generator |
| `src/console.rs`, `src/cm.rs`, `src/otp.rs`, `src/board.rs` | The PL011, clock generators, OTP and the board's identity |
| `src/spi_flash.rs`, `src/eeprom.rs`, `src/elf.rs`, `src/cache.rs` | The EEPROM and its sections, loading the ARM's image |
| `src/pcie.rs`, `src/vl805.rs`, `src/usb.rs`, `src/lzss.rs` | The PCIe link, and the VL805 and its firmware |
| `src/mailbox.rs` | The property mailbox |
| `src/arm.rs`, `src/fdt.rs` | Starting the ARM, and the device tree it gets |
| `scripts/mkcapsule.py` | Puts a signed `boot.img` and `boot.sig` in a firmware update capsule |
| `scripts/mkbootimg.py` | Puts `start4.elf` in a signed `boot.img` and `boot.sig` |
| `uefi/` | The UEFI firmware, its Secure Boot keys, and the armstub and decompressor the ARM starts in |

## Licence

MIT — see [`LICENSE`](LICENSE). This is an independent project, not
affiliated with, sanctioned by or endorsed by Raspberry Pi Ltd. or Broadcom.
"Raspberry Pi" is a trademark of Raspberry Pi Ltd., used here only to say
which hardware this runs on.

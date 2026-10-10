# pi4-server-firmware

Raspberry Pi 4 firmware for headless servers, written in Rust: an EEPROM
image with its own first stage and its own VPU firmware (`start4.elf`) in
place of Raspberry Pi's bootloader and `start4.elf`, built around a small
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
- **Everything in the EEPROM**, UEFI included, so the boot medium carries only
  the operating system ([docs/eeprom.md](docs/eeprom.md)).

Out of scope: HATs, IPv6 and ACPI (the operating system gets a device tree).

> [!NOTE]
> This is the start of the firmware, not a usable one: it brings up the SDRAM,
> starts the ARM in UEFI and runs its threads, but has not booted an operating
> system yet, and the EEPROM image runs only in pimu until its first stage is
> signed for the board.

## What it does

From the boot ROM to the threads that run for as long as the board is up:

1. The first stage, which the boot ROM loads out of the EEPROM, starts the
   clocks, brings up the SDRAM with Raspberry Pi's training firmware and
   starts `start4.elf` out of the EEPROM ([docs/eeprom.md](docs/eeprom.md)).
2. `start4.elf` programs the PL011 on GPIO 14/15 for 115200 8N1 itself, so the log is on
   the serial console with no setting anywhere.
3. Logs the firmware's commit, the board's model and revision code, the boot
   medium, the RAM size and the bootloader's version.
4. Takes over the boot watchdog the first stage armed and carries it
   through UEFI until the operating system's driver takes it over, so a hang
   anywhere in the boot resets the board ([docs/eeprom.md](docs/eeprom.md#boot-watchdog)).
5. Starts the ARM in the UEFI firmware it carries, with the board's device
   tree ([docs/uefi.md](docs/uefi.md)), once it has brought up the PCIe link
   and given the VL805 USB controller its firmware. UEFI finds the SD card and
   any USB drive and boots `\EFI\BOOT\BOOTAA64.EFI` from them.
6. Starts the scheduler: a service thread that answers the property mailbox
   (so far only Linux's `NOTIFY_XHCI_RESET`, which has the VL805's firmware
   reloaded), and a monitor thread that reports each stack's high-water mark
   as it grows.

```text
   0.001149 INFO  boot     pi4-server-firmware bootcode 1a2b3c4  board="Raspberry Pi 4 Model B" revision=d03115 pcb=1.5
   0.015312 INFO  sdram    bringing up SDRAM  ranks=2 size_gbit=64 part=0 code=0x14 odt=0
   0.264451 INFO  boot     start4.elf loaded  bytes=156172 entry=0x3ec00200
   0.267088 INFO  boot     pi4-server-firmware 1a2b3c4  board="Raspberry Pi 4 Model B" revision=d03115 pcb=1.5
   0.267218 INFO  boot     started by the EEPROM bootloader  medium=eeprom ram_mib=8192 bootloader=1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d
   0.583645 INFO  usb      VL805 xHCI controller up  bus=1 firmware=loaded registers=0x602000000
   0.595415 INFO  arm      ARM started in UEFI  image_bytes=54910 tree=0xf00000 tree_bytes=56443 memory_mib=8108
   0.595737 INFO  sched    threads running  threads=2 tick_us=1000
```

[docs/logging.md](docs/logging.md) describes the log format.

`start4.elf` also runs on its own under the stock EEPROM bootloader, loaded
from the SD card.

## Tested

✅ boots in [pimu](https://github.com/rusty-pi/pimu) · ➖ not tried

| | pimu | Pi 4B | Pi 400 | CM4 |
|---|---|---|---|---|
| Own EEPROM image: first stage, SDRAM, `start4.elf` from the EEPROM | ✅ | ➖ | ➖ | ➖ |
| `start4.elf` started by the stock EEPROM bootloader from SD | ✅ | ➖ | ➖ | ➖ |
| Console log, board identity, threads | ✅ | ➖ | ➖ | ➖ |
| Boot watchdog: a hang in UEFI resets the board, `ExitBootServices` hands it to the OS | ✅ | ➖ | ➖ | ➖ |
| Pi 4B rev 1.4 (`d03114`) and rev 1.2 (`c03112`) | ✅ | ➖ | ➖ | ➖ |
| ARM started in UEFI: SD card, a signed EFI application | ✅ | ➖ | ➖ | ➖ |
| Secure Boot: Ubuntu's shim and GRUB run, an image not signed by a key in `db` is refused | ✅ | ➖ | ➖ | ➖ |
| USB: VL805 firmware from the EEPROM, an EFI application off a USB drive | ✅ | ➖ | ➖ | ➖ |
| Property mailbox: `NOTIFY_XHCI_RESET` reloads the VL805's firmware | ✅ | ➖ | ➖ | ➖ |

## Building

With the VC4 toolchain installed ([docs/toolchain.md](docs/toolchain.md)), and
rustup, `xz`, `openssl` and `curl` for the UEFI firmware and device tree it carries
([docs/uefi.md](docs/uefi.md)), `cargo build` builds the first stage and
`start4.elf`, the UEFI firmware included.

```bash
scripts/build.sh
```

gives `out/pieeprom.bin`, and `out/start4.elf` on its own. It also needs
`python3`, and downloads the stock EEPROM image the SDRAM training firmware and
the VL805's firmware are taken from. `scripts/build.sh --features color` colours the log
with ANSI escapes.

## Running it in pimu

[`scenarios/`](scenarios/) holds the boots CI checks: each names an EEPROM
image, the files of the boot medium and the lines the console has to print.
After `scripts/build-uefi.sh --test-apps` for the EFI applications the UEFI
scenarios put on the card, signed with a test key, and `scripts/build.sh` and
`scripts/build.sh --test-keys` for the EEPROM image and its test build, which
also trusts that key:

```bash
pimu boot --scenario scenarios/sd-boot.yaml
pimu boot --scenario scenarios/uefi-hello.yaml
pimu boot --scenario scenarios/shim-grub.yaml
pimu boot --scenario scenarios/secure-boot-refused.yaml
pimu boot --scenario scenarios/rev14-hello.yaml
pimu boot --scenario scenarios/usb-hello.yaml
pimu boot --scenario scenarios/xhci-reset.yaml
pimu boot --scenario scenarios/watchdog-hang.yaml
pimu boot --scenario scenarios/watchdog-exit.yaml
```

To run it by hand, boot the image with a directory as the SD card:

```bash
pimu boot --eeprom out/pieeprom.bin --sd boot/
```

## Source

| | |
|---|---|
| `src/bin/bootcode.rs` | The first stage: clocks, SDRAM, then `start4.elf` |
| `src/bin/start4.rs` | The firmware: the boot, then the threads |
| `src/log.rs` | The structured log and its console rendering |
| `src/sched.rs`, `src/critical.rs`, `src/sync.rs`, `src/stack.rs` | Threads, critical sections, semaphores, queues and locks, stack guards |
| `src/idle.rs`, `src/timer.rs`, `src/stc.rs` | Interrupts, sleeping, the system timer |
| `src/watchdog.rs`, `src/handover.rs` | The boot watchdog, and the state the bootloader hands over |
| `src/console.rs`, `src/cm.rs`, `src/otp.rs`, `src/board.rs` | The PL011, clock generators, OTP and the board's identity |
| `src/sdram.rs`, `src/spi_flash.rs`, `src/eeprom.rs`, `src/elf.rs`, `src/cache.rs` | SDRAM bring-up, the EEPROM and its sections, loading and entering `start4.elf` |
| `src/i2c.rs`, `src/pmic.rs` | The GPIO expander and the PMICs |
| `src/pcie.rs`, `src/vl805.rs`, `src/usb.rs`, `src/lzss.rs` | The PCIe link, and the VL805 and its firmware |
| `src/mailbox.rs` | The property mailbox |
| `src/arm.rs`, `src/fdt.rs` | Starting the ARM, and the device tree it gets |
| `scripts/mkeeprom.py` | Puts `pieeprom.bin` together |
| `uefi/` | The UEFI firmware, its Secure Boot keys, and the armstub and decompressor the ARM starts in |

## Licence

MIT — see [`LICENSE`](LICENSE). This is an independent project, not
affiliated with, sanctioned by or endorsed by Raspberry Pi Ltd. or Broadcom.
"Raspberry Pi" is a trademark of Raspberry Pi Ltd., used here only to say
which hardware this runs on.

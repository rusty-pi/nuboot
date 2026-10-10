# pi4-server-firmware

Raspberry Pi 4 VPU firmware for headless servers, written in Rust. It is the
`start4.elf` the EEPROM bootloader loads from the boot medium, built around a
small preemptive thread scheduler and with its own idea of what the firmware
is for:

- **Zero config.** No `config.txt`: the firmware takes what it needs from the
  board and the boot medium.
- **Headless only.** No display, camera or audio. A server needs a serial
  console, storage, the network and a watchdog.
- **A readable log.** Every line says when, how important, which subsystem and
  what, with the values as named fields.
- **UEFI with Secure Boot** as the way an operating system is started (not
  there yet).

> [!NOTE]
> This is the start of the firmware, not a usable one: it boots, logs the
> board, takes over the boot watchdog and runs its threads, but starts no
> operating system yet.

## What it does

From the bootloader's hand-off to the threads that run for as long as the
board is up:

1. Programs the PL011 on GPIO 14/15 for 115200 8N1 itself, so the log is on
   the serial console with no setting anywhere.
2. Logs the firmware's commit, the board's model and revision code, the boot
   medium, the RAM size and the bootloader's version.
3. Takes over the boot watchdog when the bootloader armed one
   (`BOOT_WATCHDOG_TIMEOUT` in the EEPROM's `bootconf.txt`), beating it from a
   timer interrupt, and hands it back when the boot is over.
4. Starts the scheduler: a service thread and a monitor thread that reports
   each stack's high-water mark as it grows.

```text
   2.764642 INFO  boot     pi4-server-firmware 1a2b3c4  board="Raspberry Pi 4 Model B" revision=d03115 pcb=1.5
   2.764772 INFO  boot     started by the EEPROM bootloader  medium=sd ram_mib=8192 bootloader=0a7ef05fedd8ed9ab9c58591ddf79a60a78dd4b2
   2.764902 INFO  watchdog boot watchdog running  budget_s=60 left_ms=57236
   2.764990 WARN  boot     no payload to start, staying in the firmware
   2.765048 INFO  watchdog boot watchdog off  left_ms=57236
   2.765232 INFO  sched    threads running  threads=2 tick_us=1000
```

[docs/logging.md](docs/logging.md) describes the log format.

It runs under the stock EEPROM bootloader.

## Tested

✅ boots in [pimu](https://github.com/rusty-pi/pimu) · ➖ not tried

| | pimu | Pi 4B | Pi 400 | CM4 |
|---|---|---|---|---|
| Started by the stock EEPROM bootloader from SD | ✅ | ➖ | ➖ | ➖ |
| Console log, board identity, boot watchdog, threads | ✅ | ➖ | ➖ | ➖ |

## Building

With the VC4 toolchain in place ([docs/toolchain.md](docs/toolchain.md)):

```bash
scripts/build.sh
```

gives `out/start4.elf`. `scripts/build.sh --features color` colours the log
with ANSI escapes.

## Running it in pimu

[`scenarios/`](scenarios/) holds the boots CI checks: each names an EEPROM
image, the files of the boot medium and the lines the console has to print.
After `scripts/build.sh`:

```bash
pimu boot --scenario scenarios/sd-boot.yaml
```

To run it by hand, put `out/start4.elf` in a directory and boot that
directory as the SD card:

```bash
pimu boot --eeprom https://raw.githubusercontent.com/raspberrypi/rpi-eeprom/master/firmware-2711/latest/pieeprom-2026-08-04.bin --sd boot/
```

## Source

| | |
|---|---|
| `src/bin/start4.rs` | The firmware: the boot, then the threads |
| `src/log.rs` | The structured log and its console rendering |
| `src/sched.rs`, `src/critical.rs`, `src/sync.rs`, `src/stack.rs` | Threads, critical sections, semaphores, queues and locks, stack guards |
| `src/idle.rs`, `src/timer.rs`, `src/stc.rs` | Interrupts, sleeping, the system timer |
| `src/watchdog.rs`, `src/handover.rs` | The boot watchdog, and the state the bootloader hands over |
| `src/console.rs`, `src/cm.rs`, `src/otp.rs`, `src/board.rs` | The PL011, clock generators, OTP and the board's identity |

## Licence

MIT — see [`LICENSE`](LICENSE). This is an independent project, not
affiliated with, sanctioned by or endorsed by Raspberry Pi Ltd. or Broadcom.
"Raspberry Pi" is a trademark of Raspberry Pi Ltd., used here only to say
which hardware this runs on.

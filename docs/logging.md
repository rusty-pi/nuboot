# The log

Everything the firmware has to say goes through one log (`src/log.rs`). A
record carries:

| | |
|---|---|
| time | The system timer, in seconds since it started, to the microsecond |
| level | `ERROR`, `WARN`, `INFO`, `DEBUG` or `TRACE` |
| target | The subsystem it came from: `boot`, `sched`, `watchdog`, … |
| message | What happened, in words |
| fields | Named values, `key=value` |

## On the serial console

The PL011 on GPIO 14 (TXD) and 15 (RXD), 115200 8N1. One record is one line,
in columns:

```text
   2.764772 INFO  boot     started by the EEPROM bootloader  medium=sd ram_mib=8192
   3.981022 WARN  net      no DHCP offer, retrying in 4 s  attempt=2
```

The time is right-aligned in eleven columns, the level takes five and the
target eight. Two spaces separate the message from the first field. A value
that is empty or holds a space, a control character, `"` or `=` is quoted, with
`"` and `\` escaped and control characters written as `\n` or `\xNN`, so a
line always splits back into its fields. Control characters in a message are
written as `\xNN`, so a file or variable name cannot send a terminal an escape
sequence:

```text
   2.764642 INFO  boot     nuboot 1a2b3c4  board="Raspberry Pi 4 Model B" revision=d03115 pcb=1.5 version=1793000000 release=none
```

Built with `--features color`, the level is coloured and the time and the
field names are dimmed with ANSI escapes.

Records at `INFO` and above are logged; `DEBUG` and `TRACE` records are not.
The runtime services log nothing while an OS runs. A panic and a thread that
runs off its stack end with an `ERROR` record on the console and stop the VPU:

```text
  12.004113 ERROR panic    index out of bounds: the len is 4 but the index is 4  at=src/firmware.rs:120
```

## On HDMI

Only the `hdmi` build has this: `scripts/build.sh --hdmi` leaves
`out/start4-hdmi.elf`, and the release `start4.elf` lights nothing. It is for a
board with no serial line to read. HDMI0, the micro-HDMI port next to the USB-C power port, shows the same lines
as text: white 8x8 characters drawn twice as tall, 240 columns by 67 rows at
1920x1080. When the text reaches the bottom the screen is cleared and the next
line starts at the top. The output is DVI-style RGB without audio. HDMI1 stays
dark.

The mode is the display's own: the first detailed timing in the base block of
its EDID that is progressive, has a pixel clock of 25 to 140 MHz and is at most
1920x1200. A display whose first timing is faster gets that resolution in
reduced-blanking timings (VESA CVT-RB at 60 Hz), 1920x1080 at 138.5 MHz for
1080p, or 1920x1080 when that resolution is too large as well. With no
display, or an EDID that does not check, the mode is 1280x720 at 60 Hz. The
output shows a ripple at 148.5 MHz on a Raspberry Pi 4B d03115, which is why
the limit is below it.
The EDID is read once, when the firmware
starts: a display plugged in later shows the mode chosen then.

The same framebuffer is the OS's console: UEFI gives it the framebuffer as a
`EFI_GRAPHICS_OUTPUT_PROTOCOL` ([uefi.md](uefi.md#what-it-provides)), with the
ACPI tables and the device tree alike, and a kernel with `efifb` or `simpledrm`
draws on it. `console=tty0` puts the kernel's log there.

## In the code

```rust
info!("sd", "card ready"; capacity_mb = 30436, kind = "SDHC");
warn!("net", "no DHCP offer, retrying in {} s", 4; attempt = 2);
debug!("sched", "switch"; state = log::dbg(&state));
```

The first argument is the target, then the message as `format_args!` takes
it, then, after a `;`, the fields. A field's value is anything that implements
`Display`; `log::dbg` wraps one that only implements `Debug`. Nothing is
formatted for a record below the current level.

A record is written whole: a thread that logs while another thread is
mid-line waits for it. An interrupt handler must not log.

Every record goes to the console and to each sink attached with
`log::attach`, at most four.

`tools/log-check` builds the renderer for the host; `scripts/test-tpm.sh` runs
its tests of the quoting and escaping.

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
that is empty or holds a space, `"` or `=` is quoted, with `"` and `\`
escaped, so a line always splits back into its fields:

```text
   2.764642 INFO  boot     pi4-server-firmware 1a2b3c4  board="Raspberry Pi 4 Model B" revision=d03115
```

Built with `--features color`, the level is coloured and the time and the
field names are dimmed with ANSI escapes.

Records at `INFO` and above are logged. A panic, and a thread that runs off
its stack, end with an `ERROR` record and stop the VPU:

```text
  12.004113 ERROR panic    index out of bounds: the len is 4 but the index is 4  at=src/bin/start4.rs:120
```

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
`log::attach`.

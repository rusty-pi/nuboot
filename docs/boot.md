# Boot

Raspberry Pi's EEPROM bootloader, as it ships, starts this firmware. It is
signed by Raspberry Pi, so a board with secure boot programmed in its OTP
accepts it, and nothing of this firmware is in the EEPROM. What this tree
builds is `start4.elf`: the VPU firmware, with the UEFI firmware and the
board's device tree inside it.

## Boot sequence

1. The boot ROM loads the bootloader out of the EEPROM, which brings up the
   SDRAM with its training firmware, reads its configuration from the EEPROM,
   and looks for `start4.elf` on the boot medium in the order `BOOT_ORDER`
   gives: the SD card, a USB drive or the network.
2. On a board with signed boot the bootloader takes `start4.elf` out of
   `boot.img`, whose signature `boot.sig` it checks against the customer key
   fused in the OTP.
3. It leaves the handover block (the SDRAM size, the boot medium, the
   watchdog's budget, and where it put `boot.img`) at ARM physical `0x40000` and
   enters `start4.elf` at its ELF entry point.
4. `start4.elf` looks for an update bundle that UEFI left in RAM at ARM
   physical `0x3e000000` before a reset. A bundle that an update key signed and
   that is newer than this firmware replaces it: the image goes to the update
   slot at `0x3ee00200` and starts as `start4.elf` does from here on
   ([updates.md](updates.md#updates-the-owner-does-not-sign)).
5. `start4.elf` reads `owner-db.der` out of the `boot.img`, if it started out
   of one ([Signed boot](#signed-boot)), and measures it.
6. It brings up the PCIe link, gives the VL805 its firmware out of the EEPROM's
   `vl805hub.bin` and `vl805mcu.bin` on a board that needs it, and puts the
   controller's registers in the outbound window at `0x6_0200_0000`.
7. It starts the ARM in UEFI ([uefi.md](uefi.md)).

## Signed boot

On a board with signed boot, the bootloader runs `start4.elf` only out of
`boot.img`, a FAT image on the boot medium, after checking `boot.sig` against
the RSA-2048 public key in the EEPROM's `pubkey.bin`, whose hash is fused in
the OTP. `boot.sig` holds the image's SHA-256, a timestamp and an RSA signature
over the image. `scripts/mkbootimg.py` writes both:

```bash
scripts/mkbootimg.py customer-private.pem out/start4.elf out
```

gives `out/boot.img` and `out/boot.sig`. With `--pubkey file` it also writes the
key as `pubkey.bin` has it, for `rpi-eeprom-config --pubkey` or, in pimu,
`eeprom_pubkey`. Signing the EEPROM's own configuration and programming the OTP
are Raspberry Pi's procedure ([secure-boot-recovery](https://github.com/raspberrypi/usbboot/tree/master/secure-boot-recovery)).

The signature covers every file in `boot.img`, so a file there is the owner's.
`owner-db.der`, a certificate, makes the UEFI firmware trust that certificate
for the images it runs, in place of its built-in `db`:

```bash
scripts/mkbootimg.py customer-private.pem out/start4.elf out --add owner.der:owner-db.der
```

`start4.elf` finds the `boot.img` the bootloader left in RAM through the `RDSK`
tag of the handover block, reads the file out of it before the ARM starts and
measures it into PCR 7 ([uefi.md](uefi.md#the-owners-db) has the format and the
rules). A board that boots from a medium with no `boot.img` has no such file.

## Boot watchdog

Every boot runs under the board's watchdog, with no setting of this firmware's to turn it off,
until the operating system's own driver for it (Linux's `bcm2835_wdt`) takes
it over. A hang anywhere before that resets the board.

| from | until | span |
|---|---|---|
| `start4.elf`'s start | the ARM is started | 30 s, or the bootloader's own `BOOT_WATCHDOG_TIMEOUT` when it armed one; beaten by the VPU |
| the ARM is started | `ExitBootServices` | 300 s, beaten by UEFI; a `SetWatchdogTimer` call starts a new span of the seconds it asks for, or of 300 s when it asks for none |
| `ExitBootServices` | the operating system's driver beats the dog | 120 s, beaten by the VPU |

The dog itself counts at most 16 s. When the ARM starts, `start4.elf` gives the
dog to it with a full reload, and UEFI reloads it from then on from the
hypervisor timer's interrupt every half second, while the span lasts. An
ARM that has stopped (a fault, a hang with interrupts masked, a core that never
ran) stops beating, and the board resets up to 16 s later whatever span was
asked for; one that is running but never returns from a payload is reset when
the span ends. At `ExitBootServices` UEFI stops the interrupt and tells
`start4.elf`, through the word at ARM physical `0xfc` in the armstub's page,
which takes the dog back and beats it for 120 s, the time a kernel has to load
`bcm2835_wdt`, a module in most distributions' kernels, and have it find the
dog running. The VPU stops reloading as soon as the dog has less than 8 s left
at a reload, which is the operating system having armed it with a timeout of its
own. A kernel that takes neither driver leaves the board to reset 120 s after
`ExitBootServices`.

An operating system that describes the board with the ACPI tables takes the
dog through the WDAT table instead, with the generic `wdat_wdt` driver every
distribution's arm64 kernel has. The table's registers are four words of a
page of the ARM's memory that the VPU serves ([`src/wdat.rs`](../src/wdat.rs)):
the control word (bit 0: running), the timeout in seconds, a reload word and
the seconds left. The page says the dog is running, with 120 s left, from
`ExitBootServices` on; the first word the driver writes to the timeout or the
reload is the operating system taking it over. From then on the VPU holds the
countdown the operating system set, reloads the board's dog while it has time
left, and asks the dog for a reset the moment it runs out; a stop through the
control word takes the dog off, and a start puts it back. A VPU that stops
looking stops reloading the dog, which resets the board within 16 s. A timeout
from 2 s to an hour is offered, and the page is clamped to that. The
device tree route is unchanged, so an operating system on the device tree still
needs `bcm2835_wdt`. The two never meet: the ACPI tables have no power manager
device for `bcm2835_wdt` to bind to, and a kernel that uses the device tree
ignores the WDAT table.

The timer is the EL2 hypervisor timer (`CNTHP`, GIC interrupt 26), routed to EL2
until `ExitBootServices`: a payload that uses either takes the beat from UEFI.
A reset with a short count that an operating system's own driver makes within
the 120 s after `ExitBootServices` is delayed if one of the VPU's reloads lands
in the 160 µs before it fires, which is rare. `ResetSystem`, which Linux's
`reboot` and `poweroff` call, asks for its count again as long as the board has
not reset.

## ARM clock and core voltage

The ARM runs at the rate the board is made for: 1800 MHz on a Raspberry Pi 400
and a 4B from rev 1.4, whose silicon and core PMIC take it, and 1500 MHz on the
other boards. Before the ARM starts, the VPU sets the core rail for that rate:

- It characterises the die. The SoC's speed monitors (24 ring oscillators and
  18 more in the PVT block) are read at two rail voltages, and the rail is set
  to the lowest voltage at which every monitor runs at its target speed, within
  0.835 to 1.1 V and above the floor of the die's process corner. The result is
  kept in the SoC across a reset, so only the first boot after power-up
  measures; a later one only trims the rail.
- The rail is that voltage, 880 mV plus what the characterisation added, plus
  3.3 mV for each percent of 1500 MHz the rate is above. The PMIC at `0x1E` runs
  in its fast mode above 600 MHz. The rail is read back, and the ARM stays at
  600 MHz, which needs no more than the base voltage, if it does not hold the
  setpoint or the board's power parts are not known.

Every 100 ms the monitor thread reads the SoC temperature and the PMICs' status
words. From 80 °C, or while any PMIC reports trouble with the power, it drops
the ARM to 600 MHz and the rail to match; it gives the rate back below 75 °C
with no trouble reported. The clock is the
VPU's: Linux has no clock service to read or change it, so the kernel's
`raspberrypi-cpufreq` finds none, and the OS's own thermal zone only has its
critical trip.

## Wake-on-LAN

When the OS powers the board off, the VPU firmware stays up and waits for a
magic packet on the Ethernet port. Linux's power off is a reset that ends in the
bootloader's halt, which nothing but GPIO 3 wakes from; this firmware sees the
power off coming and takes it instead of resetting.

- Linux's firmware driver sends `NOTIFY_REBOOT` as the last of the devices shuts
  down, before a reboot and before a power off. The firmware then watches
  `PM_RSTS` and `PM_RSTC` for up to five seconds for what a power off writes,
  through the firmware's `ResetSystem` or `bcm2835-wdt`: partition 63 (halt) and
  the watchdog armed for a full reset. A reboot writes another partition, and the
  board resets.
- On a power off the firmware takes the watchdog off before it expires and stops
  the ARM's clock. It resets the PCIe endpoint and powers the SerDes down, so the
  VL805 idles, and puts the VPU on the oscillator and stops the clock generators
  nothing uses. The Ethernet MAC and PHY are brought up at 10 or 100 Mbit/s,
  with both DMA engines off and the MAC's magic packet detector armed for the
  address the OS had (the one in the device tree, [uefi.md](uefi.md)). The power
  LED and the Ethernet port's LEDs go out, and the VPU sleeps and looks at the detector and at GPIO 3 every
  100 ms.
- A magic packet for that address, or GPIO 3 pulled low, takes the halt out of
  `PM_RSTS`, lights the LEDs again and resets the SoC, which boots as it does from
  power on.
- With no PHY or no link to wake from, the firmware arms the watchdog again with
  `PM_RSTS` as the OS left it, and the stock bootloader halts.

The boot partition the OS asked for with `reboot N` is taken out of `PM_RSTS`
when the firmware starts: the bootloader has acted on it, and a watchdog reset
after a boot that hangs goes to the default partition. An EEPROM section such as
`[partition=62]` therefore applies to one boot, as `tryboot` does.

In stand-by the board draws about 2.4 W at the wall on a Raspberry Pi 4B
`d03115`, against about 1.8 W in the stock bootloader's halt and 3.1 to 3.4 W
with Raspberry Pi OS idle. The stock halt comes before the bootloader starts the
PLLs and the SDRAM; this firmware runs from the SDRAM, which stays up.

Nothing in the OS needs setting: the OS does not know the board waits, and
powers off as it does without it.

An OS started on the ACPI tables has no firmware driver to send `NOTIFY_REBOOT`
(the tables do not describe the mailbox), so its power off ends in the
bootloader's halt.

The EEPROM's `POWER_OFF_ON_HALT` is not read. A power off the OS asks for
before the OS runs (UEFI's `ResetSystem` in boot services) halts in the
bootloader.

## Running it in pimu

[`scenarios/`](../scenarios/) holds the boots CI checks. Each one runs with
`pimu boot --scenario`:

```bash
pimu boot --scenario scenarios/sd-boot.yaml      # start4.elf alone, under the stock bootloader
pimu boot --scenario scenarios/signed-boot.yaml  # start4.elf out of a signed boot.img
pimu boot --scenario scenarios/uefi-hello.yaml   # a signed EFI application
pimu boot --eeprom out/stock-pieeprom.bin --sd boot/   # a directory holding start4.elf as the SD card
```

`scripts/run-scenarios.sh` boots several by name. The scenarios that run the
test applications boot `out/start4-test.elf` (`scripts/build.sh --test-keys`),
whose UEFI firmware also trusts the key they are signed with
([uefi.md](uefi.md#secure-boot)). The Linux scenarios need
`scripts/build-linux-test.sh` first.

## Property mailbox

The OS and UEFI reach the VPU through the property mailbox. It answers these
tags and no other. None returns a fuse.

| Tag | Channel | What |
|---|---|---|
| `0x00030048` | 8 | `NOTIFY_REBOOT`: starts the [watch for a power off](#wake-on-lan) |
| `0x00030064`, `0x00038064` | 8 | `GET_REBOOT_FLAGS`, `SET_REBOOT_FLAGS`; bit 0 is the one-shot tryboot request in `PM_RSTS`, which Linux's `reboot '0 tryboot'` sets |
| `0x00030058` | 8 | `NOTIFY_XHCI_RESET`: reload the VL805's firmware after the OS has reset the PCIe link |
| `0x00030041`, `0x00038041`, `0x00030043`, `0x00038043` | 8 | The GPIO expander's two SD pins, the card's power switch and signalling voltage select. The other pins belong to the radios, the power LED, the reset and the camera, and are not answered |
| `0x000300a3` | 8 | A TPM 2.0 command and its response |
| `0x000300a1`, `0x000300a4` | 8 | Extend a PCR; read an event the VPU measured before the ARM started |
| `0x0003008e` to `0x00030095`, `0x0003009c`, `0x0003809c` | 8 | The device key's signatures, HMACs and public key ([keystore.md](keystore.md#the-firmware-cryptography-service)) |
| none | 6 | The TPM's doorbell: the ACPI start method of the command response buffer, which makes the VPU run the command in the page at `0x3EBFF000` ([tpm2.md](tpm2.md#the-command-response-buffer)) |
| `0x000300a9` | 7 | Seal a variable's write; the runtime services keep it until `ResetSystem` |
| `0x000300aa`, `0x000300ac` | 7 | Power the SD card off and on, or reset the PCIe link and the VL805, so the runtime services can write the store at `ResetSystem` |
| `0x000300ad` | 7 | The outcome of that write, which the VPU logs because the ARM cannot |
| `0x000300ae` | 7, 8 | The next change to a TPM NV index, as a sealed record for the store |
| `0x000300af` | 8, UEFI only | Put an NV index back from a record; refused once UEFI has handed the board to the OS |
| `0x000300a8`, `0x000300ab` | 8 | The owner's `db` from `boot.img`; the medium the firmware was loaded from, which tells UEFI the disk the store is on |

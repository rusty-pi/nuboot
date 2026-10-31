# Boot

Raspberry Pi's EEPROM bootloader, as it ships, starts this firmware. It is
signed by Raspberry Pi, so a board with secure boot programmed in its OTP
accepts it, and nothing of this firmware is in the EEPROM except the variable
store. What this tree builds is `start4.elf`: the VPU firmware, with the UEFI
firmware and the board's device tree inside it.

## Boot

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

## What the EEPROM holds besides the bootloader

| from | what |
|---|---|
| `0x00000` | the bootloader's sections: the boot ROM's bootcode, `bootmain`, the SDRAM training firmware, `vl805hub.bin`, `vl805mcu.bin`, its configuration |
| `0x7fff8` | after an update, its time and the time's complement, which the ESRT reports as the EEPROM's version |

The sections end near `0x73068`. The firmware only reads the EEPROM: the
variable store is on the boot disk ([uefi.md](uefi.md#the-variable-store)).

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
  board resets as it did before.
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
  `PM_RSTS` as the OS left it, and the stock bootloader halts as it always has.

In stand-by the board draws about 2.4 W at the wall on a Raspberry Pi 4B
`d03115`, against about 1.8 W in the stock bootloader's halt and 3.1 to 3.4 W
with Raspberry Pi OS idle. The stock halt comes before the bootloader starts the
PLLs and the SDRAM; this firmware runs from the SDRAM, which stays up.

Nothing in the OS needs setting: the OS does not know the board waits, and
powers off as it does without it.

An OS started on the ACPI tables has no firmware driver to send `NOTIFY_REBOOT`
(the tables do not describe the mailbox), so its power off ends in the
bootloader's halt, as it did before.

The EEPROM's `POWER_OFF_ON_HALT` is not read. A power off the OS asks for
before the OS runs (UEFI's `ResetSystem` in boot services) halts in the
bootloader.

## Running it in pimu

```bash
pimu boot --scenario scenarios/sd-boot.yaml      # start4.elf alone, under the stock bootloader
pimu boot --scenario scenarios/signed-boot.yaml  # start4.elf out of a signed boot.img
pimu boot --scenario scenarios/signed-boot-refused.yaml  # boot.img signed by another key
pimu boot --scenario scenarios/uefi-hello.yaml   # a signed EFI application
pimu boot --scenario scenarios/shim-grub.yaml    # Ubuntu's shim, signed with the test key, and GRUB
pimu boot --scenario scenarios/secure-boot-refused.yaml  # an image not signed by a key in db
pimu boot --scenario scenarios/rev14-hello.yaml  # an EFI application on a 4B rev 1.4
pimu boot --scenario scenarios/usb-hello.yaml    # an EFI application off a USB drive
pimu boot --scenario scenarios/xhci-reset.yaml   # NOTIFY_XHCI_RESET over the property mailbox
pimu boot --scenario scenarios/reboot-flags.yaml  # the tryboot request over the property mailbox
pimu boot --scenario scenarios/gpio-tags.yaml     # the SD card's pins on the GPIO expander over the property mailbox
pimu boot --scenario scenarios/tpm2-commands.yaml  # TPM 2.0 commands on the VPU
pimu boot --scenario scenarios/capsule.yaml     # firmware update capsules on the card
pimu boot --scenario scenarios/capsule-stage.yaml   # a capsule written as tryboot.img and tryboot.sig
pimu boot --scenario scenarios/capsule-trial.yaml   # the updated firmware proves itself
pimu boot --scenario scenarios/capsule-commit.yaml  # the proven update becomes boot.img
pimu boot --scenario scenarios/capsule-drop.yaml    # an update that never reached the OS is dropped
pimu boot --scenario scenarios/capsule-eeprom-stage.yaml    # an EEPROM update staged
pimu boot --scenario scenarios/capsule-eeprom-updated.yaml  # after the bootloader made it
pimu boot --scenario scenarios/capsule-eeprom-failed.yaml   # an EEPROM update the bootloader did not make
pimu boot --scenario scenarios/runtime-variables.yaml  # variables through the runtime services
pimu boot --scenario scenarios/persist.yaml     # what the OS writes through them outlasts a reset
pimu boot --scenario scenarios/shutdown.yaml    # a shutdown through them ends in the bootloader's halt
pimu boot --scenario scenarios/store-compact.yaml  # the store has room again at the next boot
pimu boot --scenario scenarios/crypto.yaml      # the firmware cryptography service, locked from the OS
scripts/build-linux-test.sh && pimu boot --scenario scenarios/linux.yaml  # Debian's kernel, from its own initramfs, to a power off a magic packet wakes from
pimu boot --scenario scenarios/linux-acpi.yaml   # the same kernel with acpi=on
pimu boot --scenario scenarios/linux-no-dt.yaml  # and with an empty device tree, which it takes the ACPI tables for
pimu boot --scenario scenarios/watchdog-hang.yaml  # a hang in UEFI resets the board
pimu boot --scenario scenarios/watchdog-exit.yaml  # ExitBootServices hands the dog to the OS
pimu boot --eeprom out/stock-pieeprom.bin --sd boot/   # a directory holding start4.elf as the SD card
```

The scenarios that run the test applications boot `out/start4-test.elf`
(`scripts/build.sh --test-keys`), whose UEFI firmware also trusts the key
they are signed with ([uefi.md](uefi.md#secure-boot)).

## Known limitations

- On a board, only a Raspberry Pi 4B rev 1.5 (`d03115`) has run it, started by the stock EEPROM bootloader from the network; the rest
  is tested in pimu, which models the bootloader, including its signed boot
  ([README](../README.md#tested)).
- The property mailbox answers `NOTIFY_REBOOT` (which starts the [watch for a power off](#wake-on-lan)), `GET_REBOOT_FLAGS` and `SET_REBOOT_FLAGS` (bit 0 is the one-shot tryboot request in `PM_RSTS`, which Linux's `reboot '0 tryboot'` sets), `NOTIFY_XHCI_RESET` (reload the VL805's
  firmware after the OS has reset the PCIe link), the TPM 2.0 on the VPU (tag
  `0x000300a3` carries a command, `0x000300a1` extends a PCR) and the
  device key's signatures, HMACs and
  public key (`0x0003008e` to `0x00030095`, [keystore.md](keystore.md#the-firmware-cryptography-service)),
  and, on channel 6, the TPM's doorbell (the ACPI start method of the TPM's
  command response buffer, which makes the VPU run the command in the page at
  `0x3EBFF000`, [tpm2.md](tpm2.md#the-command-response-buffer)), and, on channel 7 for the
  runtime services, the store's `0x000300a9` (seal a variable's write) and
  `0x000300aa` (power the SD card off and on and hand its host back, so that the
  runtime services can write the store at `ResetSystem`), and, for the SD card's regulators, the GPIO expander's
  two SD pins (`0x00030041`, `0x00038041`, `0x00030043` and `0x00038043`: the
  card's power switch and its signalling voltage select), and no other tag. None
  returns a fuse. The expander's other pins, which belong to the radios, the
  power LED, the reset and the camera, are not answered.

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
   watchdog's budget) at ARM physical `0x40000` and enters `start4.elf` at its
   ELF entry point.
4. `start4.elf` brings up the PCIe link, gives the VL805 its firmware out of
   the EEPROM's `vl805hub.bin` and `vl805mcu.bin` on a board that needs it, and
   puts the controller's registers in the outbound window at `0x6_0200_0000`.
5. It starts the ARM in UEFI ([uefi.md](uefi.md)).

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

## What the EEPROM holds besides the bootloader

| from | what |
|---|---|
| `0x00000` | the bootloader's sections: the boot ROM's bootcode, `bootmain`, the SDRAM training firmware, `vl805hub.bin`, `vl805mcu.bin`, its configuration |
| `0x74000` | the variable store, two banks of 20 KiB ([uefi.md](uefi.md#the-variable-store)) |
| `0x7fff8` | after an update, its time and the time's complement, which the ESRT reports as the EEPROM's version |

The sections end near `0x73068`; the store sits in the flash that follows,
which the bootloader and its signature do not cover. Writing a whole new
`pieeprom.bin` clears the store.

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
own.

The timer is the EL2 hypervisor timer (`CNTHP`, GIC interrupt 26), routed to EL2
until `ExitBootServices`: a payload that uses either takes the beat from UEFI.
A reset with a short count that an operating system's own driver makes within
the 120 s after `ExitBootServices` is delayed if one of the VPU's reloads lands
in the 160 µs before it fires, which is rare. `ResetSystem`, which Linux's
`reboot` and `poweroff` call, asks for its count again as long as the board has
not reset.

## Running it in pimu

```bash
pimu boot --scenario scenarios/sd-boot.yaml      # start4.elf alone, under the stock bootloader
pimu boot --scenario scenarios/signed-boot.yaml  # start4.elf out of a signed boot.img
pimu boot --scenario scenarios/signed-boot-refused.yaml  # boot.img signed by another key
pimu boot --scenario scenarios/uefi-hello.yaml   # a signed EFI application
pimu boot --scenario scenarios/shim-grub.yaml    # Ubuntu's signed shim and GRUB
pimu boot --scenario scenarios/secure-boot-refused.yaml  # an image not signed by a key in db
pimu boot --scenario scenarios/rev14-hello.yaml  # an EFI application on a 4B rev 1.4
pimu boot --scenario scenarios/usb-hello.yaml    # an EFI application off a USB drive
pimu boot --scenario scenarios/xhci-reset.yaml   # NOTIFY_XHCI_RESET over the property mailbox
pimu boot --scenario scenarios/reboot-flags.yaml  # the tryboot request over the property mailbox
pimu boot --scenario scenarios/boot-key.yaml     # the boot key bound to PCR 4, once
pimu boot --scenario scenarios/boot-key-unbound.yaml    # bound to PCR 7
pimu boot --scenario scenarios/tpm2-commands.yaml  # TPM 2.0 commands on the VPU
pimu boot --scenario scenarios/capsule.yaml     # firmware update capsules on the card
pimu boot --scenario scenarios/capsule-stage.yaml   # a capsule written as tryboot.img and tryboot.sig
pimu boot --scenario scenarios/capsule-trial.yaml   # the updated firmware proves itself
pimu boot --scenario scenarios/capsule-commit.yaml  # the proven update becomes boot.img
pimu boot --scenario scenarios/capsule-drop.yaml    # an update that never reached the OS is dropped
pimu boot --scenario scenarios/capsule-eeprom-stage.yaml    # an EEPROM update staged, the store saved
pimu boot --scenario scenarios/capsule-eeprom-restore.yaml  # after it, the store put back
pimu boot --scenario scenarios/capsule-eeprom-failed.yaml   # an EEPROM update the bootloader did not make
pimu boot --scenario scenarios/runtime-variables.yaml  # variables through the runtime services
pimu boot --scenario scenarios/persist.yaml     # what the OS writes through them outlasts a reset
pimu boot --scenario scenarios/shutdown.yaml    # a shutdown through them ends in the bootloader's halt
pimu boot --scenario scenarios/store-compact.yaml  # the flash store has room again at the next boot
pimu boot --scenario scenarios/crypto.yaml      # the firmware cryptography service, locked from the OS
scripts/build-linux-test.sh && pimu boot --scenario scenarios/linux.yaml  # Debian's kernel, from its own initramfs
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
- The property mailbox answers `GET_REBOOT_FLAGS` and `SET_REBOOT_FLAGS` (bit 0 is the one-shot tryboot request in `PM_RSTS`, which Linux's `reboot '0 tryboot'` sets), `NOTIFY_XHCI_RESET` (reload the VL805's
  firmware after the OS has reset the PCIe link), the TPM 2.0 on the VPU (tag
  `0x000300a3` carries a command, `0x000300a1` extends a PCR) and the
  one-time boot key (tag `0x000300a0`) and the device key's signatures, HMACs and
  public key (`0x0003008e` to `0x00030095`, [keystore.md](keystore.md#the-firmware-cryptography-service)),
  and, on channel 6, the TPM's doorbell (the ACPI start method of the TPM's
  command response buffer, which makes the VPU run the command in the page at
  `0x3EBFF000`, [tpm2.md](tpm2.md#the-command-response-buffer)), and, on channel 7 for the
  runtime services, the store's `0x000300a6` (append the record of a signed
  `KEK`, `db` or `dbx` update as it is) and `0x000300a7` (seal and append a
  variable's write), and no other tag. None returns a fuse.
- The ARM runs at 600 MHz, the one rate the VPU sets.

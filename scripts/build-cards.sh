#!/usr/bin/env bash
# Build the card images of the scenarios that need a variable store, which only
# a GPT disk holds, and so are not the MBR card pimu makes of a list of files
# (scripts/mkcard.py): some start from a store an earlier boot left on the card
# (the tamper scenario's, and the capsule scenarios', which start from the record
# an update leaves), the others from a blank window. Run it
# after scripts/build-uefi.sh --test-apps, scripts/build.sh --test-keys and
# scripts/build-capsule-test.sh.
#
#   out/card-store-tamper.img            a store with damage in it
#   out/card-capsule-trial.img           the tryboot of an update that is pending
#   out/card-capsule-commit.img          the boot after an update proved itself
#   out/card-capsule-drop.img            an update that is pending, booted from
#                                        boot.img again
#   out/card-capsule-eeprom-failed.img   an EEPROM update the bootloader did not
#                                        make
#   out/card-capsule-eeprom-updated.img  one it made (the scenario's EEPROM is
#                                        out/pieeprom-stamped.bin)
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
out="$here/out"
card="$here/scripts/mkcard.py"

"$card" "$out/card-store-tamper.img" --store "$out/store-tamper.bin" \
  start4.elf="$out/start4-test.elf" EFI/BOOT/BOOTAA64.EFI="$out/store-tamper.efi"
"$card" "$out/card-capsule-trial.img" --store "$out/store-pending.bin" \
  boot.img="$out/boot-next.img" boot.sig="$out/boot-next.sig" EFI/BOOT/BOOTAA64.EFI="$out/watchdog-takeover.efi"
"$card" "$out/card-capsule-commit.img" --store "$out/store-proven.bin" \
  boot.img="$out/boot-test.img" boot.sig="$out/boot-test.sig" \
  tryboot.img="$out/boot-next.img" tryboot.sig="$out/boot-next.sig" EFI/BOOT/BOOTAA64.EFI="$out/hello.efi"
"$card" "$out/card-capsule-drop.img" --store "$out/store-pending.bin" \
  boot.img="$out/boot-test.img" boot.sig="$out/boot-test.sig" \
  tryboot.img="$out/boot-next.img" tryboot.sig="$out/boot-next.sig" EFI/BOOT/BOOTAA64.EFI="$out/hello.efi"
"$card" "$out/card-capsule-eeprom-failed.img" --store "$out/store-eeprom-pending.bin" \
  boot.img="$out/boot-test.img" boot.sig="$out/boot-test.sig" \
  tryboot.img="$out/boot-eeprom.img" tryboot.sig="$out/boot-eeprom.sig" EFI/BOOT/BOOTAA64.EFI="$out/hello.efi"
"$card" "$out/card-capsule-eeprom-updated.img" --store "$out/store-eeprom-pending.bin" \
  boot.img="$out/boot-test.img" boot.sig="$out/boot-test.sig" \
  tryboot.img="$out/boot-eeprom.img" tryboot.sig="$out/boot-eeprom.sig" EFI/BOOT/BOOTAA64.EFI="$out/hello.efi"

# Cards with a blank window, for the scenarios that need a variable store: the
# firmware lists the window at the first boot.
"$card" "$out/card-persist.img" \
  start4.elf="$out/start4-test.elf" EFI/BOOT/BOOTAA64.EFI="$out/persist.efi"
"$card" "$out/card-store.img" \
  start4.elf="$out/start4-test.elf" EFI/BOOT/BOOTAA64.EFI="$out/store-enroll.efi" enrolled.efi="$out/store-enrolled.efi" db-x.auth="$out/db-x.auth" db-bad.auth="$out/db-bad.auth"
"$card" "$out/card-store-compact.img" \
  start4.elf="$out/start4-test.elf" EFI/BOOT/BOOTAA64.EFI="$out/store-compact.efi"
"$card" "$out/card-capsule-stage.img" \
  boot.img="$out/boot-test.img" boot.sig="$out/boot-test.sig" EFI/BOOT/BOOTAA64.EFI="$out/hello.efi" EFI/UpdateCapsule/next.cap="$out/capsule-apply.cap"
"$card" "$out/card-capsule-eeprom-stage.img" \
  boot.img="$out/boot-test.img" boot.sig="$out/boot-test.sig" EFI/BOOT/BOOTAA64.EFI="$out/hello.efi" EFI/UpdateCapsule/eeprom.cap="$out/capsule-eeprom.cap"
"$card" "$out/card-watchdog-fault.img" \
  start4.elf="$out/start4-test.elf" EFI/BOOT/BOOTAA64.EFI="$out/watchdog-fault.efi"
"$card" "$out/card-watchdog-hang.img" \
  start4.elf="$out/start4-test.elf" EFI/BOOT/BOOTAA64.EFI="$out/watchdog-hang.efi"
"$card" "$out/card-watchdog-stuck.img" \
  start4.elf="$out/start4-test.elf" EFI/BOOT/BOOTAA64.EFI="$out/watchdog-stuck.efi"
"$card" "$out/card-watchdog-takeover.img" \
  start4.elf="$out/start4-test.elf" EFI/BOOT/BOOTAA64.EFI="$out/watchdog-takeover.efi"

# The update scenarios, which keep what they must remember in the store.
"$card" "$out/card-update-apply.img" \
  start4.elf="$out/start4-test.elf" EFI/BOOT/BOOTAA64.EFI="$out/watchdog-takeover.efi" EFI/UpdateCapsule/next.cap="$out/capsule-update.cap"
"$card" "$out/card-update-counting.img" \
  start4.elf="$out/start4-test.elf" EFI/BOOT/BOOTAA64.EFI="$out/watchdog-takeover.efi" nuboot-200.0.0+3.upd="$out/bundle-next.bin"
"$card" "$out/card-update-dropped.img" \
  start4.elf="$out/start4-test.elf" EFI/BOOT/BOOTAA64.EFI="$out/watchdog-takeover.efi" nuboot-200.1.0+0-3.upd="$out/bundle-next.bin" nuboot-200.0.0.upd="$out/bundle-next.bin"
"$card" "$out/card-update-refused.img" \
  start4.elf="$out/start4-test.elf" EFI/BOOT/BOOTAA64.EFI="$out/watchdog-takeover.efi" EFI/UpdateCapsule/next.cap="$out/capsule-update-stranger.cap"
"$card" "$out/card-owner-db-update.img" \
  boot.img="$out/boot-owner.img" boot.sig="$out/boot-owner.sig" EFI/BOOT/BOOTAA64.EFI="$out/hello-owner.efi" EFI/UpdateCapsule/next.cap="$out/capsule-update.cap"

# Debian's kernel, started by systemd-boot.
loader="$(mktemp)"
trap 'rm -f "$loader"' EXIT
printf 'timeout 0\nconsole-mode keep\n' >"$loader"
"$card" "$out/card-linux.img" \
  start4.elf="$out/start4-test.elf" EFI/BOOT/BOOTAA64.EFI="$out/systemd-bootaa64.efi" \
  EFI/Linux/linux-test.efi="$out/linux-test.efi" loader/loader.conf="$loader"
"$card" "$out/card-linux-acpi.img" \
  start4.elf="$out/start4-test.elf" EFI/BOOT/BOOTAA64.EFI="$out/systemd-bootaa64.efi" \
  EFI/Linux/linux-acpi-test.efi="$out/linux-acpi-test.efi" loader/loader.conf="$loader"
"$card" "$out/card-linux-no-dt.img" \
  start4.elf="$out/start4-test.elf" EFI/BOOT/BOOTAA64.EFI="$out/systemd-bootaa64.efi" \
  EFI/Linux/linux-no-dt-test.efi="$out/linux-no-dt-test.efi" loader/loader.conf="$loader"

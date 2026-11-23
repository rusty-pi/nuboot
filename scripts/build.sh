#!/bin/sh
# Build out/start4.elf, the VPU firmware Raspberry Pi's bootloader starts.
# `cargo build` (build.rs) builds what start4.elf hands the ARM: the UEFI image
# (scripts/build-uefi.sh) and the board's device tree. It also fetches
# out/stock-pieeprom.bin, the EEPROM image the scenarios boot.
#
# It also leaves out/start4-update.bin: the same firmware linked for the
# update slot, which scripts/mkbundle.py signs as an update.
#
# --hdmi builds out/start4-hdmi.elf: the firmware with the HDMI0 text console
# of the log (docs/logging.md), for a board with no serial line to read.
#
# --test-keys builds out/start4-test.elf instead, whose UEFI firmware also
# trusts the test key the scenarios' EFI applications are signed with
# (`cargo build --features test-keys`), and out/start4-update-test.bin, whose
# updates a test update key may also sign.
set -eu

# The stock EEPROM image the scenarios boot.
STOCK_URL="${STOCK_URL:-https://raw.githubusercontent.com/raspberrypi/rpi-eeprom/v2026.09.23-2711-0138c0/firmware-2711/latest/pieeprom-2026-08-04.bin}"
STOCK_SHA256="${STOCK_SHA256:-4bf80784983f7bd1013f880599cb8c37327fb2d84f93a08699e430d552cae693}"

# Download $2 to $1 unless it is there already with checksum $3.
fetch() {
  if ! echo "$3  $1" | sha256sum -c --quiet >/dev/null 2>&1; then
    curl -sSfL -o "$1" "$2"
    echo "$3  $1" | sha256sum -c --quiet
  fi
}

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

mkdir -p out
fetch out/stock-pieeprom.bin "$STOCK_URL" "$STOCK_SHA256"

suffix=""
test_suffix=""
features=""
while [ $# -gt 0 ]; do
  case "$1" in
    --test-keys) test_suffix="-test"; features="${features:+$features,}test-keys"; shift ;;
    --hdmi) features="${features:+$features,}hdmi"; shift ;;
    *) break ;;
  esac
done
suffix="$test_suffix"
case ",$features," in *,hdmi,*) suffix="$suffix-hdmi" ;; esac
cargo build --locked --release ${features:+--features "$features"} "$@"

mkdir -p out
# start4.elf goes on the medium without its debug information, but with the
# relocations the bootloader needs to place it lower for a USB boot.
toolchain/bin/vc4-elf-objcopy --strip-debug target/vc4-none-elf/release/start4 "out/start4$suffix.elf"
toolchain/bin/vc4-elf-size "out/start4$suffix.elf"
# The same firmware linked for the update slot, as the flat binary that
# scripts/mkbundle.py signs.
toolchain/bin/vc4-elf-objcopy -O binary target/vc4-none-elf/release/start4-update "out/start4-update$suffix.bin"
# The test build's extras: variable stores for the scenarios that start from
# what an earlier boot left (one with damage in it for the tamper scenario),
# and start4-test.elf as the signed boot.img of a board with
# signed boot, once with a key the EEPROM trusts (out/boot-test-pubkey.bin) and
# once with one it does not; and with the owner's db in it (owner-db.der, the
# CA scripts/build-uefi.sh --test-apps makes), and with a file in its place that
# is no certificate and one that is too long.
if [ -n "$test_suffix" ]; then
  mkdir -p out/test-keys
  for name in boot boot-stranger; do
    [ -f "out/test-keys/$name.key" ] || openssl genrsa -out "out/test-keys/$name.key" 2048 2>/dev/null
  done
  scripts/mkstore.py out/store-tamper.bin
  scripts/mkstore.py out/store-pending.bin --update pending 2147483000
  scripts/mkstore.py out/store-proven.bin --update proven 2147483000
  # An EEPROM update: the image the capsule carries as the update, the store
  # with the update under way, and the EEPROM after the bootloader made it,
  # stamped.
  scripts/mkbootimg.py out/test-keys/boot.key out/start4-test.elf out --prefix boot-eeprom --eeprom out/stock-pieeprom.bin:1790000001
  scripts/mkcapsule.py out/test-keys/db.key out/test-keys/db.crt 1790000001 out/capsule-eeprom.cap --class eeprom \
    --boot-img out/boot-eeprom.img --boot-sig out/boot-eeprom.sig
  scripts/mkstore.py out/store-eeprom-pending.bin --update pending 1790000001 --eeprom
  scripts/stampeeprom.py out/stock-pieeprom.bin out/pieeprom-stamped.bin 1790000001
  scripts/mkbootimg.py out/test-keys/boot.key out/start4-test.elf out --prefix boot-test --pubkey out/boot-test-pubkey.bin
  scripts/mkbootimg.py out/test-keys/boot-stranger.key out/start4-test.elf out --prefix boot-stranger
  # The EEPROM of a board with signed boot, with and without the request for
  # the firmware to fuse the device key, and the fuses it goes with (pimu's
  # otp_signed_boot reads out/boot-test-pubkey.bin).
  scripts/mksignedeeprom.py out/test-keys/boot.key out/stock-pieeprom.bin out/pieeprom-signed.bin BOOT_ORDER=0x1 BOOT_UART=1
  scripts/mksignedeeprom.py out/test-keys/boot.key out/stock-pieeprom.bin out/pieeprom-signed-provision.bin BOOT_ORDER=0x1 BOOT_UART=1 SIGNED_BOOT=1 NUBOOT_PROVISION_DEVICE_KEY=1
  echo 'not a certificate' >out/test-keys/owner-junk.der
  scripts/mkbootimg.py out/test-keys/boot.key out/start4-test.elf out --prefix boot-owner --add out/test-keys/owner.der:owner-db.der
  scripts/mkbootimg.py out/test-keys/boot.key out/start4-test.elf out --prefix boot-owner-junk --add out/test-keys/owner-junk.der:owner-db.der
  head -c 5000 /dev/zero >out/test-keys/owner-oversize.der
  scripts/mkbootimg.py out/test-keys/boot.key out/start4-test.elf out --prefix boot-owner-oversize --add out/test-keys/owner-oversize.der:owner-db.der
  # A 512 MiB FAT32 disk (MBR, one partition) with systemd-boot 262 and the
  # unified kernel image `system_1+3-0.efi` read-only, as systemd-sysupdate's
  # Mode=0444 leaves a file on a vfat file system.
  esp=out/esp-partition.tmp
  truncate -s 512M "$esp"
  mkfs.vfat -F 32 -n ESP "$esp" >/dev/null
  mmd -i "$esp" ::EFI ::EFI/BOOT ::EFI/Linux ::loader
  mcopy -i "$esp" out/start4-test.elf ::start4.elf
  mcopy -i "$esp" out/systemd-bootaa64-262.efi ::EFI/BOOT/BOOTAA64.EFI
  mcopy -i "$esp" out/uki.efi "::EFI/Linux/system_1+3-0.efi"
  printf 'timeout 0\nconsole-mode keep\n' | mcopy -i "$esp" - ::loader/loader.conf
  mattrib -i "$esp" +r "::EFI/Linux/system_1+3-0.efi"
  truncate -s 513M out/esp-read-only-entry.img
  printf 'label: dos\nstart=2048, size=1048576, type=c\n' | sfdisk -q out/esp-read-only-entry.img
  dd if="$esp" of=out/esp-read-only-entry.img bs=1M seek=1 conv=notrunc status=none
  rm -f "$esp"
fi

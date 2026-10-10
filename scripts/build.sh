#!/bin/sh
# Build out/pieeprom.bin: the first stage, the SDRAM training firmware and
# out/start4.elf, which carries what it hands the ARM: the UEFI image
# (scripts/build-uefi.sh) and the board's device tree.
set -eu

# Raspberry Pi's device tree for the Pi 4B, from the firmware release the
# scenarios boot.
DTB_URL="${DTB_URL:-https://raw.githubusercontent.com/raspberrypi/firmware/1.20260915/boot/bcm2711-rpi-4-b.dtb}"
DTB_SHA256="${DTB_SHA256:-75761b73c284e26623e4d1624bff13e67bce2ae620880efd81d6571a3739fcfb}"
# The stock EEPROM image the SDRAM training firmware is taken from.
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
scripts/build-uefi.sh
fetch out/bcm2711-rpi-4-b.dtb "$DTB_URL" "$DTB_SHA256"
fetch out/stock-pieeprom.bin "$STOCK_URL" "$STOCK_SHA256"

cargo build --release "$@"

mkdir -p out
# start4.elf goes on the medium without its debug information, but with the
# relocations the bootloader needs to place it lower for a USB boot.
toolchain/bin/vc4-elf-objcopy --strip-debug target/vc4-none-elf/release/start4 out/start4.elf
toolchain/bin/vc4-elf-size out/start4.elf
toolchain/bin/vc4-elf-objcopy -O binary target/vc4-none-elf/release/bootcode out/bootcode.bin
scripts/mkeeprom.py out/bootcode.bin out/start4.elf out/stock-pieeprom.bin out/pieeprom.bin

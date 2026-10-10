#!/bin/sh
# Build out/start4.elf, with what it hands the ARM inside it: the UEFI image
# (scripts/build-uefi.sh) and the board's device tree.
set -eu

# Raspberry Pi's device tree for the Pi 4B, from the firmware release the
# scenarios boot.
DTB_URL="${DTB_URL:-https://raw.githubusercontent.com/raspberrypi/firmware/1.20260915/boot/bcm2711-rpi-4-b.dtb}"
DTB_SHA256="${DTB_SHA256:-75761b73c284e26623e4d1624bff13e67bce2ae620880efd81d6571a3739fcfb}"

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

mkdir -p out
scripts/build-uefi.sh
dtb=out/bcm2711-rpi-4-b.dtb
if ! echo "$DTB_SHA256  $dtb" | sha256sum -c --quiet >/dev/null 2>&1; then
  curl -sSfL -o "$dtb" "$DTB_URL"
  echo "$DTB_SHA256  $dtb" | sha256sum -c --quiet
fi

cargo build --release "$@"

mkdir -p out
# start4.elf goes on the medium without its debug information, but with the
# relocations the bootloader needs to place it lower for a USB boot.
toolchain/bin/vc4-elf-objcopy --strip-debug target/vc4-none-elf/release/start4 out/start4.elf
toolchain/bin/vc4-elf-size out/start4.elf

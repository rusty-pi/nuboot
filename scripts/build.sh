#!/bin/sh
# Build out/pieeprom.bin: the first stage, the SDRAM training firmware and
# out/start4.elf. `cargo build` (build.rs) builds what start4.elf hands the
# ARM: the UEFI image (scripts/build-uefi.sh) and the board's device tree.
#
# --test-keys builds out/pieeprom-test.bin and out/start4-test.elf instead,
# whose UEFI firmware also trusts the test key the scenarios' EFI
# applications are signed with (`cargo build --features test-keys`).
set -eu

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
fetch out/stock-pieeprom.bin "$STOCK_URL" "$STOCK_SHA256"

suffix=""
if [ "${1:-}" = "--test-keys" ]; then
  shift
  suffix="-test"
  set -- --features test-keys "$@"
fi
cargo build --release "$@"

mkdir -p out
# start4.elf goes on the medium without its debug information, but with the
# relocations the bootloader needs to place it lower for a USB boot.
toolchain/bin/vc4-elf-objcopy --strip-debug target/vc4-none-elf/release/start4 "out/start4$suffix.elf"
toolchain/bin/vc4-elf-size "out/start4$suffix.elf"
toolchain/bin/vc4-elf-objcopy -O binary target/vc4-none-elf/release/bootcode out/bootcode.bin
scripts/mkeeprom.py out/bootcode.bin "out/start4$suffix.elf" out/stock-pieeprom.bin "out/pieeprom$suffix.bin"
# The tamper scenario's image: a variable store with damage in it.
if [ -n "$suffix" ]; then
  scripts/mkstore.py "out/pieeprom$suffix.bin" out/pieeprom-tamper.bin
fi

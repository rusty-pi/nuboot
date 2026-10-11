#!/bin/sh
# Build out/start4.elf, the VPU firmware Raspberry Pi's bootloader starts.
# `cargo build` (build.rs) builds what start4.elf hands the ARM: the UEFI image
# (scripts/build-uefi.sh) and the board's device tree. It also fetches
# out/stock-pieeprom.bin, the EEPROM image the scenarios boot.
#
# --test-keys builds out/start4-test.elf instead, whose UEFI firmware also
# trusts the test key the scenarios' EFI applications are signed with
# (`cargo build --features test-keys`).
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
# The test build's extras: the tamper scenario's EEPROM image, a variable store
# with damage in it, and start4-test.elf as the signed boot.img of a board with
# signed boot, once with a key the EEPROM trusts (out/boot-test-pubkey.bin) and
# once with one it does not.
if [ -n "$suffix" ]; then
  scripts/mkstore.py out/stock-pieeprom.bin out/pieeprom-tamper.bin
  scripts/mkstore.py out/stock-pieeprom.bin out/pieeprom-pending.bin --update pending 2147483000
  scripts/mkstore.py out/stock-pieeprom.bin out/pieeprom-proven.bin --update proven 2147483000
  # An EEPROM update: the image the capsule carries as the update, the EEPROM
  # before it with the update under way, the store it was staged with, and the
  # EEPROM after it, stamped and with an empty store.
  scripts/mkbootimg.py out/test-keys/boot.key out/start4-test.elf out --prefix boot-eeprom --eeprom out/stock-pieeprom.bin:1790000001
  scripts/mkcapsule.py out/test-keys/db.key out/test-keys/db.crt 1790000001 out/capsule-eeprom.cap --class eeprom \
    --boot-img out/boot-eeprom.img --boot-sig out/boot-eeprom.sig
  scripts/mkstore.py out/stock-pieeprom.bin out/pieeprom-eeprom-pending.bin --update pending 1790000001 --eeprom --backup out/store-eeprom.bak
  scripts/mkstore.py out/stock-pieeprom.bin out/pieeprom-stamped.bin --stamp 1790000001 --empty
  mkdir -p out/test-keys
  for name in boot boot-stranger; do
    [ -f "out/test-keys/$name.key" ] || openssl genrsa -out "out/test-keys/$name.key" 2048 2>/dev/null
  done
  scripts/mkbootimg.py out/test-keys/boot.key out/start4-test.elf out --prefix boot-test --pubkey out/boot-test-pubkey.bin
  scripts/mkbootimg.py out/test-keys/boot-stranger.key out/start4-test.elf out --prefix boot-stranger
fi

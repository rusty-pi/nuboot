#!/bin/sh
# Build out/start4.elf.
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

cargo build --release "$@"

mkdir -p out
# start4.elf goes on the medium without its debug information, but with the
# relocations the bootloader needs to place it lower for a USB boot.
toolchain/bin/vc4-elf-objcopy --strip-debug target/vc4-none-elf/release/start4 out/start4.elf
toolchain/bin/vc4-elf-size out/start4.elf

#!/bin/sh
# Build rustc_codegen_gcc against the libgccjit in $VC4_PREFIX, either from
# scripts/build-toolchain.sh or from the vc4-elf-binutils and vc4-elf-gcc
# packages (VC4_PREFIX=/opt/vc4).
set -eu

VC4_PREFIX="${VC4_PREFIX:-$HOME/.local/opt/vc4}"
CG_GCC_DIR="${CG_GCC_DIR:-$HOME/src/rustc_codegen_gcc}"
# Where it is cloned from if it is not there yet; CI has no SSH key, so it
# passes https://github.com/ instead.
CLONE_BASE="${CLONE_BASE:-git@github.com:}"
# The rustc_codegen_gcc commit the GCC port and rust-toolchain.toml match.
CG_GCC_REV="${CG_GCC_REV:-529a10db7c972bf2dfcf587f3d75cac299f15e5c}"

if [ ! -d "$CG_GCC_DIR" ]; then
  git clone "${CLONE_BASE}rust-lang/rustc_codegen_gcc.git" "$CG_GCC_DIR"
  git -C "$CG_GCC_DIR" checkout -q "$CG_GCC_REV"
fi

cd "$CG_GCC_DIR"
printf 'gcc-path = "%s/lib"\n' "$VC4_PREFIX" > config.toml
./y.sh build --release

#!/bin/sh
# Build the VC4 cross toolchain rustc_codegen_gcc needs -- binutils, GCC (C and
# libgccjit) and libgcc, all into $VC4_PREFIX -- then rustc_codegen_gcc itself.
# On Ubuntu 26.04 the binutils-vc4 and rust-gcc-vc4 releases carry the first
# part prebuilt; see README.md.
set -eu

scripts="$(cd "$(dirname "$0")" && pwd)"
VC4_PREFIX="${VC4_PREFIX:-$HOME/.local/opt/vc4}"
BINUTILS_SRC="${BINUTILS_SRC:-$HOME/src/binutils-vc4}"
GCC_SRC="${GCC_SRC:-$HOME/src/gcc-vc4}"
BUILD_DIR="${BUILD_DIR:-$HOME/src/vc4-build}"
JOBS="${JOBS:-$(nproc)}"
# Where missing sources are cloned from.
CLONE_BASE="${CLONE_BASE:-git@github.com:}"

[ -d "$BINUTILS_SRC" ] ||
  git clone --depth 1 -b vc4-2.46.1 "${CLONE_BASE}rusty-pi/binutils-vc4.git" "$BINUTILS_SRC"
[ -d "$GCC_SRC" ] ||
  git clone --depth 1 -b vc4-rust "${CLONE_BASE}rusty-pi/gcc-vc4.git" "$GCC_SRC"

mkdir -p "$BUILD_DIR/binutils" "$BUILD_DIR/gcc"

cd "$BUILD_DIR/binutils"
"$BINUTILS_SRC/configure" --target=vc4-elf --prefix="$VC4_PREFIX" \
  --disable-nls --disable-werror --disable-gdb --disable-gdbserver \
  --disable-sim --disable-gprofng
make -j"$JOBS"
make install

# GCC has to be configured after binutils is installed: it probes the
# assembler, and libgcc doesn't build without one.
cd "$BUILD_DIR/gcc"
"$GCC_SRC/configure" --target=vc4-elf --prefix="$VC4_PREFIX" \
  --with-as="$VC4_PREFIX/bin/vc4-elf-as" --with-ld="$VC4_PREFIX/bin/vc4-elf-ld" \
  --enable-languages=c,jit --enable-host-shared --disable-bootstrap \
  --disable-multilib --without-headers --with-newlib --disable-nls \
  --disable-shared --disable-threads --disable-libssp --disable-libquadmath \
  --disable-libatomic --disable-libgomp --disable-lto --disable-libstdcxx \
  --enable-checking=release --disable-werror
make -j"$JOBS" all-gcc all-target-libgcc
make install-gcc install-target-libgcc

export VC4_PREFIX CLONE_BASE
"$scripts/build-codegen.sh"

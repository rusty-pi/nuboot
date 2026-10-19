#!/bin/sh
# Build rustc_codegen_gcc against the libgccjit in $VC4_PREFIX, either from
# scripts/build-toolchain.sh or from the vc4-elf-binutils and vc4-elf-gcc
# packages (VC4_PREFIX=/opt/vc4).
set -eu

. "$(cd "$(dirname "$0")" && pwd)/toolchain.env"
VC4_PREFIX="${VC4_PREFIX:-$HOME/.local/opt/vc4}"
CG_GCC_DIR="${CG_GCC_DIR:-$HOME/src/rustc_codegen_gcc}"
# Where it is cloned from if it is not there yet; CI has no SSH key, so it
# passes https://github.com/ instead.
CLONE_BASE="${CLONE_BASE:-git@github.com:}"

if [ ! -d "$CG_GCC_DIR" ]; then
  git clone "${CLONE_BASE}rust-lang/rustc_codegen_gcc.git" "$CG_GCC_DIR"
  git -C "$CG_GCC_DIR" checkout -q "$CG_GCC_REV"
fi

want="$(git -C "$CG_GCC_DIR" show "$CG_GCC_REV:libgccjit.version")"
have="$(curl -fsSL "https://github.com/rusty-pi/gcc-vc4/releases/download/$GCC_VC4_TAG/libgccjit-base")"
if [ "$have" != "$want" ]; then
  echo "error: gcc-vc4 $GCC_VC4_TAG is built on libgccjit $have, but rustc_codegen_gcc $CG_GCC_REV needs $want; bump GCC_VC4_TAG and CG_GCC_REV in scripts/toolchain.env together" >&2
  exit 1
fi

cd "$CG_GCC_DIR"
printf 'gcc-path = "%s/lib"\n' "$VC4_PREFIX" > config.toml
./y.sh build --release

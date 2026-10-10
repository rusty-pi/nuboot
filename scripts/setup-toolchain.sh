#!/bin/sh
# Point ./toolchain at a VC4 GCC install (with libgccjit) and a
# rustc_codegen_gcc build, which .cargo/config.toml uses.
set -eu

VC4_PREFIX="${VC4_PREFIX:-$HOME/.local/opt/vc4}"
CG_GCC_DIR="${CG_GCC_DIR:-$HOME/src/rustc_codegen_gcc}"

root="$(cd "$(dirname "$0")/.." && pwd)"
host="$(rustc -vV | sed -n 's/^host: //p')"
tc="$root/toolchain"
jitdir="$tc/sysroot/lib/rustlib/$host/codegen-backends/lib/vc4-none-elf"

mkdir -p "$tc/bin" "$jitdir"
for tool in gcc objcopy objdump size; do
  ln -sfn "$VC4_PREFIX/bin/vc4-elf-$tool" "$tc/bin/vc4-elf-$tool"
done
ln -sfn "$VC4_PREFIX/lib/libgccjit.so" "$jitdir/libgccjit.so"
ln -sfn "$CG_GCC_DIR/target/release/librustc_codegen_gcc.so" "$tc/librustc_codegen_gcc.so"

for f in "$tc/bin/vc4-elf-gcc" "$jitdir/libgccjit.so" "$tc/librustc_codegen_gcc.so"; do
  [ -e "$f" ] || echo "warning: $f -> $(readlink "$f") does not exist yet" >&2
done

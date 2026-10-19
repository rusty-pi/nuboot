#!/bin/sh
# Install the vc4-elf-binutils and vc4-elf-gcc packages scripts/toolchain.env
# pins into /opt/vc4, unless that exact pair is installed already.
set -eu

scripts="$(cd "$(dirname "$0")" && pwd)"
. "$scripts/toolchain.env"
VC4_PREFIX=/opt/vc4

installed() {
  dpkg-query -W -f='${Version}' "$1" 2>/dev/null | grep -q "\.${2#vc4-}\$"
}

# Not just the exit status: a binary the loader refuses ("CPU ISA level is
# lower than required") still leaves it 0.
if installed vc4-elf-binutils "$BINUTILS_VC4_TAG" && installed vc4-elf-gcc "$GCC_VC4_TAG" &&
  "$VC4_PREFIX/bin/vc4-elf-as" --version 2>/dev/null | grep -q "GNU assembler"; then
  echo "vc4-elf-binutils $BINUTILS_VC4_TAG and vc4-elf-gcc $GCC_VC4_TAG in $VC4_PREFIX"
  exit 0
fi

# libgccjit finds its assembler under the prefix it was built for, so the
# packages cannot simply be unpacked elsewhere.
if ! sudo -n true 2>/dev/null; then
  echo "error: $VC4_PREFIX does not have binutils $BINUTILS_VC4_TAG and gcc $GCC_VC4_TAG, and installing them needs sudo" >&2
  exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl -fsSL -o "$tmp/vc4-elf-binutils.deb" \
  "https://github.com/rusty-pi/binutils-vc4/releases/download/$BINUTILS_VC4_TAG/vc4-elf-binutils.deb"
curl -fsSL -o "$tmp/vc4-elf-gcc.deb" \
  "https://github.com/rusty-pi/gcc-vc4/releases/download/$GCC_VC4_TAG/vc4-elf-gcc.deb"
(cd "$tmp" && sha256sum -c - <<SUMS
$BINUTILS_VC4_SHA256  vc4-elf-binutils.deb
$GCC_VC4_SHA256  vc4-elf-gcc.deb
SUMS
)
sudo apt-get install -y --no-install-recommends --allow-downgrades \
  "$tmp/vc4-elf-binutils.deb" "$tmp/vc4-elf-gcc.deb"

#!/usr/bin/env bash
# Build the UEFI payload into out/pi4-uefi.bin, and with --test-apps also what
# uefi/scenarios/ boot it with:
#
#   out/hello.efi     CrabEFI's minimal test application
#   out/grubaa64.efi  Ubuntu's signed GRUB for arm64
#
# Extra arguments go to cargo (`--features secure-boot`). Needs rustup and
# llvm-objcopy (rustup's llvm-tools component provides one).
set -euo pipefail

GRUB_DEB="${GRUB_DEB:-pool/main/g/grub2-signed/grub-efi-arm64-signed_1.202.5+2.12-1ubuntu7.3_arm64.deb}"
GRUB_SHA256="${GRUB_SHA256:-728d506c28c56d3e4372f5f5b143d837d96b202c82ed05cbbd3ec27a5d4de955}"

here="$(cd "$(dirname "$0")/.." && pwd)"
out="$here/out"
test_apps=0
cargo_args=()
for arg in "$@"; do
  case "$arg" in
    --test-apps) test_apps=1 ;;
    *) cargo_args+=("$arg") ;;
  esac
done
mkdir -p "$out"

objcopy() {
  if command -v llvm-objcopy >/dev/null; then
    llvm-objcopy "$@"
  else
    (cd "$here/uefi" && "$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin/llvm-objcopy" "$@")
  fi
}

"$here/scripts/fetch-crabefi.sh"
(cd "$here/uefi" && cargo build --release "${cargo_args[@]}")
objcopy -O binary "$here/uefi/target/aarch64-unknown-none/release/pi4-uefi" "$out/pi4-uefi.bin"
echo "out/pi4-uefi.bin: $(stat -c %s "$out/pi4-uefi.bin") bytes"

[[ $test_apps == 1 ]] || exit 0

hello="$here/third_party/crabefi/test-apps/hello"
(cd "$hello" && rustup target add aarch64-unknown-uefi >/dev/null &&
  cargo build --release --target aarch64-unknown-uefi)
cp "$hello/target/aarch64-unknown-uefi/release/hello-efi.efi" "$out/hello.efi"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl -sSfL -o "$tmp/grub.deb" "https://ports.ubuntu.com/ubuntu-ports/$GRUB_DEB"
echo "$GRUB_SHA256  $tmp/grub.deb" | sha256sum -c --quiet
(cd "$tmp" && ar x grub.deb && tar xf data.tar.*)
cp "$tmp/usr/lib/grub/arm64-efi-signed/grubaa64.efi.signed" "$out/grubaa64.efi"

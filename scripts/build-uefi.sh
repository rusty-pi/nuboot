#!/usr/bin/env bash
# Build the UEFI firmware into out/pi4-uefi.bin, and with --test-apps also the
# EFI applications the scenarios boot with it:
#
# out/pi4-uefi.bin is the image the ARM cores start in (uefi/stub/: an
# armstub, then the payload coded with xz's ARM64 filter and LZMA);
# out/pi4-uefi-payload.bin is the payload as it runs. scripts/build.sh puts
# out/pi4-uefi.bin inside start4.elf.
#
#   out/hello.efi     CrabEFI's minimal test application
#   out/watchdog-hang.efi, out/watchdog-exit.efi
#                     uefi/test-apps/watchdog: hang in boot services, and
#                     exit them as an OS loader does
#   out/xhci-reset.efi
#                     uefi/test-apps/mailbox: ask over the property mailbox
#                     for the VL805's firmware to be reloaded, as Linux does
#   out/grubaa64.efi  Ubuntu's signed GRUB for arm64
#
# Extra arguments go to cargo (`--features secure-boot`). Needs rustup, xz and
# llvm-objcopy and llvm-nm (rustup's llvm-tools component provides them).
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

# The LZMA literal/position bits that suit AArch64 code: lc=1, lp=2, pb=2.
LZMA_OPTS="preset=9e,lc=1,lp=2,pb=2"
LZMA_PROPS=$(((2 * 5 + 2) * 9 + 1))

llvm() {
  local tool="$1"
  shift
  if command -v "llvm-$tool" >/dev/null; then
    "llvm-$tool" "$@"
  else
    (cd "$here/uefi" && "$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin/llvm-$tool" "$@")
  fi
}

symbol() {
  llvm nm "$1" | awk -v name="$2" '$3 == name { print "0x" $1 }'
}

"$here/scripts/fetch-crabefi.sh"
(cd "$here/uefi" && cargo build --release "${cargo_args[@]}")
elf="$here/uefi/target/aarch64-unknown-none/release/pi4-uefi"
llvm objcopy -O binary "$elf" "$out/pi4-uefi-payload.bin"
xz -c --format=raw --arm64 --lzma1="$LZMA_OPTS" "$out/pi4-uefi-payload.bin" >"$out/pi4-uefi-payload.lzma"

(cd "$here/uefi/stub" &&
  PI4_UEFI_LZMA="$out/pi4-uefi-payload.lzma" \
  PI4_UEFI_PROPS="$LZMA_PROPS" \
  PI4_UEFI_LEN="$(stat -c %s "$out/pi4-uefi-payload.bin")" \
  PI4_UEFI_BASE="$(symbol "$elf" _start)" \
  PI4_UEFI_END="$(symbol "$elf" _deferred_buffer_end)" \
    cargo build --release)
llvm objcopy -O binary "$here/uefi/stub/target/aarch64-unknown-none/release/pi4-uefi-stub" "$out/pi4-uefi.bin"
echo "out/pi4-uefi-payload.bin: $(stat -c %s "$out/pi4-uefi-payload.bin") bytes"
echo "out/pi4-uefi.bin: $(stat -c %s "$out/pi4-uefi.bin") bytes"

[[ $test_apps == 1 ]] || exit 0

hello="$here/third_party/crabefi/test-apps/hello"
(cd "$hello" && rustup target add aarch64-unknown-uefi >/dev/null &&
  cargo build --release --target aarch64-unknown-uefi)
cp "$hello/target/aarch64-unknown-uefi/release/hello-efi.efi" "$out/hello.efi"

wd="$here/uefi/test-apps/watchdog"
(cd "$wd" && cargo build --release --target aarch64-unknown-uefi)
cp "$wd/target/aarch64-unknown-uefi/release/hang.efi" "$out/watchdog-hang.efi"
cp "$wd/target/aarch64-unknown-uefi/release/exit.efi" "$out/watchdog-exit.efi"

mb="$here/uefi/test-apps/mailbox"
(cd "$mb" && cargo build --release --target aarch64-unknown-uefi)
cp "$mb/target/aarch64-unknown-uefi/release/xhci-reset.efi" "$out/xhci-reset.efi"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl -sSfL -o "$tmp/grub.deb" "https://ports.ubuntu.com/ubuntu-ports/$GRUB_DEB"
echo "$GRUB_SHA256  $tmp/grub.deb" | sha256sum -c --quiet
(cd "$tmp" && ar x grub.deb && tar xf data.tar.*)
cp "$tmp/usr/lib/grub/arm64-efi-signed/grubaa64.efi.signed" "$out/grubaa64.efi"

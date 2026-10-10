#!/usr/bin/env bash
# Build the UEFI firmware into out/pi4-uefi.bin, and with --test-apps also the
# EFI applications the scenarios boot with it:
#
# out/pi4-uefi.bin is the image the ARM cores start in (uefi/stub/: an
# armstub, then the payload coded with xz's ARM64 filter and LZMA);
# out/pi4-uefi-payload.bin is the payload as it runs. scripts/build.sh puts
# out/pi4-uefi.bin inside start4.elf.
#
# --test-keys builds out/pi4-uefi-test.bin instead, which also trusts the
# test key in out/test-keys/ (generated on first use). --test-apps signs the
# applications with that key:
#
#   out/hello.efi     uefi/test-apps/hello: checks a few of the firmware's
#                     services and says what it found
#   out/watchdog-hang.efi, out/watchdog-exit.efi
#                     uefi/test-apps/watchdog: hang in boot services, and
#                     exit them as an OS loader does
#   out/xhci-reset.efi
#                     uefi/test-apps/mailbox: ask over the property mailbox
#                     for the VL805's firmware to be reloaded, as Linux does
#   out/shimaa64.efi, out/grubaa64.efi
#                     Ubuntu's shim, signed by Microsoft, and its GRUB,
#                     signed by Canonical
#
# Extra arguments go to cargo. Needs rustup, xz, openssl, llvm-objcopy and
# llvm-nm (rustup's llvm-tools component provides them), and sbsign
# (sbsigntool) for --test-apps.
set -euo pipefail

GRUB_DEB="${GRUB_DEB:-pool/main/g/grub2-signed/grub-efi-arm64-signed_1.202.5+2.12-1ubuntu7.3_arm64.deb}"
GRUB_SHA256="${GRUB_SHA256:-728d506c28c56d3e4372f5f5b143d837d96b202c82ed05cbbd3ec27a5d4de955}"
SHIM_DEB="${SHIM_DEB:-pool/main/s/shim-signed/shim-signed_1.58+15.8-0ubuntu1_arm64.deb}"
SHIM_SHA256="${SHIM_SHA256:-58b0f8a0f43bdff2122af8f52b05a5eb73b1964079e36e3eed8d06b4d5164917}"

here="$(cd "$(dirname "$0")/.." && pwd)"
out="$here/out"
test_apps=0
test_keys=0
cargo_args=()
for arg in "$@"; do
  case "$arg" in
    --test-apps) test_apps=1 ;;
    --test-keys) test_keys=1 ;;
    *) cargo_args+=("$arg") ;;
  esac
done
mkdir -p "$out"

# The test key: a self-signed certificate the test build puts in db.
keys="$out/test-keys"
test_key() {
  [[ -f "$keys/db.key" && -f "$keys/db.der" ]] && return
  mkdir -p "$keys"
  openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 3650 \
    -subj "/CN=pi4-server-firmware test key" \
    -keyout "$keys/db.key" -out "$keys/db.crt" 2>/dev/null
  openssl x509 -in "$keys/db.crt" -outform DER -out "$keys/db.der"
}
suffix=""
test_cert=""
if [[ $test_keys == 1 ]]; then
  test_key
  suffix="-test"
  test_cert="$keys/db.der"
fi

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

(cd "$here/uefi" &&
  FIRMWARE_COMMIT="$(git -C "$here" rev-parse --short=7 HEAD 2>/dev/null || echo 0000000)" \
  PI4_UEFI_TEST_CERT="$test_cert" \
    cargo build --release "${cargo_args[@]}")
elf="$here/uefi/target/aarch64-unknown-none/release/pi4-uefi"
llvm objcopy -O binary "$elf" "$out/pi4-uefi$suffix-payload.bin"
xz -c --format=raw --arm64 --lzma1="$LZMA_OPTS" "$out/pi4-uefi$suffix-payload.bin" >"$out/pi4-uefi$suffix-payload.lzma"

(cd "$here/uefi/stub" &&
  PI4_UEFI_LZMA="$out/pi4-uefi$suffix-payload.lzma" \
  PI4_UEFI_PROPS="$LZMA_PROPS" \
  PI4_UEFI_LEN="$(stat -c %s "$out/pi4-uefi$suffix-payload.bin")" \
  PI4_UEFI_BASE="$(symbol "$elf" _start)" \
  PI4_UEFI_END="$(symbol "$elf" _end)" \
    cargo build --release)
llvm objcopy -O binary "$here/uefi/stub/target/aarch64-unknown-none/release/pi4-uefi-stub" "$out/pi4-uefi$suffix.bin"
echo "out/pi4-uefi$suffix-payload.bin: $(stat -c %s "$out/pi4-uefi$suffix-payload.bin") bytes"
echo "out/pi4-uefi$suffix.bin: $(stat -c %s "$out/pi4-uefi$suffix.bin") bytes"

[[ $test_apps == 1 ]] || exit 0

test_key
# Sign with the test key: $1 the unsigned image, $2 where it goes.
sign() {
  sbsign --key "$keys/db.key" --cert "$keys/db.crt" --output "$2" "$1" 2>/dev/null
}

hello="$here/uefi/test-apps/hello"
(cd "$hello" && rustup target add aarch64-unknown-uefi >/dev/null &&
  cargo build --release --target aarch64-unknown-uefi)
sign "$hello/target/aarch64-unknown-uefi/release/hello.efi" "$out/hello.efi"

wd="$here/uefi/test-apps/watchdog"
(cd "$wd" && cargo build --release --target aarch64-unknown-uefi)
sign "$wd/target/aarch64-unknown-uefi/release/hang.efi" "$out/watchdog-hang.efi"
sign "$wd/target/aarch64-unknown-uefi/release/exit.efi" "$out/watchdog-exit.efi"

mb="$here/uefi/test-apps/mailbox"
(cd "$mb" && cargo build --release --target aarch64-unknown-uefi)
sign "$mb/target/aarch64-unknown-uefi/release/xhci-reset.efi" "$out/xhci-reset.efi"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
# Fetch a package out of Ubuntu's ports archive into $tmp/$1: $2 the path in
# the archive, $3 its SHA-256.
deb() {
  mkdir -p "$tmp/$1"
  curl -sSfL -o "$tmp/$1/p.deb" "https://ports.ubuntu.com/ubuntu-ports/$2"
  echo "$3  $tmp/$1/p.deb" | sha256sum -c --quiet
  (cd "$tmp/$1" && ar x p.deb && tar xf data.tar.*)
}
deb grub "$GRUB_DEB" "$GRUB_SHA256"
cp "$tmp/grub/usr/lib/grub/arm64-efi-signed/grubaa64.efi.signed" "$out/grubaa64.efi"
deb shim "$SHIM_DEB" "$SHIM_SHA256"
cp "$tmp/shim/usr/lib/shim/shimaa64.efi.signed.latest" "$out/shimaa64.efi"

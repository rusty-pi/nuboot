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
#   out/otp-probe.efi uefi/test-apps/otp-probe: for a board, not a scenario:
#                     reads OTP rows from the ARM at EL0, EL1 and EL2 the way the
#                     VPU does, and says whether the secret ones are zero, never
#                     what they hold
#   out/watchdog-hang.efi, out/watchdog-exit.efi
#                     uefi/test-apps/watchdog: hang in boot services, and
#                     exit them as an OS loader does
#   out/xhci-reset.efi
#                     uefi/test-apps/mailbox: ask over the property mailbox
#                     for the VL805's firmware to be reloaded, as Linux does
#   out/tpm2-test.efi
#                     the same crate: send the TPM on the VPU a series of
#                     commands
#   out/runtime-variables.efi, out/crypto.efi, out/persist.efi,
#   out/store-compact.efi, out/runtime-shutdown.efi
#                     uefi/test-apps/runtime: exit boot services and use the
#                     variable services the OS is left with, fill the flash
#                     store with them, and shut down
#   out/capsule-*.cap firmware update capsules the capsule scenario puts on the
#                     card: new, old, corrupt, signed by a stranger, and junk
#   out/reboot-flags.efi
#                     the same crate: set and read the reboot flags, as Linux's
#                     reboot '0 tryboot' does
#   out/gpio-tags.efi
#                     the same crate: ask for the GPIO expander's pins, as the
#                     OS's regulators do
#   out/systemd-bootaa64.efi, out/uki.efi
#                     Debian's systemd-boot, and a unified kernel image of its
#                     systemd-stub around hello.efi, signed with the test key
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
SYSTEMD_BOOT_URL="${SYSTEMD_BOOT_URL:-https://deb.debian.org/debian/pool/main/s/systemd/systemd-boot-efi_257.13-1~deb13u1_arm64.deb}"
SYSTEMD_BOOT_SHA256="${SYSTEMD_BOOT_SHA256:-0e4529d9a72b35c31f34151ef8a0df20f322cfef679f4f5439394e60505b91a2}"
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

# The built-in keys: PI4_PK_CERT, PI4_KEK_CERT and PI4_DB_CERT name DER
# certificates, which is all a build needs; without any of them keys/ is
# generated. Naming only some is an error: it would be replaced by generated
# keys that nobody holds a signing key for.
named=0
for var in PI4_PK_CERT PI4_KEK_CERT PI4_DB_CERT; do
  [[ -z "${!var:-}" ]] || named=$((named + 1))
done
if [[ $named == 0 ]]; then
  "$here/scripts/genkeys.sh"
  PI4_PK_CERT="$here/keys/pk.der"
  PI4_KEK_CERT="$here/keys/kek.der"
  PI4_DB_CERT="$here/keys/db.der"
elif [[ $named != 3 ]]; then
  echo "error: PI4_PK_CERT, PI4_KEK_CERT and PI4_DB_CERT go together: name all three or none" >&2
  exit 1
fi
# Each is a DER certificate, the three differ, and a real build's are not the
# test key's; say which they are.
declare -A seen=()
for var in PI4_PK_CERT PI4_KEK_CERT PI4_DB_CERT; do
  der="${!var}"
  openssl x509 -inform DER -in "$der" -noout 2>/dev/null || { echo "error: $var=$der is not a DER certificate" >&2; exit 1; }
  fingerprint="$(openssl x509 -inform DER -in "$der" -noout -fingerprint -sha256 | sed 's/.*=//; s/://g')"
  if [[ -n "${seen[$fingerprint]:-}" ]]; then
    echo "error: $var and ${seen[$fingerprint]} are the same certificate" >&2
    exit 1
  fi
  seen[$fingerprint]="$var"
  if [[ $test_keys == 0 ]] && openssl x509 -inform DER -in "$der" -noout -subject | grep -q 'test key'; then
    echo "error: $var=$der is a test key, which a real build does not trust" >&2
    exit 1
  fi
  echo "$var sha256 $fingerprint"
done

# The test key: a self-signed certificate the test build puts in db.
keys="$out/test-keys"
test_key() {
  mkdir -p "$keys"
  if [[ ! -f "$keys/update.pub" ]]; then
    openssl ecparam -name prime256v1 -genkey -noout -out "$keys/update.key"
    openssl ec -in "$keys/update.key" -pubout -outform DER 2>/dev/null | tail -c 64 >"$keys/update.pub"
  fi
  [[ -f "$keys/db.key" && -f "$keys/db.der" ]] && return
  openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 3650 \
    -subj "/CN=nuboot test key" \
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

# The standard library is built from rust-src. Give where rustup keeps it the
# name the prebuilt one has, as scripts/rustc-vc4.sh does for the VPU: the image
# must not say, or depend on, where it was built. This replaces the rustflags
# of uefi/.cargo/config.toml, whose -Zfixed-x18 it repeats.
sysroot="$(cd "$here/uefi" && rustc --print sysroot)"
commit="$(cd "$here/uefi" && rustc -vV | sed -n 's/^commit-hash: //p')"
export CARGO_TARGET_AARCH64_UNKNOWN_NONE_RUSTFLAGS="-Zfixed-x18 --remap-path-prefix=$sysroot/lib/rustlib/src/rust=/rustc/$commit"

(cd "$here/uefi" &&
  FIRMWARE_COMMIT="$(git -C "$here" rev-parse --short=7 HEAD 2>/dev/null || echo 0000000)" \
  PI4_UEFI_TEST_CERT="$test_cert" \
  PI4_PK_CERT="$PI4_PK_CERT" PI4_KEK_CERT="$PI4_KEK_CERT" PI4_DB_CERT="$PI4_DB_CERT" \
    cargo build --locked --release "${cargo_args[@]}")
elf="$here/uefi/target/aarch64-unknown-none/release/pi4-uefi"
llvm objcopy -O binary "$elf" "$out/pi4-uefi$suffix-payload.bin"
xz -c --format=raw --arm64 --lzma1="$LZMA_OPTS" "$out/pi4-uefi$suffix-payload.bin" >"$out/pi4-uefi$suffix-payload.lzma"

(cd "$here/uefi/stub" &&
  PI4_UEFI_LZMA="$out/pi4-uefi$suffix-payload.lzma" \
  PI4_UEFI_PROPS="$LZMA_PROPS" \
  PI4_UEFI_LEN="$(stat -c %s "$out/pi4-uefi$suffix-payload.bin")" \
  PI4_UEFI_BASE="$(symbol "$elf" _start)" \
  PI4_UEFI_END="$(symbol "$elf" _end)" \
    cargo build --locked --release)
llvm objcopy -O binary "$here/uefi/stub/target/aarch64-unknown-none/release/pi4-uefi-stub" "$out/pi4-uefi$suffix.bin"
echo "out/pi4-uefi$suffix-payload.bin: $(stat -c %s "$out/pi4-uefi$suffix-payload.bin") bytes"
echo "out/pi4-uefi$suffix.bin: $(stat -c %s "$out/pi4-uefi$suffix.bin") bytes"

[[ $test_apps == 1 ]] || exit 0

test_key
# Sign with the test key: $1 the unsigned image, $2 where it goes.
sign() {
  sbsign --key "$keys/db.key" --cert "$keys/db.crt" --output "$2" "$1" 2>/dev/null
}

# A second certificate, enrolled in db at run time by the store test with an
# update the test key signs, and a third that signs an update the test key
# does not hold KEK for.
for name in x stranger; do
  [[ -f "$keys/$name.key" ]] || openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 3650 \
    -subj "/CN=nuboot $name test key" \
    -keyout "$keys/$name.key" -out "$keys/$name.crt" 2>/dev/null
done
"$here/scripts/mkauth.py" "$keys/db.key" "$keys/db.crt" db "$keys/x.crt" "$out/db-x.auth"
"$here/scripts/mkauth.py" "$keys/stranger.key" "$keys/stranger.crt" db "$keys/stranger.crt" "$out/db-bad.auth"

# Firmware update capsules: a newer version, an older one, a newer one with a
# byte changed after it was signed, one signed by a key db does not hold, and
# a file that is not a capsule.
"$here/scripts/mkcapsule.py" "$keys/db.key" "$keys/db.crt" 0x7fffffff "$out/capsule-new.cap"
"$here/scripts/mkcapsule.py" "$keys/db.key" "$keys/db.crt" 1 "$out/capsule-old.cap"
"$here/scripts/mkcapsule.py" "$keys/db.key" "$keys/db.crt" 0x7fffffff --corrupt "$out/capsule-corrupt.cap"
"$here/scripts/mkcapsule.py" "$keys/stranger.key" "$keys/stranger.crt" 0x7fffffff "$out/capsule-stranger.cap"
"$here/scripts/mkcapsule.py" "$keys/db.key" "$keys/db.crt" 0x7fffffff --class eeprom --header-class firmware "$out/capsule-relabeled.cap"
head -c 300 /dev/urandom >"$out/capsule-junk.cap"

hello="$here/uefi/test-apps/hello"
(cd "$hello" && rustup target add aarch64-unknown-uefi >/dev/null &&
  cargo build --release --target aarch64-unknown-uefi)
sign "$hello/target/aarch64-unknown-uefi/release/hello.efi" "$out/hello.efi"

probe="$here/uefi/test-apps/otp-probe"
(cd "$probe" && cargo build --release --target aarch64-unknown-uefi)
sign "$probe/target/aarch64-unknown-uefi/release/otp-probe.efi" "$out/otp-probe.efi"

wd="$here/uefi/test-apps/watchdog"
(cd "$wd" && cargo build --release --target aarch64-unknown-uefi)
sign "$wd/target/aarch64-unknown-uefi/release/hang.efi" "$out/watchdog-hang.efi"
sign "$wd/target/aarch64-unknown-uefi/release/exit.efi" "$out/watchdog-exit.efi"
sign "$wd/target/aarch64-unknown-uefi/release/takeover.efi" "$out/watchdog-takeover.efi"
sign "$wd/target/aarch64-unknown-uefi/release/stuck.efi" "$out/watchdog-stuck.efi"
sign "$wd/target/aarch64-unknown-uefi/release/fault.efi" "$out/watchdog-fault.efi"

mb="$here/uefi/test-apps/mailbox"
(cd "$mb" && cargo build --release --target aarch64-unknown-uefi)
sign "$mb/target/aarch64-unknown-uefi/release/xhci-reset.efi" "$out/xhci-reset.efi"
sign "$mb/target/aarch64-unknown-uefi/release/tpm2-test.efi" "$out/tpm2-test.efi"
sign "$mb/target/aarch64-unknown-uefi/release/reboot-flags.efi" "$out/reboot-flags.efi"
sign "$mb/target/aarch64-unknown-uefi/release/gpio-tags.efi" "$out/gpio-tags.efi"

rt="$here/uefi/test-apps/runtime"
(cd "$rt" && cargo build --release --target aarch64-unknown-uefi)
sign "$rt/target/aarch64-unknown-uefi/release/variables.efi" "$out/runtime-variables.efi"
sign "$rt/target/aarch64-unknown-uefi/release/crypto.efi" "$out/crypto.efi"
sign "$rt/target/aarch64-unknown-uefi/release/persist.efi" "$out/persist.efi"
sign "$rt/target/aarch64-unknown-uefi/release/compact.efi" "$out/store-compact.efi"
sign "$rt/target/aarch64-unknown-uefi/release/shutdown.efi" "$out/runtime-shutdown.efi"

st="$here/uefi/test-apps/store"
(cd "$st" && cargo build --release --target aarch64-unknown-uefi)
sign "$st/target/aarch64-unknown-uefi/release/enroll.efi" "$out/store-enroll.efi"
sign "$st/target/aarch64-unknown-uefi/release/tamper.efi" "$out/store-tamper.efi"
sbsign --key "$keys/x.key" --cert "$keys/x.crt" --output "$out/store-enrolled.efi" \
  "$st/target/aarch64-unknown-uefi/release/enrolled.efi" 2>/dev/null

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
# systemd-boot, from Debian, signed with the test key.
mkdir -p "$tmp/systemd-boot"
curl -sSfL -o "$tmp/systemd-boot/p.deb" "$SYSTEMD_BOOT_URL"
echo "$SYSTEMD_BOOT_SHA256  $tmp/systemd-boot/p.deb" | sha256sum -c --quiet
(cd "$tmp/systemd-boot" && ar x p.deb && tar xf data.tar.*)
sign "$tmp/systemd-boot/usr/lib/systemd/boot/efi/systemd-bootaa64.efi" "$out/systemd-bootaa64.efi"
# A unified kernel image around systemd-stub, whose kernel is the hello
# application, signed with the test key as well. The stub checks for the
# arm64 kernel image magic, which sits in the DOS header's unused bytes,
cp "$hello/target/aarch64-unknown-uefi/release/hello.efi" "$tmp/kernel.efi"
printf 'ARM\x64' | dd of="$tmp/kernel.efi" bs=1 seek=56 conv=notrunc 2>/dev/null
# and the EFI stub version, 1.1 (initrd through LINUX_INITRD_MEDIA), in the
# optional header's image version fields.
python3 - "$tmp/kernel.efi" <<'PY'
import struct, sys
data = bytearray(open(sys.argv[1], "rb").read())
(pe,) = struct.unpack_from("<I", data, 0x3C)
struct.pack_into("<HH", data, pe + 24 + 44, 1, 1)
open(sys.argv[1], "wb").write(data)
PY
sign "$tmp/kernel.efi" "$tmp/kernel-signed.efi"
printf 'ID=test\nNAME="Test"\nPRETTY_NAME="Test OS"\nVERSION_ID=1\n' >"$tmp/osrel"
printf 'console=ttyAMA0 root=/dev/test' >"$tmp/cmdline"
"$here/scripts/mkuki.py" "$tmp/systemd-boot/usr/lib/systemd/boot/efi/linuxaa64.efi.stub" "$tmp/uki.efi" \
  --section .osrel="$tmp/osrel" --section .cmdline="$tmp/cmdline" --section .linux="$tmp/kernel-signed.efi"
sign "$tmp/uki.efi" "$out/uki.efi"
deb shim "$SHIM_DEB" "$SHIM_SHA256"
cp "$tmp/shim/usr/lib/shim/shimaa64.efi.signed.latest" "$out/shimaa64.efi"

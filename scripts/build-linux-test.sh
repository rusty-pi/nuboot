#!/usr/bin/env bash
# Build out/linux-test.efi: Debian's arm64 kernel and a busybox initramfs
# (uefi/test-apps/linux/init) in a unified kernel image, signed with the test
# key, which scenarios/linux.yaml boots to see the firmware from a running
# Linux. Needs what scripts/build-uefi.sh --test-keys --test-apps does, and
# sbsign, xz, ar, tar and cpio's gzip.
set -euo pipefail

KERNEL_URL="${KERNEL_URL:-https://deb.debian.org/debian/pool/main/l/linux/linux-image-6.12.107+deb13-arm64-unsigned_6.12.107-1_arm64.deb}"
KERNEL_SHA256="${KERNEL_SHA256:-2f986ade1a1336423adf2316ea89c3525dd4c05a646b2141626490ca2f388339}"
BUSYBOX_URL="${BUSYBOX_URL:-https://deb.debian.org/debian/pool/main/b/busybox/busybox-static_1.37.0-6+b9_arm64.deb}"
BUSYBOX_SHA256="${BUSYBOX_SHA256:-c833be48abfa16bc19c4966ec93e289ff1ce5d2f1476cad3a57bd105378cd15c}"
STUB_URL="${STUB_URL:-https://deb.debian.org/debian/pool/main/s/systemd/systemd-boot-efi_257.13-1~deb13u1_arm64.deb}"
STUB_SHA256="${STUB_SHA256:-0e4529d9a72b35c31f34151ef8a0df20f322cfef679f4f5439394e60505b91a2}"

here="$(cd "$(dirname "$0")/.." && pwd)"
out="$here/out"
keys="$out/test-keys"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Fetch a package into $tmp/$1 and unpack it: $2 its URL, $3 its SHA-256.
deb() {
  mkdir -p "$tmp/$1"
  curl -sSfL -o "$tmp/$1/p.deb" "$2"
  echo "$3  $tmp/$1/p.deb" | sha256sum -c --quiet
  (cd "$tmp/$1" && ar x p.deb && tar xf data.tar.*)
}
deb kernel "$KERNEL_URL" "$KERNEL_SHA256"
deb busybox "$BUSYBOX_URL" "$BUSYBOX_SHA256"
deb stub "$STUB_URL" "$STUB_SHA256"

root="$tmp/initramfs"
mkdir -p "$root/bin" "$root/proc" "$root/sys"
cp "$tmp/busybox/usr/bin/busybox" "$root/bin/busybox"
xz -dc "$tmp"/kernel/usr/lib/modules/*/kernel/fs/efivarfs/efivarfs.ko.xz >"$root/efivarfs.ko"
cp "$here/uefi/test-apps/linux/init" "$root/init"
chmod +x "$root/init"
"$here/scripts/mkinitramfs.py" "$root" "$tmp/initrd.gz"

sbsign --key "$keys/db.key" --cert "$keys/db.crt" --output "$tmp/vmlinuz.signed" "$tmp"/kernel/boot/vmlinuz-* 2>/dev/null
printf 'ID=test\nNAME="Test"\nPRETTY_NAME="Test OS"\nVERSION_ID=1\n' >"$tmp/osrel"
printf 'console=ttyAMA0,115200 earlycon=pl011,0xfe201000 rdinit=/init panic=-1 ignore_loglevel printk.devkmsg=on' >"$tmp/cmdline"
"$here/scripts/mkuki.py" "$tmp/stub/usr/lib/systemd/boot/efi/linuxaa64.efi.stub" "$tmp/uki.efi" \
  --section .osrel="$tmp/osrel" --section .cmdline="$tmp/cmdline" --section .linux="$tmp/vmlinuz.signed" --section .initrd="$tmp/initrd.gz"
sbsign --key "$keys/db.key" --cert "$keys/db.crt" --output "$out/linux-test.efi" "$tmp/uki.efi" 2>/dev/null
ls -l "$out/linux-test.efi"

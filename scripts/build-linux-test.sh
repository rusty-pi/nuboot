#!/usr/bin/env bash
# Build out/linux-test.efi and out/linux-acpi-test.efi: Debian's arm64 kernel
# and a busybox initramfs (uefi/test-apps/linux/init) in a unified kernel
# image, signed with the test key, which scenarios/linux.yaml and
# scenarios/linux-acpi.yaml boot to see the firmware from a running Linux,
# with the device tree and with the ACPI tables. Needs what
# scripts/build-uefi.sh --test-keys --test-apps does, and sbsign, xz, ar, tar
# and cpio's gzip.
set -euo pipefail

KERNEL_URL="${KERNEL_URL:-https://deb.debian.org/debian/pool/main/l/linux/linux-image-6.12.107+deb13-arm64-unsigned_6.12.107-1_arm64.deb}"
KERNEL_SHA256="${KERNEL_SHA256:-2f986ade1a1336423adf2316ea89c3525dd4c05a646b2141626490ca2f388339}"
BUSYBOX_URL="${BUSYBOX_URL:-https://deb.debian.org/debian/pool/main/b/busybox/busybox-static_1.37.0-6+b9_arm64.deb}"
BUSYBOX_SHA256="${BUSYBOX_SHA256:-c833be48abfa16bc19c4966ec93e289ff1ce5d2f1476cad3a57bd105378cd15c}"
STUB_URL="${STUB_URL:-https://deb.debian.org/debian/pool/main/s/systemd/systemd-boot-efi_257.13-1~deb13u1_arm64.deb}"
STUB_SHA256="${STUB_SHA256:-0e4529d9a72b35c31f34151ef8a0df20f322cfef679f4f5439394e60505b91a2}"
HEADERS_URL="${HEADERS_URL:-https://deb.debian.org/debian/pool/main/l/linux/linux-headers-6.12.107+deb13-arm64_6.12.107-1_arm64.deb}"
HEADERS_SHA256="${HEADERS_SHA256:-20cc55bde5ceae6411b7554d5fffc937f2df022bf47b6df9cad32b51cb1219f3}"
COMMON_URL="${COMMON_URL:-https://deb.debian.org/debian/pool/main/l/linux/linux-headers-6.12.107+deb13-common_6.12.107-1_all.deb}"
COMMON_SHA256="${COMMON_SHA256:-12dc292d7c238928fbcb7eebbe79208758fe263a4e2ea0e9b6734e6df12020a5}"
case "$(uname -m)" in
  aarch64)
    CROSS=""
    KBUILD_URL="${KBUILD_URL:-https://deb.debian.org/debian/pool/main/l/linux/linux-kbuild-6.12.107+deb13_6.12.107-1_arm64.deb}"
    KBUILD_SHA256="${KBUILD_SHA256:-939949f1c1525dc7c4d4414b9fad095a4a3291d727ddb1c7dc56e4ac371ca0a7}" ;;
  *)
    CROSS="aarch64-linux-gnu-"
    KBUILD_URL="${KBUILD_URL:-https://deb.debian.org/debian/pool/main/l/linux/linux-kbuild-6.12.107+deb13_6.12.107-1_amd64.deb}"
    KBUILD_SHA256="${KBUILD_SHA256:-0a88527eb05bca1ce75e7d39ec27539d385a24cf90b2b28917cc4903a4f710d3}" ;;
esac

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
  (cd "$tmp/$1" && ar x p.deb && tar xf data.tar.* && rm -f p.deb data.tar.* control.tar.* debian-binary)
}
deb kernel "$KERNEL_URL" "$KERNEL_SHA256"
deb busybox "$BUSYBOX_URL" "$BUSYBOX_SHA256"
deb stub "$STUB_URL" "$STUB_SHA256"
deb headers "$HEADERS_URL" "$HEADERS_SHA256"
deb headers "$COMMON_URL" "$COMMON_SHA256"
deb headers "$KBUILD_URL" "$KBUILD_SHA256"
while read -r name path sha; do
  case "$name" in ''|'#'*) continue ;; esac
  deb userland "https://deb.debian.org/debian/$path" "$sha"
done <"$here/scripts/linux-test-userland.txt"

src="$tmp/headers/usr/src"
kdir="$src/linux-headers-6.12.107+deb13-arm64"
sed -i "s|/usr/src/|$src/|" "$kdir/Makefile"
cp -r "$here/tools/tpm-vpu" "$tmp/tpm-vpu"
make -C "$tmp/tpm-vpu" KDIR="$kdir" CC="${CROSS}gcc" CONFIG_DEBUG_INFO_BTF_MODULES= >/dev/null
"${CROSS}strip" --strip-debug "$tmp/tpm-vpu/tpm_vpu.ko"
"$tmp"/headers/usr/lib/linux-kbuild-*/scripts/sign-file sha256 "$keys/db.key" "$keys/db.crt" "$tmp/tpm-vpu/tpm_vpu.ko"

root="$tmp/initramfs"
mkdir -p "$root/bin" "$root/proc" "$root/sys"
cp "$tmp/busybox/usr/bin/busybox" "$root/bin/busybox"
mkdir -p "$root/usr/bin" "$root/usr/lib" "$root/lib" "$root/etc"
cp "$tmp/userland/usr/bin/bootctl" "$root/usr/bin/bootctl"
cp -a "$tmp"/userland/usr/lib/aarch64-linux-gnu "$root/usr/lib/aarch64-linux-gnu"
cp -a "$tmp"/userland/usr/lib/ld-linux-aarch64.so.1 "$root/usr/lib/ld-linux-aarch64.so.1"
ln -s /usr/lib/ld-linux-aarch64.so.1 "$root/lib/ld-linux-aarch64.so.1"
rm -rf "$root/usr/lib/aarch64-linux-gnu/gconv" "$root/usr/lib/aarch64-linux-gnu/audit" "$root/usr/lib/aarch64-linux-gnu/ossl-modules"
printf 'ID=test\nNAME="Test"\nPRETTY_NAME="Test OS"\nVERSION_ID=1\n' >"$root/etc/os-release"
xz -dc "$tmp"/kernel/usr/lib/modules/*/kernel/fs/efivarfs/efivarfs.ko.xz >"$root/efivarfs.ko"
mkdir -p "$root/modules"
# The reset controller xhci-pci waits for, then what `modprobe --show-depends xhci_pci usb_storage sd_mod` gives for this kernel, in load order;
# then what the SD host, the network interface and the platform xHCI driver need, for the boot that describes the board with the ACPI tables.
for module in reset-raspberrypi usb-common usbcore xhci-hcd xhci-pci scsi_common scsi_mod usb-storage sd_mod \
    sdhci sdhci-pltfm sdhci-iproc libphy fwnode_mdio fixed_phy of_mdio mdio-bcm-unimac genet xhci-plat-hcd; do
  path="$(find "$tmp"/kernel/usr/lib/modules -name "$module.ko.xz" | head -n 1)"
  [ -n "$path" ] || { echo "this kernel has no module $module: list what its drivers need with modprobe --show-depends" >&2; exit 1; }
  xz -dc "$path" >"$root/modules/$module.ko"
done
cp "$tmp/tpm-vpu/tpm_vpu.ko" "$root/tpm_vpu.ko"
"${CROSS}gcc" -static -O2 -o "$root/bin/rmvar" "$here/uefi/test-apps/linux/rmvar.c"
"${CROSS}strip" "$root/bin/rmvar"
cp "$here/uefi/test-apps/linux/init" "$root/init"
chmod +x "$root/init"
"$here/scripts/mkinitramfs.py" "$root" "$tmp/initrd.gz"

sbsign --key "$keys/db.key" --cert "$keys/db.crt" --output "$tmp/vmlinuz.signed" "$tmp"/kernel/boot/vmlinuz-* 2>/dev/null
printf 'ID=test\nNAME="Test"\nPRETTY_NAME="Test OS"\nVERSION_ID=1\n' >"$tmp/osrel"
printf 'console=ttyAMA0,115200 earlycon=pl011,0xfe201000 rdinit=/init panic=-1 ignore_loglevel printk.devkmsg=on maxcpus=2' >"$tmp/cmdline"
# The same kernel and initramfs twice: told to describe the board with its
# device tree, as it does by default and with two cores, and with the ACPI
# tables (acpi=on) and all four.
for name in linux-test linux-acpi-test; do
  cp "$tmp/cmdline" "$tmp/cmdline.$name"
  [ "$name" = linux-test ] || sed -i 's/ maxcpus=2/ acpi=on/' "$tmp/cmdline.$name"
  "$here/scripts/mkuki.py" "$tmp/stub/usr/lib/systemd/boot/efi/linuxaa64.efi.stub" "$tmp/uki.efi" \
    --section .osrel="$tmp/osrel" --section .cmdline="$tmp/cmdline.$name" --section .linux="$tmp/vmlinuz.signed" --section .initrd="$tmp/initrd.gz"
  sbsign --key "$keys/db.key" --cert "$keys/db.crt" --output "$out/$name.efi" "$tmp/uki.efi" 2>/dev/null
  ls -l "$out/$name.efi"
done

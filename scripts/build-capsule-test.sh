#!/usr/bin/env bash
# Build what scenarios/capsule-apply.yaml boots: the test build, and a capsule
# that carries the next one, a build whose version is later
# (FIRMWARE_TIME=2147483000), as the signed boot.img and boot.sig the bootloader
# takes. Run it after scripts/build-uefi.sh --test-keys --test-apps. It leaves
# the test build as the current one, and makes
#
#   out/boot-next.img, out/boot-next.sig   the next build, signed
#   out/capsule-apply.cap                  a capsule for them, signed with the
#                                          test key
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
out="$here/out"
version=2147483000

FIRMWARE_TIME=$version "$here/scripts/build.sh" --test-keys >/dev/null
cp "$out/boot-test.img" "$out/boot-next.img"
cp "$out/boot-test.sig" "$out/boot-next.sig"
"$here/scripts/mkcapsule.py" "$out/test-keys/db.key" "$out/test-keys/db.crt" $version \
  --boot-img "$out/boot-next.img" --boot-sig "$out/boot-next.sig" "$out/capsule-apply.cap"

"$here/scripts/build.sh" --test-keys >/dev/null

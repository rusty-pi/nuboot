#!/usr/bin/env bash
# Build what scenarios/capsule-apply.yaml boots: the test EEPROM image, and a
# capsule that carries the next one, a build whose version is later
# (FIRMWARE_TIME=2147483000). Run it after scripts/build-uefi.sh --test-keys
# --test-apps. It builds both and leaves out/pieeprom-test.bin as the current
# one:
#
#   out/pieeprom-next-test.bin   the next firmware
#   out/capsule-apply.cap        a capsule for it, signed with the test key
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
out="$here/out"
version=2147483000

FIRMWARE_TIME=$version "$here/scripts/build.sh" --test-keys >/dev/null
cp "$out/pieeprom-test.bin" "$out/pieeprom-next-test.bin"
head -c $((0x70000)) "$out/pieeprom-next-test.bin" >"$out/next-region.bin"
"$here/scripts/mkcapsule.py" "$out/test-keys/db.key" "$out/test-keys/db.crt" $version \
  --image "$out/next-region.bin" "$out/capsule-apply.cap"
rm "$out/next-region.bin"

"$here/scripts/build.sh" --test-keys >/dev/null

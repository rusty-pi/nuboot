#!/usr/bin/env bash
# Build what scenarios/update-*.yaml boot: the test build, and capsules that
# carry the next one, a build whose version is later (FIRMWARE_TIME=2147483000),
# as an update bundle. Run it after scripts/build-uefi.sh --test-keys
# --test-apps. It leaves the test build as the current one, and makes
#
#   out/bundle-next.bin                  the next build, signed by the test
#                                        update key
#   out/bundle-stranger.bin              the same, signed by a key no build trusts
#   out/capsule-update.cap               a capsule for the first, signed with the
#                                        test db key
#   out/capsule-update-stranger.cap      a capsule for the second
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
out="$here/out"
keys="$out/test-keys"
version=2147483000

FIRMWARE_TIME=$version "$here/scripts/build.sh" --test-keys >/dev/null
cp "$out/start4-update-test.bin" "$out/update-next.bin"
[[ -f "$keys/update-stranger.key" ]] || openssl ecparam -name prime256v1 -genkey -noout -out "$keys/update-stranger.key"
"$here/scripts/mkbundle.py" "$keys/update.key" "$out/update-next.bin" $version "$out/bundle-next.bin"
"$here/scripts/mkbundle.py" "$keys/update-stranger.key" "$out/update-next.bin" $version "$out/bundle-stranger.bin"
"$here/scripts/mkcapsule.py" "$keys/db.key" "$keys/db.crt" $version "$out/capsule-update.cap" --class update --bundle "$out/bundle-next.bin"
"$here/scripts/mkcapsule.py" "$keys/db.key" "$keys/db.crt" $version "$out/capsule-update-stranger.cap" --class update --bundle "$out/bundle-stranger.bin"

"$here/scripts/build.sh" --test-keys >/dev/null

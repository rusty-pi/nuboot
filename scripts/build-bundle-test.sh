#!/usr/bin/env bash
# Build what scenarios/update-*.yaml boot: the test build, and capsules that
# carry a later build as an update bundle. The first build is a release, 200.0.0
# (a number above any commit's time, so the test build takes it), the second
# one has no release and the version FIRMWARE_TIME=2147483000. Run it after
# scripts/build-uefi.sh --test-keys --test-apps. It leaves the test build as the
# current one, and makes
#
#   out/bundle-next.bin                  200.0.0, signed by the test update key
#   out/bundle-stranger.bin              2147483000, signed by a key no build trusts
#   out/capsule-update.cap               a capsule for the first, signed with the
#                                        test db key
#   out/capsule-update-stranger.cap      a capsule for the second
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
out="$here/out"
keys="$out/test-keys"

[[ -f "$keys/update-stranger.key" ]] || openssl ecparam -name prime256v1 -genkey -noout -out "$keys/update-stranger.key"

FIRMWARE_VERSION=200.0.0 "$here/scripts/build.sh" --test-keys >/dev/null
cp "$out/start4-update-test.bin" "$out/update-next.bin"
"$here/scripts/mkbundle.py" "$keys/update.key" "$out/update-next.bin" 200.0.0 "$out/bundle-next.bin"
"$here/scripts/mkcapsule.py" "$keys/db.key" "$keys/db.crt" 200.0.0 "$out/capsule-update.cap" --class update --bundle "$out/bundle-next.bin"

FIRMWARE_TIME=2147483000 "$here/scripts/build.sh" --test-keys >/dev/null
cp "$out/start4-update-test.bin" "$out/update-stranger.bin"
"$here/scripts/mkbundle.py" "$keys/update-stranger.key" "$out/update-stranger.bin" 2147483000 "$out/bundle-stranger.bin"
"$here/scripts/mkcapsule.py" "$keys/db.key" "$keys/db.crt" 2147483000 "$out/capsule-update-stranger.cap" --class update --bundle "$out/bundle-stranger.bin"

"$here/scripts/build.sh" --test-keys >/dev/null

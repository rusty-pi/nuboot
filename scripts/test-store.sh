#!/bin/sh
# Test the UEFI firmware's variable store and the listing of its window in a
# disk's partition table on the host (tools/store-check): the real modules, run
# on disk images.
#
# The repository's cargo configuration is for the VPU build and applies to
# every directory under it, so cargo runs from outside, on the manifest.
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
export CARGO_TARGET_DIR="$root/tools/store-check/target"
cd "${TMPDIR:-/tmp}"
cargo test --release --manifest-path "$root/tools/store-check/Cargo.toml" "$@"

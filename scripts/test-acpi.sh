#!/bin/sh
# Test the UEFI firmware's ACPI tables on the host: their checksums and
# links, and the ACPICA tools' view of them (tools/acpi-check). The tools'
# check needs `iasl` (acpica-tools) and is skipped without it.
#
# The repository's cargo configuration is for the VPU build and applies to
# every directory under it, so cargo runs from outside, on the manifest.
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
export CARGO_TARGET_DIR="$root/tools/acpi-check/target"
cd "${TMPDIR:-/tmp}"
cargo test --release --manifest-path "$root/tools/acpi-check/Cargo.toml" "$@"

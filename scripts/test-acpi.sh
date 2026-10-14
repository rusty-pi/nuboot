#!/bin/sh
# Test the UEFI firmware's ACPI and SMBIOS tables on the host: their checksums
# and links, the ACPICA tools' view of the ACPI tables and `dmidecode`'s of the
# SMBIOS ones (tools/acpi-check). Each check needs its tool (`iasl` and
# `acpiexec` from acpica-tools, `dmidecode`) and is skipped without it.
#
# The repository's cargo configuration is for the VPU build and applies to
# every directory under it, so cargo runs from outside, on the manifest.
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
export CARGO_TARGET_DIR="$root/tools/acpi-check/target"
cd "${TMPDIR:-/tmp}"
cargo test --release --manifest-path "$root/tools/acpi-check/Cargo.toml" "$@"

#!/bin/sh
# Test the TPM's code on the host: the crypto against reference vectors, and
# the whole TPM through tpm2-tools when they are installed (tools/tpm-sim).
#
# The repository's cargo configuration is for the VPU build and applies to
# every directory under it, so cargo runs from outside, on the manifest.
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
export CARGO_TARGET_DIR="$root/tools/tpm-sim/target"
cd "${TMPDIR:-/tmp}"
cargo test --release --manifest-path "$root/tools/tpm-sim/Cargo.toml" "$@"

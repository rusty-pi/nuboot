#!/bin/sh
# Test the TPM's code on the host: the crypto against reference vectors, and
# the whole TPM through tpm2-tools when they are installed (tools/tpm-sim).
# TPM2_TOOLS can name the directory of tools that are not on the PATH.
#
# The repository's cargo configuration is for the VPU build and applies to
# every directory under it, so cargo runs from outside, on the manifest.
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
export CARGO_TARGET_DIR="$root/tools/tpm-sim/target"
cd "${TMPDIR:-/tmp}"
cargo test --release --manifest-path "$root/tools/tpm-sim/Cargo.toml" "$@"

# With the tools, the whole TPM: TPM2_TOOLS names a directory they are in, for
# an unpacked package.
if [ -n "${TPM2_TOOLS:-}" ] || command -v tpm2_getcap >/dev/null; then
  cargo build --release --manifest-path "$root/tools/tpm-sim/Cargo.toml"
  "$root/tools/tpm-sim/tpm2-tools-test.sh" "$root/tools/tpm-sim/target/release/tpm-sim" "${TPM2_TOOLS:-}"
else
  echo "tpm2-tools are not installed: the TPM itself is not tested through them"
fi

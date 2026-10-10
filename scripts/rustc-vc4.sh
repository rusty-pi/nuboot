#!/bin/sh
# Cargo rustc wrapper: everything built for the VC4 target goes through
# rustc_codegen_gcc (see scripts/setup-toolchain.sh); host crates don't.
root="$(cd "$(dirname "$0")/.." && pwd)"
rustc="$1"
shift

case " $* " in
  *" --target "*vc4-none-elf*)
    # -Zbuild-std compiles core from wherever rustup keeps rust-src, and the
    # images must not depend on where that is. The path itself ends up in
    # panic locations: give it the name the prebuilt standard library has.
    src="$("$rustc" --print sysroot)/lib/rustlib/src/rust"
    commit="$("$rustc" -vV | sed -n 's/^commit-hash: //p')"
    # Cargo also hashes it into core's -C metadata, and from there into every
    # crate's, which renames every symbol -- and GCC's inlining depends on the
    # names. Replace the hash with what it is meant to tell apart: the
    # package, its version and its features.
    metadata="$CARGO_PKG_NAME $CARGO_PKG_VERSION"
    for arg do
      case "$arg" in feature=*) metadata="$metadata $arg" ;; esac
    done
    for arg do
      shift
      case "$arg" in metadata=*) arg="metadata=$metadata" ;; esac
      set -- "$@" "$arg"
    done
    # A fresh checkout has no links yet: make them from the default places
    # (scripts/setup-toolchain.sh), so a plain `cargo build` works.
    if [ ! -e "$root/toolchain/librustc_codegen_gcc.so" ] || [ ! -e "$root/toolchain/bin/vc4-elf-gcc" ]; then
      "$root/scripts/setup-toolchain.sh" >&2 2>/dev/null || true
      if [ ! -e "$root/toolchain/librustc_codegen_gcc.so" ] || [ ! -e "$root/toolchain/bin/vc4-elf-gcc" ]; then
        echo "error: no VC4 toolchain: no GCC under ${VC4_PREFIX:-~/.local/opt/vc4 or /opt/vc4}" \
          "or no rustc_codegen_gcc build in ${CG_GCC_DIR:-~/src/rustc_codegen_gcc}; see docs/toolchain.md" >&2
        exit 1
      fi
    fi
    exec "$rustc" "$@" \
      --remap-path-prefix="$src=/rustc/$commit" \
      -Zcodegen-backend="$root/toolchain/librustc_codegen_gcc.so" \
      --sysroot="$root/toolchain/sysroot"
    ;;
esac
exec "$rustc" "$@"

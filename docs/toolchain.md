# Toolchain

There is no LLVM backend for the VideoCore IV, so the Rust code goes through
[rustc_codegen_gcc](https://github.com/rust-lang/rustc_codegen_gcc) and a
libgccjit built from a VC4 port of GCC:

```
rustc ── rustc_codegen_gcc ── libgccjit (GCC 17 + VC4 backend) ── vc4-elf-as/ld
```

- **GCC**: [rusty-pi/gcc-vc4](https://github.com/rusty-pi/gcc-vc4) (branch `vc4-rust`),
  the GCC 6 VC4 backend from [itszor/gcc-vc4](https://github.com/itszor/gcc-vc4)
  (`vc4-gcc6`) forward ported to the `rust-lang/gcc` commit rustc_codegen_gcc
  pins (`libgccjit.version`).
- **binutils**: [rusty-pi/binutils-vc4](https://github.com/rusty-pi/binutils-vc4)
  (branch `vc4-2.46.1`), poizan42's fork with the `elf32-vc4.c` hook signatures fixed
  for bfd 2.46.
- **Target**: `vc4-none-elf.json`. rustc has no VC4 `arch` and panics on an
  unknown one for `extern "C"`, so the spec says `csky` (a plain 32-bit
  little-endian ABI); the data layout is VC4's (`i64`/`f64` 4-byte aligned).
  `core` and `compiler_builtins` are built with `-Zbuild-std`.

## Installing it

Toolchain (binutils, GCC with libgccjit and libgcc, rustc_codegen_gcc), into
`~/.local/opt/vc4` by default:

```bash
scripts/build-toolchain.sh
```

It uses `~/src/binutils-vc4`, `~/src/gcc-vc4` and `~/src/rustc_codegen_gcc`,
cloning the pinned tag or commit for any that is missing, over SSH
(`CLONE_BASE=https://github.com/` for HTTPS), and builds in `~/src/vc4-build`.
`VC4_PREFIX`, `BINUTILS_SRC`, `GCC_SRC`, `CG_GCC_DIR`, `BUILD_DIR` and `JOBS`
change those.

On Ubuntu 26.04, binutils and GCC can come prebuilt instead, as packages
that install into `/opt/vc4` (the script needs `sudo` and checks their SHA-256).
Then only rustc_codegen_gcc is built here:

```bash
scripts/install-toolchain.sh
VC4_PREFIX=/opt/vc4 scripts/build-codegen.sh
```

`scripts/toolchain.env` pins the toolchain: the rustc_codegen_gcc commit
(`CG_GCC_REV`) and the binutils-vc4 and gcc-vc4 release tags with the SHA-256
of their packages. Each gcc-vc4 commit is published as its own release,
`vc4-<commit>`, with the `rust-lang/gcc` commit it is built on in its
`libgccjit-base` asset. `scripts/build-codegen.sh` stops when that is not the
`libgccjit.version` of `CG_GCC_REV`, so a move to a newer rustc_codegen_gcc
changes `GCC_VC4_TAG`, `CG_GCC_REV` and the nightly in `rust-toolchain.toml`
together.

The first `cargo build` links `toolchain/` to GCC in `~/.local/opt/vc4` or
`/opt/vc4` and to rustc_codegen_gcc in `~/src/rustc_codegen_gcc`
(`scripts/setup-toolchain.sh`). With either somewhere else, run
`scripts/setup-toolchain.sh` once with `VC4_PREFIX` and `CG_GCC_DIR` set to
where they are.

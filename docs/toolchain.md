# Toolchain

There is no LLVM backend for the VideoCore IV, so the Rust code goes through
[rustc_codegen_gcc](https://github.com/rust-lang/rustc_codegen_gcc) and a
libgccjit built from a VC4 port of GCC:

```
rustc ── rustc_codegen_gcc ── libgccjit (GCC 17 + VC4 backend) ── vc4-elf-as/ld
```

- **GCC**: [rusty-pi/gcc-vc4](https://github.com/rusty-pi/gcc-vc4) (`vc4-rust`),
  the GCC 6 VC4 backend from [itszor/gcc-vc4](https://github.com/itszor/gcc-vc4)
  (`vc4-gcc6`) forward ported to the `rust-lang/gcc` commit rustc_codegen_gcc
  pins (`libgccjit.version`).
- **binutils**: [rusty-pi/binutils-vc4](https://github.com/rusty-pi/binutils-vc4)
  (`vc4-2.46.1`), poizan42's fork with the `elf32-vc4.c` hook signatures fixed
  for bfd 2.46.
- **Target**: `vc4-none-elf.json`. rustc has no VC4 `arch` and panics on an
  unknown one for `extern "C"`, so the spec says `csky` (a plain 32-bit
  little-endian ABI); the data layout is VC4's (`i64`/`f64` 4-byte aligned).
  `core` and `compiler_builtins` are built with `-Zbuild-std`.

## Installing it

Toolchain (binutils, GCC with libgccjit and libgcc, rustc_codegen_gcc), into
`~/.local/opt/vc4` by default, then the links `.cargo/config.toml` uses:

```bash
scripts/build-toolchain.sh
scripts/setup-toolchain.sh
```

On Ubuntu 26.04, binutils and GCC can come prebuilt instead: the `latest`
releases of the two forks carry them as packages that install into `/opt/vc4`.
Then only rustc_codegen_gcc is built here:

```bash
gh release download latest -R rusty-pi/binutils-vc4 -p vc4-elf-binutils.deb
gh release download latest -R rusty-pi/gcc-vc4 -p vc4-elf-gcc.deb
sudo apt-get install ./vc4-elf-binutils.deb ./vc4-elf-gcc.deb
VC4_PREFIX=/opt/vc4 scripts/build-codegen.sh
VC4_PREFIX=/opt/vc4 scripts/setup-toolchain.sh
```

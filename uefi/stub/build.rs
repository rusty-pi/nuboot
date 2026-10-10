//! scripts/build-uefi.sh hands over the compressed payload: its path, the
//! LZMA properties byte, its size uncompressed, the address it runs at and the
//! end of everything it occupies there, stacks and buffers included.

use std::{env, fs, path::Path};

fn main() {
    let dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rerun-if-changed=link.ld");
    println!("cargo:rustc-link-arg=-T{dir}/link.ld");
    println!("cargo:rustc-link-arg=-no-pie");

    let var = |name: &str| {
        println!("cargo:rerun-if-env-changed={name}");
        env::var(name).unwrap_or_else(|_| panic!("{name} is not set: build with scripts/build-uefi.sh"))
    };
    let lzma = var("PI4_UEFI_LZMA");
    let props = var("PI4_UEFI_PROPS");
    let len = var("PI4_UEFI_LEN");
    let base = var("PI4_UEFI_BASE");
    let end = var("PI4_UEFI_END");
    println!("cargo:rerun-if-changed={lzma}");

    let out = Path::new(&env::var("OUT_DIR").unwrap()).join("payload.rs");
    fs::write(
        out,
        format!(
            "const PAYLOAD_LZMA: &[u8] = include_bytes!({lzma:?});\n\
             const PAYLOAD_PROPS: u8 = {props};\n\
             const PAYLOAD_LEN: usize = {len};\n\
             const PAYLOAD_BASE: usize = {base};\n\
             const PAYLOAD_END: usize = {end};\n"
        ),
    )
    .unwrap();
}

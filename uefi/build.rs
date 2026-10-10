fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let out = std::env::var("OUT_DIR").unwrap();
    println!("cargo:rerun-if-changed=link.ld");
    println!("cargo:rustc-link-arg=-T{dir}/link.ld");
    println!("cargo:rustc-link-arg=-no-pie");

    // keys/dbx-aarch64.txt as the 32-byte hashes one after the other.
    println!("cargo:rerun-if-changed=keys");
    let text = std::fs::read_to_string(format!("{dir}/keys/dbx-aarch64.txt")).unwrap();
    let mut dbx = Vec::new();
    for line in text.lines().filter(|l| !l.starts_with('#') && !l.trim().is_empty()) {
        let hex = line.split_whitespace().next().unwrap();
        assert_eq!(hex.len(), 64, "keys/dbx-aarch64.txt: not a SHA-256 hash: {line}");
        dbx.extend((0..32).map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap()));
    }
    std::fs::write(format!("{out}/dbx.bin"), dbx).unwrap();

    // The test build's own certificate in `db`: what scripts/build-uefi.sh
    // --test-keys signs the test applications with. Empty in a real build.
    println!("cargo:rerun-if-env-changed=PI4_UEFI_TEST_CERT");
    let test = match std::env::var("PI4_UEFI_TEST_CERT") {
        Ok(path) if !path.is_empty() => {
            println!("cargo:rerun-if-changed={path}");
            std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
        }
        _ => Vec::new(),
    };
    std::fs::write(format!("{out}/test-db.der"), test).unwrap();
}

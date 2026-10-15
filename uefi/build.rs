fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let out = std::env::var("OUT_DIR").unwrap();
    println!("cargo:rerun-if-changed=link.ld");
    println!("cargo:rustc-link-arg=-T{dir}/link.ld");
    println!("cargo:rustc-link-arg=-no-pie");

    // What orders one build after another, as the VPU firmware reads it
    // (build.rs of the VPU firmware): FIRMWARE_TIME, else the release
    // FIRMWARE_VERSION packed as X<<24 | Y<<16 | Z, else the commit's time.
    println!("cargo:rerun-if-env-changed=FIRMWARE_COMMIT");
    println!("cargo:rerun-if-env-changed=FIRMWARE_TIME");
    println!("cargo:rerun-if-env-changed=FIRMWARE_VERSION");
    let release = std::env::var("FIRMWARE_VERSION").ok().filter(|v| !v.is_empty());
    let time = std::env::var("FIRMWARE_TIME")
        .ok()
        .and_then(|t| t.parse::<u32>().ok())
        .or_else(|| release.as_deref().map(pack_release))
        .unwrap_or_else(|| {
            std::process::Command::new("git")
                .args(["log", "-1", "--format=%ct"])
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .and_then(|t| t.trim().parse().ok())
                .unwrap_or(0)
        });
    println!("cargo:rustc-env=FIRMWARE_TIME={time}");

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

    // The platform key, the KEK and the db key scripts/genkeys.sh makes.
    for (var, file) in [("PI4_PK_CERT", "pk.der"), ("PI4_KEK_CERT", "kek.der"), ("PI4_DB_CERT", "db.der")] {
        println!("cargo:rerun-if-env-changed={var}");
        let path = std::env::var(var).unwrap_or_else(|_| panic!("{var} is not set: build with scripts/build-uefi.sh"));
        println!("cargo:rerun-if-changed={path}");
        let der = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
        std::fs::write(format!("{out}/{file}"), der).unwrap();
    }
}

fn pack_release(release: &str) -> u32 {
    let parts: Vec<u32> = release
        .split('.')
        .map(|part| part.parse().ok().filter(|n: &u32| part == n.to_string()))
        .collect::<Option<_>>()
        .unwrap_or_default();
    match parts[..] {
        [major, minor, patch] if major <= 0xff && minor <= 0xff && patch <= 0xffff => major << 24 | minor << 16 | patch,
        _ => panic!("FIRMWARE_VERSION={release}: a release is X.Y.Z, at most 255.255.65535"),
    }
}

use std::process::Command;

fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-arg-bin=start4=-T{dir}/start4.ld");
    // start4 keeps its relocations, so the bootloader can place it lower for a
    // USB boot.
    println!("cargo:rustc-link-arg-bin=start4=-Wl,-q");
    println!("cargo:rerun-if-changed=start4.ld");
    commit();
    arm_files(&dir);
}

/// What the firmware hands the ARM: the image the cores start in, which
/// scripts/build-uefi.sh builds into `out/`, and the board's device tree.
fn arm_files(dir: &str) {
    let out = format!("{dir}/out");
    std::fs::create_dir_all(&out).unwrap();
    for input in [
        "uefi/src", "uefi/stub/src", "uefi/Cargo.toml", "uefi/Cargo.lock", "uefi/build.rs",
        "uefi/link.ld", "uefi/keys", "uefi/rust-toolchain.toml", "uefi/.cargo/config.toml", "uefi/stub/Cargo.toml",
        "uefi/stub/Cargo.lock", "uefi/stub/build.rs", "uefi/stub/link.ld", "src/log.rs",
        "scripts/build-uefi.sh",
    ] {
        println!("cargo:rerun-if-changed={dir}/{input}");
    }
    println!("cargo:rerun-if-changed={dir}/keys");
    for var in ["PI4_PK_CERT", "PI4_KEK_CERT", "PI4_DB_CERT", "FIRMWARE_TIME"] {
        println!("cargo:rerun-if-env-changed={var}");
        if let Some(path) = std::env::var_os(var).filter(|_| var.ends_with("_CERT")) {
            println!("cargo:rerun-if-changed={}", path.to_string_lossy());
        }
    }
    let test = std::env::var_os("CARGO_FEATURE_TEST_KEYS").is_some();
    build_uefi(dir, test);
    let image = if test { "pi4-uefi-test.bin" } else { "pi4-uefi.bin" };
    let tree = format!("{out}/bcm2711-rpi-4-b.dtb");
    fetch(&tree, DTB_URL, DTB_SHA256);
    println!("cargo:rustc-env=ARM_IMAGE={out}/{image}");
    println!("cargo:rustc-env=ARM_TREE={tree}");
}

/// Raspberry Pi's device tree for the Pi 4B, from the firmware release the
/// scenarios boot.
const DTB_URL: &str = "https://raw.githubusercontent.com/raspberrypi/firmware/1.20260915/boot/bcm2711-rpi-4-b.dtb";
const DTB_SHA256: &str = "75761b73c284e26623e4d1624bff13e67bce2ae620880efd81d6571a3739fcfb";

/// Run scripts/build-uefi.sh, a cargo build of its own on another nightly
/// and target: none of what this cargo set for its build script goes with it.
fn build_uefi(dir: &str, test: bool) {
    let mut cmd = Command::new("bash");
    cmd.arg(format!("{dir}/scripts/build-uefi.sh"));
    if test {
        cmd.arg("--test-keys");
    }
    for (key, _) in std::env::vars_os() {
        let key = key.to_string_lossy().into_owned();
        let cargo_own = key.starts_with("CARGO_") && key != "CARGO_HOME";
        if cargo_own
            || key.starts_with("RUSTC")
            || key.starts_with("RUSTUP_TOOLCHAIN")
            || key.starts_with("DEP_")
            || ["RUSTFLAGS", "RUSTDOCFLAGS", "TARGET", "HOST", "OUT_DIR", "OPT_LEVEL", "PROFILE", "DEBUG", "NUM_JOBS"]
                .contains(&key.as_str())
        {
            cmd.env_remove(&key);
        }
    }
    // Its progress goes to cargo's log, not to the directives cargo reads.
    cmd.stdout(std::io::stderr());
    match cmd.status() {
        Ok(status) if status.success() => {}
        Ok(status) => panic!("scripts/build-uefi.sh failed ({status}); see docs/uefi.md for what it needs"),
        Err(e) => panic!("scripts/build-uefi.sh could not be run: {e}"),
    }
}

/// Download `url` to `path` unless it is there already with checksum
/// `sha256`.
fn fetch(path: &str, url: &str, sha256: &str) {
    let check = |path: &str| {
        Command::new("sha256sum")
            .arg(path)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .is_some_and(|o| String::from_utf8_lossy(&o.stdout).starts_with(sha256))
    };
    if check(path) {
        return;
    }
    let status = Command::new("curl").args(["-sSfL", "-o", path, url]).status();
    if !matches!(status, Ok(s) if s.success()) || !check(path) {
        let _ = std::fs::remove_file(path);
        panic!("could not download {url} with SHA-256 {sha256}");
    }
}

/// The commit being built, which the firmware reports as its version. A build
/// outside a git checkout reports zeros.
fn commit() {
    println!("cargo:rerun-if-changed=.git/logs/HEAD");
    let output = Command::new("git").args(["rev-parse", "HEAD"]).output();
    let hash = match output.ok().filter(|o| o.status.success()) {
        Some(output) => String::from_utf8_lossy(&output.stdout).trim().to_string(),
        None => "0".repeat(40),
    };
    println!("cargo:rustc-env=FIRMWARE_COMMIT={hash}");
}

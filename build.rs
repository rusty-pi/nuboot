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

/// What the firmware hands the ARM, which scripts/build.sh puts in `out/`
/// first: the image the cores start in (scripts/build-uefi.sh) and the
/// board's device tree.
fn arm_files(dir: &str) {
    for (var, file) in [("ARM_IMAGE", "pi4-uefi.bin"), ("ARM_TREE", "bcm2711-rpi-4-b.dtb")] {
        let path = format!("{dir}/out/{file}");
        println!("cargo:rerun-if-changed={path}");
        if !std::path::Path::new(&path).exists() {
            panic!("{path} is missing: build with scripts/build.sh");
        }
        println!("cargo:rustc-env={var}={path}");
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

use std::process::Command;

fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-arg-bin=start4=-T{dir}/start4.ld");
    // start4 keeps its relocations, so the bootloader can place it lower for a
    // USB boot.
    println!("cargo:rustc-link-arg-bin=start4=-Wl,-q");
    println!("cargo:rerun-if-changed=start4.ld");
    commit();
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

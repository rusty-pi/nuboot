use std::path::PathBuf;
use std::process::Command;

use acpi_check::{BASE, acpi::tables, sample, walk};

const HARNESS: &str = r#"DefinitionBlock ("", "SSDT", 2, "TEST", "TEST", 1)
{
  External (\_SB.TPM0._DSM, MethodObj)
  Method (MAIN)
  {
    Local0 = \_SB.TPM0._DSM (ToUUID ("6bbf6cab-5463-4714-b7cd-f0203c0368d4"), 1, 0, Zero)
    Debug = Local0
    Local1 = \_SB.TPM0._DSM (ToUUID ("6bbf6cab-5463-4714-b7cd-f0203c0368d4"), 1, 1, Zero)
    Debug = Local1
    Local2 = \_SB.TPM0._DSM (ToUUID ("00000000-5463-4714-b7cd-f0203c0368d4"), 1, 1, Zero)
    Debug = Local2
  }
}
"#;

fn tool(name: &str) -> bool {
    Command::new(name).arg("-v").output().is_ok() || Command::new(name).arg("-h").output().is_ok()
}

fn workdir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("acpi-check-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// What the interpreter says evaluating the start method three times does:
/// the functions it supports, the start, and a UUID it does not know. The
/// memory the operation regions describe reads as `fill`.
fn evaluate(name: &str, fill: &str) -> Option<String> {
    if !tool("iasl") || !tool("acpiexec") {
        eprintln!("iasl and acpiexec are not installed: the start method is not evaluated");
        return None;
    }
    let dir = workdir(name);
    let block = tables::assemble(&sample(), BASE);
    let dsdt = walk(&block, BASE).into_iter().find(|t| t.signature == "DSDT").unwrap();
    std::fs::write(dir.join("DSDT.aml"), dsdt.bytes).unwrap();
    std::fs::write(dir.join("harness.asl"), HARNESS).unwrap();
    let compiled = Command::new("iasl").arg("harness.asl").current_dir(&dir).output().unwrap();
    assert!(compiled.status.success(), "{}", String::from_utf8_lossy(&compiled.stdout));
    let run = Command::new("acpiexec")
        .args(["-di", "-fv", fill, "-b", "execute MAIN", "DSDT.aml", "harness.aml"])
        .current_dir(&dir)
        .output()
        .unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    Some(String::from_utf8_lossy(&run.stdout).to_string() + &String::from_utf8_lossy(&run.stderr))
}

fn results(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        if let Some(value) = line.strip_prefix("ACPI Debug:  ") {
            if value.starts_with("Buffer") {
                let data = lines.next().unwrap_or_default();
                found.push(data.split_once(": ").map_or(String::new(), |(_, d)| d.split("//").next().unwrap().trim().to_string()));
            } else {
                found.push(value.trim().to_string());
            }
        }
    }
    found
}

#[test]
fn the_start_method_rings_the_doorbell_and_reports_success() {
    let Some(text) = evaluate("start", "0") else { return };
    assert_eq!(results(&text), ["03", "0x0000000000000000", "00"], "{text}");
}

#[test]
fn the_start_method_gives_up_when_the_mailbox_stays_full() {
    let Some(text) = evaluate("full", "0xff") else { return };
    assert_eq!(results(&text), ["03", "0x0000000000000001", "00"], "{text}");
}

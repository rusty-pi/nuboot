use std::path::PathBuf;
use std::process::Command;

use acpi_check::{BASE, acpi::tables, sample, walk};

const START: &str = r#"DefinitionBlock ("", "SSDT", 2, "TEST", "TEST", 1)
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

const THERMAL: &str = r#"DefinitionBlock ("", "SSDT", 2, "TEST", "TEST", 1)
{
  External (\_TZ.TZ00._TMP, MethodObj)
  External (\_TZ.TZ00._CRT, MethodObj)
  External (\_TZ.TZ00._TZP, MethodObj)
  Method (MAIN)
  {
    Debug = \_TZ.TZ00._TMP ()
    Debug = \_TZ.TZ00._CRT ()
    Debug = \_TZ.TZ00._TZP ()
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

/// What the interpreter says evaluating what `harness` calls: the memory the
/// operation regions describe reads as `fill`.
fn evaluate(name: &str, harness: &str, fill: &str) -> Option<String> {
    if !tool("iasl") || !tool("acpiexec") {
        eprintln!("iasl and acpiexec are not installed: the methods are not evaluated");
        return None;
    }
    let dir = workdir(name);
    let block = tables::assemble(&sample(), BASE);
    let dsdt = walk(&block, BASE).into_iter().find(|t| t.signature == "DSDT").unwrap();
    std::fs::write(dir.join("DSDT.aml"), dsdt.bytes).unwrap();
    std::fs::write(dir.join("harness.asl"), harness).unwrap();
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

/// What the interpreter says evaluating the start method three times does:
/// the functions it supports, the start, and a UUID it does not know.
#[test]
fn the_start_method_rings_the_doorbell_and_reports_success() {
    let Some(text) = evaluate("start", START, "0") else { return };
    assert_eq!(results(&text), ["03", "0x0000000000000000", "00"], "{text}");
}

#[test]
fn the_start_method_gives_up_when_the_mailbox_stays_full() {
    let Some(text) = evaluate("full", START, "0xff") else { return };
    assert_eq!(results(&text), ["03", "0x0000000000000001", "00"], "{text}");
}

/// What Linux's `bcm2711_thermal` makes of a result word, in tenths of a kelvin
/// as ACPI has it, with 0 for no sample.
fn decikelvin(word: u32) -> u64 {
    let count = (word & 0x3ff) as u64;
    if word & 0x1_0400 == 0 {
        return 0;
    }
    (410_040 + 273_200 - 487 * count) / 100
}

fn temperature(fill: u8) -> Option<Vec<String>> {
    evaluate(&format!("thermal-{fill}"), THERMAL, &format!("{fill:#x}")).map(|text| results(&text))
}

#[test]
fn the_thermal_zone_reads_the_temperature_the_sensor_gives_and_has_a_critical_limit_and_a_polling_period() {
    // A fill of 0x01 makes the word 0x01010101: a count of 257 that is valid by
    // bit 16 alone. 0x55 makes 0x55555555: a count of 341 valid by bit 10. 0xff
    // is a count of 1023, 88 degrees below zero, which is still a temperature.
    for fill in [0x01u8, 0x55, 0xff] {
        let word = u32::from_le_bytes([fill; 4]);
        let Some(found) = temperature(fill) else { return };
        assert_ne!(decikelvin(word), 0);
        assert_eq!(found, [format!("0x{:016X}", decikelvin(word)), "0x0000000000000DFE".to_string(), "0x000000000000000A".to_string()]);
    }
}

#[test]
fn the_thermal_zone_has_no_temperature_without_a_valid_sample() {
    let Some(found) = temperature(0x00) else { return };
    assert_eq!(found[0], "0x0000000000000000", "{found:?}");
}

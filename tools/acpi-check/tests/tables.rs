use std::process::Command;

use acpi_check::acpi::{aml, tables};
use acpi_check::{BASE, Found, sample, walk};

fn sum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |sum, b| sum.wrapping_add(*b))
}

fn block() -> tables::Block {
    tables::assemble(&sample(), BASE)
}

fn table<'a>(found: &'a [Found], signature: &str) -> &'a Found {
    found.iter().find(|t| t.signature == signature).unwrap_or_else(|| panic!("no {signature}"))
}

#[test]
fn the_rsdp_leads_to_every_table() {
    let block = block();
    let rsdp = &block.bytes[block.rsdp..block.rsdp + 36];
    assert_eq!(&rsdp[..8], b"RSD PTR ");
    assert_eq!(sum(&rsdp[..20]), 0);
    assert_eq!(sum(rsdp), 0);
    assert_eq!(rsdp[15], 2);
    assert_eq!(block.rsdp % 16, 0);
    let signatures: Vec<String> = walk(&block, BASE).into_iter().map(|t| t.signature).collect();
    assert_eq!(signatures, ["XSDT", "FACP", "DSDT", "APIC", "GTDT", "SPCR", "PPTT", "TPM2", "IORT"]);
}

#[test]
fn every_table_checks_out() {
    let block = block();
    for table in walk(&block, BASE) {
        assert_eq!(sum(&table.bytes), 0, "{} checksum", table.signature);
        let length = u32::from_le_bytes(table.bytes[4..8].try_into().unwrap()) as usize;
        assert_eq!(length, table.bytes.len(), "{} length", table.signature);
        assert_eq!(&table.bytes[10..16], b"PI4FW ");
    }
}

#[test]
fn the_tables_leave_out_the_tpm_when_the_vpu_has_none() {
    let machine = tables::Machine { tpm: None, ..sample() };
    let block = tables::assemble(&machine, BASE);
    let found = walk(&block, BASE);
    assert!(found.iter().all(|t| t.signature != "TPM2"));
    assert!(!found.iter().find(|t| t.signature == "DSDT").unwrap().bytes.windows(8).any(|w| w == b"MSFT0101"));
}

#[test]
fn the_tables_leave_out_the_usb_controller_when_the_board_has_none() {
    let machine = tables::Machine { xhci: None, ..sample() };
    let found = walk(&tables::assemble(&machine, BASE), BASE);
    assert!(found.iter().all(|t| t.signature != "IORT"));
    let dsdt = &found.iter().find(|t| t.signature == "DSDT").unwrap().bytes;
    assert!(!dsdt.windows(8).any(|w| w == b"PNP0D10\0"));
    assert!(!dsdt.windows(4).any(|w| w == b"SCB0"));
}

#[test]
fn the_iort_limits_the_usb_controller_to_the_bottom_2_gib_by_the_path_the_dsdt_gives_it() {
    let found = walk(&block(), BASE);
    let iort = &table(&found, "IORT").bytes;
    assert_eq!(iort[8], 0);
    assert_eq!(u32::from_le_bytes(iort[36..40].try_into().unwrap()), 1, "one node");
    let nodes = u32::from_le_bytes(iort[40..44].try_into().unwrap()) as usize;
    assert_eq!(nodes, 48);
    let node = &iort[nodes..];
    assert_eq!(node[0], 1, "a named component");
    let length = u16::from_le_bytes(node[1..3].try_into().unwrap()) as usize;
    assert_eq!(length % 4, 0);
    assert_eq!(nodes + length, iort.len());
    assert_eq!(u32::from_le_bytes(node[8..12].try_into().unwrap()), 0, "no ID mappings");
    assert_eq!(node[28], 31, "the address size limit");
    let name = &node[29..length];
    assert_eq!(&name[..16], b"\\_SB_.SCB0.XHC0\0");
    assert!(name[16..].iter().all(|b| *b == 0));
}

#[test]
fn the_fadt_is_hardware_reduced_acpi_6_3() {
    let found = walk(&block(), BASE);
    let fadt = &table(&found, "FACP").bytes;
    assert_eq!(fadt.len(), 276);
    assert_eq!(fadt[8], 6);
    assert_eq!(fadt[131], 3);
    let flags = u32::from_le_bytes(fadt[112..116].try_into().unwrap());
    assert_ne!(flags & (1 << 20), 0);
    let dsdt = u64::from_le_bytes(fadt[140..148].try_into().unwrap());
    assert_eq!(&block().bytes[(dsdt - BASE) as usize..][..4], b"DSDT");
}

#[test]
fn the_madt_enables_the_cores_asked_for() {
    let machine = tables::Machine { cores: 3, ..sample() };
    let found = walk(&tables::assemble(&machine, BASE), BASE);
    let madt = &table(&found, "APIC").bytes;
    let entries = &madt[44..];
    let enabled: Vec<bool> = entries
        .chunks(80)
        .take(4)
        .map(|gicc| {
            assert_eq!(gicc[0], 0xb);
            assert_eq!(gicc[1], 80);
            u32::from_le_bytes(gicc[12..16].try_into().unwrap()) & 1 == 1
        })
        .collect();
    assert_eq!(enabled, [true, true, true, false]);
    let parking: Vec<(u32, u64)> = entries
        .chunks(80)
        .take(4)
        .map(|gicc| {
            (u32::from_le_bytes(gicc[16..20].try_into().unwrap()), u64::from_le_bytes(gicc[24..32].try_into().unwrap()))
        })
        .collect();
    assert_eq!(parking, [(0, 0), (1, 0x810), (1, 0x820), (1, 0x830)]);
    assert_eq!(entries[4 * 80], 0xc);
    assert_eq!(entries[4 * 80 + 1], 24);
}

#[test]
fn the_tpm_table_names_the_control_area_and_the_acpi_start() {
    let found = walk(&block(), BASE);
    let tpm2 = &table(&found, "TPM2").bytes;
    assert_eq!(tpm2.len(), 64);
    assert_eq!(u64::from_le_bytes(tpm2[40..48].try_into().unwrap()), 0x3ebf_f040);
    assert_eq!(u32::from_le_bytes(tpm2[48..52].try_into().unwrap()), 8);
}

/// The length a package's own bytes declare, and how many bytes declare it.
fn package_length(bytes: &[u8]) -> (usize, usize) {
    let follow = (bytes[0] >> 6) as usize;
    if follow == 0 {
        return ((bytes[0] & 0x3f) as usize, 1);
    }
    let mut value = (bytes[0] & 0xf) as usize;
    for (i, b) in bytes[1..=follow].iter().enumerate() {
        value |= (*b as usize) << (4 + 8 * i);
    }
    (value, 1 + follow)
}

#[test]
fn a_package_counts_its_own_length_bytes() {
    for size in (0..70_000).step_by(7).chain([0x3d, 0x3e, 0x3f, 0x40, 0xfec, 0xfed, 0xfee, 0xfef, 0xff0]) {
        let data = vec![0xa5; size];
        let buffer = aml::buffer(&data);
        let (length, used) = package_length(&buffer[1..]);
        let inner = &buffer[1 + used..];
        assert_eq!(length, used + inner.len(), "buffer of {size} bytes");
        assert!(inner.ends_with(&data));
    }
}

/// The disassembly without its comments, which name what iasl recognises
/// (and "Unknown UUID" for what an older iasl does not).
fn without_comments(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(start) = rest.find("/*") {
        out.push_str(&rest[..start]);
        rest = rest[start..].find("*/").map_or("", |end| &rest[start + end + 2..]);
    }
    out + rest
}

fn iasl() -> Option<String> {
    Command::new("iasl").arg("-v").output().ok().map(|_| "iasl".to_string())
}

#[test]
fn iasl_disassembles_every_table() {
    let Some(iasl) = iasl() else {
        eprintln!("iasl is not installed: the tables are not checked with it");
        return;
    };
    let dir = std::env::temp_dir().join(format!("acpi-check-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for table in walk(&block(), BASE) {
        let path = dir.join(format!("{}.dat", table.signature));
        std::fs::write(&path, &table.bytes).unwrap();
        let output = Command::new(&iasl).arg("-d").arg(&path).output().unwrap();
        let text = String::from_utf8_lossy(&output.stdout).to_string() + &String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{}: {text}", table.signature);
        assert!(!text.contains("Error"), "{}: {text}", table.signature);
        let dsl = without_comments(&std::fs::read_to_string(dir.join(format!("{}.dsl", table.signature))).unwrap()).to_lowercase();
        for complaint in ["invalid", "unknown", "unexpected"] {
            assert!(!dsl.contains(complaint), "{} disassembles with a complaint ({complaint}):\n{dsl}", table.signature);
        }
    }
    let dsl = std::fs::read_to_string(dir.join("DSDT.dsl")).unwrap();
    for needed in [
        "ACPI0007", "ARMH0011", "BRCME88C", "BCM6E4E", "rgmii-rxid", "sdhci-caps-mask", "MSFT0101", "PRP0001",
        "6bbf6cab-5463-4714-b7cd-f0203c0368d4", "ACPI0004", "PNP0D10", "_DMA", "SCB0", "XHC0",
    ] {
        assert!(dsl.contains(needed), "DSDT has no {needed}:\n{dsl}");
    }
    let compiled = Command::new(&iasl).arg(dir.join("DSDT.dsl")).output().unwrap();
    let text = String::from_utf8_lossy(&compiled.stdout).to_string() + &String::from_utf8_lossy(&compiled.stderr);
    assert!(compiled.status.success(), "{text}");
    assert!(text.contains("0 Errors"), "{text}");
    let again = std::fs::read(dir.join("DSDT.aml")).unwrap();
    let original = std::fs::read(dir.join("DSDT.dat")).unwrap();
    assert_eq!(again[36..], original[36..], "the AML iasl makes from the disassembly differs from ours");
    std::fs::remove_dir_all(&dir).unwrap();
}

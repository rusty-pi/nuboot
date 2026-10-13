//! Write the sample tables into a directory, one file each, for `iasl -d` and
//! `acpiexec`, and the SMBIOS tables as `dmidecode --from-dump` reads them.

use acpi_check::{BASE, acpi::tables, sample, smbios, smbios_sample, walk};

fn main() {
    let dir = std::env::args().nth(1).expect("usage: acpi-dump <directory>");
    std::fs::create_dir_all(&dir).unwrap();
    let block = tables::assemble(&sample(), BASE);
    for table in walk(&block, BASE) {
        std::fs::write(format!("{dir}/{}.dat", table.signature), table.bytes).unwrap();
    }
    std::fs::write(format!("{dir}/SMBIOS3.bin"), smbios::tables::assemble(&smbios_sample(), 0)).unwrap();
}

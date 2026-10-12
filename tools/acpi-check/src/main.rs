//! Write the sample tables into a directory, one file each, for `iasl -d`
//! and `acpiexec`.

use acpi_check::{BASE, acpi::tables, sample, walk};

fn main() {
    let dir = std::env::args().nth(1).expect("usage: acpi-dump <directory>");
    std::fs::create_dir_all(&dir).unwrap();
    let block = tables::assemble(&sample(), BASE);
    for table in walk(&block, BASE) {
        std::fs::write(format!("{dir}/{}.dat", table.signature), table.bytes).unwrap();
    }
}

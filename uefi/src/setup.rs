//! The firmware's own screen, for an OS that asked for it with
//! `OsIndications` (`systemctl reboot --firmware-setup`): what this firmware
//! is and what it found, on the serial console, before the boot goes on. There
//! is nothing to set; the board takes its defaults from the board and the boot
//! medium.

use core::fmt::Write;

use r_efi::efi;

use crate::console::{Console, getc};
use crate::util::{Deadline, delay_us};
use crate::{COMMIT, REMOVABLE_PATH, esrt, fdt, info, mailbox, mem, secure, smbios, var, warn};

/// How long the screen waits for a key before the boot goes on: nobody may be
/// at the console.
const WAIT_US: u64 = 30_000_000;

fn requested() -> Option<u64> {
    let data = var::bytes("OsIndications", &var::GLOBAL)?;
    let mut word = [0; 8];
    let n = data.len().min(8);
    word[..n].copy_from_slice(&data[..n]);
    let indications = u64::from_le_bytes(word);
    (indications & esrt::BOOT_TO_FW_UI != 0).then_some(indications)
}

fn medium_name(code: u32) -> &'static str {
    match code {
        0 => "SD card",
        1 => "network",
        2 => "USB drive on the VL805",
        4 => "USB-C",
        5 => "boot.img in RAM",
        _ => "unknown",
    }
}

/// Show the screen if the OS asked for it, and take the request back first,
/// as the specification has it: the next boot goes on as usual.
pub fn show_if_asked(tree: &fdt::Fdt) {
    let Some(indications) = requested() else { return };
    let status = var::update("OsIndications", var::GLOBAL, &(indications & !esrt::BOOT_TO_FW_UI).to_le_bytes());
    if status != efi::Status::SUCCESS {
        warn!("setup", "the request was not taken back"; status = crate::util::Hex(status.as_usize()));
    }
    info!("setup", "the OS asked for the firmware's screen");
    draw(tree);
    wait_for_key();
}

fn draw(tree: &fdt::Fdt) {
    let mut out = Console;
    let model = smbios::model(tree);
    let _ = writeln!(out, "\nFirmware setup\n");
    let _ = writeln!(out, "  Firmware      nuboot {} ({})", COMMIT, esrt::VERSION);
    let _ = writeln!(out, "  Board         {}", core::str::from_utf8(&model).unwrap_or(""));
    if let Some(revision) = smbios::revision(tree) {
        let _ = writeln!(out, "  Revision      {:x}", revision);
    }
    let _ = writeln!(out, "  Memory        {} MiB", mem::map().total_mib());
    let keys = if secure::owned() { "the owner's db" } else { "the builder's db" };
    let _ = writeln!(out, "  Secure Boot   enabled (deployed), {}", keys);
    if let Some(medium) = mailbox::boot_medium() {
        let _ = writeln!(out, "  Loaded from   {}", medium_name(medium.code));
    }
    let _ = writeln!(out, "  Boot option   {}", REMOVABLE_PATH);
    let _ = writeln!(out, "\nNothing here is configurable. Press a key to boot, or wait {} s.", WAIT_US / 1_000_000);
}

fn wait_for_key() {
    while getc().is_some() {}
    let deadline = Deadline::after_us(WAIT_US);
    while !deadline.passed() && getc().is_none() {
        delay_us(1_000);
    }
}

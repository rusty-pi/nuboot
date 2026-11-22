//! What the VPU measures into the TPM before the ARM starts: the firmware's
//! identity and the hardware it runs on. The events are kept so that UEFI can
//! put them in the log it hands to the OS (tag `0x000300a4`), which then
//! replays to the PCRs the way a TPM's event log does.
//!
//! PCR 0 holds the firmware: its version, and the UEFI image and the device tree
//! it starts the ARM with. PCR 2 holds the firmware of the peripherals: the
//! EEPROM's bootloader and the VL805's images when the VPU loads them, so that
//! a change of either is told apart from a change of this firmware. PCR 1 holds
//! the board: the revision code, the serial number, the extended revision, the
//! MAC address fuses, the boot mode row and the SDRAM size, each as a
//! `name=value` event. PCR 3 holds the configuration of the peripherals: the
//! EEPROM's `bootconf.txt`, so an EEPROM update moves PCR 2 and 3 and not PCR 1.

use core::fmt::Write;
use core::ptr::{read_volatile, write_volatile};

use crate::eeprom;
use crate::keystore;
use crate::sha256;

pub const EV_S_CRTM_VERSION: u32 = 0x0000_0008;
pub const EV_PLATFORM_CONFIG_FLAGS: u32 = 0x0000_000a;
pub const EV_EFI_ACTION: u32 = 0x8000_0007;
pub const EV_EFI_PLATFORM_FIRMWARE_BLOB2: u32 = 0x8000_000a;

const PCR_FIRMWARE: usize = 0;
const PCR_BOARD: usize = 1;
const PCR_PERIPHERAL: usize = 2;
const PCR_PERIPHERAL_CONFIG: usize = 3;
const PCR_SECURE_BOOT: usize = 7;

pub const MAX_EVENTS: usize = 24;
pub const MAX_DATA: usize = 80;

#[derive(Clone, Copy)]
pub struct Event {
    pub pcr: u32,
    pub kind: u32,
    pub digest: [u8; 32],
    pub len: usize,
    pub data: [u8; MAX_DATA],
}

const NONE: Event = Event { pcr: 0, kind: 0, digest: [0; 32], len: 0, data: [0; MAX_DATA] };

static mut EVENTS: [Event; MAX_EVENTS] = [NONE; MAX_EVENTS];
static mut COUNT: usize = 0;

/// Event `index`, in the order they were measured.
pub fn event(index: usize) -> Option<Event> {
    (index < unsafe { read_volatile(&raw const COUNT) }).then(|| unsafe { (*(&raw const EVENTS))[index] })
}

/// Extend `pcr` with `digest` and keep the event.
fn record(pcr: usize, kind: u32, digest: [u8; 32], data: &[u8]) {
    let n = unsafe { read_volatile(&raw const COUNT) };
    if n == MAX_EVENTS || data.len() > MAX_DATA || keystore::extend(pcr, &digest).is_err() {
        return;
    }
    let mut event = NONE;
    event.pcr = pcr as u32;
    event.kind = kind;
    event.digest = digest;
    event.len = data.len();
    event.data[..data.len()].copy_from_slice(data);
    unsafe {
        (*(&raw mut EVENTS))[n] = event;
        write_volatile(&raw mut COUNT, n + 1);
    }
}

/// A small text buffer for `name=value` events.
struct Text {
    bytes: [u8; MAX_DATA],
    len: usize,
}

impl Write for Text {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let end = self.len + s.len();
        self.bytes.get_mut(self.len..end).ok_or(core::fmt::Error)?.copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}

fn setting(pcr: usize, args: core::fmt::Arguments) {
    let mut text = Text { bytes: [0; MAX_DATA], len: 0 };
    if text.write_fmt(args).is_ok() {
        let data = &text.bytes[..text.len];
        record(pcr, EV_PLATFORM_CONFIG_FLAGS, sha256::digest(data), data);
    }
}

/// `UEFI_PLATFORM_FIRMWARE_BLOB2`: what is measured is the blob, and the
/// event says which it is.
fn blob(pcr: usize, description: &str, blob: &[u8]) {
    blob_at(pcr, description, sha256::digest(blob), blob.as_ptr() as u64, blob.len() as u64);
}

/// A blob event for a blob that was hashed where it is, `len` bytes at `base`.
fn blob_at(pcr: usize, description: &str, digest: [u8; 32], base: u64, len: u64) {
    let mut data = [0u8; MAX_DATA];
    data[0] = description.len() as u8;
    data[1..1 + description.len()].copy_from_slice(description.as_bytes());
    let at = 1 + description.len();
    data[at..at + 8].copy_from_slice(&base.to_le_bytes());
    data[at + 8..at + 16].copy_from_slice(&len.to_le_bytes());
    record(pcr, EV_EFI_PLATFORM_FIRMWARE_BLOB2, digest, &data[..at + 16]);
}

/// A firmware version event: `text` as UTF-16.
fn crtm_version(args: core::fmt::Arguments) {
    let mut text = Text { bytes: [0; MAX_DATA], len: 0 };
    if text.write_fmt(args).is_err() {
        return;
    }
    let mut version = [0u8; MAX_DATA];
    let mut len = 0;
    for unit in core::str::from_utf8(&text.bytes[..text.len]).unwrap_or("").encode_utf16() {
        if len + 2 > MAX_DATA {
            break;
        }
        version[len..len + 2].copy_from_slice(&unit.to_le_bytes());
        len += 2;
    }
    record(PCR_FIRMWARE, EV_S_CRTM_VERSION, sha256::digest(&version[..len]), &version[..len]);
}

/// The EEPROM's boot configuration, `bootconf.txt`, as the SHA-256 of its
/// bytes, into PCR 3; `none` when the EEPROM has no such file.
pub fn eeprom_config(digest: Option<[u8; 32]>) {
    let mut hex = [0u8; 64];
    let value = match &digest {
        Some(digest) => {
            for (i, byte) in digest.iter().enumerate() {
                hex[2 * i] = b"0123456789abcdef"[(byte >> 4) as usize];
                hex[2 * i + 1] = b"0123456789abcdef"[(byte & 15) as usize];
            }
            core::str::from_utf8(&hex).unwrap_or("")
        }
        None => "none",
    };
    setting(PCR_PERIPHERAL_CONFIG, format_args!("eeprom.bootconf={value}"));
}

/// The EEPROM's bootloader, `bootcode.bin`, which ran before this firmware, into PCR 2: the
/// SHA-256 of the section as the flash stores it, `at` and `len` placing it in
/// the flash. Nothing when the EEPROM has none.
pub fn eeprom_bootcode(bootcode: Option<&eeprom::Digest>) {
    if let Some(b) = bootcode {
        blob_at(PCR_PERIPHERAL, "eeprom-bootcode", b.sha256, b.at as u64, b.len as u64);
    }
}

/// The images the VPU loaded into the VL805, which is the firmware the
/// controller runs, into PCR 2.
pub fn vl805(hub: &[u8], mcu: &[u8]) {
    blob(PCR_PERIPHERAL, "vl805-hub", hub);
    blob(PCR_PERIPHERAL, "vl805-mcu", mcu);
}

/// Measure the firmware that started this one as an update, ahead of this one:
/// its commit and version, and the SHA-256 the loader took of this image before
/// it ran it, which `base` and `len` place in memory.
pub fn loader(commit: &str, version: u32, digest: [u8; 32], base: u32, len: u32) {
    crtm_version(format_args!("nuboot-loader {commit} {version}"));
    blob_at(PCR_FIRMWARE, "start4-update", digest, base as u64, len as u64);
}

/// The certificate the owner's `boot.img` holds for UEFI to trust in place of
/// its built-in `db` (`owner-db.der`), into PCR 7 where the Secure Boot policy
/// is: `owner-db sha256=<hex>` for the file's SHA-256, or `owner-db invalid`
/// for a file the firmware could not read, which leaves UEFI with no `db`. A
/// board without one measures nothing, and UEFI measures its built-in `db`.
pub fn owner_db(file: Option<&[u8]>) {
    let mut text = Text { bytes: [0; MAX_DATA], len: 0 };
    let written = match file {
        Some(file) => {
            let digest = sha256::digest(file);
            let _ = text.write_str("owner-db sha256=");
            digest.iter().try_for_each(|byte| write!(text, "{byte:02x}"))
        }
        None => text.write_str("owner-db invalid"),
    };
    if written.is_ok() {
        let data = &text.bytes[..text.len];
        record(PCR_SECURE_BOOT, EV_EFI_ACTION, sha256::digest(data), data);
    }
}

/// Measure the firmware and the board. Once, before the ARM starts.
pub fn platform(commit: &str, uefi: &[u8], tree: &[u8], revision: u32, ext_revision: u32, serial: u32, mac: (u32, u32), bootmode: u32, sdram_mib: u32) {
    crtm_version(format_args!("nuboot {commit}"));
    blob(PCR_FIRMWARE, "pi4-uefi", uefi);
    blob(PCR_FIRMWARE, "device-tree", tree);

    setting(PCR_BOARD, format_args!("board.revision={revision:08x}"));
    setting(PCR_BOARD, format_args!("board.ext_revision={ext_revision:08x}"));
    setting(PCR_BOARD, format_args!("board.serial={serial:08x}"));
    setting(PCR_BOARD, format_args!("board.mac_rows={:08x}{:08x}", mac.0, mac.1));
    setting(PCR_BOARD, format_args!("otp.bootmode={bootmode:08x}"));
    setting(PCR_BOARD, format_args!("sdram.mib={sdram_mib}"));
}

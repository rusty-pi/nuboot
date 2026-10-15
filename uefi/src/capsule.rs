//! Firmware update capsules on the disk. fwupd puts a capsule for this
//! firmware's ESRT entry in `\EFI\UpdateCapsule` on the EFI system partition
//! and reboots; at boot this looks there, checks each file against the keys
//! the firmware's own `db` entries hold, and stages what it carries as a
//! tryboot.
//!
//! A capsule is an `EFI_CAPSULE_HEADER` for one of the ESRT's resources, this
//! firmware ([`esrt::FIRMWARE_CLASS`]) or the EEPROM bootloader
//! ([`esrt::EEPROM_CLASS`]), then a
//! `WIN_CERTIFICATE_UEFI_GUID` holding a detached PKCS #7 signature over what
//! follows it: `P4FW`, the resource's class GUID again, the version as a
//! little-endian `u32`, the length of `boot.sig` as one, `boot.sig`, and
//! `boot.img`. The class is in the signed part so that a capsule signed for the
//! EEPROM bootloader cannot be handed to the firmware, or the other way round.
//! The bootloader checks the pair against the EEPROM's customer key when it
//! boots it.
//!
//! An update of the firmware takes three boots:
//!
//! 1. The firmware that finds the capsule writes `tryboot.img` and
//!    `tryboot.sig` next to `boot.img` and `boot.sig`, records that an update
//!    is pending, and resets with the bootloader's tryboot request set.
//! 2. The bootloader starts the new firmware out of `tryboot.img`. When that
//!    firmware reaches `ExitBootServices` it records the update as proven.
//!    The request is one-shot, so a boot that fails before then is followed by
//!    one from `boot.img`.
//! 3. The firmware that starts from `boot.img` finds the update proven and
//!    makes `tryboot.img` and `tryboot.sig` the boot pair, or finds it
//!    unproven and removes them.
//!
//! An update of the EEPROM carries a `pieeprom.upd` and `pieeprom.sig` in its
//! `boot.img`, which the bootloader writes to the EEPROM when it boots the
//! tryboot. That wipes the variable store in the EEPROM's tail, so the store
//! is copied to the file system first, and put back once the EEPROM says it was
//! updated. The version of an EEPROM capsule is the time in `pieeprom.sig`.

use alloc::vec::Vec;

use r_efi::efi;
use r_efi::protocols::simple_file_system;

use crate::util::{W, eq_ignore_case};
use crate::{esrt, fat, info, proto, secure, tables, var, warn};

const DIRECTORY: &str = "\\EFI\\UpdateCapsule";
const MAGIC: &[u8; 4] = b"P4FW";
const HEADER: usize = 28;
/// The most an image may carry.
const MAX_IMAGE: usize = 16 * 1024 * 1024;
/// The most capsules one scan reads, and how long it goes on: each is read
/// whole before it is checked, and every volume is scanned, USB drives included.
const MAX_CAPSULES: usize = 8;
const SCAN_BUDGET_US: u64 = 30_000_000;
const MAX_SIGNATURE: usize = 4096;
/// The most a capsule file may be: the image, and the header and the signature
/// around it.
const MAX_CAPSULE: usize = MAX_IMAGE + 64 * 1024;
/// The most a copy of the variable store may be.
const MAX_BACKUP: usize = 1024 * 1024;

/// What an update leaves in the flash store: the state and the version the
/// update carries.
const RECORD: &str = "FwUpdate";
/// What the last update came to, for the OS to read in the ESRT: the version
/// and the status.
const RESULT: &str = "FwUpdateResult";
const PENDING: u8 = 1;
const PROVEN: u8 = 2;

/// `EFI_CERT_TYPE_PKCS7_GUID`.
const PKCS7: efi::Guid =
    efi::Guid::from_fields(0x4aafd29d, 0x68df, 0x49ee, 0x8a, 0xa9, &[0x34, 0x7d, 0x37, 0x56, 0x65, 0xa7]);

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Firmware,
    Eeprom,
}

impl Kind {
    fn class(self) -> &'static efi::Guid {
        match self {
            Kind::Firmware => &esrt::FIRMWARE_CLASS,
            Kind::Eeprom => &esrt::EEPROM_CLASS,
        }
    }

    fn running(self) -> u32 {
        match self {
            Kind::Firmware => esrt::VERSION,
            Kind::Eeprom => crate::eeprom::version(),
        }
    }

    fn result_name(self) -> &'static str {
        match self {
            Kind::Firmware => RESULT,
            Kind::Eeprom => "EepromUpdateResult",
        }
    }

    fn of(class: &[u8]) -> Option<Kind> {
        [Kind::Firmware, Kind::Eeprom].into_iter().find(|k| k.class().as_bytes() == class)
    }

    fn name(self) -> &'static str {
        match self {
            Kind::Firmware => "firmware",
            Kind::Eeprom => "EEPROM",
        }
    }
}

/// A capsule that passed every check.
pub struct Capsule {
    kind: Kind,
    pub version: u32,
    pub sig: Vec<u8>,
    pub img: Vec<u8>,
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

fn hex(bytes: &[u8]) -> alloc::string::String {
    bytes.iter().map(|b| alloc::format!("{b:02x}")).collect()
}

/// What a capsule file is, if it passes: otherwise the status the ESRT gets
/// and why.
fn check(file: &[u8]) -> Result<Capsule, (u32, &'static str)> {
    let invalid = |why| (esrt::INVALID_FORMAT, why);
    let kind = file.get(..16).and_then(Kind::of).ok_or(invalid("not a capsule for this firmware"))?;
    let header = u32_at(file, 16).ok_or(invalid("truncated"))? as usize;
    let size = u32_at(file, 24).ok_or(invalid("truncated"))? as usize;
    if header < HEADER || size > file.len() || header > size {
        return Err(invalid("header sizes do not fit the file"));
    }
    let body = &file[header..size];
    let length = u32_at(body, 0).ok_or(invalid("no signature"))? as usize;
    if length < 24 || body.get(4..6) != Some(&[0x00, 0x02]) || body.get(6..8) != Some(&[0xf1, 0x0e]) || body.get(8..24) != Some(PKCS7.as_bytes()) {
        return Err(invalid("signature is not a PKCS #7 certificate"));
    }
    let signature = body.get(24..length).ok_or(invalid("signature runs past the capsule"))?;
    let image = &body[length..];
    secure::verify_own(signature, image).map_err(|why| (esrt::AUTH_ERROR, why))?;
    if image.get(..4) != Some(MAGIC) {
        return Err(invalid("image is not firmware"));
    }
    if image.get(4..20) != Some(kind.class().as_bytes()) {
        return Err(invalid("the signed image is for another resource than the capsule header names"));
    }
    let version = u32_at(image, 20).ok_or(invalid("no version"))?;
    let sig_len = u32_at(image, 24).ok_or(invalid("no boot.sig"))? as usize;
    let sig = image.get(28..28 + sig_len).filter(|_| sig_len <= MAX_SIGNATURE).ok_or(invalid("boot.sig does not fit"))?;
    let img = &image[28 + sig_len..];
    if img.is_empty() || img.len() > MAX_IMAGE {
        return Err((esrt::INSUFFICIENT_RESOURCES, "boot.img is empty or too large"));
    }
    let text = core::str::from_utf8(sig).map_err(|_| invalid("boot.sig is not text"))?;
    if !text.starts_with(hex(&crate::sha256::digest(img)).as_str()) || !text.contains("rsa2048:") {
        return Err(invalid("boot.sig is not an RSA signature of this boot.img"));
    }
    if version <= kind.running() {
        return Err((esrt::INCORRECT_VERSION, "version is not newer than the running one's"));
    }
    Ok(Capsule { kind, version, sig: sig.to_vec(), img: img.to_vec() })
}

/// The update under way: its state, what it updates and its version.
fn record() -> Option<(u8, Kind, u32)> {
    let data = var::bytes(RECORD, &esrt::FIRMWARE_CLASS)?;
    let kind = if *data.get(1)? == 1 { Kind::Eeprom } else { Kind::Firmware };
    Some((*data.first()?, kind, u32_at(&data, 2)?))
}

fn set_record(state: u8, kind: Kind, version: u32) -> efi::Status {
    let mut data = alloc::vec![state, (kind == Kind::Eeprom) as u8];
    data.extend_from_slice(&version.to_le_bytes());
    var::keep(RECORD, esrt::FIRMWARE_CLASS, &data)
}

fn set_result(kind: Kind, version: u32, status: u32) {
    let mut data = version.to_le_bytes().to_vec();
    data.extend_from_slice(&status.to_le_bytes());
    var::keep(kind.result_name(), esrt::FIRMWARE_CLASS, &data);
    esrt::attempted(kind.class(), version, status);
}

/// The file system with the bootloader's `boot.img` on it.
fn boot_fs() -> Option<efi::Handle> {
    let boot = wide("boot.img");
    proto::with(Some(&simple_file_system::PROTOCOL_GUID)).into_iter().find(|&fs| {
        fat::list_files(fs, &[]).is_ok_and(|names| names.iter().any(|n| eq_ignore_case(n, &boot)))
    })
}

fn staged(fs: efi::Handle) -> bool {
    let names = fat::list_files(fs, &[]).unwrap_or_default();
    ["tryboot.img", "tryboot.sig"].iter().all(|f| names.iter().any(|n| eq_ignore_case(n, &wide(f))))
}

/// Whether the file `name` on `fs` holds exactly `data`.
fn holds(fs: efi::Handle, name: &str, data: &[u8]) -> bool {
    fat::read_file(fs, &wide(name), MAX_IMAGE).is_ok_and(|read| read == data)
}

/// Whether the signature file `sig` on `fs` is the digest of the image `img`.
fn pair(fs: efi::Handle, img: &str, sig: &str) -> bool {
    let (Ok(img), Ok(sig)) = (fat::read_file(fs, &wide(img), MAX_IMAGE), fat::read_file(fs, &wide(sig), MAX_SIGNATURE)) else { return false };
    core::str::from_utf8(&sig).is_ok_and(|text| text.starts_with(hex(&crate::sha256::digest(&img)).as_str()))
}

fn remove_staged(fs: efi::Handle) {
    for name in ["tryboot.img", "tryboot.sig"] {
        let _ = fat::remove_file(fs, &[], &wide(name));
    }
}

/// The firmware that started from `tryboot.img` has reached the OS.
fn prove() {
    if let Some((PENDING, Kind::Firmware, version)) = record() {
        if version == esrt::VERSION {
            set_record(PROVEN, Kind::Firmware, version);
            info!("capsule", "the updated firmware reached the OS"; version = version);
        }
    }
}

/// The variable store as it was before an EEPROM update.
const BACKUP: &str = "STORE.BAK";

/// Say how an update an earlier boot started has gone, and finish it.
pub fn resume() {
    if restore_store() {
        return;
    }
    for kind in [Kind::Firmware, Kind::Eeprom] {
        if let Some(data) = var::bytes(kind.result_name(), &esrt::FIRMWARE_CLASS) {
            if let (Some(version), Some(status)) = (u32_at(&data, 0), u32_at(&data, 4)) {
                esrt::attempted(kind.class(), version, status);
            }
        }
    }
    let Some((state, kind, version)) = record() else { return };
    match kind {
        Kind::Firmware => resume_firmware(state, version),
        Kind::Eeprom => resume_eeprom(version),
    }
}

fn resume_firmware(state: u8, version: u32) {
    let kind = Kind::Firmware;
    if version == esrt::VERSION {
        info!("capsule", "firmware updated"; version = version);
        esrt::attempted(kind.class(), version, esrt::SUCCESS);
        tables::before_exit_boot_services(prove);
        return;
    }
    let Some(fs) = boot_fs() else {
        var::forget(RECORD, esrt::FIRMWARE_CLASS);
        return;
    };
    if state == PROVEN && staged(fs) && pair(fs, "tryboot.img", "tryboot.sig") {
        let (img, sig) = (wide("boot.img"), wide("boot.sig"));
        let (timg, tsig) = (wide("tryboot.img"), wide("tryboot.sig"));
        match fat::adopt(fs, &[], &[(&timg, &img), (&tsig, &sig)]) {
            Ok(()) if !pair(fs, "boot.img", "boot.sig") => {
                warn!("capsule", "boot.img and boot.sig do not belong together after the commit"; version = version);
            }
            Ok(()) => {
                set_result(kind, version, esrt::SUCCESS);
                var::forget(RECORD, esrt::FIRMWARE_CLASS);
                info!("capsule", "firmware committed"; version = version);
                crate::watchdog::reset(false);
            }
            Err(status) => warn!("capsule", "update not committed"; version = version, status = status.as_usize()),
        }
        return;
    }
    warn!("capsule", "the updated firmware did not reach the OS, update dropped"; version = version);
    remove_staged(fs);
    set_result(kind, version, esrt::UNSUCCESSFUL);
    var::forget(RECORD, esrt::FIRMWARE_CLASS);
}

/// The boot after the bootloader was asked to update the EEPROM: it has, or it
/// has not.
fn resume_eeprom(version: u32) {
    let kind = Kind::Eeprom;
    let Some(fs) = boot_fs() else {
        var::forget(RECORD, esrt::FIRMWARE_CLASS);
        return;
    };
    remove_staged(fs);
    var::forget(RECORD, esrt::FIRMWARE_CLASS);
    let _ = fat::remove_file(fs, &[], &wide(BACKUP));
    if kind.running() < version {
        warn!("capsule", "the bootloader did not update the EEPROM, update dropped"; version = version, eeprom = kind.running());
        set_result(kind, version, esrt::UNSUCCESSFUL);
        return;
    }
    set_result(kind, version, esrt::SUCCESS);
    info!("capsule", "EEPROM updated"; version = version);
}

/// An EEPROM update wipes the variable store, record of the update included.
/// With the store empty and the copy the update was staged with on the file
/// system, put the copy back and start again: the record says what came of it.
fn restore_store() -> bool {
    if !crate::eeprom::store_is_empty() {
        return false;
    }
    let Some(fs) = boot_fs() else { return false };
    let Ok(backup) = fat::read_file(fs, &wide(BACKUP), MAX_BACKUP) else { return false };
    let _ = fat::remove_file(fs, &[], &wide(BACKUP));
    if !crate::eeprom::restore(&backup) {
        warn!("capsule", "variable store not restored");
        return false;
    }
    info!("capsule", "variable store restored after an EEPROM update, restarting");
    crate::watchdog::reset(false);
}

/// Look for capsules on every file system and check each one.
pub fn scan() {
    resume();
    let directory = wide(DIRECTORY);
    let (started, mut read) = (crate::util::counter_us(), 0);
    for fs in proto::with(Some(&simple_file_system::PROTOCOL_GUID)) {
        let Ok(names) = fat::list_files(fs, &directory) else { continue };
        for name in names.into_iter().filter(|n| n.len() > 4 && eq_ignore_case(&n[n.len() - 4..], &wide(".cap"))) {
            if read == MAX_CAPSULES || crate::util::counter_us() - started > SCAN_BUDGET_US {
                warn!("capsule", "no more capsules are read at this boot"; read = read);
                return;
            }
            read += 1;
            let mut path = directory.clone();
            path.push(b'\\' as u16);
            path.extend_from_slice(&name);
            let file = match fat::read_file(fs, &path, MAX_CAPSULE) {
                Ok(file) => file,
                Err(status) => {
                    warn!("capsule", "capsule unreadable"; path = W(&path), status = status.as_usize());
                    continue;
                }
            };
            match check(&file) {
                Ok(capsule) => {
                    info!("capsule", "capsule verified"; path = W(&path), version = capsule.version, bytes = capsule.img.len());
                    stage(fs, &directory, &name, &capsule);
                }
                Err((status, why)) => {
                    warn!("capsule", "capsule refused"; path = W(&path), reason = why);
                    esrt::attempted(&esrt::FIRMWARE_CLASS, 0, status);
                }
            }
        }
    }
}

/// Write the capsule's pair as the tryboot, and restart on it.
fn stage(capsule_fs: efi::Handle, directory: &[u16], name: &[u16], capsule: &Capsule) {
    let failed = |why: &str, status: efi::Status| {
        warn!("capsule", "update not staged"; reason = why, status = status.as_usize());
        esrt::attempted(capsule.kind.class(), capsule.version, esrt::UNSUCCESSFUL);
    };
    if !var::keeps() {
        return failed("no device key or flash store to record the update in", efi::Status::UNSUPPORTED);
    }
    let Some(fs) = boot_fs() else { return failed("no file system holds boot.img", efi::Status::NOT_FOUND) };
    let status = set_record(PENDING, capsule.kind, capsule.version);
    if status.is_error() {
        return failed("the update could not be recorded", status);
    }
    let written = fat::write_file(fs, &[], &wide("tryboot.img"), &capsule.img)
        .and_then(|()| fat::write_file(fs, &[], &wide("tryboot.sig"), &capsule.sig));
    if let Err(status) = written {
        remove_staged(fs);
        var::forget(RECORD, esrt::FIRMWARE_CLASS);
        return failed("tryboot.img and tryboot.sig could not be written", status);
    }
    if !holds(fs, "tryboot.img", &capsule.img) || !holds(fs, "tryboot.sig", &capsule.sig) {
        remove_staged(fs);
        var::forget(RECORD, esrt::FIRMWARE_CLASS);
        return failed("what was written does not read back", efi::Status::DEVICE_ERROR);
    }
    let _ = fat::remove_file(capsule_fs, directory, name);
    if capsule.kind == Kind::Eeprom {
        let saved = crate::eeprom::backup().is_some_and(|bytes| {
            fat::write_file(fs, &[], &wide(BACKUP), &bytes).is_ok() && holds(fs, BACKUP, &bytes)
        });
        if !saved {
            remove_staged(fs);
            var::forget(RECORD, esrt::FIRMWARE_CLASS);
            return failed("the variable store could not be saved", efi::Status::DEVICE_ERROR);
        }
    }
    info!("capsule", "update staged, restarting as a tryboot"; version = capsule.version, kind = capsule.kind.name());
    crate::watchdog::request_tryboot();
    crate::watchdog::reset(false);
}

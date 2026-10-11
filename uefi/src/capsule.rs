//! Firmware update capsules on the disk. fwupd puts a capsule for this
//! firmware's ESRT entry in `\EFI\UpdateCapsule` on the EFI system partition
//! and reboots; at boot this looks there, and checks each file against the
//! keys the firmware's own `db` entries hold.
//!
//! A capsule is an `EFI_CAPSULE_HEADER` for [`esrt::FIRMWARE_CLASS`], then a
//! `WIN_CERTIFICATE_UEFI_GUID` holding a detached PKCS #7 signature over what
//! follows it: `P4FW`, the version as a little-endian `u32`, and the flash
//! region the firmware owns (`0` to `0x6ffff`), as much of it as is written.

use alloc::vec::Vec;

use r_efi::efi;
use r_efi::protocols::simple_file_system;

use crate::util::{W, eq_ignore_case};
use crate::{error, esrt, fat, firmware, info, proto, secure, var, warn};

const DIRECTORY: &str = "\\EFI\\UpdateCapsule";
const MAGIC: &[u8; 4] = b"P4FW";
/// What the firmware owns of the flash: below the variable store.
const HEADER: usize = 28;

/// `EFI_CERT_TYPE_PKCS7_GUID`.
const PKCS7: efi::Guid =
    efi::Guid::from_fields(0x4aafd29d, 0x68df, 0x49ee, 0x8a, 0xa9, &[0x34, 0x7d, 0x37, 0x56, 0x65, 0xa7]);

/// A capsule that passed every check.
pub struct Capsule {
    pub version: u32,
    pub region: Vec<u8>,
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// What a capsule file is, if it passes: otherwise the status the ESRT gets
/// and why.
fn check(file: &[u8]) -> Result<Capsule, (u32, &'static str)> {
    let invalid = |why| (esrt::INVALID_FORMAT, why);
    if file.get(..16) != Some(esrt::FIRMWARE_CLASS.as_bytes()) {
        return Err(invalid("not a capsule for this firmware"));
    }
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
    let version = u32_at(image, 4).ok_or(invalid("no version"))?;
    let region = &image[8..];
    if region.len() > firmware::REGION {
        return Err((esrt::INSUFFICIENT_RESOURCES, "image is larger than the firmware's flash region"));
    }
    if version <= esrt::VERSION {
        return Err((esrt::INCORRECT_VERSION, "version is not newer than the running firmware"));
    }
    Ok(Capsule { version, region: region.to_vec() })
}

/// What a capsule's application leaves for the boot after it, until that boot
/// has told the OS how it went: the version it installed.
const PENDING: &str = "FwUpdateVersion";

/// If a capsule was applied before this boot, say how it went: the firmware
/// that started is the version the capsule carried or it is not.
pub fn resume() {
    let Some(data) = var::bytes(PENDING, &esrt::FIRMWARE_CLASS) else { return };
    var::forget(PENDING, esrt::FIRMWARE_CLASS);
    let version = data.get(..4).and_then(|b| b.try_into().ok()).map_or(0, u32::from_le_bytes);
    if version == esrt::VERSION {
        info!("capsule", "firmware updated"; version = version);
        esrt::attempted(version, esrt::SUCCESS);
    } else {
        warn!("capsule", "the firmware that started is not the capsule's version"; capsule = version, running = esrt::VERSION);
        esrt::attempted(version, esrt::UNSUCCESSFUL);
    }
}

/// Look for capsules on every file system and check each one.
pub fn scan() {
    resume();
    let directory: Vec<u16> = DIRECTORY.encode_utf16().collect();
    for fs in proto::with(Some(&simple_file_system::PROTOCOL_GUID)) {
        let Ok(names) = fat::list_files(fs, &directory) else { continue };
        for name in names.into_iter().filter(|n| n.len() > 4 && eq_ignore_case(&n[n.len() - 4..], &[b'.' as u16, b'c' as u16, b'a' as u16, b'p' as u16])) {
            let mut path = directory.clone();
            path.push(b'\\' as u16);
            path.extend_from_slice(&name);
            let file = match fat::read_file(fs, &path) {
                Ok(file) => file,
                Err(status) => {
                    warn!("capsule", "capsule unreadable"; path = W(&path), status = status.as_usize());
                    continue;
                }
            };
            match check(&file) {
                Ok(capsule) => {
                    info!("capsule", "capsule verified"; path = W(&path), version = capsule.version, bytes = capsule.region.len());
                    apply(&capsule);
                }
                Err((status, why)) => {
                    warn!("capsule", "capsule refused"; path = W(&path), reason = why);
                    esrt::attempted(0, status);
                }
            }
        }
    }
}

/// Write the capsule's image over the firmware and restart on it.
fn apply(capsule: &Capsule) {
    if !var::keeps() {
        warn!("capsule", "no device key or flash store to record the update in, not applying"; version = capsule.version);
        esrt::attempted(capsule.version, esrt::UNSUCCESSFUL);
        return;
    }
    let status = var::keep(PENDING, esrt::FIRMWARE_CLASS, &capsule.version.to_le_bytes());
    if status.is_error() {
        warn!("capsule", "update not recorded, not applying"; status = status.as_usize());
        esrt::attempted(capsule.version, esrt::UNSUCCESSFUL);
        return;
    }
    info!("capsule", "applying"; version = capsule.version, bytes = capsule.region.len());
    if firmware::write(&capsule.region) {
        info!("capsule", "firmware written, restarting"; version = capsule.version);
        crate::watchdog::reset(false);
    }
    error!("capsule", "firmware not written"; version = capsule.version);
    var::forget(PENDING, esrt::FIRMWARE_CLASS);
    esrt::attempted(capsule.version, esrt::UNSUCCESSFUL);
}

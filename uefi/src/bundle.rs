//! Update bundles: a whole firmware image, signed by an update key, that
//! replaces the firmware at the next boot without the board owner signing it.
//! The VPU firmware the bootloader loaded (`src/update.rs`) is the one that
//! checks the signature and runs the image; this firmware finds the bundle,
//! leaves it in RAM for that firmware and resets.
//!
//! A capsule for [`esrt::UPDATE_CLASS`] carries the bundle after the version
//! (`P4FW`, the class, the version, the bundle), and `db` signs the capsule as
//! it does every other. The bundle is kept in the root of the file system the
//! capsule came from, as its version in eight hex digits and `.UPD`, because
//! the firmware that runs first at every power-up is the one the bootloader
//! loaded, and it stages the newest bundle again each time. A new bundle does
//! not replace the one running: the older one stays until the newer has reached
//! the OS, and is what runs when it does not.
//!
//! The record in the flash store keeps an update from running away: staging a
//! bundle makes it pending, the updated firmware proves it at
//! `ExitBootServices`, and a bundle found pending by a firmware that is not
//! it did not get that far and is not staged again.

use alloc::vec::Vec;

use r_efi::efi;
use r_efi::protocols::simple_file_system;

use crate::util::eq_ignore_case;
use crate::{esrt, fat, info, mem, proto, tables, var, warn};

/// Where the VPU firmware looks for the bundle, which is in the ARM's memory
/// that survives the reset (`src/update.rs`).
const BUNDLE_ADDR: u64 = 0x3e00_0000;
/// The address the image in a bundle is linked at.
const SLOT_BASE: u32 = 0x3ee0_0200;
const MAGIC: &[u8; 4] = b"P4UB";
const FORMAT: u32 = 1;
const HEADER: usize = 88;
const MAX_IMAGE: usize = 2 << 20;
const PAGE: usize = 4096;

const EXTENSION: &str = ".UPD";
const RECORD: &str = "BundleUpdate";
const RESULT: &str = "BundleUpdateResult";
/// The newest bundle that has reached the OS. It only grows, and nothing older
/// is staged after it.
const NEWEST: &str = "BundleNewest";
const PENDING: u8 = 1;
const PROVEN: u8 = 2;
const REFUSED: u8 = 3;

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

/// The name a bundle is kept under: its version as eight hex digits, which an
/// 8.3 name holds.
fn file_name(version: u32) -> Vec<u16> {
    wide(&alloc::format!("{version:08X}{EXTENSION}"))
}

/// The version a file name says, when it is one of these.
fn version_in(name: &[u16]) -> Option<u32> {
    if name.len() != 8 + EXTENSION.len() || !eq_ignore_case(&name[8..], &wide(EXTENSION)) {
        return None;
    }
    name[..8].iter().try_fold(0u32, |version, &unit| Some(version << 4 | char::from_u32(unit as u32)?.to_digit(16)?))
}

/// The version a bundle carries, when it has the layout the VPU firmware
/// reads: its signature is that firmware's to check.
fn version_of(bundle: &[u8]) -> Option<u32> {
    let len = u32_at(bundle, 16)? as usize;
    let fits = bundle.len() == HEADER + len && (1..=MAX_IMAGE).contains(&len);
    (bundle.get(..4) == Some(MAGIC) && u32_at(bundle, 4)? == FORMAT && u32_at(bundle, 12)? == SLOT_BASE && fits)
        .then(|| u32_at(bundle, 8))
        .flatten()
}

/// Whether `bundle` is one for `version`.
pub fn well_formed(bundle: &[u8], version: u32) -> bool {
    version_of(bundle) == Some(version)
}

fn record() -> Option<(u8, u32)> {
    let data = var::bytes(RECORD, &esrt::FIRMWARE_CLASS)?;
    Some((*data.first()?, u32_at(&data, 1)?))
}

fn set_record(state: u8, version: u32) -> efi::Status {
    let mut data = alloc::vec![state];
    data.extend_from_slice(&version.to_le_bytes());
    var::keep(RECORD, esrt::FIRMWARE_CLASS, &data)
}

/// The version of the newest bundle that has reached the OS, 0 for none.
pub fn newest() -> u32 {
    var::bytes(NEWEST, &esrt::FIRMWARE_CLASS).and_then(|data| u32_at(&data, 0)).unwrap_or(0)
}

fn set_result(version: u32, status: u32) {
    let mut data = version.to_le_bytes().to_vec();
    data.extend_from_slice(&status.to_le_bytes());
    var::keep(RESULT, esrt::FIRMWARE_CLASS, &data);
    esrt::attempted(&esrt::UPDATE_CLASS, version, status);
}

/// The bundle is running: it has reached the OS.
fn prove() {
    if let Some((PENDING, version)) = record() {
        if version == esrt::VERSION {
            set_record(PROVEN, version);
            if newest() < version {
                var::keep(NEWEST, esrt::FIRMWARE_CLASS, &version.to_le_bytes());
            }
            set_result(version, esrt::SUCCESS);
            info!("bundle", "the updated firmware reached the OS"; version = version);
            for older in kept().iter().filter(|k| k.version < version) {
                older.remove();
            }
        }
    }
}

/// Put the bundle where the VPU firmware looks for it, and reset into it.
fn launch(bundle: &[u8], version: u32) {
    let failed = |why: &str| {
        warn!("bundle", "update not staged"; reason = why, version = version);
        set_record(REFUSED, version);
        set_result(version, esrt::UNSUCCESSFUL);
    };
    let pages = bundle.len().div_ceil(PAGE) as u64;
    if mem::map().allocate(efi::ALLOCATE_ADDRESS, efi::LOADER_DATA, pages, BUNDLE_ADDR, 0).is_err() {
        return failed("the memory the VPU firmware reads the bundle from is not free");
    }
    if set_record(PENDING, version).is_error() {
        return failed("the update could not be recorded");
    }
    unsafe { core::ptr::copy_nonoverlapping(bundle.as_ptr(), BUNDLE_ADDR as *mut u8, bundle.len()) };
    crate::util::cache_flush(BUNDLE_ADDR, bundle.len());
    info!("bundle", "update staged, resetting into it"; version = version, bytes = bundle.len());
    crate::watchdog::reset(false);
}

/// A capsule for the update resource that passed every check: keep its bundle
/// on the file system it came from, drop the capsule and reset into it.
pub fn install(fs: efi::Handle, directory: &[u16], name: &[u16], bundle: &[u8], version: u32) {
    let failed = |why: &str, status: efi::Status| {
        warn!("bundle", "update not kept"; reason = why, status = status.as_usize());
        esrt::attempted(&esrt::UPDATE_CLASS, version, esrt::UNSUCCESSFUL);
    };
    if !var::keeps() {
        return failed("no device key or flash store to record the update in", efi::Status::UNSUPPORTED);
    }
    let file = file_name(version);
    if let Err(status) = fat::write_file(fs, &[], &file, bundle) {
        return failed("the bundle could not be written", status);
    }
    if !fat::read_file(fs, &file, HEADER + MAX_IMAGE).is_ok_and(|read| read == bundle) {
        return failed("what was written does not read back", efi::Status::DEVICE_ERROR);
    }
    let _ = fat::remove_file(fs, directory, name);
    launch(bundle, version);
}

/// A bundle kept on a file system.
struct Kept {
    fs: efi::Handle,
    version: u32,
}

impl Kept {
    fn read(&self) -> Option<Vec<u8>> {
        let bundle = fat::read_file(self.fs, &file_name(self.version), HEADER + MAX_IMAGE).ok()?;
        well_formed(&bundle, self.version).then_some(bundle)
    }

    fn remove(&self) {
        let _ = fat::remove_file(self.fs, &[], &file_name(self.version));
    }
}

/// Every bundle kept on any file system, the newest first. Only the names are
/// read: a bundle's version is in its file's.
fn kept() -> Vec<Kept> {
    let mut all = Vec::new();
    for fs in proto::with(Some(&simple_file_system::PROTOCOL_GUID)) {
        let Ok(names) = fat::list_files(fs, &[]) else { continue };
        all.extend(names.iter().filter_map(|name| version_in(name)).map(|version| Kept { fs, version }));
    }
    all.sort_by(|a, b| b.version.cmp(&a.version));
    all
}

/// At every boot: say how an update an earlier boot started has gone, and
/// stage the newest kept bundle that is newer than this firmware. A bundle that
/// did not reach the OS is dropped, and the next newest is tried: the one that
/// was running before the update.
pub fn boot() {
    if let Some(data) = var::bytes(RESULT, &esrt::FIRMWARE_CLASS) {
        if let (Some(version), Some(status)) = (u32_at(&data, 0), u32_at(&data, 4)) {
            esrt::attempted(&esrt::UPDATE_CLASS, version, status);
        }
    }
    let mut state = record();
    if let Some((PENDING, version)) = state {
        if version == esrt::VERSION {
            tables::before_exit_boot_services(prove);
        }
    }
    if !var::keeps() {
        return;
    }
    for candidate in kept() {
        let version = candidate.version;
        if version <= esrt::VERSION || version < newest() {
            break;
        }
        match state {
            Some((PENDING, recorded)) if recorded == version => {
                warn!("bundle", "the update did not reach the OS, it is dropped"; version = version);
                set_record(REFUSED, version);
                set_result(version, esrt::UNSUCCESSFUL);
                candidate.remove();
                state = Some((REFUSED, version));
            }
            Some((REFUSED, recorded)) if recorded == version => {
                warn!("bundle", "a refused update is dropped"; version = version);
                candidate.remove();
            }
            _ => match candidate.read() {
                Some(bundle) => launch(&bundle, version),
                None => warn!("bundle", "a kept bundle is not the one its name says"; version = version),
            },
        }
    }
}

//! Update bundles: a whole firmware image, signed by an update key, that
//! replaces the firmware at the next boot without the board owner signing it.
//! The VPU firmware the bootloader loaded (`src/update.rs`) is the one that
//! checks the signature and runs the image; this firmware finds the bundle,
//! leaves it in RAM for that firmware and resets.
//!
//! A capsule for [`esrt::UPDATE_CLASS`] carries the bundle after the version
//! (`P4FW`, the class, the version, the bundle), and `db` signs the capsule as
//! it does every other. The bundle is kept in the root of the file system UEFI
//! boots from, the first with `\EFI\BOOT\BOOTAA64.EFI` and no other, because
//! the firmware that runs first at every power-up is the one the bootloader
//! loaded, and it stages the newest bundle again each time. A new bundle does not replace the one running: the older one stays
//! until the newer has reached the OS, and is what runs when it does not.
//!
//! The name of the file is the bundle's state, as with boot assessment in
//! systemd (<https://systemd.io/AUTOMATIC_BOOT_ASSESSMENT/>): its release
//! (`nuboot-0.2.0`) or, for a build with none, its version in
//! eight hex digits, then `+` and the tries left, and `-` and the tries done
//! once there are any, then `.upd`. A new bundle starts with three tries,
//! `…+3.upd`, and every attempt to run it takes one before it starts. The
//! updated firmware blesses the bundle when it reaches `ExitBootServices`, by
//! dropping the counter; a bundle with no tries left is removed, and the next
//! newest is staged instead. A transient failure costs a try, not the update.
//!
//! The variable store keeps what media must not decide: the version of the newest
//! bundle that has reached the OS, below which nothing is staged.

use alloc::string::String;
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
const HEADER: usize = 104;
const MAX_IMAGE: usize = 2 << 20;
const PAGE: usize = 4096;

const EXTENSION: &str = ".upd";
const PREFIX: &str = "nuboot-";
/// The attempts a new bundle gets to reach the OS.
const TRIES: u8 = 3;
const RESULT: &str = "BundleUpdateResult";
/// The newest bundle that has reached the OS. It only grows, and nothing older
/// is staged after it.
const NEWEST: &str = "BundleNewest";

/// Tries left and tries done, or none for a bundle that has reached the OS.
type Tries = Option<(u8, u8)>;

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

/// A release `X.Y.Z` as the number that orders releases, `X<<24 | Y<<16 | Z`
/// (`scripts/fwversion.py` packs the same).
fn pack_release(text: &str) -> Option<u32> {
    let mut parts = text.split('.');
    let mut field = |most: u32| {
        let part = parts.next()?;
        let number: u32 = part.parse().ok()?;
        (part == alloc::format!("{number}") && number <= most).then_some(number)
    };
    let (major, minor, patch) = (field(0xff)?, field(0xff)?, field(0xffff)?);
    parts.next().is_none().then_some(major << 24 | minor << 16 | patch)
}

/// The release a bundle's header names, when it is one and agrees with the
/// version the bundle carries.
fn release_of(bundle: &[u8]) -> Option<&str> {
    let text = bundle.get(24..40)?;
    let len = text.iter().position(|&b| b == 0).unwrap_or(text.len());
    let release = core::str::from_utf8(&text[..len]).ok().filter(|r| !r.is_empty())?;
    (pack_release(release)? == version_of(bundle)?).then_some(release)
}

/// What names a bundle apart from its state: its release, or its version as
/// eight hex digits when it has none.
fn stem_of(bundle: &[u8], version: u32) -> String {
    match release_of(bundle) {
        Some(release) => alloc::format!("{PREFIX}{release}"),
        None => alloc::format!("{version:08X}"),
    }
}

/// The file name of a bundle in a state.
fn file_name(stem: &str, tries: Tries) -> Vec<u16> {
    let counter = match tries {
        None => String::new(),
        Some((left, 0)) => alloc::format!("+{left}"),
        Some((left, done)) => alloc::format!("+{left}-{done}"),
    };
    wide(&alloc::format!("{stem}{counter}{EXTENSION}"))
}

fn digits(text: &str) -> Option<u8> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// The version and the state a file name says, when it is one of these.
fn parse_name(name: &[u16]) -> Option<(u32, Tries)> {
    let text = String::from_utf16(name).ok()?.to_ascii_lowercase();
    let body = text.strip_suffix(EXTENSION)?;
    let (stem, tries) = match body.rsplit_once('+') {
        Some((stem, counter)) => {
            let (left, done) = counter.split_once('-').unwrap_or((counter, "0"));
            (stem, Some((digits(left)?, digits(done)?)))
        }
        None => (body, None),
    };
    let version = match stem.strip_prefix(PREFIX) {
        Some(release) => pack_release(release)?,
        None if stem.len() == 8 && stem.bytes().all(|b| b.is_ascii_hexdigit()) => u32::from_str_radix(stem, 16).ok()?,
        None => return None,
    };
    Some((version, tries))
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

/// A bundle kept on a file system.
struct Kept {
    fs: efi::Handle,
    version: u32,
    tries: Tries,
    name: Vec<u16>,
}

impl Kept {
    fn read(&self) -> Option<Vec<u8>> {
        let bundle = fat::read_file(self.fs, &self.name, HEADER + MAX_IMAGE).ok()?;
        well_formed(&bundle, self.version).then_some(bundle)
    }

    fn remove(&self) {
        let _ = fat::remove_file(self.fs, &[], &self.name);
    }

    /// Give the file the state `tries`, under the name it already has.
    fn set_tries(&self, tries: Tries) -> Result<(), efi::Status> {
        let text = String::from_utf16_lossy(&self.name);
        let body = &text[..text.len() - EXTENSION.len()];
        let stem = body.rsplit_once('+').map_or(body, |(stem, _)| stem);
        fat::rename_file(self.fs, &[], &self.name, &file_name(stem, tries))
    }

    /// How far along its tries the bundle is: the less, the further.
    fn progress(&self) -> u16 {
        self.tries.map_or(0, |(left, _)| 1 + left as u16)
    }
}

/// The file system UEFI boots from: the first, in the order the drivers found
/// them, that has the removable-media boot file.
pub fn boot_volume() -> Option<efi::Handle> {
    let directory = wide("\\EFI\\BOOT");
    let file = wide("BOOTAA64.EFI");
    proto::with(Some(&simple_file_system::PROTOCOL_GUID)).into_iter().find(|&fs| {
        fat::list_files(fs, &directory).is_ok_and(|names| names.iter().any(|name| eq_ignore_case(name, &file)))
    })
}

/// Every bundle on the file system UEFI boots from.
fn listing() -> Vec<Kept> {
    let Some(fs) = boot_volume() else { return Vec::new() };
    let Ok(names) = fat::list_files(fs, &[]) else { return Vec::new() };
    names
        .iter()
        .filter_map(|name| {
            let (version, tries) = parse_name(name)?;
            Some(Kept { fs, version, tries, name: name.clone() })
        })
        .collect()
}

/// Every bundle kept, the newest first, one for each version: a rename that
/// stopped half way leaves two names for one bundle, and the one further along
/// its tries is the one that counts. Only the names are read.
fn kept() -> Vec<Kept> {
    let mut all = listing();
    all.sort_by(|a, b| b.version.cmp(&a.version).then(a.progress().cmp(&b.progress())));
    let mut out: Vec<Kept> = Vec::new();
    for bundle in all {
        if out.last().is_some_and(|last| last.version == bundle.version) {
            bundle.remove();
        } else {
            out.push(bundle);
        }
    }
    out
}

/// The running bundle has reached the OS: bless it, record it as the newest
/// and remove the older ones.
fn prove() {
    let all = kept();
    let Some(mine) = all.iter().find(|k| k.version == esrt::VERSION && k.tries.is_some()) else { return };
    let version = mine.version;
    let blessed = mine.set_tries(None);
    if let Err(status) = &blessed {
        warn!("bundle", "the update could not be blessed"; version = version, status = status.as_usize());
    }
    if newest() < version {
        var::keep(NEWEST, esrt::FIRMWARE_CLASS, &version.to_le_bytes());
    }
    set_result(version, esrt::SUCCESS);
    info!("bundle", "the updated firmware reached the OS"; version = version);
    if blessed.is_ok() {
        for older in all.iter().filter(|k| k.version < version) {
            older.remove();
        }
    }
}

/// Put the bundle where the VPU firmware looks for it, and reset into it.
fn launch(bundle: &[u8], version: u32) {
    let pages = bundle.len().div_ceil(PAGE) as u64;
    if mem::map().allocate(efi::ALLOCATE_ADDRESS, efi::LOADER_DATA, pages, BUNDLE_ADDR, 0).is_err() {
        warn!("bundle", "update not staged"; reason = "the memory the VPU firmware reads the bundle from is not free", version = version);
        set_result(version, esrt::UNSUCCESSFUL);
        return;
    }
    unsafe { core::ptr::copy_nonoverlapping(bundle.as_ptr(), BUNDLE_ADDR as *mut u8, bundle.len()) };
    crate::util::cache_flush(BUNDLE_ADDR, bundle.len());
    info!("bundle", "update staged, resetting into it"; version = version, bytes = bundle.len());
    crate::watchdog::reset(false);
}

/// A capsule for the update resource that passed every check: keep its bundle
/// on the file system UEFI boots from with its first try spent, drop the
/// capsule from the file system it came from and reset into it. What was kept
/// of the same version is replaced.
pub fn install(capsule_fs: efi::Handle, directory: &[u16], name: &[u16], bundle: &[u8], version: u32) {
    let failed = |why: &str, status: efi::Status| {
        warn!("bundle", "update not kept"; reason = why, status = status.as_usize());
        esrt::attempted(&esrt::UPDATE_CLASS, version, esrt::UNSUCCESSFUL);
    };
    if !var::keeps() {
        return failed("no device key or variable store to record the update in", efi::Status::UNSUPPORTED);
    }
    let Some(fs) = boot_volume() else {
        return failed("no file system with a boot file to keep the update on", efi::Status::NOT_FOUND);
    };
    let file = file_name(&stem_of(bundle, version), Some((TRIES - 1, 1)));
    for same in listing().iter().filter(|k| k.version == version) {
        same.remove();
    }
    if let Err(status) = fat::write_file(fs, &[], &file, bundle) {
        return failed("the bundle could not be written", status);
    }
    if !fat::read_file(fs, &file, HEADER + MAX_IMAGE).is_ok_and(|read| read == bundle) {
        return failed("what was written does not read back", efi::Status::DEVICE_ERROR);
    }
    let _ = fat::remove_file(capsule_fs, directory, name);
    info!("bundle", "trying the update"; version = version, tries_left = TRIES - 1);
    launch(bundle, version);
}

/// At every boot: say how an update an earlier boot started has gone, and
/// stage the newest kept bundle that is newer than this firmware, spending a
/// try on it if it has not been blessed. A bundle with no tries left is
/// dropped, and the next newest is tried: the one that was running before the
/// update.
pub fn boot() {
    if let Some(data) = var::bytes(RESULT, &esrt::FIRMWARE_CLASS) {
        if let (Some(version), Some(status)) = (u32_at(&data, 0), u32_at(&data, 4)) {
            esrt::attempted(&esrt::UPDATE_CLASS, version, status);
        }
    }
    if !var::keeps() {
        return;
    }
    let all = kept();
    if all.iter().any(|k| k.version == esrt::VERSION && k.tries.is_some()) {
        tables::before_exit_boot_services(prove);
    }
    for candidate in all {
        let version = candidate.version;
        if version <= esrt::VERSION || version < newest() {
            break;
        }
        match candidate.tries {
            Some((0, done)) => {
                warn!("bundle", "the update did not reach the OS in its tries, it is dropped"; version = version, tries = done);
                set_result(version, esrt::UNSUCCESSFUL);
                candidate.remove();
            }
            Some((left, done)) => {
                let Some(bundle) = candidate.read() else {
                    warn!("bundle", "a kept bundle is not the one its name says"; version = version);
                    continue;
                };
                if let Err(status) = candidate.set_tries(Some((left - 1, done + 1))) {
                    warn!("bundle", "the attempt could not be written down, the update is skipped"; version = version, status = status.as_usize());
                    continue;
                }
                info!("bundle", "trying the update"; version = version, tries_left = left - 1);
                launch(&bundle, version);
            }
            None => match candidate.read() {
                Some(bundle) => launch(&bundle, version),
                None => warn!("bundle", "a kept bundle is not the one its name says"; version = version),
            },
        }
    }
}

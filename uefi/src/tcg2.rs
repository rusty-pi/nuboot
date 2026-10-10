//! `EFI_TCG2_PROTOCOL` over the VPU's PCRs (`src/keystore.rs`): the interface
//! shim, GRUB, systemd-boot and the Linux EFI stub measure into. The TPM is on
//! the VPU (`src/tpm2.rs`): `SubmitCommand` sends it a command, and
//! `HashLogExtendEvent` hashes, extends the VPU's register and appends the
//! event to a crypto-agile log.
//!
//! This firmware measures the way a PC's does: the Secure Boot configuration
//! (`SecureBoot`, `PK`, `KEK`, `db`, `dbx`) and the certificate that verified
//! each image go to PCR 7, each image's Authenticode hash to PCR 4, and a
//! separator follows the configuration in both.

use alloc::vec::Vec;
use core::ffi::c_void;

use r_efi::efi;

use crate::sha256;
use crate::util::Global;
use crate::{info, warn};

const GUID: efi::Guid =
    efi::Guid::from_fields(0x607f766c, 0x7455, 0x42be, 0x93, 0x0b, &[0xe4, 0xd7, 0x6d, 0xb2, 0x72, 0x0f]);

const EV_NO_ACTION: u32 = 0x3;
const EV_SEPARATOR: u32 = 0x4;
const EV_EFI_VARIABLE_DRIVER_CONFIG: u32 = 0x8000_0001;
const EV_EFI_BOOT_SERVICES_APPLICATION: u32 = 0x8000_0003;
const EV_EFI_VARIABLE_AUTHORITY: u32 = 0x8000_00e0;

const PCR_IMAGES: u32 = 4;
const PCR_SECURE_BOOT: u32 = 7;

const FLAG_EXTEND_ONLY: u64 = 1;
const FLAG_PE_COFF_IMAGE: u64 = 0x10;
const ALG_SHA256: u16 = 0x000b;
const BANK_SHA256: u32 = 0x2;
const LOG_FORMAT_TCG_2: u32 = 0x2;
const PCRS: usize = 24;
const LOG_MAX: usize = 64 * 1024;

#[repr(C)]
struct Protocol {
    get_capability: extern "efiapi" fn(*mut Protocol, *mut u8) -> efi::Status,
    get_event_log: extern "efiapi" fn(*mut Protocol, u32, *mut u64, *mut u64, *mut u8) -> efi::Status,
    hash_log_extend_event: extern "efiapi" fn(*mut Protocol, u64, u64, u64, *mut u8) -> efi::Status,
    submit_command: extern "efiapi" fn(*mut Protocol, u32, *mut u8, u32, *mut u8) -> efi::Status,
    get_active_pcr_banks: extern "efiapi" fn(*mut Protocol, *mut u32) -> efi::Status,
    set_active_pcr_banks: extern "efiapi" fn(*mut Protocol, u32) -> efi::Status,
    get_result_of_set_active_pcr_banks: extern "efiapi" fn(*mut Protocol, *mut u32, *mut u32) -> efi::Status,
}

static PROTOCOL: Global<Protocol> = Global::new(Protocol {
    get_capability,
    get_event_log,
    hash_log_extend_event,
    submit_command,
    get_active_pcr_banks,
    set_active_pcr_banks,
    get_result_of_set_active_pcr_banks,
});

/// The event log, in a buffer that never moves.
struct Log {
    bytes: Vec<u8>,
    last: usize,
    truncated: bool,
}

static LOG: Global<Log> = Global::new(Log { bytes: Vec::new(), last: 0, truncated: false });

fn put16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

/// The log's first event: `TCG_PCR_EVENT` in the SHA-1 layout carrying the
/// `Spec ID Event03` structure, which says the rest is crypto agile.
fn spec_id_event() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(b"Spec ID Event03\0");
    put32(&mut body, 0);
    body.extend_from_slice(&[0, 2, 2, 2]);
    put32(&mut body, 1);
    put16(&mut body, ALG_SHA256);
    put16(&mut body, 32);
    body.push(0);
    let mut event = Vec::new();
    put32(&mut event, 0);
    put32(&mut event, EV_NO_ACTION);
    event.extend_from_slice(&[0; 20]);
    put32(&mut event, body.len() as u32);
    event.extend_from_slice(&body);
    event
}

fn append(pcr: u32, event_type: u32, digest: &[u8; 32], data: &[u8]) {
    let log = LOG.get();
    let mut entry = Vec::with_capacity(54 + data.len());
    put32(&mut entry, pcr);
    put32(&mut entry, event_type);
    put32(&mut entry, 1);
    put16(&mut entry, ALG_SHA256);
    entry.extend_from_slice(digest);
    put32(&mut entry, data.len() as u32);
    entry.extend_from_slice(data);
    if log.bytes.len() + entry.len() > LOG_MAX {
        log.truncated = true;
        return;
    }
    log.last = log.bytes.len();
    log.bytes.extend_from_slice(&entry);
}

/// Extend `pcr` with `digest` and log the event.
fn record(pcr: u32, event_type: u32, digest: &[u8; 32], data: &[u8]) {
    crate::mailbox::extend(pcr, digest);
    append(pcr, event_type, digest, data);
}

/// `UEFI_VARIABLE_DATA`: what the measured variable events hash.
fn variable_data(name: &str, guid: &efi::Guid, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(guid.as_bytes());
    out.extend_from_slice(&(name.len() as u64).to_le_bytes());
    out.extend_from_slice(&(data.len() as u64).to_le_bytes());
    for c in name.bytes() {
        put16(&mut out, c as u16);
    }
    out.extend_from_slice(data);
    out
}

/// A Secure Boot configuration variable, into PCR 7.
pub fn measure_variable(name: &str, guid: &efi::Guid, data: &[u8]) {
    let event = variable_data(name, guid, data);
    record(PCR_SECURE_BOOT, EV_EFI_VARIABLE_DRIVER_CONFIG, &sha256::digest(&event), &event);
}

/// The configuration is measured: the separators PCs put after it.
pub fn separators() {
    let event = [0u8; 4];
    for pcr in [PCR_IMAGES, PCR_SECURE_BOOT] {
        record(pcr, EV_SEPARATOR, &sha256::digest(&event), &event);
    }
}

/// An image the firmware has verified: its hash into PCR 4, and the `db`
/// certificate that verified it into PCR 7.
pub fn measure_image(hash: &[u8; 32], anchor_signature: &[u8], device_path: &[u8], len: usize) {
    let mut event = Vec::new();
    event.extend_from_slice(&0u64.to_le_bytes());
    event.extend_from_slice(&(len as u64).to_le_bytes());
    event.extend_from_slice(&0u64.to_le_bytes());
    event.extend_from_slice(&(device_path.len() as u64).to_le_bytes());
    event.extend_from_slice(device_path);
    record(PCR_IMAGES, EV_EFI_BOOT_SERVICES_APPLICATION, hash, &event);
    let authority = variable_data("db", &crate::var::SECURITY_DB, anchor_signature);
    record(PCR_SECURE_BOOT, EV_EFI_VARIABLE_AUTHORITY, &sha256::digest(&authority), &authority);
}

/// `EFI_TCG2_BOOT_SERVICE_CAPABILITY`, laid out as a C compiler lays it out
/// with natural alignment, which is how EDK2 declares it: 28 bytes up to
/// `ManufacturerID` for a 1.0 caller, 36 with the PCR banks.
extern "efiapi" fn get_capability(_this: *mut Protocol, out: *mut u8) -> efi::Status {
    if out.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    const V1_0: u8 = 28;
    const V1_1: u8 = 36;
    let size = unsafe { *out };
    if size < V1_0 {
        unsafe { *out = V1_1 };
        return efi::Status::BUFFER_TOO_SMALL;
    }
    let full = size >= V1_1;
    let mut c = [0u8; V1_1 as usize];
    c[0] = if full { V1_1 } else { V1_0 };
    c[1..5].copy_from_slice(&[1, if full { 1 } else { 0 }, 1, 1]);
    c[8..12].copy_from_slice(&BANK_SHA256.to_le_bytes());
    c[12..16].copy_from_slice(&LOG_FORMAT_TCG_2.to_le_bytes());
    c[16] = 1;
    c[18..20].copy_from_slice(&0x800u16.to_le_bytes());
    c[20..22].copy_from_slice(&0x800u16.to_le_bytes());
    if full {
        c[28..32].copy_from_slice(&1u32.to_le_bytes());
        c[32..36].copy_from_slice(&BANK_SHA256.to_le_bytes());
    }
    unsafe { core::ptr::copy_nonoverlapping(c.as_ptr(), out, c[0] as usize) };
    efi::Status::SUCCESS
}

extern "efiapi" fn get_event_log(
    _this: *mut Protocol,
    format: u32,
    location: *mut u64,
    last: *mut u64,
    truncated: *mut u8,
) -> efi::Status {
    if location.is_null() || last.is_null() || truncated.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    if format != LOG_FORMAT_TCG_2 {
        return efi::Status::UNSUPPORTED;
    }
    let log = LOG.get();
    unsafe {
        *location = log.bytes.as_ptr() as u64;
        *last = log.bytes.as_ptr() as u64 + log.last as u64;
        *truncated = log.truncated as u8;
    }
    efi::Status::SUCCESS
}

extern "efiapi" fn hash_log_extend_event(
    _this: *mut Protocol,
    flags: u64,
    data: u64,
    len: u64,
    event: *mut u8,
) -> efi::Status {
    if event.is_null() || (data == 0 && len != 0) {
        return efi::Status::INVALID_PARAMETER;
    }
    let read32 = |at: usize| u32::from_le_bytes(unsafe { core::slice::from_raw_parts(event.add(at), 4) }.try_into().unwrap());
    let (size, pcr, event_type) = (read32(0) as usize, read32(10), read32(14));
    const HEADER: usize = 18;
    if size < HEADER || pcr as usize >= PCRS {
        return efi::Status::INVALID_PARAMETER;
    }
    let hashed = if len == 0 { &[][..] } else { unsafe { core::slice::from_raw_parts(data as *const u8, len as usize) } };
    let digest = if flags & FLAG_PE_COFF_IMAGE != 0 {
        match crate::secure::authenticode_hash(hashed) {
            Some(h) => h,
            None => return efi::Status::UNSUPPORTED,
        }
    } else {
        sha256::digest(hashed)
    };
    crate::mailbox::extend(pcr, &digest);
    if flags & FLAG_EXTEND_ONLY == 0 {
        append(pcr, event_type, &digest, unsafe { core::slice::from_raw_parts(event.add(HEADER), size - HEADER) });
    }
    efi::Status::SUCCESS
}

extern "efiapi" fn submit_command(_this: *mut Protocol, in_size: u32, command: *mut u8, out_size: u32, out: *mut u8) -> efi::Status {
    if command.is_null() || out.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    let command = unsafe { core::slice::from_raw_parts(command, in_size as usize) };
    let mut response = [0u8; 2048];
    match crate::mailbox::tpm2_command(command, &mut response) {
        Some(n) if n <= out_size as usize => {
            unsafe { core::ptr::copy_nonoverlapping(response.as_ptr(), out, n) };
            efi::Status::SUCCESS
        }
        Some(_) => efi::Status::BUFFER_TOO_SMALL,
        None => efi::Status::DEVICE_ERROR,
    }
}

extern "efiapi" fn get_active_pcr_banks(_this: *mut Protocol, banks: *mut u32) -> efi::Status {
    if banks.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    unsafe { *banks = BANK_SHA256 };
    efi::Status::SUCCESS
}

extern "efiapi" fn set_active_pcr_banks(_this: *mut Protocol, _banks: u32) -> efi::Status {
    efi::Status::UNSUPPORTED
}

extern "efiapi" fn get_result_of_set_active_pcr_banks(_this: *mut Protocol, _present: *mut u32, _response: *mut u32) -> efi::Status {
    efi::Status::UNSUPPORTED
}

/// Start the log and publish the protocol.
pub fn init() {
    let log = LOG.get();
    log.bytes = Vec::with_capacity(LOG_MAX);
    log.bytes.extend_from_slice(&spec_id_event());
    log.last = 0;
    let p = PROTOCOL.get() as *mut Protocol as *mut c_void;
    match crate::proto::install(core::ptr::null_mut(), &GUID, p) {
        Ok(_) => info!("tcg2", "measured boot on the VPU's PCRs"),
        Err(e) => warn!("tcg2", "EFI_TCG2_PROTOCOL not installed"; status = crate::log::dbg(&e)),
    }
}

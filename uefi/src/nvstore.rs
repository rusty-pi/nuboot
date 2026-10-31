//! The TPM's NV indices in the variable store. The VPU holds the indices and
//! hands over each change as a record it has encrypted and authenticated
//! ([`crate::mailbox::nv_export`]); UEFI keeps the record in the store, as the
//! record of a variable of a GUID of its own, and gives the records back at
//! the next boot ([`crate::mailbox::nv_import`]), where the VPU takes only
//! what it made. The store is the disk's: UEFI appends what the boot changed
//! before the OS has the board, and the runtime services what the OS changed
//! when it resets ([`crate::rtvar`]).

use alloc::vec::Vec;

use crate::mailbox::{self, NvExport, NvImport};
use crate::store;
use crate::util::Global;
use crate::{info, warn};

/// The GUID the records are filed under, which no variable has.
pub const GUID: [u8; 16] = [0x4e, 0x56, 0x49, 0x58, 0x6e, 0x75, 0x62, 0x6f, 0x6f, 0x74, 0x4e, 0x56, 0x72, 0x65, 0x63, 0x31];

/// The characters of a record's name: `NV` and the handle in hex.
pub const NAME_UNITS: usize = 10;

/// What the VPU is asked for at most at one flush: more than there are
/// indices and removals.
pub const FLUSH_MAX: usize = 64;

/// The newest record of each index the TPM holds, oldest first.
static LIVE: Global<Vec<store::Record>> = Global::new(Vec::new());
static SILENT: Global<bool> = Global::new(false);

pub fn name(handle: u32) -> [u16; NAME_UNITS] {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = [b'N' as u16, b'V' as u16, 0, 0, 0, 0, 0, 0, 0, 0];
    for (n, unit) in out[2..].iter_mut().enumerate() {
        *unit = DIGITS[(handle >> (28 - 4 * n)) as usize & 0xf] as u16;
    }
    out
}

/// The handle and the kind of change a record of the VPU's carries: a
/// removal has no body.
pub fn describe(record: &[u8]) -> Option<(u32, u32)> {
    if record.len() < 30 {
        return None;
    }
    let handle = u32::from_le_bytes(record[8..12].try_into().unwrap());
    let removal = u16::from_le_bytes(record[28..30].try_into().unwrap()) == 0;
    Some((handle, if removal { store::DELETE } else { store::SET }))
}

/// The seq the VPU numbered the record with, as the 16 bytes a store record
/// keeps a time in.
pub fn time(record: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&record[..8]);
    out
}

fn as_record(blob: Vec<u8>) -> Option<store::Record> {
    let (handle, kind) = describe(&blob)?;
    Some(store::Record { kind, attributes: 0, guid: GUID, time: time(&blob), name: name(handle).to_vec(), data: blob, auth: Vec::new() })
}

fn keep(record: store::Record) {
    LIVE.get().retain(|r| r.name != record.name);
    if record.kind == store::SET {
        LIVE.get().push(record);
    }
}

/// The records the TPM still needs, for a bank that is started afresh.
pub fn live() -> Vec<store::Record> {
    LIVE.get().clone()
}

/// Whether the VPU failed to answer for a record: what the boot put back is
/// then not all the store holds.
pub fn silent() -> bool {
    *SILENT.get()
}

pub fn is_nv(record: &store::Record) -> bool {
    record.guid == GUID
}

/// Put back the index a record of the store holds.
pub fn replay(record: store::Record) {
    match mailbox::nv_import(&record.data) {
        NvImport::Taken => keep(record),
        NvImport::Refused(2) => warn!("nv", "stored index ignored: older than one before it"),
        NvImport::Refused(5) => warn!("nv", "stored index ignored: no device key is fused"),
        NvImport::Refused(status) => warn!("nv", "stored index ignored: the VPU refused it"; status = status),
        NvImport::Silent => {
            warn!("nv", "stored index not put back: the VPU did not answer");
            *SILENT.get() = true;
        }
    }
}

/// Append what the TPM changed since boot to the store, before the OS has
/// the board. What the OS changes after that is the runtime services' to keep
/// until `ResetSystem`.
pub fn flush(live_records: fn() -> Vec<store::Record>) {
    if !store::available() {
        return;
    }
    let mut kept = 0;
    for _ in 0..FLUSH_MAX {
        let NvExport::Record(blob) = mailbox::nv_export() else { break };
        let Some(record) = as_record(blob) else { break };
        keep(record.clone());
        if !store::append(&record, live_records) {
            warn!("nv", "an index change did not reach the store, it lasts until reset");
            return;
        }
        kept += 1;
    }
    if kept > 0 {
        info!("nv", "index changes kept in the store"; records = kept);
    }
}

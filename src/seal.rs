//! The seal on a variable write the OS makes once UEFI is gone. UEFI keeps
//! the variable store on the boot disk and the VPU cannot reach a disk, so
//! the runtime services build the record and keep it until `ResetSystem`; what
//! only the VPU can do is the device key's HMAC-SHA256 over it, so that the
//! seal says the write went through this firmware.
//!
//! The seal is of the runtime domain, which UEFI accepts for these attributes
//! and no others: what the OS asks the VPU to seal is the OS's own say, never
//! a firmware variable's.

use crate::keystore;
use crate::sha256::Sha256;

const SET: u32 = 1;
const DELETE: u32 = 2;
const NV: u32 = 1;
const BS: u32 = 2;
const RT: u32 = 4;

pub const MAX_NAME_UNITS: usize = 256;
pub const MAX_SEALED_DATA: usize = 16 * 1024;

const LABEL: &[u8] = b"nuboot runtime variable record v2";

#[derive(Debug)]
pub enum Error {
    Refused,
    NoDeviceKey,
}

/// Seal the write of a variable no signature guards: a non-volatile variable
/// the OS can read, or the deletion of one, numbered `seq`. `name` is UCS-2, as
/// bytes.
pub fn seal(kind: u32, attributes: u32, guid: &[u8; 16], seq: u64, name: &[u8], data: &[u8]) -> Result<[u8; 32], Error> {
    let units = name.len() / 2;
    if !(kind == SET || kind == DELETE)
        || name.len() % 2 != 0
        || units == 0
        || units > MAX_NAME_UNITS
        || name.chunks_exact(2).any(|unit| unit == [0, 0])
        || attributes != NV | BS | RT
        || (kind == DELETE && !data.is_empty())
        || data.len() > MAX_SEALED_DATA
        || seq == u64::MAX
    {
        return Err(Error::Refused);
    }
    let mut time = [0u8; 16];
    time[..8].copy_from_slice(&seq.to_le_bytes());
    let mut digest = Sha256::new();
    digest.update(LABEL);
    digest.update(&kind.to_le_bytes());
    digest.update(&attributes.to_le_bytes());
    digest.update(guid);
    digest.update(&time);
    digest.update(&(units as u32).to_le_bytes());
    digest.update(&(data.len() as u32).to_le_bytes());
    digest.update(name);
    digest.update(data);
    keystore::device_hmac(&digest.finish()).map_err(|_| Error::NoDeviceKey)
}

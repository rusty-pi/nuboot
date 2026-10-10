//! `EFI_RNG_PROTOCOL` from RNG200. Only the raw algorithm: the hardware's
//! output as it comes.

use core::ffi::c_void;

use r_efi::efi;
use r_efi::protocols::rng;

use crate::util::{Global, read32, wait_for, write32};

const BASE: u64 = 0xFE10_4000;
const CTRL: u64 = BASE;
const RNG_SOFT_RESET: u64 = BASE + 0x04;
const RBG_SOFT_RESET: u64 = BASE + 0x08;
const CTRL_RBGEN: u32 = 0x1fff;
const FIFO_DATA: u64 = 0xFE10_4020;
const FIFO_COUNT: u64 = 0xFE10_4024;

static PROTOCOL: Global<rng::Protocol> = Global::new(rng::Protocol { get_info, get_rng });

/// Fill `buf` from the FIFO; false if it stays empty.
pub fn fill(buf: &mut [u8]) -> bool {
    for chunk in buf.chunks_mut(4) {
        if !wait_for(100_000, || read32(FIFO_COUNT) & 0xff != 0) {
            return false;
        }
        chunk.copy_from_slice(&read32(FIFO_DATA).to_le_bytes()[..chunk.len()]);
    }
    true
}

extern "efiapi" fn get_info(_this: *mut rng::Protocol, size: *mut usize, list: *mut rng::Algorithm) -> efi::Status {
    if size.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    let room = unsafe { *size };
    unsafe { *size = core::mem::size_of::<rng::Algorithm>() };
    if room < core::mem::size_of::<rng::Algorithm>() {
        return efi::Status::BUFFER_TOO_SMALL;
    }
    unsafe { *list = rng::ALGORITHM_RAW };
    efi::Status::SUCCESS
}

extern "efiapi" fn get_rng(_this: *mut rng::Protocol, algorithm: *mut rng::Algorithm, len: usize, out: *mut u8) -> efi::Status {
    if out.is_null() || len == 0 {
        return efi::Status::INVALID_PARAMETER;
    }
    if !algorithm.is_null() && unsafe { *algorithm } != rng::ALGORITHM_RAW {
        return efi::Status::UNSUPPORTED;
    }
    if fill(unsafe { core::slice::from_raw_parts_mut(out, len) }) { efi::Status::SUCCESS } else { efi::Status::DEVICE_ERROR }
}

/// Start the generator unless something before this firmware has.
fn start() {
    if read32(CTRL) & CTRL_RBGEN != 0 && read32(RNG_SOFT_RESET) & 1 == 0 && read32(RBG_SOFT_RESET) & 1 == 0 {
        return;
    }
    write32(CTRL, read32(CTRL) & !CTRL_RBGEN);
    write32(RBG_SOFT_RESET, 1);
    write32(RNG_SOFT_RESET, 1);
    write32(RNG_SOFT_RESET, 0);
    write32(RBG_SOFT_RESET, 0);
    write32(CTRL, read32(CTRL) | 1);
}

pub fn install() {
    start();
    let p = PROTOCOL.get() as *mut rng::Protocol as *mut c_void;
    let _ = crate::proto::install(core::ptr::null_mut(), &rng::PROTOCOL_GUID, p);
}

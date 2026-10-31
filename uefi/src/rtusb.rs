//! The variable store written to a drive on the VL805 at `ResetSystem`.
//!
//! The OS owns the controller until then. The VPU resets the PCIe link and the
//! chip and gives it its firmware again, and this brings the controller up the
//! way the boot did, with the same driver on the runtime services' own heap and
//! DMA arena ([`crate::rtmode`]), finds the drive by what the store's active
//! bank starts with, and writes the records after the end of the log.

use alloc::vec;

use crate::rtvar::{FLUSH_NO_DRIVE, FLUSH_WRITE_FAILED, FLUSH_WRITTEN};

/// Where the records go and how the drive is known.
pub struct Job {
    pub block: usize,
    /// The block of the drive the log ends in, and where in it.
    pub lba: u64,
    pub skip: usize,
    /// The first block of the active bank, and the eight bytes it starts with.
    pub bank_lba: u64,
    pub expect: [u8; 8],
}

/// Write `queue`, whole blocks from `job.lba`, to the drive that holds the
/// store. How it went, for the flush to report: a code from [`crate::rtvar`] and
/// the number of drives found above it.
pub fn write(job: &Job, queue: &[u8]) -> u32 {
    crate::rtmode::enter();
    crate::xhci::forget_boot_state();
    crate::xhci::init();
    let (mut offered, mut outcome) = (0u32, FLUSH_NO_DRIVE);
    for found in crate::rtmode::offered().iter_mut() {
        offered += 1;
        let disk = &mut found.disk;
        if disk.block_size() as usize != job.block {
            continue;
        }
        let mut bank = vec![0u8; job.block];
        let mut tail = vec![0u8; job.block];
        let known = disk.read(job.bank_lba, &mut bank).is_ok()
            && bank[..8] == job.expect
            && disk.read(job.lba, &mut tail).is_ok()
            && tail[..job.skip] == queue[..job.skip]
            && tail[job.skip..].iter().all(|&b| b == 0xff);
        if !known {
            continue;
        }
        outcome = if disk.write(job.lba, queue).is_ok() { FLUSH_WRITTEN } else { FLUSH_WRITE_FAILED };
        break;
    }
    crate::rtmode::leave();
    outcome | offered.min(255) << 8
}

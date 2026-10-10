//! Starting the ARM: the image its cores run first goes at ARM physical 0,
//! the device tree at [`TREE_ADDR`] with the board's memory in it, and then
//! the cores come out of reset.
//!
//! The image is `uefi/stub`: an armstub that takes each core from EL3 to EL2,
//! with the primary core going on to decompress the UEFI payload. The
//! address of the tree goes in the image's word at [`IMAGE_TREE_WORD`].

use crate::{fdt, handover, mmio};

/// The ARM control block, and the bit that lets the cores out of reset.
const ARMCTRL: u32 = 0x7e00_b000;
const ARMCTRL_RELEASE: u32 = 0x1000;

/// Where the image reads the address of the device tree from.
const IMAGE_TREE_WORD: usize = 0xf8;
/// The word after it, where the UEFI firmware says what it wants of the boot
/// watchdog ([`crate::watchdog::carry_poll`]): a sequence number in bits
/// 31:24, so the same request twice is two requests, what happened in 23:20
/// (1: `SetWatchdogTimer` with the seconds in 19:0, 2: `ExitBootServices`).
const IMAGE_WATCHDOG_WORD: u32 = 0xfc;
pub const WATCHDOG_SET: u32 = 1;
pub const WATCHDOG_EXIT: u32 = 2;

/// The UEFI firmware's last watchdog request: (sequence, what, seconds), all
/// zero until it makes one.
pub fn watchdog_request() -> (u32, u32, u32) {
    let w = mmio::read(0xc000_0000 | IMAGE_WATCHDOG_WORD);
    (w >> 24, (w >> 20) & 0xf, w & 0xf_ffff)
}

/// Where the device tree goes: under the payload at 16 MiB, above the image.
pub const TREE_ADDR: u32 = 0x00f0_0000;
const TREE_MAX: usize = 0x0010_0000;

/// Where the VPU firmware's own memory starts (`start4.ld`), and with it the
/// end of the ARM's share of the first gigabyte.
pub const VPU_BASE: u32 = 0x3ec0_0000;

/// What the OS's driver for the TPM on the VPU matches (`tools/tpm-vpu`).
const TPM_COMPATIBLE: &[u8] = b"rusty-pi,pi4-vpu-tpm\0";

/// The second bank the ARM gets, above the first gigabyte, and how far it can
/// reach: the peripherals sit in the 64 MiB below 4 GiB.
const HIGH_MEMORY: u32 = 0x4000_0000;
const HIGH_MEMORY_MAX: u32 = 0xbc00_0000;
/// Where the banks above the 32-bit window start, and how much of one a
/// range with a 32-bit size cell carries.
const BANK_ABOVE_4G: u64 = 0x1_0000_0000;
const BANK_STEP: u32 = 0x8000_0000;
/// Ranges of two address cells and one size cell: the low one, the high one,
/// and up to 8 GiB above 4 GiB.
const MEMORY_REG_MAX: usize = 12 * 6;

/// The VPU's uncached view of ARM physical memory.
fn arm_memory(addr: u32, len: usize) -> &'static mut [u8] {
    unsafe { core::slice::from_raw_parts_mut((0xc000_0000 | addr) as usize as *mut u8, len) }
}

/// `/memory@0`'s `reg` for a board with `total` bytes of SDRAM: the ARM's
/// share of the first gigabyte, the rest of the low 4 GiB less the
/// peripherals' window, and whole banks above 4 GiB.
fn memory_reg(total: u64, out: &mut [u8; MEMORY_REG_MAX]) -> usize {
    let mut range = |at: usize, base: u64, size: u32| {
        out[at..at + 8].copy_from_slice(&base.to_be_bytes());
        out[at + 8..at + 12].copy_from_slice(&size.to_be_bytes());
        at + 12
    };
    let mut at = range(0, 0, VPU_BASE);
    if total > HIGH_MEMORY as u64 {
        let high = (total - HIGH_MEMORY as u64).min(HIGH_MEMORY_MAX as u64) as u32;
        at = range(at, HIGH_MEMORY as u64, high);
    }
    let mut base = BANK_ABOVE_4G;
    while base < total && at + 12 <= MEMORY_REG_MAX {
        at = range(at, base, (total - base).min(BANK_STEP as u64) as u32);
        base += BANK_STEP as u64;
    }
    at
}

pub enum Error {
    /// The built-in device tree is not one, or has no `/memory@0` `reg`.
    Tree,
}

/// What [`start`] handed the ARM.
pub struct Started {
    pub image_bytes: usize,
    pub tree_bytes: usize,
    pub memory_mib: u64,
}

/// Put `image` at ARM physical 0 and `tree`, with the board's memory filled
/// in, at [`TREE_ADDR`], then let the cores out of reset.
pub fn start(image: &[u8], tree: &[u8]) -> Result<Started, Error> {
    let total = if handover::present() { handover::sdram_mib() as u64 } else { 1024 } << 20;
    let mut reg = [0u8; MEMORY_REG_MAX];
    let reg_len = memory_reg(total, &mut reg);
    // The TPM's node goes in first, into the second half of the window, and
    // the memory's `reg` is set as the tree is copied from there to where it
    // belongs.
    let staged = fdt::copy_with_node(
        tree,
        arm_memory(TREE_ADDR + TREE_MAX as u32 / 2, TREE_MAX / 2),
        &[b""],
        b"vpu-tpm",
        &[(b"compatible", TPM_COMPATIBLE)],
    )
    .ok_or(Error::Tree)?;
    let staged: &[u8] = arm_memory(TREE_ADDR + TREE_MAX as u32 / 2, staged);
    let tree_bytes = fdt::copy_with_property(
        staged,
        arm_memory(TREE_ADDR, TREE_MAX / 2),
        &[b"", b"memory@0"],
        b"reg",
        &reg[..reg_len],
    )
    .ok_or(Error::Tree)?;

    let at = arm_memory(0, image.len());
    at.copy_from_slice(image);
    at[IMAGE_TREE_WORD..IMAGE_TREE_WORD + 4].copy_from_slice(&TREE_ADDR.to_le_bytes());

    // The two words the stock firmware writes just before the release; what
    // they do is not documented.
    mmio::write(ARMCTRL + 0x41c, 0xa);
    mmio::write(ARMCTRL + 0x008, 0x3030);
    mmio::write(ARMCTRL, ARMCTRL_RELEASE);

    let memory_mib = reg[..reg_len]
        .chunks_exact(12)
        .map(|r| u32::from_be_bytes([r[8], r[9], r[10], r[11]]) as u64)
        .sum::<u64>()
        >> 20;
    Ok(Started { image_bytes: image.len(), tree_bytes, memory_mib })
}

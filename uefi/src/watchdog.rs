//! The boot watchdog is the VPU firmware's: this firmware tells it about
//! `SetWatchdogTimer` and `ExitBootServices` through a word in the armstub's
//! page, and resets the board through the power manager's watchdog.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::util::{read32, write32};

/// The word the VPU firmware reads requests from: a sequence number in bits
/// 31:24, what happened in 23:20 (1: `SetWatchdogTimer`, its seconds in 19:0;
/// 2: `ExitBootServices`, 3: `ResetSystem`). It beats the board's watchdog until the span asked
/// for runs out.
const WORD: u64 = 0xfc;
const SET: u32 = 1;
const EXIT: u32 = 2;
const RESET: u32 = 3;

static SEQ: AtomicU32 = AtomicU32::new(0);

fn tell_vpu(what: u32, seconds: u32) {
    let seq = SEQ.load(Ordering::Relaxed).wrapping_add(1) & 0xff;
    SEQ.store(seq, Ordering::Relaxed);
    write32(WORD, seq << 24 | what << 20 | seconds.min(0xf_ffff));
    // The VPU reads memory past the ARM's caches.
    crate::util::cache_flush(WORD, 4);
}

pub fn set(seconds: usize) {
    tell_vpu(SET, seconds.min(u32::MAX as usize) as u32);
}

pub fn exit_boot_services() {
    tell_vpu(EXIT, 0);
}

const PM_RSTC: u64 = 0xFE10_001C;
const PM_RSTS: u64 = 0xFE10_0020;
const PM_WDOG: u64 = 0xFE10_0024;
const PM_PASSWORD: u32 = 0x5A00_0000;
const PM_RSTC_WRCFG_FULL_RESET: u32 = 0x20;
const PM_RSTC_WRCFG_CLR: u32 = 0xFFFF_FFCF;
/// `PM_RSTS` partition 63: halt in the bootloader.
const PM_RSTS_HALT: u32 = 0x555;

/// The watchdog's count for a reset UEFI asks for, about a second and a half:
/// the VPU stops reloading it at its next beat, which is at least once a
/// second, and a short count would run out before it has read the request.
const PM_WDOG_AFTER_VPU: u32 = 0x18000;

/// Reset the board, as `bcm2835-wdt` does; with `halt`, to stay off.
pub fn reset(halt: bool) -> ! {
    if halt {
        let rsts = read32(PM_RSTS);
        write32(PM_RSTS, PM_PASSWORD | (rsts & !0xFFF) | PM_RSTS_HALT);
    }
    tell_vpu(RESET, 0);
    write32(PM_WDOG, PM_PASSWORD | PM_WDOG_AFTER_VPU);
    let rstc = read32(PM_RSTC);
    write32(PM_RSTC, PM_PASSWORD | (rstc & PM_RSTC_WRCFG_CLR) | PM_RSTC_WRCFG_FULL_RESET);
    crate::util::halt()
}

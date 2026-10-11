//! The boot watchdog from the ARM's side: this firmware reloads the board's
//! watchdog from a timer interrupt, so an ARM that stops (a fault, a hang with
//! interrupts masked, a core that never ran) lets it run out and the board
//! resets within 16 s. The VPU firmware hands the dog over when it starts the
//! ARM, and takes it back for a while at `ExitBootServices`, through a word in
//! the armstub's page, so an operating system has time to start its driver.
//!
//! The timer beats only while the span `SetWatchdogTimer` asks for lasts (five
//! minutes to begin with, and again when it is asked to turn the dog off), so
//! a payload that never comes back ends in a reset too.
//!
//! The interrupt is the EL2 hypervisor timer's (`CNTHP`, GIC interrupt 26),
//! routed to EL2 with `HCR_EL2.IMO` until `ExitBootServices`. A payload that
//! uses that timer or that routing, which no loader or kernel stub does, takes
//! the beat from it.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::util::{counter_us, read32, write32};

/// The word the VPU firmware reads requests from: a sequence number in bits
/// 31:24, what happened in 23:20 (2: `ExitBootServices`).
const WORD: u64 = 0xfc;
const EXIT: u32 = 2;

const PM_RSTC: u64 = 0xFE10_001C;
const PM_RSTS: u64 = 0xFE10_0020;
const PM_WDOG: u64 = 0xFE10_0024;
const PM_PASSWORD: u32 = 0x5A00_0000;
const PM_RSTC_WRCFG_FULL_RESET: u32 = 0x20;
const PM_RSTC_WRCFG_CLR: u32 = 0xFFFF_FFCF;
/// `PM_RSTS` partition 63: halt in the bootloader.
const PM_RSTS_HALT: u32 = 0x555;
const PM_RSTS_TRYBOOT: u32 = 1 << 1;
/// The most the dog counts: 16 s.
const PM_WDOG_MAX: u32 = 0xF_FFFF;

/// The GIC-400: the distributor, and the CPU interface a page above it.
const GICD: u64 = 0xFF84_1000;
const GICC: u64 = GICD + 0x1000;
const GICD_ISENABLER0: u64 = GICD + 0x100;
const GICD_ICENABLER0: u64 = GICD + 0x180;
const GICD_ICPENDR0: u64 = GICD + 0x280;
const GICD_IPRIORITYR: u64 = GICD + 0x400;
const GICC_IAR: u64 = GICC + 0x0c;
const GICC_EOIR: u64 = GICC + 0x10;
/// The hypervisor timer's private interrupt: what the EL2 physical timer
/// raises.
const TIMER_INTID: u32 = 26;
const SPURIOUS: u32 = 1020;

/// How often the dog is reloaded.
const BEAT_US: u64 = 500_000;
/// How long the ARM gets before the dog is let go, unless it asks for another
/// span with `SetWatchdogTimer`: the five minutes the UEFI specification gives
/// a boot option.
const DEFAULT_SPAN_S: u64 = 300;

/// Whether the end of the span has been said.
static EXPIRED: AtomicBool = AtomicBool::new(false);

/// When the span ends, in [`counter_us`].
static END_US: AtomicU64 = AtomicU64::new(0);

fn timer_frequency() -> u64 {
    let f: u64;
    unsafe { core::arch::asm!("mrs {0}, CNTFRQ_EL0", out(reg) f) };
    f
}

fn arm_timer() {
    let ticks = timer_frequency() * BEAT_US / 1_000_000;
    unsafe {
        core::arch::asm!("msr CNTHP_TVAL_EL2, {0}", "msr CNTHP_CTL_EL2, {1}", "isb", in(reg) ticks, in(reg) 1u64);
    }
}

fn stop_timer() {
    unsafe { core::arch::asm!("msr CNTHP_CTL_EL2, xzr", "isb") };
}

/// `HCR_EL2.IMO`: route physical interrupts to EL2, where this firmware runs;
/// without it an interrupt is for EL1 and never taken here.
const HCR_IMO: u64 = 1 << 4;

fn route_interrupts_to_el2(on: bool) {
    unsafe {
        let hcr: u64;
        core::arch::asm!("mrs {0}, HCR_EL2", out(reg) hcr);
        let hcr = if on { hcr | HCR_IMO } else { hcr & !HCR_IMO };
        core::arch::asm!("msr HCR_EL2, {0}", "isb", in(reg) hcr);
    }
}

fn mask_interrupts() {
    unsafe { core::arch::asm!("msr daifset, #2", "isb") };
}

fn unmask_interrupts() {
    unsafe { core::arch::asm!("msr daifclr, #2", "isb") };
}

fn reload() {
    write32(PM_WDOG, PM_PASSWORD | PM_WDOG_MAX);
}

/// Take the dog from the VPU and beat it from here on: reload it now, start
/// the timer and take its interrupt.
pub fn start() {
    END_US.store(counter_us() + DEFAULT_SPAN_S * 1_000_000, Ordering::Relaxed);
    reload();
    unsafe { core::ptr::write_volatile((GICD_IPRIORITYR + TIMER_INTID as u64) as *mut u8, 0x80) };
    write32(GICD_ISENABLER0, 1 << TIMER_INTID);
    arm_timer();
    route_interrupts_to_el2(true);
    unmask_interrupts();
}

/// `SetWatchdogTimer`: the span the dog is beaten for from now. 0 turns the dog
/// off in the specification; here it is the default span again, since a board
/// nobody is at must not stay in a boot menu for good.
pub fn set(seconds: usize) {
    let span = if seconds == 0 { DEFAULT_SPAN_S } else { seconds as u64 };
    END_US.store(counter_us().saturating_add(span.saturating_mul(1_000_000)), Ordering::Relaxed);
    EXPIRED.store(false, Ordering::Relaxed);
    crate::info!("watchdog", "UEFI set the boot watchdog"; asked_s = seconds, span_s = span);
}

/// What the timer interrupt does: reload the dog while the span lasts, and
/// start the timer again.
#[unsafe(no_mangle)]
extern "C" fn pi4_irq() {
    let acknowledged = read32(GICC_IAR);
    let id = acknowledged & 0x3ff;
    if id == TIMER_INTID {
        if counter_us() < END_US.load(Ordering::Relaxed) {
            reload();
        } else if !EXPIRED.swap(true, Ordering::Relaxed) {
            crate::log::emergency("watchdog", format_args!("the boot did not finish in time, letting the board reset"));
        }
        arm_timer();
    }
    if id < SPURIOUS {
        write32(GICC_EOIR, acknowledged);
    }
}

/// The operating system has the board: stop the interrupt and the timer, and
/// say so to the VPU, which carries the dog for a while.
pub fn exit_boot_services() {
    mask_interrupts();
    stop_timer();
    write32(GICD_ICENABLER0, 1 << TIMER_INTID);
    write32(GICD_ICPENDR0, 1 << TIMER_INTID);
    route_interrupts_to_el2(false);
    tell_vpu(EXIT);
}

fn tell_vpu(what: u32) {
    let seq = (read32(WORD) >> 24).wrapping_add(1) & 0xff;
    write32(WORD, seq << 24 | what << 20);
    // The VPU reads memory past the ARM's caches.
    crate::util::cache_flush(WORD, 4);
}

/// Ask the bootloader to boot from `tryboot.img` and `tryboot.sig` at the next
/// reset, once: bit 1 of `PM_RSTS`, which Linux's `reboot '0 tryboot'` sets
/// through the mailbox.
pub fn request_tryboot() {
    write32(PM_RSTS, PM_PASSWORD | read32(PM_RSTS) | PM_RSTS_TRYBOOT);
}

/// Reset the board, as `bcm2835-wdt` does; with `halt`, to stay off.
pub fn reset(halt: bool) -> ! {
    mask_interrupts();
    if halt {
        let rsts = read32(PM_RSTS);
        write32(PM_RSTS, PM_PASSWORD | (rsts & !0xFFF) | PM_RSTS_HALT);
    }
    write32(PM_WDOG, PM_PASSWORD | 10);
    let rstc = read32(PM_RSTC);
    write32(PM_RSTC, PM_PASSWORD | (rstc & PM_RSTC_WRCFG_CLR) | PM_RSTC_WRCFG_FULL_RESET);
    crate::util::halt()
}

//! `start4.elf`: the VPU firmware the first stage loads out of the EEPROM (or
//! a stock bootloader from the boot medium) into SDRAM and enters at its ELF
//! entry point.
//!
//! It says what it is running on, takes over the boot watchdog the bootloader
//! armed, brings up USB, starts the ARM in the UEFI firmware it carries and
//! carries the dog through the ARM's boot, and starts the threads the
//! firmware runs on for as long as the board is up: the service thread
//! answers the property mailbox.

#![no_std]
#![no_main]

use core::cell::Cell;

use pi4_server_firmware::board::{Board, Revision};
use pi4_server_firmware::handover::{self, BootDevice};
use pi4_server_firmware::{
    arm, console, error, idle, info, mailbox, measure, otp, sched, stack, stc, timer, usb, warn, watchdog,
};

/// What the ARM cores start in: an armstub and the compressed UEFI firmware
/// (`uefi/`).
static ARM_IMAGE: &[u8] = include_bytes!(env!("ARM_IMAGE"));
/// The device tree the ARM gets, and passes on to the operating system.
static ARM_TREE: &[u8] = include_bytes!(env!("ARM_TREE"));

/// "BSTA": the bootloader fills in the rest (word 1 points at its tagged
/// state, [`handover`]).
#[used]
#[unsafe(link_section = ".bootloader_state")]
static mut BOOTLOADER_STATE: [u32; 4] = [0x4154_5342, 0, 0, 0];

/// Capability bits the bootloader checks against the board (bit 0 is VPU
/// cpuid support, bit 1 the Pi 400 over USB device mode). Same value as the
/// stock start4.elf.
#[used]
#[unsafe(link_section = ".firmware_rev")]
static FIRMWARE_REV: [u32; 4] = [0x3fff, 0, 0, 0];

/// What the bootloader prints for the firmware it starts, with `BOOT_UART=1`.
const BUILD_ID_TEXT: &str =
    concat!("VC_BUILD_ID_VARIANT: server\0", "VC_BUILD_ID_VERSION: ", env!("FIRMWARE_COMMIT"), "\0");

#[used]
#[unsafe(link_section = ".build_id")]
static BUILD_ID: [u8; BUILD_ID_TEXT.len()] = {
    let text = BUILD_ID_TEXT.as_bytes();
    let mut out = [0; BUILD_ID_TEXT.len()];
    let mut i = 0;
    while i < text.len() {
        out[i] = text[i];
        i += 1;
    }
    out
};

/// The commit this was built from, as far as `git log --oneline` prints it.
const COMMIT: &str = {
    let full = env!("FIRMWARE_COMMIT");
    match full.split_at_checked(7) {
        Some((short, _)) => short,
        None => full,
    }
};

unsafe extern "C" {
    static mut __stack_bottom: u32;
    static __stack_top: u32;
}

/// How long the core sleeps at most when every thread has parked.
const IDLE_US: u32 = 100_000;

/// The boot thread, which goes on as the service thread once the boot is
/// over, outranks the monitor.
const SERVICE_PRIORITY: sched::Priority = sched::Priority(1);
const MONITOR_PRIORITY: sched::Priority = sched::Priority(0);

/// The monitor thread's stack. An interrupt runs on whichever stack is
/// current, so this carries the handler's frame as well as the thread's own.
const MONITOR_STACK_WORDS: usize = 2048;
static mut MONITOR_STACK: [u32; MONITOR_STACK_WORDS] = [0; MONITOR_STACK_WORDS];

#[unsafe(no_mangle)]
fn firmware_main() -> ! {
    let main_stack = unsafe { stack::Stack::paint_running(&raw mut __stack_bottom, &raw const __stack_top) };
    console::init();
    announce();
    let watchdog = take_over_watchdog();

    let board = Board::read();
    measure::platform(
        COMMIT,
        ARM_IMAGE,
        ARM_TREE,
        board.revision,
        board.ext_revision,
        board.serial,
        (otp::read(otp::MAC_HIGH), otp::read(otp::MAC_LOW)),
        otp::read(otp::BOOTMODE),
        if handover::present() { handover::sdram_mib() } else { 0 },
    );
    usb::bring_up(&board);
    let started = match arm::start(ARM_IMAGE, ARM_TREE) {
        Ok(started) => {
            info!("arm", "ARM started in UEFI";
                image_bytes = started.image_bytes, tree = format_args!("{:#x}", arm::TREE_ADDR),
                tree_bytes = started.tree_bytes, memory_mib = started.memory_mib);
            true
        }
        Err(arm::Error::Tree) => {
            error!("arm", "the built-in device tree has no /memory@0 reg, not starting the ARM");
            false
        }
    };
    // The heartbeat's stop masks interrupts, so it goes before the threads
    // take them on. The dog goes to the ARM, which beats it from UEFI; the
    // monitor thread only waits for `ExitBootServices`. With no ARM to take it,
    // nothing beats it, and the board resets.
    if watchdog {
        watchdog::set_deadline(0);
        if started {
            watchdog::hand_over();
            info!("watchdog", "boot watchdog handed to the ARM");
        }
    }

    idle::init();
    sched::spawn(unsafe { &mut *(&raw mut MONITOR_STACK) }, MONITOR_PRIORITY, monitor_thread);
    sched::start(main_stack, SERVICE_PRIORITY);
    info!("sched", "threads running"; threads = sched::stacks().count(), tick_us = sched::TICK_US);

    // The service thread answers the property mailbox from here on.
    loop {
        mailbox::serve(IDLE_US);
    }
}

/// The first lines of the log: what this is, and what it is running on.
fn announce() {
    let revision = Revision::read();
    info!("boot", "pi4-server-firmware {}", COMMIT;
        board = revision.model(), revision = revision, pcb = revision.pcb());
    if !handover::present() {
        error!("boot", "no handover from the bootloader, so no boot medium or memory size");
        return;
    }
    let device = handover::boot_device();
    info!("boot", "started by the EEPROM bootloader";
        medium = device, ram_mib = handover::sdram_mib(), bootloader = handover::version());
    if let BootDevice::Other(_) = device {
        warn!("boot", "the bootloader names a boot medium this firmware does not know");
    }
}

/// Beat the boot watchdog the bootloader armed, so a boot that hangs resets
/// the board. Whether there was one.
fn take_over_watchdog() -> bool {
    let timeout_s = handover::boot_watchdog_timeout();
    let end_at = handover::boot_watchdog_end_at();
    if timeout_s == 0 || end_at == 0 {
        return false;
    }
    let left_ms = end_at.saturating_sub(stc::now()) / 1000;
    info!("watchdog", "boot watchdog running"; budget_s = timeout_s, left_ms = left_ms);
    watchdog::arm_us(10_000_000);
    watchdog::set_deadline(end_at);
    true
}

/// How often the monitor looks at the stacks.
const MONITOR_US: u32 = 1_000_000;

/// The low thread: beats the boot watchdog through the ARM's boot, watches
/// what the firmware itself uses, and says when it changes.
extern "C" fn monitor_thread() -> ! {
    let used: [Cell<u32>; sched::THREADS] = [const { Cell::new(0) }; sched::THREADS];
    let mut looked = timer::now();
    report_stacks(&used);
    loop {
        watchdog::carry_poll();
        if timer::now().wrapping_sub(looked) >= MONITOR_US {
            report_stacks(&used);
            looked = timer::now();
        }
        sched::park(MONITOR_US);
    }
}

/// Log each stack whose high-water mark has grown since the last look.
fn report_stacks(seen: &[Cell<u32>; sched::THREADS]) {
    for (thread, stack) in sched::stacks().enumerate() {
        let used = stack.used();
        if used > seen[thread].get() {
            seen[thread].set(used);
            info!("sched", "stack high-water mark"; thread = thread, used = used, size = stack.size());
        }
    }
}

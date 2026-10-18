//! Wake-on-LAN: what the VPU does when the operating system powers the board
//! off.
//!
//! Linux's power off is a reset the OS asks the bootloader to end in a halt:
//! it sets `PM_RSTS`' partition to 63 and lets the watchdog reset the SoC, and
//! the stock bootloader that boots next halts, with nothing but GPIO 3 to wake
//! it. This firmware cannot be that halt, but it is running when the OS asks:
//! the OS's firmware driver sends `NOTIFY_REBOOT` as the last of the devices
//! shuts down, [`announce_shutdown`] notes it, and [`serve_shutdown`] watches
//! `PM_RSTS` and `PM_RSTC` for the two writes of a power off. When they come,
//! it takes the dog off before it expires and the board does not reset:
//!
//! 1. the ARM's clock stops, so the OS does not go on running,
//! 2. the Ethernet MAC and PHY come up at 10 or 100 Mbit/s with the MAC's magic
//!    packet detector armed ([`crate::genet`]), the address the OS had,
//! 3. the VPU sleeps, looking at the detector and at GPIO 3 every
//!    [`POLL_US`],
//! 4. a magic packet, or GPIO 3 pulled low, takes the halt out of `PM_RSTS` and
//!    resets the SoC, which boots as it does from power on.
//!
//! A board with no link to wake from gets the halt it asked for instead: the
//! dog is armed again with `PM_RSTS` as the OS left it.
//!
//! A reboot is the same `NOTIFY_REBOOT` and then a reset with another
//! partition, which [`serve_shutdown`] does not touch.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::board::Board;
use crate::{arm, cm, console, dvfs, expander, genet, gpio, info, mailbox, pcie, sched, timer, warn, watchdog};

/// How long after `NOTIFY_REBOOT` the OS has to ask for a power off. It does so
/// within milliseconds, once the other devices have shut down.
const WATCH_US: u32 = 5_000_000;
/// How often the detector and GPIO 3 are looked at.
const POLL_US: u32 = 100_000;
/// The power button's GPIO, which the stock halt wakes on too.
const WAKE_GPIO: u32 = 3;
/// The dog's count for the reset that boots the board: 10 ticks, 150 us.
const RESET_TICKS: u32 = 10;

/// Whether `NOTIFY_REBOOT` has come and not been served.
static ANNOUNCED: AtomicBool = AtomicBool::new(false);

/// The OS is shutting down: [`serve_shutdown`] looks for what it does next.
pub fn announce_shutdown() {
    ANNOUNCED.store(true, Ordering::Relaxed);
}

/// After `NOTIFY_REBOOT` has been answered, wait [`WATCH_US`] for the OS to
/// power the board off, and if it does, stand by for a wake and reset. Returns
/// when no power off comes, or the ARM has gone on to something else.
pub fn serve_shutdown() {
    if !ANNOUNCED.load(Ordering::Relaxed) {
        return;
    }
    ANNOUNCED.store(false, Ordering::Relaxed);
    if power_off_comes() {
        stand_by();
    }
}

/// Whether the OS powers the board off, in which case the dog is off.
///
/// Nothing here may take longer than the 150 us the OS gives the dog between
/// its two writes, so the loop reads two registers and the clock and nothing
/// else.
fn power_off_comes() -> bool {
    let start = timer::now();
    while timer::now().wrapping_sub(start) < WATCH_US {
        if watchdog::power_off_requested() {
            watchdog::quiesce();
            return true;
        }
        if mailbox::request_pending() {
            return false;
        }
    }
    false
}

fn stand_by() -> ! {
    dvfs::stop();
    crate::wdat::stop();
    cm::hold_arm(true);
    pcie::power_down();
    let mac = arm::ethernet_address(Board::read().serial);
    info!("wake", "the OS powered the board off"; mac = Address(mac));
    match genet::arm_magic_packet(mac) {
        Ok(link) => info!("wake", "waiting for a magic packet";
            mbit_s = link.mbit_s, duplex = if link.full_duplex { "full" } else { "half" }),
        Err(genet::Error::NoPhy) => halt("no PHY answers on the MDIO bus"),
        Err(genet::Error::NoLink) => halt("no link to wake from"),
    }
    cm::slow_vpu();
    cm::stop_idle_generators();
    match expander::power_led_off() {
        Some(pins) => info!("wake", "the power LED is off";
            direction = pins.direction, output = pins.output, high_z = pins.high_z),
        None => warn!("wake", "the GPIO expander does not answer, leaving the power LED on"),
    }
    gpio::set_function(WAKE_GPIO, gpio::INPUT);
    gpio::set_pull(WAKE_GPIO, gpio::Pull::Up);
    loop {
        if genet::magic_packet_seen() {
            wake("magic packet");
        }
        if !gpio::level(WAKE_GPIO) {
            wake("GPIO 3");
        }
        sched::park(POLL_US);
    }
}

/// Reset the SoC into a boot.
fn wake(reason: &str) -> ! {
    info!("wake", "waking the board"; reason = reason);
    genet::disarm();
    watchdog::clear_power_off_request();
    reset()
}

/// Reset the SoC into the stock bootloader's halt: `PM_RSTS` still holds the
/// partition the OS asked for.
fn halt(reason: &str) -> ! {
    warn!("wake", "halting in the bootloader"; reason = reason);
    reset()
}

fn reset() -> ! {
    expander::power_led_restore();
    console::drain();
    watchdog::arm_ticks(RESET_TICKS);
    crate::halt()
}

/// A MAC address as the log prints one.
struct Address([u8; 6]);

impl core::fmt::Display for Address {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

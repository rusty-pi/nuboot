//! The property mailbox, as far as the operating system needs it from this
//! firmware: the ARM posts the bus address of a buffer of tags on channel 8,
//! the firmware answers the tags it knows in place and posts the address back.
//!
//! The VPU's view of the mailboxes is at `0x7E00_B980`, the mirror of the
//! ARM's: the ARM writes mailbox 1 and reads mailbox 0, so this reads mailbox
//! 1 and writes mailbox 0. [`crate::idle`] takes the interrupt and signals
//! [`crate::idle::MAIL`]; [`serve`] drains the FIFO and listens again.
//!
//! A buffer is `size, code, tags..., 0`, and a tag `id, room, length, value`.
//! An answered tag gets `RESPONSE | length` in its third word; a tag this
//! firmware does not know is left as it came, and the buffer is marked
//! answered either way, which is what the stock firmware does.

use crate::{debug, error, idle, info, mmio, vl805, warn};

const VPU_VIEW: u32 = 0x7e00_b980;
/// Mailbox 0, which the ARM reads.
const DATA0: u32 = VPU_VIEW;
const STATUS0: u32 = VPU_VIEW + 0x18;
/// Mailbox 1, which the ARM writes.
const DATA1: u32 = VPU_VIEW + 0x20;
const STATUS1: u32 = VPU_VIEW + 0x38;
const STATUS_FULL: u32 = 1 << 31;
const STATUS_EMPTY: u32 = 1 << 30;

const CHANNEL_PROPERTY: u32 = 8;
const RESPONSE: u32 = 0x8000_0000;
const CODE_ERROR: u32 = 0x8000_0001;
/// The largest buffer walked, so a bad size word cannot run off into memory.
const MAX_BUFFER: u32 = 0x1_0000;

/// Linux's `RPI_FIRMWARE_NOTIFY_XHCI_RESET`: it has reset the PCIe link, and
/// with it a VL805 that keeps no firmware of its own.
const TAG_NOTIFY_XHCI_RESET: u32 = 0x0003_0058;

/// Wait up to `timeout_us` for the ARM to post something, and answer all it
/// has posted.
pub fn serve(timeout_us: u32) {
    idle::MAIL.wait(timeout_us);
    while mmio::read(STATUS1) & STATUS_EMPTY == 0 {
        let message = mmio::read(DATA1);
        let channel = message & 0xf;
        if channel == CHANNEL_PROPERTY {
            answer(message & !0xf);
        } else {
            warn!("mailbox", "request on a channel this firmware does not serve";
                channel = channel, message = format_args!("{message:#010x}"));
        }
        while mmio::read(STATUS0) & STATUS_FULL != 0 {}
        mmio::write(DATA0, message);
    }
    idle::listen_mailbox();
}

/// Answer the buffer at bus address `bus`, in place.
fn answer(bus: u32) {
    // The ARM's bus addresses alias SDRAM at 0xC000_0000, uncached, as the
    // VPU's own do.
    let base = 0xc000_0000 | (bus & 0x3fff_ffff);
    let word = |i: u32| unsafe { core::ptr::read_volatile((base + 4 * i) as usize as *const u32) };
    let set = |i: u32, v: u32| unsafe { core::ptr::write_volatile((base + 4 * i) as usize as *mut u32, v) };

    let size = word(0);
    if !(12..=MAX_BUFFER).contains(&size) || size % 4 != 0 {
        error!("mailbox", "property buffer with a bad size"; bus = format_args!("{bus:#010x}"), size = size);
        set(1, CODE_ERROR);
        return;
    }
    let words = size / 4;
    let mut i = 2;
    while i + 3 <= words {
        let tag = word(i);
        if tag == 0 {
            break;
        }
        let room = word(i + 1);
        let value = i + 3;
        if room % 4 != 0 || value + room / 4 > words {
            error!("mailbox", "property tag runs past its buffer"; tag = format_args!("{tag:#010x}"), room = room);
            set(1, CODE_ERROR);
            return;
        }
        match tag {
            TAG_NOTIFY_XHCI_RESET if room >= 4 => {
                let device = word(value);
                let status = vl805::firmware_reset();
                if status == 0 {
                    info!("usb", "VL805 firmware reloaded for the OS"; device = format_args!("{device:#x}"));
                } else {
                    error!("usb", "VL805 firmware reload failed"; device = format_args!("{device:#x}"));
                }
                set(i + 2, RESPONSE | 4);
            }
            _ => debug!("mailbox", "property tag not answered"; tag = format_args!("{tag:#010x}")),
        }
        i = value + room / 4;
    }
    set(1, RESPONSE);
}

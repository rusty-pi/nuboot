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

use crate::{debug, error, idle, info, keystore, measure, mmio, tpm2, vl805, warn};

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

/// The boot key, once: the mask of the PCRs it is bound to in, 32 bytes out,
/// then not answered again ([`keystore`]).
/// Tags of this firmware's own, in the range the stock firmware keeps for its
/// crypto service.
const TAG_GET_BOOT_KEY: u32 = 0x0003_00a0;
/// Extend a PCR with 32 bytes: the PCR's number, then the digest.
const TAG_EXTEND_BOOT_MEASUREMENT: u32 = 0x0003_00a1;
/// A TPM 2.0 command in, its response out ([`tpm2`]), in the tag's value: the
/// command's own header says how long it is, and the response's how long that
/// is. Linux's firmware interface cannot set the tag's length word, so it is
/// not what says.
const TAG_TPM2_COMMAND: u32 = 0x0003_00a3;
/// The key UEFI seals the variables it keeps in the flash with: 32 bytes out,
/// once ([`keystore::take_store_key`]).
const TAG_GET_STORE_KEY: u32 = 0x0003_00a5;
/// Event `n` of what the VPU measured before the ARM started, for the log
/// UEFI keeps: the index in, then the PCR, the event type, the digest, the
/// length of the data and the data.
const TAG_GET_EARLY_EVENT: u32 = 0x0003_00a4;

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
            TAG_GET_BOOT_KEY if room >= 32 => {
                let mask = word(value);
                match keystore::take(mask) {
                    Some(mut key) => {
                        for (n, bytes) in key.chunks_exact(4).enumerate() {
                            set(value + n as u32, u32::from_le_bytes(bytes.try_into().unwrap()));
                        }
                        keystore::zero(&mut key);
                        info!("keystore", "boot key handed over"; mask = format_args!("{mask:#x}"), extends = keystore::count());
                        set(i + 2, RESPONSE | 32);
                    }
                    None => warn!("keystore", "no boot key to hand over"; mask = format_args!("{mask:#x}")),
                }
            }
            TAG_GET_STORE_KEY if room >= 32 => match keystore::take_store_key() {
                Some(mut key) => {
                    for (n, bytes) in key.chunks_exact(4).enumerate() {
                        set(value + n as u32, u32::from_le_bytes(bytes.try_into().unwrap()));
                    }
                    keystore::zero(&mut key);
                    info!("keystore", "variable store key handed over");
                    set(i + 2, RESPONSE | 32);
                }
                None => warn!("keystore", "no variable store key to hand over"),
            },
            TAG_EXTEND_BOOT_MEASUREMENT if room >= 36 => {
                let pcr = word(value);
                let mut digest = [0u8; 32];
                for (n, bytes) in digest.chunks_exact_mut(4).enumerate() {
                    bytes.copy_from_slice(&word(value + 1 + n as u32).to_le_bytes());
                }
                match keystore::extend(pcr as usize, &digest) {
                    Ok(extends) => {
                        info!("keystore", "boot measurement extended"; pcr = pcr, extends = extends,
                            digest = format_args!("{:02x}{:02x}{:02x}{:02x}", digest[0], digest[1], digest[2], digest[3]));
                        set(i + 2, RESPONSE | 36);
                    }
                    Err(keystore::Refused::NoSuchRegister) => warn!("keystore", "no such PCR"; pcr = pcr),
                }
            }
            TAG_GET_EARLY_EVENT if room >= 4 * (3 + 8 + measure::MAX_DATA as u32 / 4) => {
                if let Some(event) = measure::event(word(value) as usize) {
                    set(value, event.pcr);
                    set(value + 1, event.kind);
                    for (n, bytes) in event.digest.chunks_exact(4).enumerate() {
                        set(value + 2 + n as u32, u32::from_le_bytes(bytes.try_into().unwrap()));
                    }
                    set(value + 10, event.len as u32);
                    for (n, bytes) in event.data.chunks_exact(4).enumerate() {
                        set(value + 11 + n as u32, u32::from_le_bytes(bytes.try_into().unwrap()));
                    }
                    set(i + 2, RESPONSE | room);
                }
            }
            TAG_TPM2_COMMAND if room >= 10 => {
                let header = [word(value), word(value + 1)];
                let length = u32::from_be_bytes([(header[0] >> 16) as u8, (header[0] >> 24) as u8, header[1] as u8, (header[1] >> 8) as u8]) as usize;
                if !(10..=room as usize).contains(&length) || length > tpm2::MAX_COMMAND {
                    warn!("tpm2", "command of a length the tag cannot hold"; length = length, room = room);
                } else {
                    let (command, response) = tpm2::buffers();
                    for (n, byte) in command[..length].iter_mut().enumerate() {
                        *byte = (word(value + n as u32 / 4) >> (8 * (n % 4))) as u8;
                    }
                    let out = tpm2::execute(&command[..length], response);
                    if out > room as usize {
                        warn!("tpm2", "response longer than the tag's room"; length = out, room = room);
                    } else {
                        for n in (0..out).step_by(4) {
                            let mut w = [0u8; 4];
                            let end = (n + 4).min(out);
                            w[..end - n].copy_from_slice(&response[n..end]);
                            set(value + n as u32 / 4, u32::from_le_bytes(w));
                        }
                        set(i + 2, RESPONSE | out as u32);
                    }
                }
            }
            _ => debug!("mailbox", "property tag not answered"; tag = format_args!("{tag:#010x}")),
        }
        i = value + room / 4;
    }
    set(1, RESPONSE);
}

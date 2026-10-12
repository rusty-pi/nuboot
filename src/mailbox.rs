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

use crate::{arm, crypto, debug, error, idle, info, keystore, measure, mmio, tpm2, varstore, vl805, warn, watchdog};

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
/// The channel the runtime services use to have the variable store written:
/// its messages are answered in the buffer and not on mailbox 0, where the
/// OS's own driver takes whatever arrives for its requests.
const CHANNEL_RUNTIME: u32 = 7;
const RESPONSE: u32 = 0x8000_0000;
const CODE_ERROR: u32 = 0x8000_0001;
/// The largest buffer walked, so a bad size word cannot run off into memory.
const MAX_BUFFER: u32 = 0x6000;

/// Linux's `RPI_FIRMWARE_NOTIFY_XHCI_RESET`: it has reset the PCIe link, and
/// with it a VL805 that keeps no firmware of its own.
const TAG_NOTIFY_XHCI_RESET: u32 = 0x0003_0058;

/// Linux's `RPI_FIRMWARE_GET_REBOOT_FLAGS` and `SET_REBOOT_FLAGS`, which
/// `reboot '0 tryboot'` sets: bit 0 asks the bootloader to boot the next time
/// from `tryboot.img` and `tryboot.sig` in place of `boot.img` and `boot.sig`.
const TAG_GET_REBOOT_FLAGS: u32 = 0x0003_0064;
const TAG_SET_REBOOT_FLAGS: u32 = 0x0003_8064;

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
/// The firmware cryptography service `rpi-fw-crypto` speaks ([`crypto`]).
const TAG_CRYPTO_LAST_ERROR: u32 = 0x0003_008e;
const TAG_CRYPTO_NUM_KEYS: u32 = 0x0003_008f;
const TAG_CRYPTO_KEY_STATUS: u32 = 0x0003_0090;
const TAG_CRYPTO_SET_KEY_STATUS: u32 = 0x0003_8090;
const TAG_CRYPTO_SIGN: u32 = 0x0003_0091;
const TAG_CRYPTO_HMAC_SHA256: u32 = 0x0003_0092;
const TAG_CRYPTO_PUBLIC_KEY: u32 = 0x0003_0093;
const TAG_CRYPTO_PRIVATE_KEY: u32 = 0x0003_0094;
const TAG_CRYPTO_GEN_ECDSA_KEY: u32 = 0x0003_0095;
const TAG_CRYPTO_GET_KEY_USAGE: u32 = 0x0003_009c;
const TAG_CRYPTO_SET_KEY_USAGE: u32 = 0x0003_809c;

/// Add a record to the variable store, as UEFI wrote it, or sign and add the
/// write of a variable no signature guards. Both are for the runtime services
/// ([`CHANNEL_RUNTIME`]). The answer is a status word: 0, or what went wrong.
const TAG_STORE_APPEND: u32 = 0x0003_00a6;
const TAG_STORE_PERSIST: u32 = 0x0003_00a7;

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
            answer(message & !0xf, false);
        } else if channel == CHANNEL_RUNTIME {
            answer(message & !0xf, true);
            continue;
        } else {
            warn!("mailbox", "request on a channel this firmware does not serve";
                channel = channel, message = format_args!("{message:#010x}"));
        }
        while mmio::read(STATUS0) & STATUS_FULL != 0 {}
        mmio::write(DATA0, message);
    }
    idle::listen_mailbox();
}

/// What the buffer held when the ARM posted it. The ARM goes on running while
/// the tags are answered, so nothing is read twice from the buffer it can
/// change: each tag is parsed from this copy, and an answer goes to both.
static mut REQUEST: [u32; (MAX_BUFFER / 4) as usize] = [0; (MAX_BUFFER / 4) as usize];

/// Answer the buffer at bus address `bus`, in place. A buffer that is not
/// wholly in memory the ARM owns is not touched: the firmware's own memory is
/// not the ARM's to have read or written through the mailbox.
fn answer(bus: u32, runtime: bool) {
    // The ARM's bus addresses alias SDRAM at 0xC000_0000, uncached, as the
    // VPU's own do.
    let physical = bus & 0x3fff_ffff;
    let base = 0xc000_0000 | physical;
    if physical % 4 != 0 || physical + 12 > arm::VPU_BASE {
        error!("mailbox", "property buffer outside the ARM's memory"; bus = format_args!("{bus:#010x}"));
        return;
    }
    let os_word = |i: u32| unsafe { core::ptr::read_volatile((base + 4 * i) as usize as *const u32) };
    let os_set = |i: u32, v: u32| unsafe { core::ptr::write_volatile((base + 4 * i) as usize as *mut u32, v) };

    let size = os_word(0);
    if !(12..=MAX_BUFFER).contains(&size) || size % 4 != 0 {
        error!("mailbox", "property buffer with a bad size"; bus = format_args!("{bus:#010x}"), size = size);
        os_set(1, CODE_ERROR);
        return;
    }
    if physical + size > arm::VPU_BASE {
        error!("mailbox", "property buffer outside the ARM's memory"; bus = format_args!("{bus:#010x}"), size = size);
        os_set(1, CODE_ERROR);
        return;
    }
    let copy = (&raw mut REQUEST).cast::<u32>();
    for n in 0..size / 4 {
        unsafe { core::ptr::write(copy.add(n as usize), os_word(n)) };
    }
    let word = |i: u32| if i < size / 4 { unsafe { core::ptr::read(copy.add(i as usize)) } } else { 0 };
    let set = |i: u32, v: u32| {
        if i < size / 4 {
            unsafe { core::ptr::write(copy.add(i as usize), v) };
            os_set(i, v);
        }
    };
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
        if runtime != matches!(tag, TAG_STORE_APPEND | TAG_STORE_PERSIST) {
            i = value + room / 4;
            continue;
        }
        match tag {
            TAG_STORE_APPEND => {
                let length = word(i + 2) as usize;
                let record = store_buffer();
                let status = if length <= room as usize && length <= record.len() {
                    for (n, byte) in record[..length].iter_mut().enumerate() {
                        *byte = (word(value + n as u32 / 4) >> (8 * (n % 4))) as u8;
                    }
                    store_status(varstore::append(&record[..length]))
                } else {
                    1
                };
                set(value, status);
                set(i + 2, RESPONSE | 4);
            }
            TAG_STORE_PERSIST if room >= 32 => {
                let (kind, attributes) = (word(value), word(value + 1));
                let (name_bytes, data_bytes) = (word(value + 2) as usize, word(value + 3) as usize);
                let mut guid = [0u8; 16];
                for (n, byte) in guid.iter_mut().enumerate() {
                    *byte = (word(value + 4 + n as u32 / 4) >> (8 * (n % 4))) as u8;
                }
                let status = if name_bytes <= 512 && data_bytes <= varstore::MAX_SIGNED_DATA {
                    let data_at = name_bytes.next_multiple_of(4);
                    if 32 + data_at + data_bytes <= room as usize && data_at + data_bytes <= store_buffer().len() {
                        let scratch = store_buffer();
                        for (n, byte) in scratch[..data_at + data_bytes].iter_mut().enumerate() {
                            *byte = (word(value + 8 + n as u32 / 4) >> (8 * (n % 4))) as u8;
                        }
                        let (name, data) = scratch.split_at(data_at);
                        store_status(varstore::persist(kind, attributes, &guid, &name[..name_bytes], &data[..data_bytes]))
                    } else {
                        1
                    }
                } else {
                    1
                };
                set(value, status);
                set(i + 2, RESPONSE | 4);
            }
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
            TAG_GET_REBOOT_FLAGS if room >= 4 => {
                set(value, u32::from(watchdog::tryboot_requested()));
                set(i + 2, RESPONSE | 4);
            }
            TAG_SET_REBOOT_FLAGS if room >= 4 => {
                let flags = word(value);
                watchdog::request_tryboot(flags & 1 != 0);
                info!("mailbox", "reboot flags set"; flags = format_args!("{flags:#x}"));
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
            TAG_CRYPTO_LAST_ERROR if room >= 4 => {
                set(value, crypto::last_error());
                set(i + 2, RESPONSE | 4);
            }
            TAG_CRYPTO_NUM_KEYS if room >= 4 => {
                set(value, crypto::keys());
                set(i + 2, RESPONSE | 4);
            }
            TAG_CRYPTO_KEY_STATUS if room >= 4 => {
                set(value, crypto::status(word(value)).unwrap_or(crypto::ERROR | crypto::ERR_KEY_NOT_FOUND));
                set(i + 2, RESPONSE | 4);
            }
            TAG_CRYPTO_SET_KEY_STATUS if room >= 8 => {
                let (id, bits) = (word(value), word(value + 1));
                if crypto::lock(id, bits).is_ok() {
                    info!("crypto", "key locked"; key = id, bits = format_args!("{bits:#x}"));
                }
                set(i + 2, RESPONSE | 8);
            }
            TAG_CRYPTO_SIGN if room >= 44 => {
                let (id, length) = (word(value + 1), word(value + 2) as usize);
                let mut hash = [0u8; 32];
                for (n, byte) in hash.iter_mut().enumerate() {
                    *byte = (word(value + 3 + n as u32 / 4) >> (8 * (n % 4))) as u8;
                }
                let mut der = [0u8; 72];
                let (status, len) = match if length == 32 { crypto::sign(id, &hash, &mut der) } else { Err(crypto::ERR_EINVAL) } {
                    Ok(len) if 8 + len <= room as usize => (0, len),
                    Ok(_) => (crypto::ERROR | crypto::ERR_EINVAL, 0),
                    Err(code) => (crypto::ERROR | code, 0),
                };
                set(value, status);
                set(value + 1, len as u32);
                for (n, bytes) in der[..len].chunks(4).enumerate() {
                    let mut w = [0u8; 4];
                    w[..bytes.len()].copy_from_slice(bytes);
                    set(value + 2 + n as u32, u32::from_le_bytes(w));
                }
                set(i + 2, RESPONSE | (8 + len as u32));
            }
            TAG_CRYPTO_HMAC_SHA256 if room >= 12 + 32 => {
                let (id, length) = (word(value + 1), word(value + 2) as usize);
                let message = crypto_message();
                let mac = if length <= crypto::HMAC_MESSAGE_MAX && 12 + length <= room as usize {
                    for (n, byte) in message[..length].iter_mut().enumerate() {
                        *byte = (word(value + 3 + n as u32 / 4) >> (8 * (n % 4))) as u8;
                    }
                    crypto::hmac(id, &message[..length])
                } else {
                    Err(crypto::ERR_EINVAL)
                };
                match mac {
                    Ok(mac) => {
                        set(value, 0);
                        set(value + 1, 32);
                        for (n, bytes) in mac.chunks_exact(4).enumerate() {
                            set(value + 2 + n as u32, u32::from_le_bytes(bytes.try_into().unwrap()));
                        }
                    }
                    Err(code) => {
                        set(value, crypto::ERROR | code);
                        set(value + 1, 0);
                    }
                }
                set(i + 2, RESPONSE | 40);
            }
            TAG_CRYPTO_PUBLIC_KEY if room >= 8 + 91 => {
                let mut der = [0u8; 91];
                let (status, len) = match crypto::public_key(word(value + 1), &mut der) {
                    Ok(len) => (0, len),
                    Err(code) => (crypto::ERROR | code, 0),
                };
                set(value, status);
                set(value + 1, len as u32);
                for (n, bytes) in der[..len].chunks(4).enumerate() {
                    let mut w = [0u8; 4];
                    w[..bytes.len()].copy_from_slice(bytes);
                    set(value + 2 + n as u32, u32::from_le_bytes(w));
                }
                set(i + 2, RESPONSE | (8 + len as u32));
            }
            TAG_CRYPTO_PRIVATE_KEY if room >= 8 => {
                set(value, crypto::ERROR | crypto::refused());
                set(value + 1, 0);
                set(i + 2, RESPONSE | 8);
            }
            TAG_CRYPTO_GEN_ECDSA_KEY | TAG_CRYPTO_GET_KEY_USAGE | TAG_CRYPTO_SET_KEY_USAGE if room >= 4 => {
                set(value, crypto::ERROR | crypto::unsupported());
                set(i + 2, RESPONSE | room.min(8));
            }
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

/// Room for the message of an HMAC request.
fn crypto_message() -> &'static mut [u8; crypto::HMAC_MESSAGE_MAX] {
    static mut MESSAGE: [u8; crypto::HMAC_MESSAGE_MAX] = [0; crypto::HMAC_MESSAGE_MAX];
    unsafe { &mut *(&raw mut MESSAGE) }
}

fn store_status(result: Result<(), varstore::Error>) -> u32 {
    match result {
        Ok(()) => 0,
        Err(varstore::Error::Malformed) => 1,
        Err(varstore::Error::Refused) => 2,
        Err(varstore::Error::NoDeviceKey) => 3,
        Err(varstore::Error::Full) => 4,
        Err(varstore::Error::Flash) => 5,
    }
}

/// Room for a record or a variable's name and value on its way into the store.
fn store_buffer() -> &'static mut [u8; varstore::MAX_RECORD] {
    static mut BUFFER: [u8; varstore::MAX_RECORD] = [0; varstore::MAX_RECORD];
    unsafe { &mut *(&raw mut BUFFER) }
}

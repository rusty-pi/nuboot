//! Sends the TPM on the VPU a series of commands through
//! `EFI_TCG2_PROTOCOL.SubmitCommand` and prints each response in hex, for
//! `scripts/check-tpm2.py` to check.

#![no_std]
#![no_main]

use core::ffi::c_void;

use r_efi::efi::{Guid, Handle, Status, SystemTable};

mod common;
use common::say;

#[path = "rsa_vector.rs"]
mod rsa_vector;

const TCG2: Guid = Guid::from_fields(0x607f766c, 0x7455, 0x42be, 0x93, 0x0b, &[0xe4, 0xd7, 0x6d, 0xb2, 0x72, 0x0f]);

/// `EFI_TCG2_PROTOCOL.SubmitCommand`, the fourth function of the table.
type Submit = extern "efiapi" fn(*mut c_void, u32, *const u8, u32, *mut u8) -> Status;

/// A command being put together.
struct Command {
    bytes: [u8; 1024],
    len: usize,
}

impl Command {
    fn new(tag: u16, code: u32) -> Command {
        let mut c = Command { bytes: [0; 1024], len: 0 };
        c.u16(tag);
        c.u32(0);
        c.u32(code);
        c
    }
    fn u16(&mut self, v: u16) -> &mut Self {
        self.put(&v.to_be_bytes())
    }
    fn u32(&mut self, v: u32) -> &mut Self {
        self.put(&v.to_be_bytes())
    }
    fn put(&mut self, b: &[u8]) -> &mut Self {
        self.bytes[self.len..self.len + b.len()].copy_from_slice(b);
        self.len += b.len();
        self
    }
    /// A password session with an empty password, as the authorization area.
    fn password(&mut self) -> &mut Self {
        self.password_of(&[])
    }
    /// A password session with this password.
    fn password_of(&mut self, password: &[u8]) -> &mut Self {
        self.u32(9 + password.len() as u32).u32(0x4000_0009).u16(0).put(&[0]).u16(password.len() as u16).put(password)
    }
    fn done(&mut self) -> &[u8] {
        let len = self.len as u32;
        self.bytes[2..6].copy_from_slice(&len.to_be_bytes());
        &self.bytes[..self.len]
    }
}

/// The names of the commands of a key size, as `&'static str`s: `run` takes
/// text that outlives the call.
fn concat_name(key: &str, step: &str) -> &'static str {
    match (key, step) {
        ("rsa3072", "-load") => "load-rsa3072",
        ("rsa3072", "-verify") => "verify-rsa3072",
        ("rsa3072", "-forged") => "verify-rsa3072-forged",
        ("rsa3072", "-flush") => "flush-rsa3072",
        ("rsa4096", "-load") => "load-rsa4096",
        ("rsa4096", "-verify") => "verify-rsa4096",
        ("rsa4096", "-forged") => "verify-rsa4096-forged",
        _ => "flush-rsa4096",
    }
}

fn counter() -> u64 {
    let ticks: u64;
    unsafe { core::arch::asm!("mrs {}, cntvct_el0", out(reg) ticks) };
    ticks
}

fn frequency() -> u64 {
    let hz: u64;
    unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) hz) };
    hz
}

fn decimal(system_table: *mut SystemTable, mut v: u64) {
    let mut digits = [0u8; 20];
    let mut at = digits.len();
    loop {
        at -= 1;
        digits[at] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    say(system_table, unsafe { core::str::from_utf8_unchecked(&digits[at..]) });
}

fn hex(system_table: *mut SystemTable, bytes: &[u8]) {
    for chunk in bytes.chunks(40) {
        let mut out = [0u8; 80];
        for (i, b) in chunk.iter().enumerate() {
            out[2 * i] = b"0123456789abcdef"[(b >> 4) as usize];
            out[2 * i + 1] = b"0123456789abcdef"[(b & 15) as usize];
        }
        say(system_table, unsafe { core::str::from_utf8_unchecked(&out[..2 * chunk.len()]) });
    }
}

/// Print the event log `EFI_TCG2_PROTOCOL.GetEventLog` gives, whole.
fn log_events(system_table: *mut SystemTable, protocol: *mut c_void) {
    let get: extern "efiapi" fn(*mut c_void, u32, *mut u64, *mut u64, *mut u8) -> Status =
        unsafe { core::mem::transmute(*(protocol as *const usize).add(1)) };
    let (mut location, mut last, mut truncated) = (0u64, 0u64, 0u8);
    say(system_table, "tpm2 test: eventlog ");
    if get(protocol, 2, &mut location, &mut last, &mut truncated).is_error() {
        say(system_table, "failed\r\n");
        return;
    }
    // The log ends where the last event does; its size is in its last word.
    let tail = last as usize + 4 + 4 + 4 + 2 + 32 + 4;
    let size = u32::from_le_bytes(unsafe { *((tail - 4) as *const [u8; 4]) }) as usize;
    let end = tail + size;
    hex(system_table, unsafe { core::slice::from_raw_parts(location as *const u8, end - location as usize) });
    say(system_table, "\r\n");
}

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(_image: Handle, system_table: *mut SystemTable) -> Status {
    let bs = unsafe { (*system_table).boot_services };
    let mut protocol: *mut c_void = core::ptr::null_mut();
    let mut guid = TCG2;
    if unsafe { ((*bs).locate_protocol)(&mut guid, core::ptr::null_mut(), &mut protocol) }.is_error() {
        say(system_table, "tpm2 test: no EFI_TCG2_PROTOCOL\r\n");
        return Status::NOT_FOUND;
    }
    let submit: Submit = unsafe { core::mem::transmute(*(protocol as *const usize).add(3)) };
    let mut run = |name: &str, command: &[u8]| -> ([u8; 1024], usize) {
        let mut response = [0u8; 1024];
        let status = submit(protocol, command.len() as u32, command.as_ptr(), 1024, response.as_mut_ptr());
        say(system_table, "tpm2 test: ");
        say(system_table, name);
        say(system_table, " ");
        let mut len = 0;
        if status.is_error() {
            say(system_table, "failed");
        } else {
            len = (u32::from_be_bytes(response[2..6].try_into().unwrap()) as usize).min(1024);
            hex(system_table, &response[..len]);
        }
        say(system_table, "\r\n");
        (response, len)
    };
    let digest = [0x11u8; 32];

    run("startup", Command::new(0x8001, 0x144).u16(0).done());
    run("pcr-read-all", Command::new(0x8001, 0x17e).u32(1).u16(0xb).put(&[3, 0xff, 0xff, 0xff]).done());
    run("pcr-read-mid", Command::new(0x8001, 0x17e).u32(1).u16(0xb).put(&[3, 0, 0xff, 0]).done());
    run("pcr-read-high", Command::new(0x8001, 0x17e).u32(1).u16(0xb).put(&[3, 0, 0, 0xff]).done());
    log_events(system_table, protocol);
    run("getcap-properties", Command::new(0x8001, 0x17a).u32(6).u32(0x100).u32(8).done());
    run("getcap-algs", Command::new(0x8001, 0x17a).u32(0).u32(0).u32(16).done());
    run("getcap-pcrs", Command::new(0x8001, 0x17a).u32(5).u32(0).u32(1).done());
    run("getcap-commands", Command::new(0x8001, 0x17a).u32(2).u32(0).u32(64).done());
    run("pcr-read-before", Command::new(0x8001, 0x17e).u32(1).u16(0xb).put(&[3, 0x81, 0, 0x80]).done());
    run("pcr-extend", Command::new(0x8002, 0x182).u32(23).password().u32(1).u16(0xb).put(&digest).done());
    run("pcr-read-extended", Command::new(0x8001, 0x17e).u32(1).u16(0xb).put(&[3, 0, 0, 0x80]).done());
    run("pcr-event", Command::new(0x8002, 0x14b).u32(23).password().u16(5).put(b"hello").done());
    run("pcr-read-evented", Command::new(0x8001, 0x17e).u32(1).u16(0xb).put(&[3, 0, 0, 0x80]).done());
    run("pcr-reset", Command::new(0x8002, 0x13d).u32(23).password().done());
    run("pcr-read-reset", Command::new(0x8001, 0x17e).u32(1).u16(0xb).put(&[3, 0, 0, 0x80]).done());
    run("pcr-extend-drtm", Command::new(0x8002, 0x182).u32(17).password().u32(1).u16(0xb).put(&digest).done());
    run("pcr-extend-sha1", Command::new(0x8002, 0x182).u32(16).password().u32(1).u16(4).put(&[0x22; 20]).done());
    run("pcr-extend-no-session", Command::new(0x8001, 0x182).u32(16).u32(1).u16(0xb).put(&digest).done());
    run("get-random", Command::new(0x8001, 0x17b).u16(16).done());
    run("hash", Command::new(0x8001, 0x17d).u16(3).put(b"abc").u16(0xb).u32(0x4000_0007).done());
    run("unknown-command", Command::new(0x8001, 0x129).done());
    run("short-command", &[0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x44]);

    // An ECC P-256 storage key under the owner hierarchy, and a secret sealed
    // under it.
    let storage: &[u8] = &[
        0x00, 0x23, 0x00, 0x0b, 0x00, 0x03, 0x00, 0x72, 0x00, 0x00, 0x00, 0x06, 0x00, 0x80, 0x00, 0x43, 0x00, 0x10, 0x00, 0x03,
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
    ];
    let sealed: &[u8] = &[0x00, 0x08, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x52, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00];
    let (r, _) = run(
        "create-primary",
        Command::new(0x8002, 0x131).u32(0x4000_0001).password().put(&[0, 4, 0, 0, 0, 0]).u16(storage.len() as u16).put(storage).u16(0).u32(0).done(),
    );
    let primary = u32::from_be_bytes(r[10..14].try_into().unwrap());
    let (r, n) = run(
        "create-sealed",
        Command::new(0x8002, 0x153)
            .u32(primary)
            .password()
            .u16(11)
            .u16(2)
            .put(b"pw")
            .u16(5)
            .put(b"hello")
            .u16(sealed.len() as u16)
            .put(sealed)
            .u16(0)
            .u32(0)
            .done(),
    );
    // The private and public parts, as `Load` wants them: after the response's
    // header and parameter size.
    let private_len = u16::from_be_bytes(r[14..16].try_into().unwrap()) as usize;
    let public_at = 14 + 2 + private_len;
    let public_len = u16::from_be_bytes(r[public_at..public_at + 2].try_into().unwrap()) as usize;
    let _ = n;
    let mut load = Command::new(0x8002, 0x157);
    load.u32(primary).password().put(&r[14..16 + private_len]).put(&r[public_at..public_at + 2 + public_len]);
    let (r, _) = run("load", load.done());
    let item = u32::from_be_bytes(r[10..14].try_into().unwrap());
    run("unseal", Command::new(0x8002, 0x15e).u32(item).password_of(b"pw").done());
    run("unseal-wrong-password", Command::new(0x8002, 0x15e).u32(item).password_of(b"no").done());
    run("read-public", Command::new(0x8001, 0x173).u32(item).done());
    run("getcap-transient", Command::new(0x8001, 0x17a).u32(1).u32(0x8000_0000).u32(8).done());

    // An ECDSA signing key under the primary, a signature and a quote by it.
    let signing: &[u8] = &[
        0x00, 0x23, 0x00, 0x0b, 0x00, 0x04, 0x00, 0x72, 0x00, 0x00, 0x00, 0x10, 0x00, 0x18, 0x00, 0x0b, 0x00, 0x03, 0x00, 0x10, 0x00, 0x00,
        0x00, 0x00,
    ];
    let (r, _) = run(
        "create-signing",
        Command::new(0x8002, 0x153).u32(primary).password().u16(4).u16(0).u16(0).u16(signing.len() as u16).put(signing).u16(0).u32(0).done(),
    );
    let private_len = u16::from_be_bytes(r[14..16].try_into().unwrap()) as usize;
    let public_at = 14 + 2 + private_len;
    let public_len = u16::from_be_bytes(r[public_at..public_at + 2].try_into().unwrap()) as usize;
    let mut load = Command::new(0x8002, 0x157);
    load.u32(primary).password().put(&r[14..16 + private_len]).put(&r[public_at..public_at + 2 + public_len]);
    let (r, _) = run("load-signing", load.done());
    let key = u32::from_be_bytes(r[10..14].try_into().unwrap());
    let (r, _) = run(
        "sign",
        Command::new(0x8002, 0x15d).u32(key).password().u16(32).put(&digest).u16(0x10).u16(0x8024).u32(0x4000_0007).u16(0).done(),
    );
    run("sign-short-digest", Command::new(0x8002, 0x15d).u32(key).password().u16(31).put(&digest[..31]).u16(0x10).u16(0x8024).u32(0x4000_0007).u16(0).done());
    run("sign-storage-key", Command::new(0x8002, 0x15d).u32(primary).password().u16(32).put(&digest).u16(0x10).u16(0x8024).u32(0x4000_0007).u16(0).done());
    let mut verify = Command::new(0x8001, 0x177);
    verify.u32(key).u16(32).put(&digest).put(&r[14..14 + 72]);
    run("verify-signature", verify.done());
    let mut forged = [0u8; 72];
    forged.copy_from_slice(&r[14..14 + 72]);
    forged[40] ^= 1;
    let mut verify = Command::new(0x8001, 0x177);
    verify.u32(key).u16(32).put(&digest).put(&forged);
    run("verify-forged", verify.done());
    run(
        "quote",
        Command::new(0x8002, 0x158).u32(key).password().u16(4).put(&[1, 2, 3, 4]).u16(0x10).u32(1).u16(0xb).put(&[3, 0x01, 0, 0]).done(),
    );
    run("hash-ticket", Command::new(0x8001, 0x17d).u16(3).put(b"abc").u16(0xb).u32(0x4000_0001).done());
    run("flush-signing", Command::new(0x8001, 0x165).u32(key).done());

    // An RSA public key the TPM is handed, a signature it verifies, and the
    // policy that key authorizes.
    let mut template = [0u8; 300];
    let header: &[u8] = &[0x00, 0x01, 0x00, 0x0b, 0x00, 0x04, 0x00, 0x40, 0x00, 0x00, 0x00, 0x10, 0x00, 0x10, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00];
    template[..header.len()].copy_from_slice(header);
    template[header.len()..header.len() + 256].copy_from_slice(&rsa_vector::MODULUS);
    let len = header.len() + 256;
    let (r, _) = run("load-external", Command::new(0x8001, 0x167).u16(0).u16(len as u16).put(&template[..len]).u32(0x4000_0001).done());
    let rsa_key = u32::from_be_bytes(r[10..14].try_into().unwrap());
    let mut verify = Command::new(0x8001, 0x177);
    verify.u32(rsa_key).u16(32).put(&digest).u16(0x14).u16(0x0b).u16(256).put(&rsa_vector::SIGNATURE);
    run("verify-rsa", verify.done());
    let mut forged = rsa_vector::SIGNATURE;
    forged[255] ^= 1;
    let mut verify = Command::new(0x8001, 0x177);
    verify.u32(rsa_key).u16(32).put(&digest).u16(0x14).u16(0x0b).u16(256).put(&forged);
    run("verify-rsa-forged", verify.done());

    // The same with RSA-3072 and RSA-4096 keys, and how long the verifying takes.
    for (name, modulus, signature) in [
        ("rsa3072", &rsa_vector::MODULUS_3072[..], &rsa_vector::SIGNATURE_3072[..]),
        ("rsa4096", &rsa_vector::MODULUS_4096[..], &rsa_vector::SIGNATURE_4096[..]),
    ] {
        let bits = (modulus.len() * 8) as u16;
        let mut template = [0u8; 600];
        let mut header = [0u8; 22];
        header.copy_from_slice(&[0x00, 0x01, 0x00, 0x0b, 0x00, 0x04, 0x00, 0x40, 0x00, 0x00, 0x00, 0x10, 0x00, 0x10, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00]);
        header[14..16].copy_from_slice(&bits.to_be_bytes());
        header[20..22].copy_from_slice(&(modulus.len() as u16).to_be_bytes());
        template[..22].copy_from_slice(&header);
        template[22..22 + modulus.len()].copy_from_slice(modulus);
        let len = 22 + modulus.len();
        let (r, _) = run(concat_name(name, "-load"), Command::new(0x8001, 0x167).u16(0).u16(len as u16).put(&template[..len]).u32(0x4000_0001).done());
        let key = u32::from_be_bytes(r[10..14].try_into().unwrap());
        let mut verify = Command::new(0x8001, 0x177);
        verify.u32(key).u16(32).put(&digest).u16(0x14).u16(0x0b).u16(modulus.len() as u16).put(signature);
        let started = counter();
        run(concat_name(name, "-verify"), verify.done());
        let ticks = counter() - started;
        say(system_table, "tpm2 time: ");
        say(system_table, name);
        say(system_table, " ticks=");
        decimal(system_table, ticks);
        say(system_table, " freq=");
        decimal(system_table, frequency());
        say(system_table, "\r\n");
        let mut forged = [0u8; 512];
        forged[..signature.len()].copy_from_slice(signature);
        forged[signature.len() - 1] ^= 1;
        let mut verify = Command::new(0x8001, 0x177);
        verify.u32(key).u16(32).put(&digest).u16(0x14).u16(0x0b).u16(modulus.len() as u16).put(&forged[..signature.len()]);
        run(concat_name(name, "-forged"), verify.done());
        run(concat_name(name, "-flush"), Command::new(0x8001, 0x165).u32(key).done());
    }
    run("sign-external", Command::new(0x8002, 0x15d).u32(rsa_key).password().u16(32).put(&digest).u16(0x10).u16(0x8024).u32(0x4000_0007).u16(0).done());
    // A public area with a modulus longer than any key the TPM takes.
    let mut modulus = [0xc3u8; 600];
    modulus[599] |= 1;
    run(
        "load-external-long",
        Command::new(0x8001, 0x167)
            .u16(0)
            .u16(654)
            .u16(1)
            .u16(0xb)
            .u32(0x0004_0000)
            .u16(32)
            .put(&[0xaa; 32])
            .u16(0x10)
            .u16(0x10)
            .u16(2048)
            .u32(0)
            .u16(600)
            .put(&modulus)
            .u32(0x4000_0001)
            .done(),
    );
    run("flush-external", Command::new(0x8001, 0x165).u32(rsa_key).done());
    run("flush-item", Command::new(0x8001, 0x165).u32(item).done());
    run("flush-primary", Command::new(0x8001, 0x165).u32(primary).done());
    run("flush-again", Command::new(0x8001, 0x165).u32(primary).done());
    say(system_table, "tpm2 test: done\r\n");
    Status::SUCCESS
}

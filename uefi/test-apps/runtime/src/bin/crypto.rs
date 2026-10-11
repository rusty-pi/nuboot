//! The firmware cryptography service: the device key signs, HMACs and gives
//! its public key until boot services end, never gives itself, and from
//! `ExitBootServices` signs and HMACs no more.

#![no_std]
#![no_main]

use core::ptr::{read_volatile, write_volatile};

use r_efi::efi::{self, Handle, Status, SystemTable};
use runtime_efi::{check, exit_boot_services, say, settle};

#[path = "../../../../../src/p256.rs"]
#[allow(dead_code)]
mod p256;

const MAIL0_READ: usize = 0xfe00_b880;
const MAIL0_STATUS: usize = 0xfe00_b898;
const MAIL1_WRITE: usize = 0xfe00_b8a0;
const MAIL1_STATUS: usize = 0xfe00_b8b8;
const FULL: u32 = 1 << 31;
const EMPTY: u32 = 1 << 30;
const RESPONSE: u32 = 0x8000_0000;

const TAG_LAST_ERROR: u32 = 0x0003_008e;
const TAG_KEY_STATUS: u32 = 0x0003_0090;
const TAG_SIGN: u32 = 0x0003_0091;
const TAG_HMAC: u32 = 0x0003_0092;
const TAG_PUBLIC_KEY: u32 = 0x0003_0093;
const TAG_PRIVATE_KEY: u32 = 0x0003_0094;

const SIGN_LOCKED: u32 = 1 << 10;
const HMAC_LOCKED: u32 = 1 << 11;
const READ_LOCKED: u32 = 1 << 8;
const ERROR: u32 = 0x8000_0000;

const WORDS: usize = 64;

fn flush(at: usize, len: usize) {
    for line in (at & !63..at + len).step_by(64) {
        unsafe { core::arch::asm!("dc civac, {}", in(reg) line) };
    }
    unsafe { core::arch::asm!("dsb sy") };
}

/// One tag with `request` as the start of its value, in the page at `buf`:
/// the value's words.
fn call(buf: usize, tag: u32, request: &[u32]) -> Option<[u32; WORDS]> {
    let p = buf as *mut u32;
    unsafe {
        write_volatile(p, 4 * (WORDS as u32 + 6));
        write_volatile(p.add(1), 0);
        write_volatile(p.add(2), tag);
        write_volatile(p.add(3), 4 * WORDS as u32);
        write_volatile(p.add(4), 4 * request.len() as u32);
        for i in 0..WORDS {
            write_volatile(p.add(5 + i), request.get(i).copied().unwrap_or(0));
        }
        write_volatile(p.add(5 + WORDS), 0);
    }
    flush(buf, 4 * (WORDS + 6));
    let message = (0xc000_0000 | buf as u32) | 8;
    unsafe {
        while read_volatile(MAIL1_STATUS as *const u32) & FULL != 0 {}
        write_volatile(MAIL1_WRITE as *mut u32, message);
        loop {
            while read_volatile(MAIL0_STATUS as *const u32) & EMPTY != 0 {}
            if read_volatile(MAIL0_READ as *const u32) == message {
                break;
            }
        }
    }
    flush(buf, 4 * (WORDS + 6));
    if unsafe { read_volatile(p.add(4)) } & RESPONSE == 0 {
        return None;
    }
    let mut out = [0u32; WORDS];
    for (i, o) in out.iter_mut().enumerate() {
        *o = unsafe { read_volatile(p.add(5 + i)) };
    }
    Some(out)
}

fn bytes(words: &[u32], len: usize) -> [u8; 4 * WORDS] {
    let mut out = [0u8; 4 * WORDS];
    for (i, w) in words.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&w.to_le_bytes());
    }
    let _ = len;
    out
}

fn sign(buf: usize, digest: &[u8; 32]) -> Option<[u32; WORDS]> {
    let mut request = [0u32; 11];
    request[1] = 1;
    request[2] = 32;
    for (w, b) in request[3..].iter_mut().zip(digest.chunks_exact(4)) {
        *w = u32::from_le_bytes(b.try_into().unwrap());
    }
    call(buf, TAG_SIGN, &request)
}

/// `(r, s)` out of a DER signature.
fn rs(der: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    let integer = |at: usize| -> Option<([u8; 32], usize)> {
        let len = *der.get(at + 1)? as usize;
        let v = der.get(at + 2..at + 2 + len)?;
        let v = &v[v.len().saturating_sub(32)..];
        let mut out = [0u8; 32];
        out[32 - v.len()..].copy_from_slice(v);
        Some((out, at + 2 + len))
    };
    let (r, next) = integer(2)?;
    Some((r, integer(next)?.0))
}

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(image: Handle, system_table: *mut SystemTable) -> Status {
    let mut page: efi::PhysicalAddress = 0x3fff_ffff;
    let allocated = unsafe {
        let bs = (*system_table).boot_services;
        ((*bs).allocate_pages)(efi::ALLOCATE_MAX_ADDRESS, efi::LOADER_DATA, 1, &mut page)
    };
    if allocated.is_error() {
        return allocated;
    }
    let buf = page as usize;
    let digest: [u8; 32] = core::array::from_fn(|i| i as u8 * 7 + 1);

    let status = call(buf, TAG_KEY_STATUS, &[1]).map_or(ERROR, |v| v[0]);
    check("the device key may sign and HMAC at first", status & (SIGN_LOCKED | HMAC_LOCKED) == 0 && status & READ_LOCKED != 0);
    check("a key that is not there has no status", call(buf, TAG_KEY_STATUS, &[2]).is_some_and(|v| v[0] & ERROR != 0));

    let public = call(buf, TAG_PUBLIC_KEY, &[0, 1]);
    let point = public.and_then(|v| {
        let der = bytes(&v[2..], v[1] as usize);
        (v[0] == 0 && v[1] == 91 && der[..2] == [0x30, 0x59]).then(|| p256::Point {
            x: der[27..59].try_into().unwrap(),
            y: der[59..91].try_into().unwrap(),
        })
    });
    check("the public key comes as a P-256 SubjectPublicKeyInfo", point.is_some_and(|p| p256::on_curve(&p)));

    let signature = sign(buf, &digest).and_then(|v| {
        let der = bytes(&v[2..], v[1] as usize);
        (v[0] == 0 && der[0] == 0x30 && der[1] as u32 + 2 == v[1]).then(|| rs(&der[..v[1] as usize])).flatten()
    });
    check("the key signs a hash", signature.is_some());
    check(
        "the signature verifies against the public key",
        matches!((point, signature), (Some(q), Some((r, s))) if p256::verify(&q, &digest, &r, &s)),
    );
    let mut other = digest;
    other[0] ^= 1;
    check(
        "it does not verify another hash",
        matches!((point, signature), (Some(q), Some((r, s))) if !p256::verify(&q, &other, &r, &s)),
    );
    check("a hash of another length is refused", {
        let mut request = [0u32; 11];
        request[1] = 1;
        request[2] = 16;
        call(buf, TAG_SIGN, &request).is_some_and(|v| v[0] & ERROR != 0)
    });

    let mac = call(buf, TAG_HMAC, &[0, 1, 3, u32::from_le_bytes(*b"abc\0")]);
    check("the key HMACs a message", mac.is_some_and(|v| v[0] == 0 && v[1] == 32 && v[2..10] != [0u32; 8]));
    check("the private key itself is refused", call(buf, TAG_PRIVATE_KEY, &[0, 1]).is_some_and(|v| v[0] & ERROR != 0 && v[1] == 0));
    check("the refusal is the last error", call(buf, TAG_LAST_ERROR, &[]).is_some_and(|v| v[0] == 4));

    exit_boot_services(image, system_table);
    settle();
    let status = call(buf, TAG_KEY_STATUS, &[1]).map_or(0, |v| v[0]);
    check("signing and HMAC are locked once the OS has the board", status & (SIGN_LOCKED | HMAC_LOCKED) == SIGN_LOCKED | HMAC_LOCKED);
    check("the key no longer signs", sign(buf, &digest).is_some_and(|v| v[0] & ERROR != 0 && v[1] == 0));
    check("the key no longer HMACs", call(buf, TAG_HMAC, &[0, 1, 3, 0x636261]).is_some_and(|v| v[0] & ERROR != 0));
    check("the public key is still given", call(buf, TAG_PUBLIC_KEY, &[0, 1]).is_some_and(|v| v[0] == 0 && v[1] == 91));
    say("runtime test: done\r\n");
    runtime_efi::hang()
}

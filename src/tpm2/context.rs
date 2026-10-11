//! `TPM2_ContextSave`, `TPM2_ContextLoad` and `TPM2_FlushContext`: what lets a
//! tool that runs one command per process keep its objects and sessions
//! between them.
//!
//! A saved context is the object or session, encrypted and with an HMAC, under
//! keys that exist for this boot only, so it loads back until the TPM is
//! started again and not on another board.

use super::object::{self, Origin, SLOTS, TRANSIENT_FIRST};
use super::session::{self, SESSION_SLOTS};
use super::{In, RC_COMMAND_SIZE, RC_HANDLE, RC_INTEGRITY, RC_OBJECT_MEMORY, RC_P, RC_RANGE, RC_SESSION_MEMORY, RC_SIZE, RC_1};
use super::session::Authorization;
use crate::{aes, kdf, keystore, sha256};

static mut SEQUENCE: u64 = 0;

fn keys(sequence: u64) -> ([u8; 16], [u8; 32]) {
    let mut secret = keystore::tpm_secret(b"context", false);
    let mut key = [0u8; 16];
    kdf::kdfa(&secret, b"CONTEXT ENC", &sequence.to_be_bytes(), &[], 128, &mut key);
    let mut mac = [0u8; 32];
    kdf::kdfa(&secret, b"CONTEXT MAC", &sequence.to_be_bytes(), &[], 256, &mut mac);
    keystore::zero(&mut secret);
    (key, mac)
}

struct Writer<'a> {
    buf: &'a mut [u8],
    at: usize,
}

impl Writer<'_> {
    fn put(&mut self, bytes: &[u8]) {
        self.buf[self.at..self.at + bytes.len()].copy_from_slice(bytes);
        self.at += bytes.len();
    }
    fn u8(&mut self, v: u8) {
        self.put(&[v]);
    }
    fn u16(&mut self, v: u16) {
        self.put(&v.to_be_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.put(&v.to_be_bytes());
    }
}

const OBJECT: u8 = 1;
const SESSION: u8 = 2;

fn write_object(slot: &object::Slot, w: &mut Writer) {
    w.u8(OBJECT);
    w.u16(slot.public_len as u16);
    w.put(&slot.public[..slot.public_len]);
    w.put(&slot.name);
    w.u32(slot.origin.hierarchy);
    w.put(&slot.origin.template);
    w.u8(slot.is_primary as u8);
    w.put(&slot.qualified);
    w.u8(slot.auth_len as u8);
    w.put(&slot.auth);
    w.u16(slot.private_len as u16);
    w.put(&slot.private[..slot.private_len]);
}

fn read_object(input: &mut In, slot: &mut object::Slot) -> Option<()> {
    let public = input.sized()?;
    slot.public[..public.len()].copy_from_slice(public);
    slot.public_len = public.len();
    slot.name.copy_from_slice(input.take(34)?);
    slot.origin = Origin { hierarchy: input.u32()?, template: input.take(32)?.try_into().ok()? };
    slot.is_primary = input.u8()? != 0;
    slot.qualified.copy_from_slice(input.take(34)?);
    slot.auth_len = input.u8()? as usize;
    slot.auth.copy_from_slice(input.take(32)?);
    let private = input.sized()?;
    slot.private[..private.len()].copy_from_slice(private);
    slot.private_len = private.len();
    (input.rest() == 0 && slot.auth_len <= 32).then_some(())
}

fn write_session(s: &session::Session, w: &mut Writer) {
    w.u8(SESSION);
    w.u8(s.kind);
    w.u8(s.key_len as u8);
    w.put(&s.key);
    w.put(&s.nonce_tpm);
    w.put(&s.nonce_caller);
    w.u8(s.nonce_caller_len as u8);
    w.u16(s.sym_alg);
    w.put(&s.digest);
    w.u32(s.pcr_counter);
    w.u8(s.password as u8);
    w.u8(s.auth_value as u8);
    w.u32(s.command_code);
    w.u8(s.bind_len as u8);
    w.put(&s.bind_name);
}

fn read_session(input: &mut In, s: &mut session::Session) -> Option<()> {
    s.kind = input.u8()?;
    s.key_len = input.u8()? as usize;
    s.key.copy_from_slice(input.take(32)?);
    s.nonce_tpm.copy_from_slice(input.take(32)?);
    s.nonce_caller.copy_from_slice(input.take(32)?);
    s.nonce_caller_len = input.u8()? as usize;
    s.sym_alg = input.u16()?;
    s.digest.copy_from_slice(input.take(32)?);
    s.pcr_counter = input.u32()?;
    s.password = input.u8()? != 0;
    s.auth_value = input.u8()? != 0;
    s.command_code = input.u32()?;
    s.bind_len = input.u8()? as usize;
    s.bind_name.copy_from_slice(input.take(34)?);
    (input.rest() == 0 && s.key_len <= 32 && s.nonce_caller_len <= 32 && s.bind_len <= 34).then_some(())
}

/// `TPM2_ContextSave`.
pub fn save(handle: u32, params: &In, a: &mut Authorization) -> Result<(), u32> {
    if params.rest() != 0 {
        return Err(RC_COMMAND_SIZE);
    }
    let mut plain = [0u8; 700];
    let mut w = Writer { buf: &mut plain, at: 0 };
    let hierarchy;
    if let Some(slot) = object::slot_of(handle) {
        write_object(slot, &mut w);
        hierarchy = slot.origin.hierarchy;
    } else if let Some(s) = session::session_of(handle) {
        write_session(s, &mut w);
        hierarchy = object::RH_NULL;
    } else {
        return Err(RC_HANDLE | RC_1);
    }
    let len = w.at;
    let saved_session = session::session_of(handle).is_some();
    let sequence = unsafe { core::ptr::read_volatile(&raw const SEQUENCE) } + 1;
    unsafe { core::ptr::write_volatile(&raw mut SEQUENCE, sequence) };
    let (mut key, mut mac_key) = keys(sequence);
    aes::Aes128::new(&key).cfb_encrypt(&[0; 16], &mut plain[..len]);
    let mut message = [0u8; 700 + 12];
    message[..8].copy_from_slice(&sequence.to_be_bytes());
    message[8..12].copy_from_slice(&handle.to_be_bytes());
    message[12..12 + len].copy_from_slice(&plain[..len]);
    let integrity = sha256::hmac(&mac_key, &message[..12 + len]);
    keystore::zero(&mut key);
    keystore::zero(&mut mac_key);

    let mut response = [0u8; 800];
    let mut out = Writer { buf: &mut response, at: 0 };
    out.put(&sequence.to_be_bytes());
    out.u32(handle);
    out.u32(hierarchy);
    out.u16((2 + 32 + len) as u16);
    out.u16(32);
    out.put(&integrity);
    out.put(&plain[..len]);
    let n = out.at;
    a.response_params(&response[..n]);
    keystore::zero(&mut plain);
    if saved_session {
        session::flush(handle);
    }
    Ok(())
}

/// `TPM2_ContextLoad`.
pub fn load(params: &mut In, a: &mut Authorization) -> Result<(), u32> {
    let sequence = u64::from_be_bytes(params.take(8).ok_or(RC_COMMAND_SIZE)?.try_into().unwrap());
    let saved = params.u32().ok_or(RC_COMMAND_SIZE)?;
    let _hierarchy = params.u32().ok_or(RC_COMMAND_SIZE)?;
    let blob = params.sized().ok_or(RC_COMMAND_SIZE)?;
    if params.rest() != 0 {
        return Err(RC_COMMAND_SIZE);
    }
    if blob.len() < 34 || blob.len() > 34 + 700 || blob[..2] != 32u16.to_be_bytes() {
        return Err(RC_SIZE | RC_P | RC_1);
    }
    let (integrity, encrypted) = (&blob[2..34], &blob[34..]);
    let (mut key, mut mac_key) = keys(sequence);
    let mut message = [0u8; 700 + 12];
    message[..8].copy_from_slice(&sequence.to_be_bytes());
    message[8..12].copy_from_slice(&saved.to_be_bytes());
    message[12..12 + encrypted.len()].copy_from_slice(encrypted);
    let expected = sha256::hmac(&mac_key, &message[..12 + encrypted.len()]);
    keystore::zero(&mut mac_key);
    let mut diff = 0u8;
    for (x, y) in expected.iter().zip(integrity) {
        diff |= x ^ y;
    }
    if diff != 0 {
        keystore::zero(&mut key);
        return Err(RC_INTEGRITY | RC_P | RC_1);
    }
    let mut plain = [0u8; 700];
    plain[..encrypted.len()].copy_from_slice(encrypted);
    aes::Aes128::new(&key).cfb_decrypt(&[0; 16], &mut plain[..encrypted.len()]);
    keystore::zero(&mut key);
    let mut input = In { buf: &plain[..encrypted.len()], at: 0 };
    let kind = input.u8().ok_or(RC_INTEGRITY | RC_P | RC_1)?;
    let handle = match kind {
        OBJECT => {
            let wanted = saved.checked_sub(TRANSIENT_FIRST).map(|i| i as usize).filter(|i| *i < SLOTS);
            let index = match wanted.filter(|i| !object::table()[*i].used) {
                Some(i) => i,
                None => object::table().iter().position(|s| !s.used).ok_or(RC_OBJECT_MEMORY)?,
            };
            let slot = &mut object::table()[index];
            read_object(&mut input, slot).ok_or(RC_INTEGRITY | RC_P | RC_1)?;
            slot.used = true;
            TRANSIENT_FIRST + index as u32
        }
        SESSION => {
            let index = saved as usize & 0xffff;
            let family = saved & 0xff00_0000;
            let free = if index < SESSION_SLOTS && !session::table()[index].used { index } else { session::table().iter().position(|s| !s.used).ok_or(RC_SESSION_MEMORY)? };
            let s = &mut session::table()[free];
            read_session(&mut input, s).ok_or(RC_INTEGRITY | RC_P | RC_1)?;
            s.used = true;
            let base = if s.kind == 0 { 0x0200_0000 } else { 0x0300_0000 };
            let _ = family;
            base + free as u32
        }
        _ => return Err(RC_INTEGRITY | RC_P | RC_1),
    };
    keystore::zero(&mut plain);
    a.new_handle = Some(handle);
    let _ = RC_RANGE;
    Ok(())
}

/// `TPM2_FlushContext`.
pub fn flush(params: &mut In) -> Result<(), u32> {
    let handle = params.u32().ok_or(RC_COMMAND_SIZE)?;
    if params.rest() != 0 {
        return Err(RC_COMMAND_SIZE);
    }
    if object::flush(handle) || session::flush(handle) {
        Ok(())
    } else {
        Err(RC_HANDLE | RC_P | RC_1)
    }
}

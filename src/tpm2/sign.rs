//! Signatures: `Sign`, `Quote` and `VerifySignature` with ECDSA over P-256 and
//! SHA-256, and the tickets that tie what `Hash` hashed to what a restricted
//! key may then sign.
//!
//! A restricted key signs only what the TPM itself made, or a digest of data
//! that does not begin with `TPM_GENERATED` and that `Hash` ticketed, so a
//! signature of one is never taken for an attestation.

use super::object::{self, Command, ALG_ECC, ALG_ECDSA, ALG_RSASSA, RH_NULL};
use super::{
    ALG_NULL, ALG_SHA256, In, Out, RC_COMMAND_SIZE, RC_HANDLE, RC_HASH, RC_KEY, RC_P, RC_RANGE, RC_SCHEME, RC_SIZE, RC_TICKET,
    RC_SIGNATURE, RC_1, RC_2,
};
use crate::{keystore, p256, rsa, sha256, stc};

pub const CC_QUOTE: u32 = 0x158;
pub const CC_SIGN: u32 = 0x15d;
pub const CC_VERIFY_SIGNATURE: u32 = 0x177;

const GENERATED: [u8; 4] = [0xff, 0x54, 0x43, 0x47];
const ST_ATTEST_QUOTE: u16 = 0x8018;
const ST_VERIFIED: u16 = 0x8022;
pub const ST_HASHCHECK: u16 = 0x8024;

/// A ticket's digest: what the hierarchy's proof says of a tag, a digest and
/// whatever else the ticket is bound to.
pub fn ticket_digest(hierarchy: u32, tag: u16, digest: &[u8], bound: &[u8]) -> [u8; 32] {
    let mut key = object::proof(hierarchy);
    let mut message = [0u8; 2 + 32 + 34];
    message[..2].copy_from_slice(&tag.to_be_bytes());
    message[2..2 + digest.len()].copy_from_slice(digest);
    message[2 + digest.len()..2 + digest.len() + bound.len()].copy_from_slice(bound);
    let mac = sha256::hmac(&key, &message[..2 + digest.len() + bound.len()]);
    keystore::zero(&mut key);
    mac
}

/// `Hash`'s ticket for `data` hashed to `digest`: a null ticket for the null
/// hierarchy and for data that looks like something the TPM made.
pub fn hash_ticket(out: &mut Out, hierarchy: u32, data: &[u8], digest: &[u8; 32]) {
    out.u16(ST_HASHCHECK);
    if hierarchy == RH_NULL || data.starts_with(&GENERATED) {
        out.u32(RH_NULL);
        out.u16(0);
        return;
    }
    out.u32(hierarchy);
    out.u16(32);
    out.put(&ticket_digest(hierarchy, ST_HASHCHECK, digest, &[]));
}

fn ticket_valid(tag: u16, hierarchy: u32, digest: &[u8], ticket: &[u8]) -> bool {
    if tag != ST_HASHCHECK || hierarchy == RH_NULL || ticket.len() != 32 {
        return false;
    }
    let expected = ticket_digest(hierarchy, tag, digest, &[]);
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(ticket) {
        diff |= a ^ b;
    }
    diff == 0
}

/// A `TPMT_SIG_SCHEME` in a command, which has to agree with the key's own.
fn read_scheme(params: &mut In, key: &object::Public, parameter: u32) -> Result<(), u32> {
    let scheme = params.u16().ok_or(RC_COMMAND_SIZE)?;
    let hash = if scheme == ALG_NULL { 0 } else { params.u16().ok_or(RC_COMMAND_SIZE)? };
    match scheme {
        ALG_NULL if key.scheme == ALG_NULL => Err(RC_SCHEME | RC_P | parameter * RC_1),
        ALG_NULL => Ok(()),
        ALG_ECDSA if key.scheme != ALG_NULL && key.scheme != ALG_ECDSA => Err(RC_SCHEME | RC_P | parameter * RC_1),
        ALG_ECDSA if hash != ALG_SHA256 => Err(RC_HASH | RC_P | parameter * RC_1),
        ALG_ECDSA => Ok(()),
        _ => Err(RC_SCHEME | RC_P | parameter * RC_1),
    }
}

fn marshal_signature(out: &mut Out, r: &[u8; 32], s: &[u8; 32]) {
    out.u16(ALG_ECDSA);
    out.u16(ALG_SHA256);
    out.u16(32);
    out.put(r);
    out.u16(32);
    out.put(s);
}

fn signing_key(handle: u32) -> Result<(&'static mut object::Slot, object::Public), u32> {
    let slot = object::slot_of(handle).ok_or(RC_HANDLE | RC_1)?;
    let public = slot.public();
    if !public.is_signing() {
        return Err(RC_KEY | RC_1);
    }
    Ok((slot, public))
}

/// A key the TPM can sign with: one it made, not a public key it was given.
fn private_signing_key(handle: u32) -> Result<(&'static mut object::Slot, object::Public), u32> {
    let (slot, public) = signing_key(handle)?;
    if public.kind != ALG_ECC || (slot.private_len == 0 && !slot.is_primary) {
        return Err(RC_KEY | RC_1);
    }
    Ok((slot, public))
}

/// `TPM2_Sign`.
pub fn sign(c: &mut Command) -> Result<(), u32> {
    let (slot, public) = private_signing_key(c.handles[0])?;
    let digest = c.params.sized().ok_or(RC_COMMAND_SIZE)?;
    let digest: &[u8; 32] = digest.try_into().map_err(|_| RC_SIZE | RC_P | RC_1)?;
    read_scheme(&mut c.params, &public, 2)?;
    let tag = c.params.u16().ok_or(RC_COMMAND_SIZE)?;
    let hierarchy = c.params.u32().ok_or(RC_COMMAND_SIZE)?;
    let ticket = c.params.sized().ok_or(RC_COMMAND_SIZE)?;
    if c.params.rest() != 0 {
        return Err(RC_COMMAND_SIZE);
    }
    if public.is_restricted() && !ticket_valid(tag, hierarchy, digest, ticket) {
        return Err(RC_TICKET | RC_P | 3 * RC_1);
    }
    let (r, s) = object::ecdsa_sign(slot, digest)?;
    let mut parameters = Out { buf: &mut [0u8; 80], at: 0 };
    marshal_signature(&mut parameters, &r, &s);
    let n = parameters.at;
    let raw = parameters.buf;
    c.auth.response_params(&raw[..n]);
    Ok(())
}

/// `TPM2_Quote`: a signed statement of the PCRs' values, which the caller's
/// nonce makes fresh.
pub fn quote(c: &mut Command) -> Result<(), u32> {
    let (slot, public) = private_signing_key(c.handles[0])?;
    let nonce = c.params.sized().ok_or(RC_COMMAND_SIZE)?;
    if nonce.len() > 64 {
        return Err(RC_SIZE | RC_P | RC_1);
    }
    read_scheme(&mut c.params, &public, 2)?;
    let mask = super::read_selection(&mut c.params).map_err(|rc| rc | RC_P | 3 * RC_1)?;
    if c.params.rest() != 0 {
        return Err(RC_COMMAND_SIZE);
    }
    let mut pcrs = sha256::Sha256::new();
    for i in (0..keystore::PCRS).filter(|i| mask >> i & 1 != 0) {
        pcrs.update(&keystore::pcr(i).ok_or(RC_RANGE)?);
    }

    let mut raw = [0u8; 256];
    let mut attest = Out { buf: &mut raw, at: 0 };
    attest.put(&GENERATED);
    attest.u16(ST_ATTEST_QUOTE);
    attest.u16(34);
    attest.put(&slot.qualified);
    attest.u16(nonce.len() as u16);
    attest.put(nonce);
    let milliseconds = stc::now() / 1000;
    attest.u64(milliseconds);
    attest.u32(0);
    attest.u32(0);
    attest.u8(1);
    attest.u64(0);
    attest.u32(1);
    attest.u16(ALG_SHA256);
    attest.u8(3);
    attest.put(&mask.to_le_bytes()[..3]);
    attest.u16(32);
    attest.put(&pcrs.finish());
    let len = attest.at;

    let (r, s) = object::ecdsa_sign(slot, &sha256::digest(&raw[..len]))?;
    let mut parameters = Out { buf: &mut [0u8; 400], at: 0 };
    parameters.u16(len as u16);
    parameters.put(&raw[..len]);
    marshal_signature(&mut parameters, &r, &s);
    let n = parameters.at;
    let out = parameters.buf;
    c.auth.response_params(&out[..n]);
    Ok(())
}

/// `TPM2_VerifySignature`, and the ticket that says this TPM did.
pub fn verify(c: &mut Command) -> Result<(), u32> {
    let (slot, public) = signing_key(c.handles[0])?;
    let digest = c.params.sized().ok_or(RC_COMMAND_SIZE)?;
    let digest: &[u8; 32] = digest.try_into().map_err(|_| RC_SIZE | RC_P | RC_1)?;
    let algorithm = c.params.u16().ok_or(RC_COMMAND_SIZE)?;
    let wanted = if public.kind == ALG_ECC { ALG_ECDSA } else { ALG_RSASSA };
    if algorithm != wanted {
        return Err(RC_SCHEME | RC_P | RC_2);
    }
    if c.params.u16().ok_or(RC_COMMAND_SIZE)? != ALG_SHA256 {
        return Err(RC_HASH | RC_P | RC_2);
    }
    let valid = if public.kind == ALG_ECC {
        let r = c.params.sized().ok_or(RC_COMMAND_SIZE)?;
        let s = c.params.sized().ok_or(RC_COMMAND_SIZE)?;
        let (Some(r), Some(s)) = (pad(r), pad(s)) else { return Err(RC_SIGNATURE | RC_P | RC_2) };
        let q = p256::Point { x: public.unique[..32].try_into().unwrap(), y: public.unique[32..64].try_into().unwrap() };
        p256::verify(&q, digest, &r, &s)
    } else {
        let signature = c.params.sized().ok_or(RC_COMMAND_SIZE)?;
        rsa::verify_sha256(&public.unique[..public.unique_len], public.exponent, digest, signature)
    };
    if c.params.rest() != 0 {
        return Err(RC_COMMAND_SIZE);
    }
    if !valid {
        return Err(RC_SIGNATURE | RC_P | RC_2);
    }
    let hierarchy = slot.origin.hierarchy;
    let mut parameters = Out { buf: &mut [0u8; 48], at: 0 };
    parameters.u16(ST_VERIFIED);
    if hierarchy == RH_NULL {
        parameters.u32(RH_NULL);
        parameters.u16(0);
    } else {
        parameters.u32(hierarchy);
        parameters.u16(32);
        parameters.put(&ticket_digest(hierarchy, ST_VERIFIED, digest, &slot.name));
    }
    let n = parameters.at;
    let raw = parameters.buf;
    c.auth.response_params(&raw[..n]);
    Ok(())
}

/// A big-endian number of at most 32 bytes, as 32.
fn pad(bytes: &[u8]) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    out[32usize.checked_sub(bytes.len())?..].copy_from_slice(bytes);
    Some(out)
}

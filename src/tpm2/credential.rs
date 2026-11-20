//! Credential protection: `MakeCredential` wraps a secret so that only the TPM
//! that holds an endorsement key, and an object with the name the credential
//! was made for, can open it with `ActivateCredential`.
//!
//! An ephemeral ECDH exchange with the key's public point gives the seed
//! (`KDFe` with the label `IDENTITY`), from which `KDFa` derives an AES-128-CFB
//! key (`STORAGE`, with the object's name) and an HMAC key (`INTEGRITY`). The
//! credential blob is the HMAC over the encrypted credential and the name,
//! then the encrypted credential; the secret is the ephemeral point.

use super::object::{self, Command, CURVE_P256};
use super::{In, Out, RC_COMMAND_SIZE, RC_ECC_POINT, RC_HANDLE, RC_INTEGRITY, RC_P, RC_RANGE, RC_SIZE, RC_TYPE, RC_VALUE, RC_1, RC_2};
use crate::{aes, kdf, keystore, p256, rng, sha256};

pub const CC_ACTIVATE_CREDENTIAL: u32 = 0x147;
pub const CC_MAKE_CREDENTIAL: u32 = 0x168;

const CREDENTIAL_MAX: usize = 32;
const NAME_MAX: usize = 34;

struct Keys {
    cipher: [u8; 16],
    integrity: [u8; 32],
}

impl Keys {
    fn derive(scalar: &[u8; 32], peer: &p256::Point, ephemeral_x: &[u8; 32], key_x: &[u8], name: &[u8]) -> Option<Keys> {
        let mut z = p256::ecdh(scalar, peer)?;
        let mut seed = [0u8; 32];
        kdf::kdfe(&z, b"IDENTITY", ephemeral_x, key_x, 256, &mut seed);
        keystore::zero(&mut z);
        let mut keys = Keys { cipher: [0; 16], integrity: [0; 32] };
        kdf::kdfa(&seed, b"STORAGE", name, &[], 128, &mut keys.cipher);
        kdf::kdfa(&seed, b"INTEGRITY", &[], &[], 256, &mut keys.integrity);
        keystore::zero(&mut seed);
        Some(keys)
    }

    fn mac(&self, encrypted: &[u8], name: &[u8]) -> [u8; 32] {
        let mut message = [0u8; 2 + CREDENTIAL_MAX + NAME_MAX];
        message[..encrypted.len()].copy_from_slice(encrypted);
        message[encrypted.len()..encrypted.len() + name.len()].copy_from_slice(name);
        sha256::hmac(&self.integrity, &message[..encrypted.len() + name.len()])
    }

    fn wipe(&mut self) {
        keystore::zero(&mut self.cipher);
        keystore::zero(&mut self.integrity);
    }
}

fn read_point(secret: &[u8], parameter: u32) -> Result<p256::Point, u32> {
    let mut input = In { buf: secret, at: 0 };
    let x = input.sized().ok_or(RC_VALUE | RC_P | parameter * RC_1)?;
    let y = input.sized().ok_or(RC_VALUE | RC_P | parameter * RC_1)?;
    if x.len() != 32 || y.len() != 32 || input.rest() != 0 {
        return Err(RC_VALUE | RC_P | parameter * RC_1);
    }
    Ok(p256::Point { x: x.try_into().unwrap(), y: y.try_into().unwrap() })
}

fn public_point(unique: &[u8]) -> p256::Point {
    p256::Point { x: unique[..32].try_into().unwrap(), y: unique[32..64].try_into().unwrap() }
}

/// `TPM2_ActivateCredential`: the credential made for the object `handles[0]`
/// and the key `handles[1]`, opened.
pub fn activate(c: &mut Command) -> Result<(), u32> {
    let object = object::slot_of(c.handles[0]).ok_or(RC_HANDLE | RC_1)?;
    let key = object::slot_of(c.handles[1]).ok_or(RC_HANDLE | RC_2)?;
    let public = key.public();
    if !public.is_decrypt() || public.curve != CURVE_P256 {
        return Err(RC_TYPE | RC_2);
    }
    let blob = c.params.sized().ok_or(RC_COMMAND_SIZE)?;
    let secret = c.params.sized().ok_or(RC_COMMAND_SIZE)?;
    if c.params.rest() != 0 {
        return Err(RC_COMMAND_SIZE);
    }
    let mut parts = In { buf: blob, at: 0 };
    let integrity = parts.sized().ok_or(RC_INTEGRITY | RC_P | RC_1)?;
    let encrypted = &blob[parts.at..];
    if integrity.len() != 32 || encrypted.len() < 2 || encrypted.len() > 2 + CREDENTIAL_MAX {
        return Err(RC_INTEGRITY | RC_P | RC_1);
    }
    let ephemeral = read_point(secret, 2)?;
    let mut d = object::private_scalar(key)?;
    let keys = Keys::derive(&d, &ephemeral, &ephemeral.x, &public.unique[..32], &object.name);
    keystore::zero(&mut d);
    let mut keys = keys.ok_or(RC_ECC_POINT | RC_P | RC_2)?;

    let expected = keys.mac(encrypted, &object.name);
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(integrity) {
        diff |= a ^ b;
    }
    if diff != 0 {
        keys.wipe();
        return Err(RC_INTEGRITY | RC_P | RC_1);
    }
    let mut plain = [0u8; 2 + CREDENTIAL_MAX];
    let plain = &mut plain[..encrypted.len()];
    plain.copy_from_slice(encrypted);
    aes::Aes128::new(&keys.cipher).cfb_decrypt(&[0; 16], plain);
    keys.wipe();
    if u16::from_be_bytes([plain[0], plain[1]]) as usize != plain.len() - 2 {
        keystore::zero(plain);
        return Err(RC_VALUE | RC_P | RC_1);
    }
    c.auth.response_params(plain);
    keystore::zero(plain);
    Ok(())
}

/// `TPM2_MakeCredential`: wrap `credential` for the object called `name`, to
/// the public key `handles[0]`.
pub fn make(c: &mut Command) -> Result<(), u32> {
    let key = object::slot_of(c.handles[0]).ok_or(RC_HANDLE | RC_1)?;
    let public = key.public();
    if !public.is_decrypt() || public.curve != CURVE_P256 {
        return Err(RC_TYPE | RC_1);
    }
    let credential = c.params.sized().ok_or(RC_COMMAND_SIZE)?;
    let name = c.params.sized().ok_or(RC_COMMAND_SIZE)?;
    if c.params.rest() != 0 {
        return Err(RC_COMMAND_SIZE);
    }
    if credential.len() > CREDENTIAL_MAX {
        return Err(RC_SIZE | RC_P | RC_1);
    }
    if name.is_empty() || name.len() > NAME_MAX {
        return Err(RC_SIZE | RC_P | 2 * RC_1);
    }
    let mut e = [0u8; 32];
    let ephemeral = loop {
        if !rng::fill(&mut e) {
            return Err(RC_RANGE);
        }
        if let Some(point) = p256::public_key(&e) {
            break point;
        }
    };
    let keys = Keys::derive(&e, &public_point(&public.unique), &ephemeral.x, &public.unique[..32], name);
    keystore::zero(&mut e);
    let mut keys = keys.ok_or(RC_ECC_POINT)?;

    let mut encrypted = [0u8; 2 + CREDENTIAL_MAX];
    let encrypted = &mut encrypted[..2 + credential.len()];
    encrypted[..2].copy_from_slice(&(credential.len() as u16).to_be_bytes());
    encrypted[2..].copy_from_slice(credential);
    aes::Aes128::new(&keys.cipher).cfb_encrypt(&[0; 16], encrypted);
    let integrity = keys.mac(encrypted, name);
    keys.wipe();

    let mut raw = [0u8; 2 + 2 + 32 + 2 + CREDENTIAL_MAX + 2 + 2 + 32 + 2 + 32];
    let mut out = Out { buf: &mut raw, at: 0 };
    out.u16((2 + 32 + encrypted.len()) as u16);
    out.u16(32);
    out.put(&integrity);
    out.put(encrypted);
    out.u16(2 + 32 + 2 + 32);
    out.u16(32);
    out.put(&ephemeral.x);
    out.u16(32);
    out.put(&ephemeral.y);
    let n = out.at;
    c.auth.response_params(&raw[..n]);
    Ok(())
}

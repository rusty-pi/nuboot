//! The TPM's objects: the primary keys of its hierarchies, the data and keys
//! created under them, and the commands that create, load and read them.
//!
//! A hierarchy's seed is not kept: it is derived from the board's private key
//! ([`keystore::tpm_secret`]) each time a command needs it, and what the
//! command touched is overwritten before it returns. A primary key is the same
//! function of its hierarchy and its template every time it is created, which
//! is all the TPM keeps of it: the hierarchy, and the hash of the template.
//! The objects under a primary are kept as the blob [`protect`] makes, so a
//! sealed secret is plaintext only inside the command that unseals it.
//!
//! Only primary storage keys (ECC P-256, AES-128-CFB) can be parents.

use super::session::Authorization;
use super::{
    ALG_HMAC, ALG_KEYEDHASH, ALG_NULL, ALG_SHA256, In, Out, RC_ATTRIBUTES, RC_CURVE, RC_HANDLE, RC_HIERARCHY, RC_INTEGRITY,
    RC_KDF, RC_KEY, RC_OBJECT_MEMORY, RC_P, RC_RANGE, RC_SCHEME, RC_SIZE, RC_SYMMETRIC, RC_TYPE, RC_VALUE,
    RC_COMMAND_SIZE, RC_1,
};
use crate::{aes, kdf, keystore, p256, rng, sha256};

pub const ALG_ECC: u16 = 0x0023;
pub const ALG_ECDSA: u16 = 0x0018;
pub const ALG_ECDH: u16 = 0x0019;
pub const ALG_AES: u16 = 0x0006;
pub const ALG_CFB: u16 = 0x0043;
pub const ALG_SYMCIPHER: u16 = 0x0025;
pub const CURVE_P256: u16 = 0x0003;

pub const RH_OWNER: u32 = 0x4000_0001;
pub const RH_NULL: u32 = 0x4000_0007;
pub const RH_PASSWORD: u32 = 0x4000_0009;
pub const RH_ENDORSEMENT: u32 = 0x4000_000b;
pub const RH_PLATFORM: u32 = 0x4000_000c;

pub const TRANSIENT_FIRST: u32 = 0x8000_0000;
pub const SLOTS: usize = 4;

const FIXED_TPM: u32 = 1 << 1;
const FIXED_PARENT: u32 = 1 << 4;
const SENSITIVE_DATA_ORIGIN: u32 = 1 << 5;
pub const USER_WITH_AUTH: u32 = 1 << 6;
pub const RESTRICTED: u32 = 1 << 16;
const DECRYPT: u32 = 1 << 17;
const SIGN_ENCRYPT: u32 = 1 << 18;
/// What a template may set: the others are reserved.
const ATTRIBUTES_ALLOWED: u32 = FIXED_TPM
    | (1 << 2)
    | FIXED_PARENT
    | SENSITIVE_DATA_ORIGIN
    | USER_WITH_AUTH
    | (1 << 7)
    | (1 << 10)
    | (1 << 11)
    | RESTRICTED
    | DECRYPT
    | SIGN_ENCRYPT;

pub const CC_CREATE_PRIMARY: u32 = 0x131;
pub const CC_CREATE: u32 = 0x153;
pub const CC_LOAD: u32 = 0x157;
pub const CC_UNSEAL: u32 = 0x15e;
pub const CC_READ_PUBLIC: u32 = 0x173;
pub const CC_FLUSH_CONTEXT: u32 = 0x165;
pub const CC_CONTEXT_SAVE: u32 = 0x162;
pub const CC_CONTEXT_LOAD: u32 = 0x161;
pub const CC_TEST_PARMS: u32 = 0x18a;

const MAX_PUBLIC: usize = 200;
const MAX_PRIVATE: usize = 260;

/// The parts of a `TPMT_PUBLIC` the TPM acts on.
#[derive(Clone)]
pub struct Public {
    pub kind: u16,
    pub name_alg: u16,
    pub attributes: u32,
    pub policy: [u8; 32],
    pub policy_len: usize,
    pub sym_alg: u16,
    pub sym_bits: u16,
    pub sym_mode: u16,
    pub scheme: u16,
    pub scheme_hash: u16,
    pub curve: u16,
    pub unique: [u8; 64],
    pub unique_len: usize,
}

impl Public {
    /// Read a `TPMT_PUBLIC`, the whole of `bytes`.
    pub fn parse(bytes: &[u8]) -> Result<Public, u32> {
        let mut input = In { buf: bytes, at: 0 };
        let mut p = Public {
            kind: input.u16().ok_or(RC_COMMAND_SIZE)?,
            name_alg: input.u16().ok_or(RC_COMMAND_SIZE)?,
            attributes: 0,
            policy: [0; 32],
            policy_len: 0,
            sym_alg: ALG_NULL,
            sym_bits: 0,
            sym_mode: 0,
            scheme: ALG_NULL,
            scheme_hash: 0,
            curve: 0,
            unique: [0; 64],
            unique_len: 0,
        };
        p.attributes = u32::from_be_bytes(input.take(4).ok_or(RC_COMMAND_SIZE)?.try_into().unwrap());
        let policy = input.sized().ok_or(RC_COMMAND_SIZE)?;
        if policy.len() > 32 {
            return Err(RC_SIZE);
        }
        p.policy[..policy.len()].copy_from_slice(policy);
        p.policy_len = policy.len();
        match p.kind {
            ALG_KEYEDHASH => {
                p.scheme = input.u16().ok_or(RC_COMMAND_SIZE)?;
                if p.scheme == ALG_HMAC {
                    p.scheme_hash = input.u16().ok_or(RC_COMMAND_SIZE)?;
                } else if p.scheme != ALG_NULL {
                    return Err(RC_SCHEME);
                }
                let unique = input.sized().ok_or(RC_COMMAND_SIZE)?;
                if unique.len() > 32 {
                    return Err(RC_SIZE);
                }
                p.unique[..unique.len()].copy_from_slice(unique);
                p.unique_len = unique.len();
            }
            ALG_ECC => {
                p.sym_alg = input.u16().ok_or(RC_COMMAND_SIZE)?;
                if p.sym_alg != ALG_NULL {
                    p.sym_bits = input.u16().ok_or(RC_COMMAND_SIZE)?;
                    p.sym_mode = input.u16().ok_or(RC_COMMAND_SIZE)?;
                }
                p.scheme = input.u16().ok_or(RC_COMMAND_SIZE)?;
                if p.scheme != ALG_NULL {
                    p.scheme_hash = input.u16().ok_or(RC_COMMAND_SIZE)?;
                }
                p.curve = input.u16().ok_or(RC_COMMAND_SIZE)?;
                let kdf = input.u16().ok_or(RC_COMMAND_SIZE)?;
                if kdf != ALG_NULL {
                    input.u16().ok_or(RC_COMMAND_SIZE)?;
                }
                let x = input.sized().ok_or(RC_COMMAND_SIZE)?;
                let y = input.sized().ok_or(RC_COMMAND_SIZE)?;
                if x.len() != y.len() || (x.len() != 0 && x.len() != 32) {
                    return Err(RC_SIZE);
                }
                p.unique[..x.len()].copy_from_slice(x);
                p.unique[32..32 + y.len()].copy_from_slice(y);
                p.unique_len = x.len() * 2;
            }
            _ => return Err(RC_TYPE),
        }
        if input.rest() != 0 {
            return Err(RC_SIZE);
        }
        Ok(p)
    }

    /// Check what the TPM supports of a template: SHA-256 names, and for an
    /// ECC key P-256 with AES-128-CFB for a storage key or none for another.
    pub fn check(&self) -> Result<(), u32> {
        if self.name_alg != ALG_SHA256 {
            return Err(super::RC_HASH);
        }
        if self.attributes & !ATTRIBUTES_ALLOWED != 0 {
            return Err(RC_ATTRIBUTES);
        }
        match self.kind {
            ALG_KEYEDHASH => {
                if self.scheme != ALG_NULL {
                    return Err(RC_SCHEME);
                }
                if self.attributes & (RESTRICTED | DECRYPT | SIGN_ENCRYPT) != 0 {
                    return Err(RC_ATTRIBUTES);
                }
            }
            ALG_ECC => {
                if self.curve != CURVE_P256 {
                    return Err(RC_CURVE);
                }
                if self.is_storage() {
                    if self.sym_alg != ALG_AES || self.sym_bits != 128 || self.sym_mode != ALG_CFB {
                        return Err(RC_SYMMETRIC);
                    }
                    if self.scheme != ALG_NULL {
                        return Err(RC_SCHEME);
                    }
                } else {
                    if self.sym_alg != ALG_NULL {
                        return Err(RC_SYMMETRIC);
                    }
                    match self.scheme {
                        ALG_NULL => {}
                        ALG_ECDSA | ALG_ECDH if self.scheme_hash == ALG_SHA256 => {}
                        ALG_ECDSA | ALG_ECDH => return Err(super::RC_HASH),
                        _ => return Err(RC_SCHEME),
                    }
                    if self.attributes & RESTRICTED != 0 && self.scheme != ALG_ECDSA {
                        return Err(RC_SCHEME);
                    }
                }
            }
            _ => return Err(RC_TYPE),
        }
        Ok(())
    }

    pub fn is_storage(&self) -> bool {
        self.kind == ALG_ECC && self.attributes & (RESTRICTED | DECRYPT) == RESTRICTED | DECRYPT
    }

    /// A key that signs: ECDSA, restricted to what the TPM itself attests or not.
    pub fn is_signing(&self) -> bool {
        self.kind == ALG_ECC && self.attributes & SIGN_ENCRYPT != 0 && !self.is_storage() && self.scheme != ALG_ECDH
    }

    pub fn is_restricted(&self) -> bool {
        self.attributes & RESTRICTED != 0
    }

    /// A sealed data object: a keyed hash that signs and decrypts nothing.
    pub fn is_sealed(&self) -> bool {
        self.kind == ALG_KEYEDHASH && self.scheme == ALG_NULL && self.attributes & (SIGN_ENCRYPT | DECRYPT) == 0
    }

    pub fn marshal(&self, out: &mut Out) {
        out.u16(self.kind);
        out.u16(self.name_alg);
        out.u32(self.attributes);
        out.u16(self.policy_len as u16);
        out.put(&self.policy[..self.policy_len]);
        match self.kind {
            ALG_KEYEDHASH => {
                out.u16(self.scheme);
                if self.scheme == ALG_HMAC {
                    out.u16(self.scheme_hash);
                }
                out.u16(self.unique_len as u16);
                out.put(&self.unique[..self.unique_len]);
            }
            _ => {
                out.u16(self.sym_alg);
                if self.sym_alg != ALG_NULL {
                    out.u16(self.sym_bits);
                    out.u16(self.sym_mode);
                }
                out.u16(self.scheme);
                if self.scheme != ALG_NULL {
                    out.u16(self.scheme_hash);
                }
                out.u16(self.curve);
                out.u16(ALG_NULL);
                let half = self.unique_len / 2;
                out.u16(half as u16);
                out.put(&self.unique[..half]);
                out.u16(half as u16);
                out.put(&self.unique[32..32 + half]);
            }
        }
    }

    /// The marshaled form, and its length.
    pub fn bytes(&self) -> ([u8; MAX_PUBLIC], usize) {
        let mut raw = [0u8; MAX_PUBLIC];
        let mut out = Out { buf: &mut raw, at: 0 };
        self.marshal(&mut out);
        let len = out.at;
        (raw, len)
    }
}

/// The name of an object: its name algorithm, then the hash of its public
/// area.
pub fn name_of(public: &[u8]) -> [u8; 34] {
    let mut name = [0u8; 34];
    name[..2].copy_from_slice(&ALG_SHA256.to_be_bytes());
    name[2..].copy_from_slice(&sha256::digest(public));
    name
}

/// The name that qualifies `name` under a parent whose qualified name is
/// `parent`.
pub fn qualify(parent: &[u8], name: &[u8; 34]) -> [u8; 34] {
    let mut hash = sha256::Sha256::new();
    hash.update(parent);
    hash.update(name);
    let mut qualified = [0u8; 34];
    qualified[..2].copy_from_slice(&ALG_SHA256.to_be_bytes());
    qualified[2..].copy_from_slice(&hash.finish());
    qualified
}

/// What a primary is made from, which is also all there is to keep of it.
#[derive(Clone, Copy)]
pub struct Origin {
    pub hierarchy: u32,
    pub template: [u8; 32],
}

fn hierarchy_label(hierarchy: u32) -> Option<(&'static [u8], bool)> {
    Some(match hierarchy {
        RH_OWNER => (b"owner seed", true),
        RH_ENDORSEMENT => (b"endorsement seed", true),
        RH_PLATFORM => (b"platform seed", true),
        RH_NULL => (b"null seed", false),
        _ => return None,
    })
}

/// What a hierarchy proves its tickets with.
pub fn proof(hierarchy: u32) -> [u8; 32] {
    let (label, stable) = hierarchy_label(hierarchy).unwrap_or((b"null seed", false));
    let mut name = [0u8; 40];
    name[..label.len()].copy_from_slice(label);
    name[label.len()..label.len() + 6].copy_from_slice(b" proof");
    keystore::tpm_secret(&name[..label.len() + 6], stable)
}

impl Origin {
    /// The secret called `label` of the primary key: its own seed first.
    fn secret(&self, label: &[u8], out: &mut [u8]) {
        let (hierarchy, stable) = hierarchy_label(self.hierarchy).unwrap_or((b"null seed", false));
        let mut seed = keystore::tpm_secret(hierarchy, stable);
        let mut primary = [0u8; 32];
        kdf::kdfa(&seed, b"PRIMARY", &self.template, &[], 256, &mut primary);
        kdf::kdfa(&primary, label, &[], &[], out.len() as u32 * 8, out);
        crate::keystore::zero(&mut seed);
        crate::keystore::zero(&mut primary);
    }

    /// The seed that protects what is created under the key.
    fn protection_seed(&self) -> [u8; 32] {
        let mut seed = [0u8; 32];
        self.secret(b"PROTECT", &mut seed);
        seed
    }

    /// The key's private scalar.
    pub fn private(&self) -> [u8; 32] {
        let mut d = [0u8; 32];
        self.secret(b"ECC", &mut d);
        let mut d = p256::reduce_order(&d);
        if !p256::valid_scalar(&d) {
            d[31] = 1;
        }
        d
    }
}

/// An object in the TPM's memory.
#[derive(Clone)]
pub struct Slot {
    pub used: bool,
    pub public: [u8; MAX_PUBLIC],
    pub public_len: usize,
    pub name: [u8; 34],
    pub origin: Origin,
    pub is_primary: bool,
    /// The name of the object qualified by its parents': what says which
    /// hierarchy and chain of keys it came from.
    pub qualified: [u8; 34],
    /// A primary's authorization value (a child's is in its blob).
    pub auth: [u8; 32],
    pub auth_len: usize,
    pub private: [u8; MAX_PRIVATE],
    pub private_len: usize,
}

const EMPTY: Slot = Slot {
    used: false,
    public: [0; MAX_PUBLIC],
    public_len: 0,
    name: [0; 34],
    origin: Origin { hierarchy: 0, template: [0; 32] },
    is_primary: false,
    qualified: [0; 34],
    auth: [0; 32],
    auth_len: 0,
    private: [0; MAX_PRIVATE],
    private_len: 0,
};

static mut SLOTS_TABLE: [Slot; SLOTS] = [EMPTY; SLOTS];

pub fn table() -> &'static mut [Slot; SLOTS] {
    unsafe { &mut *(&raw mut SLOTS_TABLE) }
}

pub fn slot_of(handle: u32) -> Option<&'static mut Slot> {
    let index = handle.checked_sub(TRANSIENT_FIRST)? as usize;
    table().get_mut(index).filter(|s| s.used)
}

fn free_slot() -> Result<usize, u32> {
    table().iter().position(|s| !s.used).ok_or(RC_OBJECT_MEMORY)
}

pub fn flush(handle: u32) -> bool {
    match slot_of(handle) {
        Some(slot) => {
            *slot = EMPTY;
            true
        }
        None => false,
    }
}

impl Slot {
    pub fn public(&self) -> Public {
        Public::parse(&self.public[..self.public_len]).unwrap_or_else(|_| unreachable_public())
    }
}

fn unreachable_public() -> Public {
    Public {
        kind: 0,
        name_alg: 0,
        attributes: 0,
        policy: [0; 32],
        policy_len: 0,
        sym_alg: ALG_NULL,
        sym_bits: 0,
        sym_mode: 0,
        scheme: ALG_NULL,
        scheme_hash: 0,
        curve: 0,
        unique: [0; 64],
        unique_len: 0,
    }
}

/// `TPMT_SENSITIVE`'s parts the TPM uses.
struct Sensitive {
    kind: u16,
    auth: [u8; 32],
    auth_len: usize,
    seed: [u8; 32],
    value: [u8; 128],
    value_len: usize,
}

impl Sensitive {
    fn marshal(&self, out: &mut Out) {
        out.u16(self.kind);
        out.u16(self.auth_len as u16);
        out.put(&self.auth[..self.auth_len]);
        out.u16(32);
        out.put(&self.seed);
        out.u16(self.value_len as u16);
        out.put(&self.value[..self.value_len]);
    }

    fn parse(bytes: &[u8]) -> Option<Sensitive> {
        let mut input = In { buf: bytes, at: 0 };
        let kind = input.u16()?;
        let auth = input.sized()?;
        let seed = input.sized()?;
        let value = input.sized()?;
        if auth.len() > 32 || seed.len() != 32 || value.len() > 128 || input.rest() != 0 {
            return None;
        }
        let mut s = Sensitive { kind, auth: [0; 32], auth_len: auth.len(), seed: [0; 32], value: [0; 128], value_len: value.len() };
        s.auth[..auth.len()].copy_from_slice(auth);
        s.seed.copy_from_slice(seed);
        s.value[..value.len()].copy_from_slice(value);
        Some(s)
    }

    fn wipe(&mut self) {
        keystore::zero(&mut self.auth);
        keystore::zero(&mut self.seed);
        keystore::zero(&mut self.value);
    }
}

/// Wrap a sensitive area for an object called `name` under a parent: AES-128-CFB
/// under a key the parent's seed and the name make, and an HMAC over that and
/// the name, which `TPM2B_PRIVATE` carries first.
fn protect(sensitive: &Sensitive, name: &[u8; 34], parent: &Origin, out: &mut [u8; MAX_PRIVATE]) -> usize {
    let mut seed = parent.protection_seed();
    let mut key = [0u8; 16];
    kdf::kdfa(&seed, b"STORAGE", name, &[], 128, &mut key);
    let mut hmac_key = [0u8; 32];
    kdf::kdfa(&seed, b"INTEGRITY", &[], &[], 256, &mut hmac_key);
    keystore::zero(&mut seed);

    let mut raw = [0u8; MAX_PRIVATE];
    let mut body = Out { buf: &mut raw[2..], at: 0 };
    sensitive.marshal(&mut body);
    let inner = body.at;
    raw[..2].copy_from_slice(&(inner as u16).to_be_bytes());
    let encrypted = &mut raw[..2 + inner];
    aes::Aes128::new(&key).cfb_encrypt(&[0; 16], encrypted);

    let mut message = [0u8; MAX_PRIVATE + 34];
    message[..encrypted.len()].copy_from_slice(encrypted);
    message[encrypted.len()..encrypted.len() + 34].copy_from_slice(name);
    let integrity = sha256::hmac(&hmac_key, &message[..encrypted.len() + 34]);
    keystore::zero(&mut key);
    keystore::zero(&mut hmac_key);

    out[..2].copy_from_slice(&32u16.to_be_bytes());
    out[2..34].copy_from_slice(&integrity);
    out[34..34 + encrypted.len()].copy_from_slice(encrypted);
    34 + encrypted.len()
}

/// Check and open what [`protect`] made.
fn unprotect(blob: &[u8], name: &[u8; 34], parent: &Origin) -> Result<Sensitive, u32> {
    if blob.len() < 36 || blob[..2] != 32u16.to_be_bytes() || blob.len() > MAX_PRIVATE {
        return Err(RC_INTEGRITY);
    }
    let (integrity, encrypted) = (&blob[2..34], &blob[34..]);
    let mut seed = parent.protection_seed();
    let mut key = [0u8; 16];
    kdf::kdfa(&seed, b"STORAGE", name, &[], 128, &mut key);
    let mut hmac_key = [0u8; 32];
    kdf::kdfa(&seed, b"INTEGRITY", &[], &[], 256, &mut hmac_key);
    keystore::zero(&mut seed);

    let mut message = [0u8; MAX_PRIVATE + 34];
    message[..encrypted.len()].copy_from_slice(encrypted);
    message[encrypted.len()..encrypted.len() + 34].copy_from_slice(name);
    let expected = sha256::hmac(&hmac_key, &message[..encrypted.len() + 34]);
    keystore::zero(&mut hmac_key);
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(integrity) {
        diff |= a ^ b;
    }
    if diff != 0 {
        keystore::zero(&mut key);
        return Err(RC_INTEGRITY);
    }
    let mut plain = [0u8; MAX_PRIVATE];
    plain[..encrypted.len()].copy_from_slice(encrypted);
    aes::Aes128::new(&key).cfb_decrypt(&[0; 16], &mut plain[..encrypted.len()]);
    keystore::zero(&mut key);
    let mut input = In { buf: &plain[..encrypted.len()], at: 0 };
    let sensitive = input.sized().and_then(Sensitive::parse);
    keystore::zero(&mut plain);
    sensitive.ok_or(RC_INTEGRITY)
}

/// A `TPM2B_SENSITIVE_CREATE`: the new object's authorization value and, for
/// data, the data.
struct SensitiveCreate<'a> {
    auth: &'a [u8],
    data: &'a [u8],
}

fn read_sensitive_create<'a>(input: &mut In<'a>) -> Result<SensitiveCreate<'a>, u32> {
    let body = input.sized().ok_or(RC_COMMAND_SIZE)?;
    let mut inner = In { buf: body, at: 0 };
    let auth = inner.sized().ok_or(RC_COMMAND_SIZE)?;
    let data = inner.sized().ok_or(RC_COMMAND_SIZE)?;
    if inner.rest() != 0 {
        return Err(RC_SIZE | RC_P | RC_1);
    }
    if auth.len() > 32 || data.len() > 128 {
        return Err(RC_SIZE | RC_P | RC_1);
    }
    Ok(SensitiveCreate { auth, data })
}

/// Read a `TPM2B_PUBLIC`.
fn read_public(input: &mut In, parameter: u32) -> Result<Public, u32> {
    let body = input.sized().ok_or(RC_COMMAND_SIZE)?;
    let public = Public::parse(body).map_err(|rc| rc | RC_P | parameter * RC_1)?;
    public.check().map_err(|rc| rc | RC_P | parameter * RC_1)?;
    Ok(public)
}

/// A `TPML_PCR_SELECTION` as it is on the wire, kept to put in a response.
struct Selection<'a> {
    raw: &'a [u8],
}

fn read_selection_raw<'a>(input: &mut In<'a>) -> Result<Selection<'a>, u32> {
    let start = input.at;
    let count = input.u32().ok_or(RC_COMMAND_SIZE)?;
    for _ in 0..count {
        input.u16().ok_or(RC_COMMAND_SIZE)?;
        let size = input.u8().ok_or(RC_COMMAND_SIZE)? as usize;
        input.take(size).ok_or(RC_COMMAND_SIZE)?;
    }
    Ok(Selection { raw: &input.buf[start..input.at] })
}

/// `TPM2B_CREATION_DATA` and what comes with it, as `Create` and
/// `CreatePrimary` answer: the data, its hash and the ticket.
fn creation(out: &mut Out, selection: &Selection, outside: &[u8], parent_name: &[u8], hierarchy: u32, name: &[u8; 34]) {
    let mut raw = [0u8; 256];
    let mut data = Out { buf: &mut raw, at: 0 };
    data.put(selection.raw);
    data.u16(32);
    data.put(&sha256::digest(&[]));
    data.u8(0);
    data.u16(ALG_SHA256);
    data.u16(parent_name.len() as u16);
    data.put(parent_name);
    data.u16(parent_name.len() as u16);
    data.put(parent_name);
    data.u16(outside.len() as u16);
    data.put(outside);
    let len = data.at;
    out.u16(len as u16);
    out.put(&raw[..len]);
    let hash = sha256::digest(&raw[..len]);
    out.u16(32);
    out.put(&hash);
    let mut message = [0u8; 2 + 34 + 32];
    message[..2].copy_from_slice(&0x8021u16.to_be_bytes());
    message[2..36].copy_from_slice(name);
    message[36..].copy_from_slice(&hash);
    let mut key = proof(hierarchy);
    let ticket = sha256::hmac(&key, &message);
    keystore::zero(&mut key);
    out.u16(0x8021);
    out.u32(hierarchy);
    out.u16(32);
    out.put(&ticket);
}

fn marshal_tpm2b_public(out: &mut Out, public: &Public) {
    let (raw, len) = public.bytes();
    out.u16(len as u16);
    out.put(&raw[..len]);
}

/// The handles and authorizations of one command and the room for what the
/// response carries: set by [`super::run_object`].
pub struct Command<'a, 'b> {
    pub handles: [u32; 2],
    pub params: In<'a>,
    pub auth: &'b mut Authorization,
}

/// `TPM2_CreatePrimary`.
pub fn create_primary(c: &mut Command) -> Result<(), u32> {
    let hierarchy = c.handles[0];
    if hierarchy_label(hierarchy).is_none() {
        return Err(RC_HIERARCHY | RC_1);
    }
    let create = read_sensitive_create(&mut c.params)?;
    let (public_raw_start, public_at) = (c.params.at, c.params.at);
    let _ = public_raw_start;
    let template = read_public(&mut c.params, 2)?;
    let template_bytes_len = c.params.at - public_at - 2;
    let template_bytes = &c.params.buf[public_at + 2..public_at + 2 + template_bytes_len];
    let outside = c.params.sized().ok_or(RC_COMMAND_SIZE)?;
    let selection = read_selection_raw(&mut c.params)?;
    if c.params.rest() != 0 {
        return Err(RC_COMMAND_SIZE);
    }
    if template.kind != ALG_ECC || !template.is_storage() && template.attributes & SIGN_ENCRYPT == 0 {
        return Err(RC_TYPE | RC_P | 2 * RC_1);
    }
    let slot_index = free_slot()?;

    let mut hash = sha256::Sha256::new();
    hash.update(template_bytes);
    hash.update(create.data);
    hash.update(&hierarchy.to_be_bytes());
    let origin = Origin { hierarchy, template: hash.finish() };
    let mut d = origin.private();
    let Some(point) = p256::public_key(&d) else {
        keystore::zero(&mut d);
        return Err(RC_KEY);
    };
    keystore::zero(&mut d);

    let mut public = template;
    public.unique[..32].copy_from_slice(&point.x);
    public.unique[32..].copy_from_slice(&point.y);
    public.unique_len = 64;
    let (bytes, len) = public.bytes();
    let name = name_of(&bytes[..len]);

    let slot = &mut table()[slot_index];
    *slot = EMPTY;
    slot.used = true;
    slot.public[..len].copy_from_slice(&bytes[..len]);
    slot.public_len = len;
    slot.name = name;
    slot.origin = origin;
    slot.is_primary = true;
    slot.qualified = qualify(&hierarchy.to_be_bytes(), &name);
    slot.auth[..create.auth.len()].copy_from_slice(create.auth);
    slot.auth_len = create.auth.len();

    c.auth.new_handle = Some(TRANSIENT_FIRST + slot_index as u32);
    let mut parameters = Out { buf: &mut [0u8; 600], at: 0 };
    marshal_tpm2b_public(&mut parameters, &public);
    let parent_name = hierarchy.to_be_bytes();
    creation(&mut parameters, &selection, outside, &parent_name, hierarchy, &name);
    parameters.u16(34);
    parameters.put(&name);
    let n = parameters.at;
    let raw = parameters.buf;
    c.auth.response_params(&raw[..n]);
    Ok(())
}

/// `TPM2_Create`: sealed data under a primary storage key.
pub fn create(c: &mut Command) -> Result<(), u32> {
    let parent = slot_of(c.handles[0]).ok_or(RC_HANDLE | RC_1)?;
    if !parent.is_primary || !parent.public().is_storage() {
        return Err(RC_TYPE | RC_1);
    }
    let create = read_sensitive_create(&mut c.params)?;
    let mut template = read_public(&mut c.params, 2)?;
    let outside = c.params.sized().ok_or(RC_COMMAND_SIZE)?;
    let selection = read_selection_raw(&mut c.params)?;
    if c.params.rest() != 0 {
        return Err(RC_COMMAND_SIZE);
    }
    if template.unique_len != 0 {
        return Err(RC_VALUE | RC_P | 2 * RC_1);
    }

    let mut sensitive = Sensitive { kind: template.kind, auth: [0; 32], auth_len: create.auth.len(), seed: [0; 32], value: [0; 128], value_len: 0 };
    sensitive.auth[..create.auth.len()].copy_from_slice(create.auth);
    if !rng::fill(&mut sensitive.seed) {
        return Err(RC_RANGE);
    }
    match template.kind {
        ALG_KEYEDHASH => {
            let origin = template.attributes & SENSITIVE_DATA_ORIGIN != 0;
            if origin == !create.data.is_empty() {
                sensitive.wipe();
                return Err(RC_ATTRIBUTES | RC_P | 2 * RC_1);
            }
            if origin {
                sensitive.value_len = 32;
                if !rng::fill(&mut sensitive.value[..32]) {
                    sensitive.wipe();
                    return Err(RC_RANGE);
                }
            } else {
                sensitive.value[..create.data.len()].copy_from_slice(create.data);
                sensitive.value_len = create.data.len();
            }
            let mut hash = sha256::Sha256::new();
            hash.update(&sensitive.seed);
            hash.update(&sensitive.value[..sensitive.value_len]);
            template.unique[..32].copy_from_slice(&hash.finish());
            template.unique_len = 32;
        }
        _ => {
            if !template.is_signing() {
                sensitive.wipe();
                return Err(RC_TYPE | RC_P | 2 * RC_1);
            }
            if template.attributes & SENSITIVE_DATA_ORIGIN == 0 || !create.data.is_empty() {
                sensitive.wipe();
                return Err(RC_ATTRIBUTES | RC_P | 2 * RC_1);
            }
            let Some(point) = new_scalar(&mut sensitive.value).and_then(|d| p256::public_key(&d)) else {
                sensitive.wipe();
                return Err(RC_RANGE);
            };
            sensitive.value_len = 32;
            template.unique[..32].copy_from_slice(&point.x);
            template.unique[32..].copy_from_slice(&point.y);
            template.unique_len = 64;
        }
    }
    let (bytes, len) = template.bytes();
    let name = name_of(&bytes[..len]);
    let mut blob = [0u8; MAX_PRIVATE];
    let blob_len = protect(&sensitive, &name, &parent.origin, &mut blob);
    sensitive.wipe();

    let parent_name = parent.name;
    let hierarchy = parent.origin.hierarchy;
    let mut parameters = Out { buf: &mut [0u8; 900], at: 0 };
    parameters.u16(blob_len as u16);
    parameters.put(&blob[..blob_len]);
    marshal_tpm2b_public(&mut parameters, &template);
    creation(&mut parameters, &selection, outside, &parent_name, hierarchy, &name);
    let n = parameters.at;
    let raw = parameters.buf;
    c.auth.response_params(&raw[..n]);
    Ok(())
}

/// Draw a private scalar into the start of `value`.
fn new_scalar(value: &mut [u8; 128]) -> Option<[u8; 32]> {
    let mut d = [0u8; 32];
    for _ in 0..8 {
        if !rng::fill(&mut d) {
            return None;
        }
        if p256::valid_scalar(&d) {
            value[..32].copy_from_slice(&d);
            return Some(d);
        }
    }
    None
}

/// `TPM2_Load`: put a created object in the TPM's memory.
pub fn load(c: &mut Command) -> Result<(), u32> {
    let parent = slot_of(c.handles[0]).ok_or(RC_HANDLE | RC_1)?;
    if !parent.is_primary || !parent.public().is_storage() {
        return Err(RC_TYPE | RC_1);
    }
    let blob = c.params.sized().ok_or(RC_COMMAND_SIZE)?;
    let public_at = c.params.at;
    let public = read_public(&mut c.params, 2)?;
    let public_bytes = &c.params.buf[public_at + 2..c.params.at];
    if c.params.rest() != 0 {
        return Err(RC_COMMAND_SIZE);
    }
    let name = name_of(public_bytes);
    let mut sensitive = unprotect(blob, &name, &parent.origin).map_err(|rc| rc | RC_P | RC_1)?;
    let consistent = match public.kind {
        ALG_KEYEDHASH => {
            let mut hash = sha256::Sha256::new();
            hash.update(&sensitive.seed);
            hash.update(&sensitive.value[..sensitive.value_len]);
            sensitive.kind == ALG_KEYEDHASH && public.unique_len == 32 && public.unique[..32] == hash.finish()
        }
        _ => {
            let mut d = [0u8; 32];
            d.copy_from_slice(&sensitive.value[..32]);
            let ok = sensitive.kind == ALG_ECC
                && sensitive.value_len == 32
                && p256::public_key(&d).is_some_and(|q| public.unique_len == 64 && public.unique[..32] == q.x && public.unique[32..] == q.y);
            keystore::zero(&mut d);
            ok
        }
    };
    sensitive.wipe();
    if !consistent {
        return Err(RC_INTEGRITY | RC_P | 2 * RC_1);
    }
    let origin = parent.origin;
    let parent_qualified = parent.qualified;
    let slot_index = free_slot()?;
    let slot = &mut table()[slot_index];
    *slot = EMPTY;
    slot.used = true;
    slot.public[..public_bytes.len()].copy_from_slice(public_bytes);
    slot.public_len = public_bytes.len();
    slot.name = name;
    slot.origin = origin;
    slot.qualified = qualify(&parent_qualified, &name);
    slot.private[..blob.len()].copy_from_slice(blob);
    slot.private_len = blob.len();

    c.auth.new_handle = Some(TRANSIENT_FIRST + slot_index as u32);
    let mut parameters = Out { buf: &mut [0u8; 40], at: 0 };
    parameters.u16(34);
    parameters.put(&name);
    let n = parameters.at;
    let raw = parameters.buf;
    c.auth.response_params(&raw[..n]);
    Ok(())
}

/// What `Unseal` gets by opening a loaded object.
pub fn open(slot: &Slot) -> Result<(Public, [u8; 32], usize, [u8; 128], usize), u32> {
    let mut sensitive = unprotect(&slot.private[..slot.private_len], &slot.name, &slot.origin)?;
    let result = (slot.public(), sensitive.auth, sensitive.auth_len, sensitive.value, sensitive.value_len);
    sensitive.wipe();
    Ok(result)
}

/// An ECDSA signature of `digest` by the key in `slot`. The per-signature
/// secret mixes the private key and the digest with fresh random bytes, so a
/// weak draw does not give the key away.
pub fn ecdsa_sign(slot: &Slot, digest: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), u32> {
    let mut d = if slot.is_primary {
        slot.origin.private()
    } else {
        let (_, _, _, mut value, value_len) = open(slot)?;
        let mut d = [0u8; 32];
        d.copy_from_slice(&value[..32]);
        keystore::zero(&mut value);
        if value_len != 32 {
            keystore::zero(&mut d);
            return Err(RC_KEY);
        }
        d
    };
    let mut result = Err(RC_RANGE);
    for attempt in 0..8u8 {
        let mut message = [0u8; 32 + 32 + 1];
        message[32..64].copy_from_slice(digest);
        message[64] = attempt;
        if !rng::fill((&mut message[..32]).try_into().unwrap()) {
            break;
        }
        let mut k = sha256::hmac(&d, &message);
        keystore::zero(&mut message);
        let signature = p256::sign(&d, digest, &k);
        keystore::zero(&mut k);
        if let Some(signature) = signature {
            result = Ok(signature);
            break;
        }
    }
    keystore::zero(&mut d);
    result
}

/// `TPM2_Unseal`.
pub fn unseal(c: &mut Command) -> Result<(), u32> {
    let slot = slot_of(c.handles[0]).ok_or(RC_HANDLE | RC_1)?;
    if c.params.rest() != 0 {
        return Err(RC_COMMAND_SIZE);
    }
    let public = slot.public();
    if !public.is_sealed() || slot.is_primary {
        return Err(RC_TYPE | RC_1);
    }
    let (_, _, _, mut value, value_len) = open(slot)?;
    let mut parameters = Out { buf: &mut [0u8; 140], at: 0 };
    parameters.u16(value_len as u16);
    parameters.put(&value[..value_len]);
    keystore::zero(&mut value);
    let n = parameters.at;
    let raw = parameters.buf;
    c.auth.response_params(&raw[..n]);
    keystore::zero(raw);
    Ok(())
}

/// `TPM2_ReadPublic`.
pub fn read_public_command(c: &mut Command) -> Result<(), u32> {
    let slot = slot_of(c.handles[0]).ok_or(RC_HANDLE | RC_1)?;
    if c.params.rest() != 0 {
        return Err(RC_COMMAND_SIZE);
    }
    let mut parameters = Out { buf: &mut [0u8; 400], at: 0 };
    parameters.u16(slot.public_len as u16);
    parameters.put(&slot.public[..slot.public_len]);
    parameters.u16(34);
    parameters.put(&slot.name);
    parameters.u16(34);
    parameters.put(&slot.qualified);
    let n = parameters.at;
    let raw = parameters.buf;
    c.auth.response_params(&raw[..n]);
    Ok(())
}

/// `TPM2_TestParms`: whether the TPM supports an algorithm and its parameters.
pub fn test_parms(c: &mut Command) -> Result<(), u32> {
    let kind = c.params.u16().ok_or(RC_COMMAND_SIZE)?;
    match kind {
        ALG_ECC => {
            let sym = c.params.u16().ok_or(RC_COMMAND_SIZE)?;
            if sym != ALG_NULL {
                let bits = c.params.u16().ok_or(RC_COMMAND_SIZE)?;
                let mode = c.params.u16().ok_or(RC_COMMAND_SIZE)?;
                if sym != ALG_AES || bits != 128 || mode != ALG_CFB {
                    return Err(RC_SYMMETRIC | RC_P | RC_1);
                }
            }
            let scheme = c.params.u16().ok_or(RC_COMMAND_SIZE)?;
            if scheme != ALG_NULL {
                let hash = c.params.u16().ok_or(RC_COMMAND_SIZE)?;
                if (scheme != ALG_ECDSA && scheme != ALG_ECDH) || hash != ALG_SHA256 {
                    return Err(RC_SCHEME | RC_P | RC_1);
                }
            }
            let curve = c.params.u16().ok_or(RC_COMMAND_SIZE)?;
            if curve != CURVE_P256 {
                return Err(RC_CURVE | RC_P | RC_1);
            }
            let kdf = c.params.u16().ok_or(RC_COMMAND_SIZE)?;
            if kdf != ALG_NULL {
                return Err(RC_KDF | RC_P | RC_1);
            }
        }
        ALG_KEYEDHASH => {
            let scheme = c.params.u16().ok_or(RC_COMMAND_SIZE)?;
            if scheme != ALG_NULL && scheme != ALG_HMAC {
                return Err(RC_SCHEME | RC_P | RC_1);
            }
        }
        ALG_SYMCIPHER => {
            let sym = c.params.u16().ok_or(RC_COMMAND_SIZE)?;
            let bits = c.params.u16().ok_or(RC_COMMAND_SIZE)?;
            let mode = c.params.u16().ok_or(RC_COMMAND_SIZE)?;
            if sym != ALG_AES || bits != 128 || mode != ALG_CFB {
                return Err(RC_SYMMETRIC | RC_P | RC_1);
            }
        }
        _ => return Err(RC_TYPE | RC_P | RC_1),
    }
    Ok(())
}

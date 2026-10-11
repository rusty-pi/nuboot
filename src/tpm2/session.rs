//! Sessions and authorization: the password, HMAC and policy sessions a
//! command can name, the policy commands that build a policy digest, and the
//! encryption of the first parameter that an HMAC session can ask for.
//!
//! A salted session shares a secret with the TPM through ECDH with a primary
//! storage key; an unsalted one has no key and only its nonces move. Either
//! way every command and response carries an HMAC over what was sent, so the
//! one who answers is the one who holds the session.

use super::object::{self, ALG_AES, ALG_CFB, ALG_ECC, RH_NULL, RH_PASSWORD};
use super::{
    ALG_NULL, ALG_SHA256, In, Out, RC_ATTRIBUTES, RC_AUTH_FAIL, RC_AUTH_MISSING, RC_AUTH_TYPE, RC_AUTH_UNAVAILABLE, RC_BAD_AUTH,
    RC_COMMAND_SIZE, RC_HANDLE, RC_POLICY_CC, RC_PCR_CHANGED, RC_POLICY_FAIL, RC_RANGE, RC_SESSION_MEMORY, RC_SIZE, RC_SYMMETRIC,
    RC_VALUE, RC_P, RC_S, RC_1, RC_2, ST_NO_SESSIONS, ST_SESSIONS,
};
use crate::{aes, kdf, keystore, p256, rng, sha256};

pub const SESSION_SLOTS: usize = 4;
const HMAC_SESSION_FIRST: u32 = 0x0200_0000;
const POLICY_SESSION_FIRST: u32 = 0x0300_0000;

pub const CC_START_AUTH_SESSION: u32 = 0x176;
pub const CC_POLICY_PCR: u32 = 0x17f;
pub const CC_POLICY_GET_DIGEST: u32 = 0x189;
pub const CC_POLICY_RESTART: u32 = 0x180;
pub const CC_POLICY_OR: u32 = 0x171;
pub const CC_POLICY_AUTH_VALUE: u32 = 0x16b;
pub const CC_POLICY_PASSWORD: u32 = 0x18c;
pub const CC_POLICY_COMMAND_CODE: u32 = 0x16c;

const ATTR_CONTINUE: u8 = 0x01;
const ATTR_DECRYPT: u8 = 0x20;
const ATTR_ENCRYPT: u8 = 0x40;

const KIND_HMAC: u8 = 0;
const KIND_POLICY: u8 = 1;
const KIND_TRIAL: u8 = 3;

#[derive(Clone, Copy)]
pub struct Session {
    pub used: bool,
    pub kind: u8,
    pub key: [u8; 32],
    pub key_len: usize,
    pub nonce_tpm: [u8; 32],
    pub nonce_caller: [u8; 32],
    pub nonce_caller_len: usize,
    pub sym_alg: u16,
    pub digest: [u8; 32],
    pub pcr_counter: u32,
    pub password: bool,
    pub auth_value: bool,
    pub command_code: u32,
    /// The name of the entity the session is bound to: its authorization value
    /// is in the session key, so not in the HMAC key for that entity.
    pub bind_name: [u8; 34],
    pub bind_len: usize,
}

const EMPTY: Session = Session {
    used: false,
    kind: 0,
    key: [0; 32],
    key_len: 0,
    nonce_tpm: [0; 32],
    nonce_caller: [0; 32],
    nonce_caller_len: 0,
    sym_alg: ALG_NULL,
    digest: [0; 32],
    pcr_counter: 0,
    password: false,
    auth_value: false,
    command_code: 0,
    bind_name: [0; 34],
    bind_len: 0,
};

static mut SESSIONS: [Session; SESSION_SLOTS] = [EMPTY; SESSION_SLOTS];

pub fn table() -> &'static mut [Session; SESSION_SLOTS] {
    unsafe { &mut *(&raw mut SESSIONS) }
}

fn handle_of(index: usize, kind: u8) -> u32 {
    (if kind == KIND_HMAC { HMAC_SESSION_FIRST } else { POLICY_SESSION_FIRST }) + index as u32
}

pub fn session_of(handle: u32) -> Option<&'static mut Session> {
    let (base, wants_hmac) = match handle >> 24 {
        0x02 => (HMAC_SESSION_FIRST, true),
        0x03 => (POLICY_SESSION_FIRST, false),
        _ => return None,
    };
    let session = table().get_mut(handle.checked_sub(base)? as usize)?;
    (session.used && (session.kind == KIND_HMAC) == wants_hmac).then_some(session)
}

pub fn flush(handle: u32) -> bool {
    match session_of(handle) {
        Some(session) => {
            keystore::zero(&mut session.key);
            *session = EMPTY;
            true
        }
        None => false,
    }
}

pub fn handles() -> impl Iterator<Item = u32> {
    table().iter().enumerate().filter(|(_, s)| s.used).map(|(i, s)| handle_of(i, s.kind))
}

/// One session of a command's authorization area, as it was sent.
#[derive(Clone, Copy)]
pub struct Sent<'a> {
    pub handle: u32,
    pub nonce: &'a [u8],
    pub attributes: u8,
    pub hmac: &'a [u8],
}

pub const MAX_SESSIONS: usize = 3;

pub fn parse_area<'a>(area: &'a [u8]) -> Result<([Sent<'a>; MAX_SESSIONS], usize), u32> {
    let mut input = In { buf: area, at: 0 };
    let mut sent = [Sent { handle: 0, nonce: &[], attributes: 0, hmac: &[] }; MAX_SESSIONS];
    let mut count = 0;
    while input.rest() != 0 {
        if count == MAX_SESSIONS {
            return Err(super::RC_AUTHSIZE);
        }
        let handle = input.u32().ok_or(RC_COMMAND_SIZE)?;
        let nonce = input.sized().ok_or(RC_COMMAND_SIZE)?;
        let attributes = input.u8().ok_or(RC_COMMAND_SIZE)?;
        let hmac = input.sized().ok_or(RC_COMMAND_SIZE)?;
        if nonce.len() > 32 || hmac.len() > 64 {
            return Err(RC_SIZE);
        }
        sent[count] = Sent { handle, nonce, attributes, hmac };
        count += 1;
    }
    Ok((sent, count))
}

/// What a command names that needs authorizing: its authorization value, and
/// the policy that can stand for it.
pub struct Entity {
    pub auth: [u8; 32],
    pub auth_len: usize,
    pub policy: [u8; 32],
    pub policy_len: usize,
    pub user_with_auth: bool,
}

impl Entity {
    fn hierarchy() -> Entity {
        Entity { auth: [0; 32], auth_len: 0, policy: [0; 32], policy_len: 0, user_with_auth: true }
    }

    pub fn of(handle: u32) -> Result<Entity, u32> {
        if matches!(handle, object::RH_OWNER | object::RH_ENDORSEMENT | object::RH_PLATFORM | RH_NULL) {
            return Ok(Entity::hierarchy());
        }
        let slot = object::slot_of(handle).ok_or(RC_HANDLE)?;
        let public = slot.public();
        let mut entity = Entity {
            auth: [0; 32],
            auth_len: 0,
            policy: public.policy,
            policy_len: public.policy_len,
            user_with_auth: public.attributes & object::USER_WITH_AUTH != 0,
        };
        if slot.is_primary {
            entity.auth = slot.auth;
            entity.auth_len = slot.auth_len;
        } else {
            let (_, auth, auth_len, mut value, _) = object::open(slot)?;
            keystore::zero(&mut value);
            entity.auth = auth;
            entity.auth_len = auth_len;
        }
        Ok(entity)
    }
}

/// What a session did for a command, for its response.
#[derive(Clone, Copy)]
struct Used {
    handle: u32,
    password: bool,
    attributes: u8,
    nonce_caller: [u8; 32],
    nonce_caller_len: usize,
    key: [u8; 64],
    key_len: usize,
    keyed: bool,
    flush: bool,
}

const UNUSED: Used = Used { handle: 0, password: false, attributes: 0, nonce_caller: [0; 32], nonce_caller_len: 0, key: [0; 64], key_len: 0, keyed: false, flush: false };

/// A command's authorization, and the response it gets.
pub struct Authorization {
    pub new_handle: Option<u32>,
    params: [u8; 1000],
    params_len: usize,
    plain_len: usize,
    decrypted: bool,
    count: usize,
    used: [Used; MAX_SESSIONS],
    encrypt: Option<usize>,
}

static mut PLAIN: [u8; 1100] = [0; 1100];

/// The command's parameters after a session decrypted them.
pub fn plain(len: usize) -> &'static [u8] {
    unsafe { &(&*(&raw const PLAIN))[..len] }
}

static mut AUTHORIZATION: Authorization = Authorization {
    new_handle: None,
    params: [0; 1000],
    params_len: 0,
    plain_len: 0,
    decrypted: false,
    count: 0,
    used: [UNUSED; MAX_SESSIONS],
    encrypt: None,
};

impl Authorization {
    pub fn get() -> &'static mut Authorization {
        let a = unsafe { &mut *(&raw mut AUTHORIZATION) };
        a.new_handle = None;
        a.params_len = 0;
        a.plain_len = 0;
        a.decrypted = false;
        a.count = 0;
        a.encrypt = None;
        a
    }

    /// How long the decrypted parameters are, when a session decrypted them
    /// into [`plain`].
    pub fn decrypted_len(&self) -> Option<usize> {
        self.decrypted.then_some(self.plain_len)
    }

    /// The response parameters, as the command made them.
    pub fn response_params(&mut self, params: &[u8]) {
        self.params[..params.len()].copy_from_slice(params);
        self.params_len = params.len();
    }

    /// Wipe what a command left.
    pub fn wipe(&mut self) {
        keystore::zero(&mut self.params);
        keystore::zero(unsafe { &mut *(&raw mut PLAIN) });
        for used in self.used.iter_mut() {
            keystore::zero(&mut used.key);
        }
    }
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// A session's HMAC key for one entity: its key and the entity's authorization
/// value.
fn hmac_key(session: &Session, entity: &Entity, name: &[u8]) -> ([u8; 64], usize) {
    let mut key = [0u8; 64];
    key[..session.key_len].copy_from_slice(&session.key[..session.key_len]);
    if session.bind_len != 0 && session.bind_name[..session.bind_len] == *name {
        return (key, session.key_len);
    }
    key[session.key_len..session.key_len + entity.auth_len].copy_from_slice(&entity.auth[..entity.auth_len]);
    (key, session.key_len + entity.auth_len)
}

fn session_error(rc: u32, index: usize) -> u32 {
    rc | RC_S | (index as u32 + 1) * RC_1
}

/// The first parameter's contents, which a session encrypts: after its size.
fn crypt_first(data: &mut [u8], key: &[u8], newer: &[u8], older: &[u8], decrypt: bool) -> Result<(), u32> {
    if data.len() < 2 {
        return Err(RC_SIZE);
    }
    let size = u16::from_be_bytes([data[0], data[1]]) as usize;
    let body = data.get_mut(2..2 + size).ok_or(RC_SIZE)?;
    let mut material = [0u8; 32];
    kdf::kdfa(key, b"CFB", newer, older, 256, &mut material);
    let (aes_key, iv) = material.split_at(16);
    let cipher = aes::Aes128::new(aes_key.try_into().unwrap());
    let iv: [u8; 16] = iv.try_into().unwrap();
    if decrypt {
        cipher.cfb_decrypt(&iv, body);
    } else {
        cipher.cfb_encrypt(&iv, body);
    }
    keystore::zero(&mut material);
    Ok(())
}

/// Authorize a command: check each session it carries against what it names,
/// and decrypt the first parameter when a session says it is encrypted.
///
/// `names` are the names of the command's handles, as they go into `cpHash`,
/// `sent` its sessions and `wire` its parameters.
pub fn authorize(
    a: &mut Authorization,
    code: u32,
    handles: &[u32],
    names: &[([u8; 34], usize)],
    auth_handles: usize,
    sent: &[Sent],
    wire: &[u8],
) -> Result<(), u32> {
    if sent.len() < auth_handles {
        return Err(RC_AUTH_MISSING);
    }
    let mut cp = sha256::Sha256::new();
    cp.update(&code.to_be_bytes());
    for (name, len) in names {
        cp.update(&name[..*len]);
    }
    cp.update(wire);
    let cp_hash = cp.finish();

    // The first sessions that decrypt and encrypt: which nonce goes in the
    // other sessions' HMACs.
    let mut decrypt_at = None;
    let mut encrypt_at = None;
    for (i, s) in sent.iter().enumerate() {
        if s.handle != RH_PASSWORD {
            if s.attributes & ATTR_DECRYPT != 0 && decrypt_at.is_none() {
                decrypt_at = Some(i);
            }
            if s.attributes & ATTR_ENCRYPT != 0 && encrypt_at.is_none() {
                encrypt_at = Some(i);
            }
        }
    }
    let old_nonce = |at: Option<usize>, i: usize| -> ([u8; 32], usize) {
        match at {
            Some(j) if j != i => session_of(sent[j].handle).map_or(([0; 32], 0), |s| (s.nonce_tpm, 32)),
            _ => ([0; 32], 0),
        }
    };

    a.count = sent.len();
    for (i, s) in sent.iter().enumerate() {
        let entity = if i < auth_handles { Some(Entity::of(handles[i]).map_err(|rc| rc | RC_1)?) } else { None };
        a.used[i] = UNUSED;
        a.used[i].handle = s.handle;
        a.used[i].attributes = s.attributes;
        if s.handle == RH_PASSWORD {
            a.used[i].password = true;
            if !s.nonce.is_empty() {
                return Err(session_error(RC_AUTH_FAIL, i));
            }
            if let Some(e) = &entity {
                if !e.user_with_auth {
                    return Err(session_error(RC_AUTH_UNAVAILABLE, i));
                }
                if !constant_eq(s.hmac, &e.auth[..e.auth_len]) {
                    return Err(session_error(RC_BAD_AUTH, i));
                }
            }
            continue;
        }
        let session = session_of(s.handle).ok_or(session_error(RC_HANDLE, i))?;
        if s.nonce.len() < 16 {
            return Err(session_error(RC_SIZE, i));
        }
        let plain_entity = Entity::hierarchy();
        let e = entity.as_ref().unwrap_or(&plain_entity);
        let mut keyed = true;
        if let Some(e) = &entity {
            match session.kind {
                KIND_HMAC => {
                    if !e.user_with_auth {
                        return Err(session_error(RC_AUTH_UNAVAILABLE, i));
                    }
                }
                KIND_POLICY => {
                    if e.policy_len != 32 {
                        return Err(session_error(RC_AUTH_TYPE, i));
                    }
                    if !constant_eq(&e.policy, &session.digest) {
                        return Err(session_error(RC_POLICY_FAIL, i));
                    }
                    if session.pcr_counter != 0 && session.pcr_counter != keystore::count() {
                        return Err(session_error(RC_PCR_CHANGED, i));
                    }
                    if session.command_code != 0 && session.command_code != code {
                        return Err(session_error(RC_POLICY_CC, i));
                    }
                    if session.password {
                        if !constant_eq(s.hmac, &e.auth[..e.auth_len]) {
                            return Err(session_error(RC_BAD_AUTH, i));
                        }
                        keyed = false;
                    } else if !session.auth_value {
                        keyed = false;
                    }
                }
                _ => return Err(session_error(RC_ATTRIBUTES, i)),
            }
        }
        let entity_name = if i < auth_handles { &names[i].0[..names[i].1] } else { &[][..] };
        let (mut key, mut key_len) = hmac_key(session, e, entity_name);
        if session.kind == KIND_POLICY && !session.auth_value {
            // Nothing of the entity's is in a policy session's key unless the
            // policy asked for its authorization value.
            key = [0; 64];
            key[..session.key_len].copy_from_slice(&session.key[..session.key_len]);
            key_len = session.key_len;
        }
        if keyed && entity.is_some() || (!s.hmac.is_empty() && entity.is_none()) {
            let (dn, dl) = old_nonce(decrypt_at, i);
            let (en, el) = old_nonce(encrypt_at, i);
            let mut message = [0u8; 32 + 32 + 32 + 32 + 32 + 1];
            let mut n = 0;
            for part in [&cp_hash[..], s.nonce, &session.nonce_tpm[..], &dn[..dl], &en[..el], &[s.attributes]] {
                message[n..n + part.len()].copy_from_slice(part);
                n += part.len();
            }
            let expected = sha256::hmac(&key[..key_len], &message[..n]);
            if !constant_eq(s.hmac, &expected) {
                return Err(session_error(RC_AUTH_FAIL, i));
            }
        }
        a.used[i].keyed = true;
        a.used[i].key = key;
        a.used[i].key_len = key_len;
        a.used[i].nonce_caller[..s.nonce.len()].copy_from_slice(s.nonce);
        a.used[i].nonce_caller_len = s.nonce.len();
        if s.attributes & ATTR_DECRYPT != 0 && decrypt_at == Some(i) {
            if session.sym_alg != ALG_AES {
                return Err(session_error(RC_ATTRIBUTES, i));
            }
            a.plain_len = wire.len();
            let plain = unsafe { &mut (&mut *(&raw mut PLAIN))[..wire.len()] };
            plain.copy_from_slice(wire);
            crypt_first(plain, &key[..key_len], s.nonce, &session.nonce_tpm, true)
                .map_err(|rc| session_error(rc, i))?;
            a.decrypted = true;
        }
        if s.attributes & ATTR_ENCRYPT != 0 && encrypt_at == Some(i) {
            if session.sym_alg != ALG_AES {
                return Err(session_error(RC_ATTRIBUTES, i));
            }
            a.encrypt = Some(i);
        }
        a.used[i].flush = s.attributes & ATTR_CONTINUE == 0;
    }
    // Every session moves on to a new TPM nonce once the command is accepted.
    for (i, s) in sent.iter().enumerate() {
        if s.handle == RH_PASSWORD {
            continue;
        }
        let session = session_of(s.handle).unwrap();
        session.nonce_caller[..s.nonce.len()].copy_from_slice(s.nonce);
        session.nonce_caller_len = s.nonce.len();
        let _ = i;
    }
    Ok(())
}

/// Build the successful response: the handle and the parameters (encrypted if a
/// session asked) and the authorization area. The length.
pub fn respond(a: &mut Authorization, code: u32, response: &mut [u8]) -> usize {
    let tagged_sessions = a.count != 0;
    let mut out = Out { buf: response, at: 10 };
    if let Some(handle) = a.new_handle {
        out.u32(handle);
    }
    let mut wire = [0u8; 1000];
    wire[..a.params_len].copy_from_slice(&a.params[..a.params_len]);
    let len = a.params_len;
    // The TPM nonces the response carries.
    let mut nonces = [[0u8; 32]; MAX_SESSIONS];
    for i in 0..a.count {
        if !a.used[i].password {
            if let Some(session) = session_of(a.used[i].handle) {
                rng::fill(&mut session.nonce_tpm);
                nonces[i] = session.nonce_tpm;
            }
        }
    }
    if let Some(i) = a.encrypt {
        let used = a.used[i];
        let key = &used.key[..used.key_len];
        let _ = crypt_first(&mut wire[..len], key, &nonces[i], &used.nonce_caller[..used.nonce_caller_len], false);
    }
    if tagged_sessions {
        out.u32(len as u32);
    }
    out.put(&wire[..len]);
    if tagged_sessions {
        let mut hash = sha256::Sha256::new();
        hash.update(&0u32.to_be_bytes());
        hash.update(&code.to_be_bytes());
        hash.update(&wire[..len]);
        let rp_hash = hash.finish();
        for i in 0..a.count {
            let used = a.used[i];
            if used.password {
                out.u16(0);
                out.u8(used.attributes & ATTR_CONTINUE);
                out.u16(0);
                continue;
            }
            out.u16(32);
            out.put(&nonces[i]);
            out.u8(used.attributes & 0x7f);
            if used.keyed {
                let mut message = [0u8; 32 + 32 + 32 + 1];
                let mut n = 0;
                for part in [&rp_hash[..], &nonces[i][..], &used.nonce_caller[..used.nonce_caller_len], &[used.attributes & 0x7f]] {
                    message[n..n + part.len()].copy_from_slice(part);
                    n += part.len();
                }
                let mac = sha256::hmac(&used.key[..used.key_len], &message[..n]);
                out.u16(32);
                out.put(&mac);
            } else {
                out.u16(0);
            }
        }
        for i in 0..a.count {
            if a.used[i].flush && !a.used[i].password {
                flush(a.used[i].handle);
            }
        }
    }
    keystore::zero(&mut wire);
    let total = out.at;
    let tag = if tagged_sessions { ST_SESSIONS } else { ST_NO_SESSIONS };
    response[..2].copy_from_slice(&tag.to_be_bytes());
    response[2..6].copy_from_slice(&(total as u32).to_be_bytes());
    response[6..10].copy_from_slice(&0u32.to_be_bytes());
    total
}

fn new_session(kind: u8) -> Result<(usize, &'static mut Session), u32> {
    let index = table().iter().position(|s| !s.used).ok_or(RC_SESSION_MEMORY)?;
    let session = &mut table()[index];
    *session = EMPTY;
    session.used = true;
    session.kind = kind;
    Ok((index, session))
}

/// `TPM2_StartAuthSession`.
pub fn start_auth_session(code: u32, handles: &[u32], params: &mut In, a: &mut Authorization) -> Result<(), u32> {
    let _ = code;
    let (key_handle, bind) = (handles[0], handles[1]);
    let nonce = params.sized().ok_or(RC_COMMAND_SIZE)?;
    let salt = params.sized().ok_or(RC_COMMAND_SIZE)?;
    let kind = params.u8().ok_or(RC_COMMAND_SIZE)?;
    let sym_alg = params.u16().ok_or(RC_COMMAND_SIZE)?;
    if sym_alg != ALG_NULL {
        let bits = params.u16().ok_or(RC_COMMAND_SIZE)?;
        let mode = params.u16().ok_or(RC_COMMAND_SIZE)?;
        if sym_alg != ALG_AES || bits != 128 || mode != ALG_CFB {
            return Err(RC_SYMMETRIC | RC_P | 4 * RC_1);
        }
    }
    let hash = params.u16().ok_or(RC_COMMAND_SIZE)?;
    if params.rest() != 0 {
        return Err(RC_COMMAND_SIZE);
    }
    if hash != ALG_SHA256 {
        return Err(super::RC_HASH | RC_P | 5 * RC_1);
    }
    if nonce.len() < 16 || nonce.len() > 32 {
        return Err(RC_SIZE | RC_P | RC_1);
    }
    let kind = match kind {
        0 => KIND_HMAC,
        1 => KIND_POLICY,
        3 => KIND_TRIAL,
        _ => return Err(RC_VALUE | RC_P | 3 * RC_1),
    };
    let mut bind_auth = [0u8; 32];
    let mut bind_auth_len = 0;
    let mut bind_name = [0u8; 34];
    let mut bind_len = 0;
    if bind != RH_NULL {
        let entity = Entity::of(bind).map_err(|rc| rc | RC_2)?;
        bind_auth = entity.auth;
        bind_auth_len = entity.auth_len;
        let (name, len) = super::name_for(bind);
        bind_name = name;
        bind_len = len;
    }
    let (index, session) = new_session(kind)?;
    session.bind_name = bind_name;
    session.bind_len = bind_len;
    session.sym_alg = sym_alg;
    session.nonce_caller[..nonce.len()].copy_from_slice(nonce);
    session.nonce_caller_len = nonce.len();
    if !rng::fill(&mut session.nonce_tpm) {
        session.used = false;
        return Err(RC_RANGE);
    }
    let mut salt_value = [0u8; 32];
    let mut salt_len = 0;
    if key_handle == RH_NULL {
        if !salt.is_empty() {
            session.used = false;
            return Err(RC_VALUE | RC_P | 2 * RC_1);
        }
    } else {
        match salt_of(key_handle, salt) {
            Ok(value) => {
                salt_value = value;
                salt_len = 32;
            }
            Err(rc) => {
                session.used = false;
                return Err(rc);
            }
        }
    }
    if key_handle != RH_NULL || bind != RH_NULL {
        let mut material = [0u8; 64];
        material[..bind_auth_len].copy_from_slice(&bind_auth[..bind_auth_len]);
        material[bind_auth_len..bind_auth_len + salt_len].copy_from_slice(&salt_value[..salt_len]);
        kdf::kdfa(&material[..bind_auth_len + salt_len], b"ATH", &session.nonce_tpm, nonce, 256, &mut session.key);
        session.key_len = 32;
        keystore::zero(&mut material);
        keystore::zero(&mut salt_value);
    }
    a.new_handle = Some(handle_of(index, kind));
    let mut response = [0u8; 34];
    response[..2].copy_from_slice(&32u16.to_be_bytes());
    response[2..].copy_from_slice(&session.nonce_tpm);
    a.response_params(&response);
    Ok(())
}

/// The salt of a salted session: what the caller encrypted to a primary storage
/// key, an ECC point whose x the TPM's ECDH gives back, and from it a value
/// both sides can compute.
fn salt_of(handle: u32, salt: &[u8]) -> Result<[u8; 32], u32> {
    let slot = object::slot_of(handle).ok_or(RC_HANDLE | RC_1)?;
    let public = slot.public();
    if !slot.is_primary || public.kind != ALG_ECC {
        return Err(super::RC_KEY | RC_1);
    }
    let mut point = In { buf: salt, at: 0 };
    let x = point.sized().ok_or(RC_VALUE | RC_P | 2 * RC_1)?;
    let y = point.sized().ok_or(RC_VALUE | RC_P | 2 * RC_1)?;
    if x.len() != 32 || y.len() != 32 || point.rest() != 0 {
        return Err(RC_VALUE | RC_P | 2 * RC_1);
    }
    let peer = p256::Point { x: x.try_into().unwrap(), y: y.try_into().unwrap() };
    let mut d = slot.origin.private();
    let shared = p256::ecdh(&d, &peer);
    keystore::zero(&mut d);
    let mut z = shared.ok_or(super::RC_ECC_POINT | RC_P | 2 * RC_1)?;
    let mut secret = [0u8; 32];
    kdf::kdfe(&z, b"SECRET", &peer.x, &public.unique[..32], 256, &mut secret);
    keystore::zero(&mut z);
    Ok(secret)
}

/// The policy commands: `handle` is the session, `params` what follows.
pub fn policy(code: u32, handle: u32, params: &mut In, a: &mut Authorization) -> Result<(), u32> {
    let session = session_of(handle).ok_or(RC_HANDLE | RC_1)?;
    if session.kind == KIND_HMAC {
        return Err(RC_ATTRIBUTES | RC_1);
    }
    let trial = session.kind == KIND_TRIAL;
    match code {
        CC_POLICY_PCR => {
            let given = params.sized().ok_or(RC_COMMAND_SIZE)?;
            let at = params.at;
            let count = params.u32().ok_or(RC_COMMAND_SIZE)?;
            let mut mask = 0u32;
            for _ in 0..count {
                let alg = params.u16().ok_or(RC_COMMAND_SIZE)?;
                let size = params.u8().ok_or(RC_COMMAND_SIZE)? as usize;
                let bits = params.take(size).ok_or(RC_COMMAND_SIZE)?;
                if alg == ALG_SHA256 {
                    for (i, b) in bits.iter().enumerate().take(3) {
                        mask |= (*b as u32) << (8 * i);
                    }
                }
            }
            let selection = &params.buf[at..params.at];
            if params.rest() != 0 {
                return Err(RC_COMMAND_SIZE);
            }
            mask &= (1 << keystore::PCRS) - 1;
            let mut hash = sha256::Sha256::new();
            for i in (0..keystore::PCRS).filter(|i| mask >> i & 1 != 0) {
                hash.update(&keystore::pcr(i).unwrap_or([0; 32]));
            }
            let current = hash.finish();
            if !given.is_empty() && (given.len() != 32 || !constant_eq(given, &current)) && !trial {
                return Err(RC_VALUE | RC_P | RC_1);
            }
            let digest = if given.is_empty() { current } else { <[u8; 32]>::try_from(given).map_err(|_| RC_VALUE | RC_P | RC_1)? };
            let mut update = sha256::Sha256::new();
            update.update(&session.digest);
            update.update(&CC_POLICY_PCR.to_be_bytes());
            update.update(selection);
            update.update(&digest);
            session.digest = update.finish();
            session.pcr_counter = if trial { 0 } else { keystore::count() };
        }
        CC_POLICY_GET_DIGEST => {
            if params.rest() != 0 {
                return Err(RC_COMMAND_SIZE);
            }
            let mut response = [0u8; 34];
            response[..2].copy_from_slice(&32u16.to_be_bytes());
            response[2..].copy_from_slice(&session.digest);
            a.response_params(&response);
        }
        CC_POLICY_RESTART => {
            session.digest = [0; 32];
            session.pcr_counter = 0;
            session.password = false;
            session.auth_value = false;
            session.command_code = 0;
        }
        CC_POLICY_OR => {
            let count = params.u32().ok_or(RC_COMMAND_SIZE)?;
            if !(2..=8).contains(&count) {
                return Err(RC_VALUE | RC_P | RC_1);
            }
            let mut update = sha256::Sha256::new();
            update.update(&[0u8; 32]);
            update.update(&CC_POLICY_OR.to_be_bytes());
            let mut found = false;
            for _ in 0..count {
                let digest = params.sized().ok_or(RC_COMMAND_SIZE)?;
                if digest.len() != 32 {
                    return Err(RC_SIZE | RC_P | RC_1);
                }
                found |= constant_eq(digest, &session.digest);
                update.update(digest);
            }
            if params.rest() != 0 {
                return Err(RC_COMMAND_SIZE);
            }
            if !found && !trial {
                return Err(RC_VALUE | RC_P | RC_1);
            }
            session.digest = update.finish();
        }
        CC_POLICY_AUTH_VALUE | CC_POLICY_PASSWORD => {
            if params.rest() != 0 {
                return Err(RC_COMMAND_SIZE);
            }
            let mut update = sha256::Sha256::new();
            update.update(&session.digest);
            update.update(&CC_POLICY_AUTH_VALUE.to_be_bytes());
            session.digest = update.finish();
            if code == CC_POLICY_PASSWORD {
                session.password = true;
            } else {
                session.auth_value = true;
            }
        }
        CC_POLICY_COMMAND_CODE => {
            let wanted = params.u32().ok_or(RC_COMMAND_SIZE)?;
            if params.rest() != 0 {
                return Err(RC_COMMAND_SIZE);
            }
            if session.command_code != 0 && session.command_code != wanted {
                return Err(RC_VALUE | RC_P | RC_1);
            }
            let mut update = sha256::Sha256::new();
            update.update(&session.digest);
            update.update(&CC_POLICY_COMMAND_CODE.to_be_bytes());
            update.update(&wanted.to_be_bytes());
            session.digest = update.finish();
            session.command_code = wanted;
        }
        _ => return Err(super::RC_COMMAND_CODE),
    }
    Ok(())
}

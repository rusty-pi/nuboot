//! A TPM 2.0 on the VPU, for what a boot needs of one: the PCRs
//! ([`crate::keystore`]) and the commands that read and extend them, the
//! properties and algorithms the TPM reports, and random bytes.
//!
//! UEFI reaches it as `EFI_TCG2_PROTOCOL.SubmitCommand`, and the OS over the
//! property mailbox ([`crate::mailbox`], tag `0x000300a3`). The TPM is
//! started when the firmware is: a payload that sends `TPM2_Startup` gets
//! `TPM_RC_INITIALIZE`, as it would from a TPM the firmware had started.
//!
//! One bank, SHA-256, of 24 PCRs, all extendable from locality 0 as the PC
//! Client profile has it except 17-22 (DRTM, which nothing here does), and
//! PCRs 16 and 23 resettable. The hierarchies, the primary keys under them and
//! the data and signing keys created under those are in [`object`]; sessions
//! and policies in [`session`]; signatures and quotes in [`sign`]; what lets a
//! tool keep them between commands in [`context`].

use crate::keystore::{self, PCRS};
use crate::{rng, sha256, stc};

#[path = "tpm2/context.rs"]
mod context;
#[path = "tpm2/nv.rs"]
mod nv;
pub use nv::{ExportError as NvExportError, ImportError as NvImportError, RECORD_MAX as NV_RECORD_MAX, export as nv_export, import as nv_import};
#[path = "tpm2/object.rs"]
mod object;
#[path = "tpm2/session.rs"]
mod session;
#[path = "tpm2/sign.rs"]
mod sign;

pub const MAX_COMMAND: usize = 2048;

static mut COMMAND: [u8; MAX_COMMAND] = [0; MAX_COMMAND];
static mut RESPONSE: [u8; MAX_COMMAND] = [0; MAX_COMMAND];

/// The buffers a command is copied into and its response built in. The
/// mailbox thread is the only caller, and answers one command at a time.
pub fn buffers() -> (&'static mut [u8; MAX_COMMAND], &'static mut [u8; MAX_COMMAND]) {
    unsafe { (&mut *(&raw mut COMMAND), &mut *(&raw mut RESPONSE)) }
}

const ST_NO_SESSIONS: u16 = 0x8001;
const ST_SESSIONS: u16 = 0x8002;

const RC_SUCCESS: u32 = 0;
const RC_INITIALIZE: u32 = 0x100;
const RC_COMMAND_SIZE: u32 = 0x142;
const RC_FAILURE: u32 = 0x101;
const RC_COMMAND_CODE: u32 = 0x143;
const RC_BAD_TAG: u32 = 0x1e;
/// The format-one codes: the parameter or handle number goes in bits 8-11 and
/// bit 6 says it is a parameter (as `RC_P`), bit 7 a handle.
const RC_VALUE: u32 = 0x84;
const RC_HASH: u32 = 0x083;
const RC_NV_DEFINED: u32 = 0x14c;
const RC_NV_SPACE: u32 = 0x14b;
const RC_RANGE: u32 = 0x08d;
const RC_LOCALITY: u32 = 0x107;
const RC_HANDLE: u32 = 0x08b;
const RC_AUTH_UNAVAILABLE: u32 = 0x12f;
const RC_AUTH_MISSING: u32 = 0x125;
const RC_SIZE: u32 = 0x095;
const RC_P: u32 = 0x40;
const RC_S: u32 = 0x800;
const RC_1: u32 = 0x100;
const RC_2: u32 = 0x200;
const RC_ATTRIBUTES: u32 = 0x082;
const RC_BINDING: u32 = 0x0a5;
const RC_HIERARCHY: u32 = 0x085;
const RC_KDF: u32 = 0x08c;
const RC_KEY: u32 = 0x09c;
const RC_TYPE: u32 = 0x08a;
const RC_AUTH_FAIL: u32 = 0x08e;
const RC_SCHEME: u32 = 0x092;
const RC_SYMMETRIC: u32 = 0x096;
const RC_POLICY_FAIL: u32 = 0x09d;
const RC_INTEGRITY: u32 = 0x09f;
const RC_BAD_AUTH: u32 = 0x0a2;
const RC_SIGNATURE: u32 = 0x09b;
const RC_TICKET: u32 = 0x0a0;
const RC_POLICY_CC: u32 = 0x0a4;
const RC_CURVE: u32 = 0x0a6;
const RC_ECC_POINT: u32 = 0x0a7;
const RC_REFERENCE_H0: u32 = 0x910;
const RC_POLICY: u32 = 0x126;
const RC_OBJECT_MEMORY: u32 = 0x902;
const RC_SESSION_MEMORY: u32 = 0x903;
const RC_AUTH_TYPE: u32 = 0x124;
const RC_PCR_CHANGED: u32 = 0x128;
const RC_AUTHSIZE: u32 = 0x144;

const CC_STARTUP: u32 = 0x144;
const CC_SHUTDOWN: u32 = 0x145;
const CC_SELF_TEST: u32 = 0x143;
const CC_INCREMENTAL_SELF_TEST: u32 = 0x142;
const CC_GET_TEST_RESULT: u32 = 0x17c;
const CC_GET_CAPABILITY: u32 = 0x17a;
const CC_GET_RANDOM: u32 = 0x17b;
const CC_PCR_READ: u32 = 0x17e;
const CC_PCR_EXTEND: u32 = 0x182;
const CC_PCR_EVENT: u32 = 0x14b;
const CC_PCR_RESET: u32 = 0x13d;
const CC_HASH: u32 = 0x17d;
const CC_READ_CLOCK: u32 = 0x181;
const CC_STIR_RANDOM: u32 = 0x146;

/// Commands in numeric order, for `TPM_CAP_COMMANDS`: the number of handles in
/// the command (bits 25-27 of `TPMA_CC`), and 8 more when the response has a
/// handle (bit 28).
const COMMANDS: [(u32, u32); 49] = [
    (object::CC_EVICT_CONTROL, 2),
    (nv::CC_NV_UNDEFINE_SPACE, 2),
    (nv::CC_NV_DEFINE_SPACE, 1),
    (object::CC_CREATE_PRIMARY, 1 | 8),
    (nv::CC_NV_INCREMENT, 2),
    (nv::CC_NV_SET_BITS, 2),
    (nv::CC_NV_EXTEND, 2),
    (nv::CC_NV_WRITE, 2),
    (CC_PCR_RESET, 1),
    (CC_INCREMENTAL_SELF_TEST, 0),
    (CC_SELF_TEST, 0),
    (CC_STARTUP, 0),
    (CC_SHUTDOWN, 0),
    (CC_STIR_RANDOM, 0),
    (CC_PCR_EVENT, 1),
    (nv::CC_NV_READ, 2),
    (session::CC_POLICY_SECRET, 2),
    (object::CC_CREATE, 1),
    (object::CC_LOAD, 1 | 8),
    (sign::CC_QUOTE, 1),
    (sign::CC_SIGN, 1),
    (object::CC_UNSEAL, 1),
    (session::CC_POLICY_SIGNED, 2),
    (object::CC_CONTEXT_LOAD, 8),
    (object::CC_CONTEXT_SAVE, 1),
    (object::CC_FLUSH_CONTEXT, 0),
    (object::CC_LOAD_EXTERNAL, 8),
    (nv::CC_NV_READ_PUBLIC, 1),
    (session::CC_POLICY_AUTHORIZE, 1),
    (session::CC_POLICY_AUTH_VALUE, 1),
    (session::CC_POLICY_COMMAND_CODE, 1),
    (session::CC_POLICY_OR, 1),
    (object::CC_READ_PUBLIC, 1),
    (session::CC_START_AUTH_SESSION, 2 | 8),
    (sign::CC_VERIFY_SIGNATURE, 1),
    (CC_GET_CAPABILITY, 0),
    (CC_GET_RANDOM, 0),
    (CC_GET_TEST_RESULT, 0),
    (CC_HASH, 0),
    (CC_PCR_READ, 0),
    (session::CC_POLICY_PCR, 1),
    (session::CC_POLICY_RESTART, 1),
    (CC_READ_CLOCK, 0),
    (CC_PCR_EXTEND, 1),
    (session::CC_POLICY_GET_DIGEST, 1),
    (object::CC_TEST_PARMS, 0),
    (session::CC_POLICY_PASSWORD, 1),
    (session::CC_POLICY_NV_WRITTEN, 1),
    (session::CC_POLICY_AUTHORIZE_NV, 3),
];

/// A command that names objects or sessions: how many handles it has, how many
/// of them it needs authorized, and whether it makes a handle.
struct Spec {
    code: u32,
    handles: usize,
    authorized: usize,
}

const OBJECT_COMMANDS: [Spec; 35] = [
    Spec { code: object::CC_EVICT_CONTROL, handles: 2, authorized: 1 },
    Spec { code: object::CC_CREATE_PRIMARY, handles: 1, authorized: 1 },
    Spec { code: object::CC_CREATE, handles: 1, authorized: 1 },
    Spec { code: object::CC_LOAD, handles: 1, authorized: 1 },
    Spec { code: object::CC_UNSEAL, handles: 1, authorized: 1 },
    Spec { code: object::CC_LOAD_EXTERNAL, handles: 0, authorized: 0 },
    Spec { code: session::CC_POLICY_AUTHORIZE, handles: 1, authorized: 0 },
    Spec { code: sign::CC_SIGN, handles: 1, authorized: 1 },
    Spec { code: sign::CC_QUOTE, handles: 1, authorized: 1 },
    Spec { code: sign::CC_VERIFY_SIGNATURE, handles: 1, authorized: 0 },
    Spec { code: session::CC_POLICY_SECRET, handles: 2, authorized: 1 },
    Spec { code: object::CC_READ_PUBLIC, handles: 1, authorized: 0 },
    Spec { code: object::CC_FLUSH_CONTEXT, handles: 0, authorized: 0 },
    Spec { code: object::CC_CONTEXT_SAVE, handles: 1, authorized: 0 },
    Spec { code: object::CC_CONTEXT_LOAD, handles: 0, authorized: 0 },
    Spec { code: object::CC_TEST_PARMS, handles: 0, authorized: 0 },
    Spec { code: session::CC_START_AUTH_SESSION, handles: 2, authorized: 0 },
    Spec { code: session::CC_POLICY_PCR, handles: 1, authorized: 0 },
    Spec { code: session::CC_POLICY_GET_DIGEST, handles: 1, authorized: 0 },
    Spec { code: session::CC_POLICY_RESTART, handles: 1, authorized: 0 },
    Spec { code: session::CC_POLICY_OR, handles: 1, authorized: 0 },
    Spec { code: session::CC_POLICY_AUTH_VALUE, handles: 1, authorized: 0 },
    Spec { code: session::CC_POLICY_PASSWORD, handles: 1, authorized: 0 },
    Spec { code: session::CC_POLICY_COMMAND_CODE, handles: 1, authorized: 0 },
    Spec { code: session::CC_POLICY_NV_WRITTEN, handles: 1, authorized: 0 },
    Spec { code: session::CC_POLICY_AUTHORIZE_NV, handles: 3, authorized: 1 },
    Spec { code: session::CC_POLICY_SIGNED, handles: 2, authorized: 0 },
    Spec { code: nv::CC_NV_DEFINE_SPACE, handles: 1, authorized: 1 },
    Spec { code: nv::CC_NV_UNDEFINE_SPACE, handles: 2, authorized: 1 },
    Spec { code: nv::CC_NV_READ_PUBLIC, handles: 1, authorized: 0 },
    Spec { code: nv::CC_NV_READ, handles: 2, authorized: 1 },
    Spec { code: nv::CC_NV_WRITE, handles: 2, authorized: 1 },
    Spec { code: nv::CC_NV_EXTEND, handles: 2, authorized: 1 },
    Spec { code: nv::CC_NV_INCREMENT, handles: 2, authorized: 1 },
    Spec { code: nv::CC_NV_SET_BITS, handles: 2, authorized: 1 },
];

const ALG_HMAC: u16 = 0x0005;
const ALG_KEYEDHASH: u16 = 0x0008;
const ALG_SHA256: u16 = 0x000b;
const ALG_NULL: u16 = 0x0010;
/// `TPMA_ALGORITHM`: asymmetric, symmetric, hash, object, signing, encrypting,
/// method are bits 0, 1, 2, 3, 8, 9, 10.
const ALGS: [(u16, u32); 12] = [
    (object::ALG_RSA, 1 << 0 | 1 << 3),
    (ALG_HMAC, 1 << 2 | 1 << 8),
    (object::ALG_AES, 1 << 1),
    (ALG_KEYEDHASH, 1 << 3),
    (ALG_SHA256, 1 << 2),
    (ALG_NULL, 0),
    (object::ALG_RSASSA, 1 << 0 | 1 << 8),
    (object::ALG_ECDSA, 1 << 0 | 1 << 8 | 1 << 10),
    (object::ALG_ECDH, 1 << 0 | 1 << 10),
    (object::ALG_ECC, 1 << 0 | 1 << 3),
    (object::ALG_SYMCIPHER, 1 << 3),
    (object::ALG_CFB, 1 << 10),
];

/// The first byte of the vendor strings, packed four to a property.
const fn four(s: &[u8; 4]) -> u32 {
    (s[0] as u32) << 24 | (s[1] as u32) << 16 | (s[2] as u32) << 8 | s[3] as u32
}

/// `TPM_PT_*` fixed and variable properties, in property order.
const PROPERTIES: [(u32, u32); 58] = [
    (0x100, four(b"2.0\0")),
    (0x101, 0),
    (0x102, 159),
    (0x103, 0x16),
    (0x104, 2023),
    (0x105, four(b"RPI\0")),
    (0x106, four(b"Pi 4")),
    (0x107, four(b"fTPM")),
    (0x108, 0),
    (0x109, 0),
    (0x10a, 1),
    (0x10b, 0x0001_0000),
    (0x10c, 0),
    (0x10d, MAX_COMMAND as u32),
    (0x10e, 3),
    (0x10f, 7),
    (0x110, 3),
    (0x111, 64),
    (0x112, PCRS as u32),
    (0x113, 3),
    (0x114, 0xffff),
    (0x115, 0),
    (0x116, nv::SLOTS as u32),
    (0x117, nv::DATA_MAX as u32),
    (0x118, 0),
    (0x119, 0x1000),
    (0x11a, ALG_SHA256 as u32),
    (0x11b, ALG_NULL as u32),
    (0x11c, 0),
    (0x11d, 0xff),
    (0x11e, MAX_COMMAND as u32),
    (0x11f, MAX_COMMAND as u32),
    (0x120, 32),
    (0x121, 0),
    (0x122, 0),
    (0x123, 1),
    (0x124, 0),
    (0x125, 100),
    (0x126, 0),
    (0x127, 2023),
    (0x128, 0),
    (0x129, COMMANDS.len() as u32),
    (0x12a, COMMANDS.len() as u32),
    (0x12b, 0),
    (0x12c, nv::DATA_MAX as u32),
    (0x12d, 0),
    (0x200, 0),
    (0x201, 0xf),
    (0x202, 0),
    (0x203, 0),
    (0x204, 3),
    (0x205, 0),
    (0x206, 64),
    (0x207, 3),
    (0x208, 0),
    (0x209, object::PERSISTENT_SLOTS as u32),
    (0x20a, 0),
    (0x20b, 0),
];

/// Where a response is built.
struct Out<'a> {
    buf: &'a mut [u8],
    at: usize,
}

impl Out<'_> {
    fn put(&mut self, bytes: &[u8]) -> bool {
        let Some(room) = self.buf.get_mut(self.at..self.at + bytes.len()) else { return false };
        room.copy_from_slice(bytes);
        self.at += bytes.len();
        true
    }
    fn u8(&mut self, v: u8) -> bool {
        self.put(&[v])
    }
    fn u16(&mut self, v: u16) -> bool {
        self.put(&v.to_be_bytes())
    }
    fn u32(&mut self, v: u32) -> bool {
        self.put(&v.to_be_bytes())
    }
    fn u64(&mut self, v: u64) -> bool {
        self.put(&v.to_be_bytes())
    }
}

/// Where a command is read.
struct In<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> In<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let bytes = self.buf.get(self.at..self.at.checked_add(n)?)?;
        self.at += n;
        Some(bytes)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_be_bytes(self.take(2)?.try_into().ok()?))
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }
    /// A `TPM2B`: its two-byte size, then that many bytes.
    fn sized(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
    fn rest(&self) -> usize {
        self.buf.len() - self.at
    }
}

/// A response with only a code.
fn fail(out: &mut [u8], rc: u32) -> usize {
    out[..2].copy_from_slice(&ST_NO_SESSIONS.to_be_bytes());
    out[2..6].copy_from_slice(&10u32.to_be_bytes());
    out[6..10].copy_from_slice(&rc.to_be_bytes());
    10
}

/// Run one command and build its response. The length of the response.
pub fn execute(command: &[u8], response: &mut [u8]) -> usize {
    let mut input = In { buf: command, at: 0 };
    let (Some(tag), Some(size), Some(code)) = (input.u16(), input.u32(), input.u32()) else {
        return fail(response, RC_COMMAND_SIZE);
    };
    if size as usize != command.len() {
        return fail(response, RC_COMMAND_SIZE);
    }
    if tag != ST_NO_SESSIONS && tag != ST_SESSIONS {
        return fail(response, RC_BAD_TAG);
    }
    if let Some(spec) = OBJECT_COMMANDS.iter().find(|spec| spec.code == code) {
        return object_command(spec, tag, &mut input, response);
    }
    let mut body = Out { buf: response, at: 10 };
    let result = run(code, tag, &mut input, &mut body);
    // A command that took a hierarchy's proof (`Hash`'s ticket) has had the
    // device key's pads on the stack.
    keystore::scrub();
    match result {
        Ok(sessions) => {
            let len = body.at;
            let tag = if sessions { ST_SESSIONS } else { ST_NO_SESSIONS };
            response[..2].copy_from_slice(&tag.to_be_bytes());
            response[2..6].copy_from_slice(&(len as u32).to_be_bytes());
            response[6..10].copy_from_slice(&RC_SUCCESS.to_be_bytes());
            len
        }
        Err(rc) => {
            crate::warn!("tpm2", "command failed"; code = format_args!("{:#x}", code), rc = format_args!("{:#x}", rc));
            fail(response, rc)
        }
    }
}

/// The name of what a handle stands for, as it goes into a command's hash: an
/// object's name, and for everything else the handle itself.
pub(self) fn name_for(handle: u32) -> ([u8; 34], usize) {
    let mut name = [0u8; 34];
    if let Some(index) = nv::index_of(handle) {
        return (nv::name(index), 34);
    }
    match object::slot_of(handle) {
        Some(slot) => (slot.name, 34),
        None => {
            name[..4].copy_from_slice(&handle.to_be_bytes());
            (name, 4)
        }
    }
}

/// A command on objects or sessions: its handles, authorization and
/// parameters in the form the specification gives them, and the response.
#[allow(unused_variables)]
fn object_command(spec: &Spec, tag: u16, input: &mut In, response: &mut [u8]) -> usize {
    let started = stc::now();
    let result = object_run(spec, tag, input, response);
    keystore::scrub();
    crate::debug!("tpm2", "object command done"; code = format_args!("{:#x}", spec.code), us = stc::now() - started);
    match result {
        Ok(len) => len,
        Err(rc) => {
            crate::warn!("tpm2", "command failed"; code = format_args!("{:#x}", spec.code), rc = format_args!("{:#x}", rc));
            fail(response, rc)
        }
    }
}

fn object_run(spec: &Spec, tag: u16, input: &mut In, response: &mut [u8]) -> Result<usize, u32> {
    let mut handles = [0u32; 3];
    for handle in handles.iter_mut().take(spec.handles) {
        *handle = input.u32().ok_or(RC_COMMAND_SIZE)?;
    }
    let area = if tag == ST_SESSIONS {
        let size = input.u32().ok_or(RC_COMMAND_SIZE)? as usize;
        input.take(size).ok_or(RC_COMMAND_SIZE)?
    } else {
        &[]
    };
    let (sent, count) = session::parse_area(area)?;
    let wire = &input.buf[input.at..];
    let mut names = [([0u8; 34], 0usize); 3];
    for (name, handle) in names.iter_mut().zip(&handles).take(spec.handles) {
        *name = name_for(*handle);
    }
    let a = session::Authorization::get();
    let outcome = (|| {
        session::authorize(a, spec.code, &handles[..spec.handles], &names[..spec.handles], spec.authorized, &sent[..count], wire)?;
        let plain = a.decrypted_len();
        let mut params = In { buf: if plain.is_some() { session::plain(plain.unwrap()) } else { wire }, at: 0 };
        dispatch(spec.code, &handles, &mut params, a)
    })();
    let result = match outcome {
        Ok(()) => Ok(session::respond(a, spec.code, response)),
        Err(rc) => Err(rc),
    };
    a.wipe();
    result
}

fn dispatch(code: u32, handles: &[u32; 3], params: &mut In, a: &mut session::Authorization) -> Result<(), u32> {
    let mut command = object::Command { handles: [handles[0], handles[1]], params: In { buf: params.buf, at: params.at }, auth: a };
    match code {
        object::CC_CREATE_PRIMARY => object::create_primary(&mut command),
        object::CC_CREATE => object::create(&mut command),
        object::CC_LOAD => object::load(&mut command),
        object::CC_UNSEAL => object::unseal(&mut command),
        object::CC_LOAD_EXTERNAL => object::load_external(&mut command),
        session::CC_POLICY_AUTHORIZE => session::policy_authorize(handles[0], params, a),
        session::CC_POLICY_SIGNED => session::policy_signed([handles[0], handles[1]], params, a),
        session::CC_POLICY_AUTHORIZE_NV => {
            if params.rest() != 0 {
                return Err(RC_COMMAND_SIZE);
            }
            session::policy_authorize_nv(*handles, a)
        }
        sign::CC_SIGN => sign::sign(&mut command),
        sign::CC_QUOTE => sign::quote(&mut command),
        sign::CC_VERIFY_SIGNATURE => sign::verify(&mut command),
        session::CC_POLICY_SECRET => session::policy_secret(handles[0], handles[1], params, a),
        object::CC_READ_PUBLIC => object::read_public_command(&mut command),
        object::CC_EVICT_CONTROL => object::evict_control(&mut command),
        object::CC_TEST_PARMS => object::test_parms(&mut command),
        object::CC_FLUSH_CONTEXT => context::flush(params),
        object::CC_CONTEXT_SAVE => context::save(handles[0], params, a),
        object::CC_CONTEXT_LOAD => context::load(params, a),
        nv::CC_NV_DEFINE_SPACE => nv::define_space([handles[0], handles[1]], params, a),
        nv::CC_NV_UNDEFINE_SPACE => nv::undefine_space([handles[0], handles[1]]),
        nv::CC_NV_READ_PUBLIC => nv::read_public(handles[0], a),
        nv::CC_NV_READ => nv::read([handles[0], handles[1]], params, a),
        nv::CC_NV_WRITE => nv::write([handles[0], handles[1]], params, a),
        nv::CC_NV_EXTEND => nv::extend([handles[0], handles[1]], params, a),
        nv::CC_NV_INCREMENT => nv::increment([handles[0], handles[1]], a),
        nv::CC_NV_SET_BITS => nv::set_bits([handles[0], handles[1]], params, a),
        session::CC_START_AUTH_SESSION => session::start_auth_session(code, &handles[..2], params, a),
        _ => session::policy(code, handles[0], params, a),
    }
}

/// The authorization area of a command whose first handle is a PCR: a
/// password session with an empty password, which is all a PCR has. Whether
/// the command carried sessions is what the response then has to say.
fn password_session(input: &mut In, tag: u16) -> Result<bool, u32> {
    if tag != ST_SESSIONS {
        return Err(RC_AUTH_MISSING);
    }
    let area = input.u32().ok_or(RC_COMMAND_SIZE)? as usize;
    let mut sessions = In { buf: input.take(area).ok_or(RC_COMMAND_SIZE)?, at: 0 };
    let handle = sessions.u32().ok_or(RC_COMMAND_SIZE)?;
    let nonce = sessions.sized().ok_or(RC_COMMAND_SIZE)?;
    let _attributes = sessions.u8().ok_or(RC_COMMAND_SIZE)?;
    let hmac = sessions.sized().ok_or(RC_COMMAND_SIZE)?;
    // TPM_RS_PW. Any other session would need keys this TPM does not have.
    if handle != 0x4000_0009 || !nonce.is_empty() || !hmac.is_empty() || sessions.rest() != 0 {
        return Err(RC_AUTH_UNAVAILABLE);
    }
    Ok(true)
}

/// A response's authorization area for one password session: no nonce, the
/// continue-session attribute, no HMAC.
fn password_response(out: &mut Out) {
    out.u16(0);
    out.u8(1);
    out.u16(0);
}

fn run(code: u32, tag: u16, input: &mut In, out: &mut Out) -> Result<bool, u32> {
    match code {
        CC_STARTUP => {
            input.u16().ok_or(RC_COMMAND_SIZE)?;
            Err(RC_INITIALIZE)
        }
        CC_SHUTDOWN => {
            input.u16().ok_or(RC_COMMAND_SIZE)?;
            Ok(false)
        }
        CC_SELF_TEST => {
            input.u8().ok_or(RC_COMMAND_SIZE)?;
            Ok(false)
        }
        CC_INCREMENTAL_SELF_TEST => {
            let count = input.u32().ok_or(RC_COMMAND_SIZE)? as usize;
            input.take(count * 2).ok_or(RC_COMMAND_SIZE)?;
            out.u32(0);
            Ok(false)
        }
        CC_GET_TEST_RESULT => {
            out.u16(0);
            out.u32(RC_SUCCESS);
            Ok(false)
        }
        CC_STIR_RANDOM => {
            input.sized().ok_or(RC_COMMAND_SIZE)?;
            Ok(false)
        }
        CC_GET_RANDOM => {
            let wanted = input.u16().ok_or(RC_COMMAND_SIZE)? as usize;
            let wanted = wanted.min(32);
            let mut bytes = [0u8; 32];
            if !rng::fill(&mut bytes[..wanted]) {
                return Err(RC_RANGE);
            }
            out.u16(wanted as u16);
            out.put(&bytes[..wanted]);
            Ok(false)
        }
        CC_GET_CAPABILITY => get_capability(input, out).map(|_| false),
        CC_PCR_READ => pcr_read(input, out).map(|_| false),
        CC_PCR_EXTEND => pcr_extend(tag, input, out),
        CC_PCR_EVENT => pcr_event(tag, input, out),
        CC_PCR_RESET => pcr_reset(tag, input, out),
        CC_HASH => hash(input, out).map(|_| false),
        CC_READ_CLOCK => {
            let ms = stc::now() / 1000;
            out.u64(ms);
            out.u64(ms);
            out.u32(0);
            out.u32(0);
            out.u8(1);
            Ok(false)
        }
        _ => Err(RC_COMMAND_CODE),
    }
}

fn get_capability(input: &mut In, out: &mut Out) -> Result<(), u32> {
    let capability = input.u32().ok_or(RC_COMMAND_SIZE)?;
    let property = input.u32().ok_or(RC_COMMAND_SIZE)?;
    let count = input.u32().ok_or(RC_COMMAND_SIZE)? as usize;
    // The `moreData` byte comes first, and is patched once the list is built.
    let more_at = out.at;
    out.u8(0);
    out.u32(capability);
    let mut more = false;
    match capability {
        0 => {
            let list = ALGS.iter().filter(|(alg, _)| *alg as u32 >= property);
            let shown = list.clone().take(count).count();
            more = list.count() > shown;
            out.u32(shown as u32);
            for (alg, attributes) in ALGS.iter().filter(|(alg, _)| *alg as u32 >= property).take(count) {
                out.u16(*alg);
                out.u32(*attributes);
            }
        }
        1 => {
            let kind = property >> 24;
            let mut loaded = [0u32; 16];
            let mut n = 0;
            let handles: &[u32] = match kind {
                0x00 => &PCR_HANDLES,
                0x40 => &[0x4000_0001, 0x4000_0007, 0x4000_000a, 0x4000_000b, 0x4000_000c, 0x4000_0009],
                0x80 => {
                    for (i, _) in object::table().iter().enumerate().filter(|(_, s)| s.used) {
                        loaded[n] = object::TRANSIENT_FIRST + i as u32;
                        n += 1;
                    }
                    &loaded[..n]
                }
                0x81 => {
                    for (handle, _) in object::persistent() {
                        loaded[n] = handle;
                        n += 1;
                    }
                    loaded[..n].sort_unstable();
                    &loaded[..n]
                }
                0x01 => {
                    for handle in nv::handles() {
                        loaded[n] = handle;
                        n += 1;
                    }
                    loaded[..n].sort_unstable();
                    &loaded[..n]
                }
                0x02 | 0x03 => {
                    for handle in session::handles().filter(|h| h >> 24 == kind) {
                        loaded[n] = handle;
                        n += 1;
                    }
                    &loaded[..n]
                }
                _ => &[],
            };
            let list = handles.iter().filter(|h| **h >= property);
            let shown = list.clone().take(count).count();
            more = list.count() > shown;
            out.u32(shown as u32);
            for h in handles.iter().filter(|h| **h >= property).take(count) {
                out.u32(*h);
            }
        }
        2 => {
            let list = COMMANDS.iter().filter(|(cc, _)| *cc >= property);
            let shown = list.clone().take(count).count();
            more = list.count() > shown;
            out.u32(shown as u32);
            for (cc, handles) in COMMANDS.iter().filter(|(cc, _)| *cc >= property).take(count) {
                out.u32(cc | (handles & 7) << 25 | (handles >> 3) << 28);
            }
        }
        5 => {
            out.u32(1);
            out.u16(ALG_SHA256);
            out.u8(3);
            out.put(&[0xff; 3]);
        }
        6 => {
            let list = PROPERTIES.iter().filter(|(p, _)| *p >= property);
            let shown = list.clone().take(count).count();
            more = list.count() > shown;
            out.u32(shown as u32);
            let held = object::persistent().count() as u32;
            let indices = nv::handles().count() as u32;
            let counters = nv::counters() as u32;
            for (p, v) in PROPERTIES.iter().filter(|(p, _)| *p >= property).take(count) {
                out.u32(*p);
                out.u32(match *p {
                    0x208 => held,
                    0x209 => object::PERSISTENT_SLOTS as u32 - held,
                    0x202 => indices,
                    0x20a => counters,
                    0x20b => nv::SLOTS as u32 - counters,
                    _ => *v,
                });
            }
        }
        8 => {
            let more_curves = object::CURVE_P256 as u32 >= property;
            out.u32(more_curves as u32);
            if more_curves {
                out.u16(object::CURVE_P256);
            }
        }
        // PCR properties, the audit and PP command lists, the authorization
        // policies and the vendor range: empty lists.
        3 | 4 | 7 | 9 | 0x100 => {
            out.u32(0);
        }
        _ => return Err(RC_VALUE | RC_P | RC_1),
    }
    out.buf[more_at] = more as u8;
    Ok(())
}

const PCR_HANDLES: [u32; PCRS] = {
    let mut h = [0u32; PCRS];
    let mut i = 0;
    while i < PCRS {
        h[i] = i as u32;
        i += 1;
    }
    h
};

/// A `TPML_PCR_SELECTION` read: the SHA-256 selections it names, as a mask.
/// Other banks select nothing.
fn read_selection(input: &mut In) -> Result<u32, u32> {
    let count = input.u32().ok_or(RC_COMMAND_SIZE)?;
    let mut mask = 0u32;
    for _ in 0..count {
        let alg = input.u16().ok_or(RC_COMMAND_SIZE)?;
        let size = input.u8().ok_or(RC_COMMAND_SIZE)? as usize;
        let bits = input.take(size).ok_or(RC_COMMAND_SIZE)?;
        if alg == ALG_SHA256 {
            for (i, b) in bits.iter().enumerate().take(3) {
                mask |= (*b as u32) << (8 * i);
            }
            mask &= (1 << PCRS) - 1;
        }
    }
    Ok(mask)
}

/// The most digests one `TPM2_PCR_Read` answers with (`TPML_DIGEST`).
const PCR_READ_MAX: usize = 8;

fn pcr_read(input: &mut In, out: &mut Out) -> Result<(), u32> {
    let wanted = read_selection(input).map_err(|rc| rc | RC_P | RC_1)?;
    let selected = (0..PCRS).filter(|i| wanted >> i & 1 != 0).take(PCR_READ_MAX).fold(0u32, |mask, i| mask | 1 << i);
    out.u32(keystore::count());
    out.u32(1);
    out.u16(ALG_SHA256);
    out.u8(3);
    out.put(&selected.to_le_bytes()[..3]);
    out.u32(selected.count_ones());
    for i in (0..PCRS).filter(|i| selected >> i & 1 != 0) {
        out.u16(32);
        out.put(&keystore::pcr(i).ok_or(RC_RANGE)?);
    }
    Ok(())
}

/// PCRs a command at locality 0 may extend: all but the DRTM registers.
fn extendable(pcr: u32) -> bool {
    pcr < PCRS as u32 && !(17..=22).contains(&pcr)
}

fn pcr_handle(input: &mut In) -> Result<u32, u32> {
    let handle = input.u32().ok_or(RC_COMMAND_SIZE)?;
    if handle >= PCRS as u32 {
        return Err(RC_HANDLE | RC_1);
    }
    Ok(handle)
}

fn pcr_extend(tag: u16, input: &mut In, out: &mut Out) -> Result<bool, u32> {
    let pcr = pcr_handle(input)?;
    password_session(input, tag)?;
    let count = input.u32().ok_or(RC_COMMAND_SIZE)?;
    let mut digest = None;
    for _ in 0..count {
        let alg = input.u16().ok_or(RC_COMMAND_SIZE)?;
        if alg != ALG_SHA256 {
            return Err(RC_HASH | RC_P | RC_1);
        }
        digest = Some(<[u8; 32]>::try_from(input.take(32).ok_or(RC_COMMAND_SIZE)?).unwrap());
    }
    if input.rest() != 0 {
        return Err(RC_COMMAND_SIZE);
    }
    if !extendable(pcr) {
        return Err(RC_LOCALITY);
    }
    if let Some(digest) = digest {
        keystore::extend(pcr as usize, &digest).map_err(|_| RC_HANDLE | RC_1)?;
    }
    out.u32(0);
    password_response(out);
    Ok(true)
}

fn pcr_event(tag: u16, input: &mut In, out: &mut Out) -> Result<bool, u32> {
    let pcr = pcr_handle(input)?;
    password_session(input, tag)?;
    let event = input.sized().ok_or(RC_COMMAND_SIZE)?;
    if input.rest() != 0 {
        return Err(RC_COMMAND_SIZE);
    }
    if event.len() > 1024 {
        return Err(RC_SIZE | RC_P | RC_1);
    }
    if !extendable(pcr) {
        return Err(RC_LOCALITY);
    }
    let digest = sha256::digest(event);
    keystore::extend(pcr as usize, &digest).map_err(|_| RC_HANDLE | RC_1)?;
    out.u32(4 + 2 + 32);
    out.u32(1);
    out.u16(ALG_SHA256);
    out.put(&digest);
    password_response(out);
    Ok(true)
}

fn pcr_reset(tag: u16, input: &mut In, out: &mut Out) -> Result<bool, u32> {
    let pcr = pcr_handle(input)?;
    password_session(input, tag)?;
    if input.rest() != 0 {
        return Err(RC_COMMAND_SIZE);
    }
    if pcr != 16 && pcr != 23 {
        return Err(RC_LOCALITY);
    }
    keystore::reset(pcr as usize).map_err(|_| RC_HANDLE | RC_1)?;
    out.u32(0);
    password_response(out);
    Ok(true)
}

fn hash(input: &mut In, out: &mut Out) -> Result<(), u32> {
    let data = input.sized().ok_or(RC_COMMAND_SIZE)?;
    let alg = input.u16().ok_or(RC_COMMAND_SIZE)?;
    let hierarchy = input.u32().ok_or(RC_COMMAND_SIZE)?;
    if alg != ALG_SHA256 {
        return Err(RC_HASH | RC_P | 2 * RC_1);
    }
    if !matches!(hierarchy, object::RH_NULL | object::RH_OWNER | object::RH_ENDORSEMENT | object::RH_PLATFORM) {
        return Err(RC_VALUE | RC_P | 3 * RC_1);
    }
    let digest = sha256::digest(data);
    out.u16(32);
    out.put(&digest);
    sign::hash_ticket(out, hierarchy, data, &digest);
    Ok(())
}

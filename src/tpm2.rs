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
//! PCRs 16 and 23 resettable. No hierarchy and no keys yet, so every command
//! that names a handle but a PCR gets `TPM_RC_COMMAND_CODE`.

use crate::keystore::{self, PCRS};
use crate::{rng, sha256, stc};

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
const RC_COMMAND_CODE: u32 = 0x143;
const RC_BAD_TAG: u32 = 0x1e;
/// The format-one codes: the parameter or handle number goes in bits 8-11 and
/// bit 6 says it is a parameter (as `RC_P`), bit 7 a handle.
const RC_VALUE: u32 = 0x84;
const RC_HASH: u32 = 0x083;
const RC_RANGE: u32 = 0x08d;
const RC_LOCALITY: u32 = 0x107;
const RC_HANDLE: u32 = 0x08b;
const RC_AUTH_UNAVAILABLE: u32 = 0x12f;
const RC_AUTH_MISSING: u32 = 0x125;
const RC_SIZE: u32 = 0x095;
const RC_P: u32 = 0x40;
const RC_1: u32 = 0x100;

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

/// Commands in numeric order, for `TPM_CAP_COMMANDS`; the attributes are what
/// `TPMA_CC` carries besides the code: the number of handles in the command
/// (bits 25-27).
const COMMANDS: [(u32, u32); 14] = [
    (CC_PCR_RESET, 1),
    (CC_INCREMENTAL_SELF_TEST, 0),
    (CC_SELF_TEST, 0),
    (CC_STARTUP, 0),
    (CC_SHUTDOWN, 0),
    (CC_STIR_RANDOM, 0),
    (CC_PCR_EVENT, 1),
    (CC_GET_CAPABILITY, 0),
    (CC_GET_RANDOM, 0),
    (CC_GET_TEST_RESULT, 0),
    (CC_HASH, 0),
    (CC_PCR_READ, 0),
    (CC_READ_CLOCK, 0),
    (CC_PCR_EXTEND, 1),
];

const ALG_HMAC: u16 = 0x0005;
const ALG_KEYEDHASH: u16 = 0x0008;
const ALG_SHA256: u16 = 0x000b;
const ALG_NULL: u16 = 0x0010;
/// `TPMA_ALGORITHM`: asymmetric, symmetric, hash, object, signing, encrypting,
/// method are bits 0, 1, 2, 3, 8, 9, 10.
const ALGS: [(u16, u32); 4] = [
    (ALG_HMAC, 1 << 2 | 1 << 8),
    (ALG_KEYEDHASH, 1 << 3),
    (ALG_SHA256, 1 << 2),
    (ALG_NULL, 0),
];

/// The first byte of the vendor strings, packed four to a property.
const fn four(s: &[u8; 4]) -> u32 {
    (s[0] as u32) << 24 | (s[1] as u32) << 16 | (s[2] as u32) << 8 | s[3] as u32
}

/// `TPM_PT_*` fixed and variable properties, in property order.
const PROPERTIES: [(u32, u32); 55] = [
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
    (0x116, 0),
    (0x117, 0),
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
    (0x12c, 1024),
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
    let mut body = Out { buf: response, at: 10 };
    let result = run(code, tag, &mut input, &mut body);
    match result {
        Ok(sessions) => {
            let len = body.at;
            let tag = if sessions { ST_SESSIONS } else { ST_NO_SESSIONS };
            response[..2].copy_from_slice(&tag.to_be_bytes());
            response[2..6].copy_from_slice(&(len as u32).to_be_bytes());
            response[6..10].copy_from_slice(&RC_SUCCESS.to_be_bytes());
            len
        }
        Err(rc) => fail(response, rc),
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
            let handles: &[u32] = match kind {
                0x00 => &PCR_HANDLES,
                0x40 => &[0x4000_0001, 0x4000_0007, 0x4000_000a, 0x4000_000b, 0x4000_000c, 0x4000_0009],
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
                out.u32(cc | handles << 25);
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
            for (p, v) in PROPERTIES.iter().filter(|(p, _)| *p >= property).take(count) {
                out.u32(*p);
                out.u32(*v);
            }
        }
        // PCR properties, ECC curves, the audit and PP command lists, the
        // authorization policies and the vendor range: empty lists.
        3 | 4 | 7 | 8 | 9 | 0x100 => {
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

fn pcr_read(input: &mut In, out: &mut Out) -> Result<(), u32> {
    let wanted = read_selection(input).map_err(|rc| rc | RC_P | RC_1)?;
    out.u32(keystore::count());
    out.u32(1);
    out.u16(ALG_SHA256);
    out.u8(3);
    out.put(&wanted.to_le_bytes()[..3]);
    out.u32(wanted.count_ones());
    for i in (0..PCRS).filter(|i| wanted >> i & 1 != 0) {
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
    // A ticket needs a hierarchy's proof value, which only a keyed hierarchy
    // has: asking for one is asking for something this TPM cannot do.
    if hierarchy != 0x4000_0007 {
        return Err(RC_VALUE | RC_P | 3 * RC_1);
    }
    out.u16(32);
    out.put(&sha256::digest(data));
    out.u16(0x8024);
    out.u32(0x4000_0007);
    out.u16(0);
    Ok(())
}

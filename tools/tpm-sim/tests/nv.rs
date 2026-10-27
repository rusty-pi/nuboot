//! NV indices as tpm2-tools and systemd use them: the owner defines an index, an
//! extend index takes a policy that lets the first write through one branch
//! and every later one through `PolicyNvWritten`.

use tpm_sim::tpm2;

const ST_NO_SESSIONS: u16 = 0x8001;
const ST_SESSIONS: u16 = 0x8002;
const RH_OWNER: u32 = 0x4000_0001;
const RH_PLATFORM: u32 = 0x4000_000c;
const RH_NULL: u32 = 0x4000_0007;
const RS_PW: u32 = 0x4000_0009;

const CC_NV_UNDEFINE_SPACE: u32 = 0x122;
const CC_NV_DEFINE_SPACE: u32 = 0x12a;
const CC_NV_INCREMENT: u32 = 0x134;
const CC_NV_SET_BITS: u32 = 0x135;
const CC_NV_EXTEND: u32 = 0x136;
const CC_NV_WRITE: u32 = 0x137;
const CC_NV_READ: u32 = 0x14e;
const CC_NV_READ_PUBLIC: u32 = 0x169;
const CC_START_AUTH_SESSION: u32 = 0x176;
const CC_POLICY_OR: u32 = 0x171;
const CC_POLICY_COMMAND_CODE: u32 = 0x16c;
const CC_POLICY_NV_WRITTEN: u32 = 0x18f;
const CC_POLICY_GET_DIGEST: u32 = 0x189;
const CC_POLICY_RESTART: u32 = 0x180;
const CC_GET_CAPABILITY: u32 = 0x17a;
const CC_CONTEXT_SAVE: u32 = 0x162;
const CC_CONTEXT_LOAD: u32 = 0x161;

const PPWRITE: u32 = 1;
const AUTHWRITE: u32 = 1 << 2;
const POLICYWRITE: u32 = 1 << 3;
const NT_COUNTER: u32 = 1 << 4;
const NT_BITS: u32 = 2 << 4;
const NT_EXTEND: u32 = 4 << 4;
const OWNERREAD: u32 = 1 << 17;
const AUTHREAD: u32 = 1 << 18;
const NO_DA: u32 = 1 << 25;
const CLEAR_STCLEAR: u32 = 1 << 27;
const WRITTEN: u32 = 1 << 29;
const PLATFORMCREATE: u32 = 1 << 30;

const RC_NV_DEFINED: u32 = 0x14c;
const RC_NV_SPACE: u32 = 0x14b;
const RC_NV_UNINITIALIZED: u32 = 0x14a;
const RC_NV_RANGE: u32 = 0x146;
const RC_AUTH_UNAVAILABLE: u32 = 0x12f;
const RC_POLICY: u32 = 0x126;

fn sized(bytes: &[u8]) -> Vec<u8> {
    let mut out = (bytes.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(bytes);
    out
}

fn send(tag: u16, code: u32, handles: &[u32], auth: &[u8], params: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    for h in handles {
        body.extend_from_slice(&h.to_be_bytes());
    }
    if tag == ST_SESSIONS {
        body.extend_from_slice(&(auth.len() as u32).to_be_bytes());
        body.extend_from_slice(auth);
    }
    body.extend_from_slice(params);
    let mut command = tag.to_be_bytes().to_vec();
    command.extend_from_slice(&((10 + body.len()) as u32).to_be_bytes());
    command.extend_from_slice(&code.to_be_bytes());
    command.extend_from_slice(&body);
    let mut response = vec![0u8; tpm2::MAX_COMMAND];
    let n = tpm2::execute(&command, &mut response);
    response.truncate(n);
    response
}

fn rc(response: &[u8]) -> u32 {
    u32::from_be_bytes(response[6..10].try_into().unwrap())
}

/// The response parameters of a command with no handle in its response.
fn params(response: &[u8]) -> &[u8] {
    if u16::from_be_bytes(response[..2].try_into().unwrap()) == ST_SESSIONS {
        let size = u32::from_be_bytes(response[10..14].try_into().unwrap()) as usize;
        &response[14..14 + size]
    } else {
        &response[10..]
    }
}

fn password(secret: &[u8]) -> Vec<u8> {
    let mut a = RS_PW.to_be_bytes().to_vec();
    a.extend(sized(&[]));
    a.push(0);
    a.extend(sized(secret));
    a
}

fn policy_auth(session: u32) -> Vec<u8> {
    let mut a = session.to_be_bytes().to_vec();
    a.extend(sized(&[1; 16]));
    a.push(0);
    a.extend(sized(&[]));
    a
}

fn public(index: u32, attributes: u32, policy: &[u8], size: u16) -> Vec<u8> {
    let mut p = index.to_be_bytes().to_vec();
    p.extend_from_slice(&0x000bu16.to_be_bytes());
    p.extend_from_slice(&attributes.to_be_bytes());
    p.extend(sized(policy));
    p.extend_from_slice(&size.to_be_bytes());
    p
}

fn define(hierarchy: u32, index: u32, attributes: u32, policy: &[u8], size: u16, auth: &[u8]) -> u32 {
    let mut p = sized(auth);
    p.extend(sized(&public(index, attributes, policy, size)));
    rc(&send(ST_SESSIONS, CC_NV_DEFINE_SPACE, &[hierarchy], &password(&[]), &p))
}

fn nv_attributes(index: u32) -> u32 {
    let response = send(ST_NO_SESSIONS, CC_NV_READ_PUBLIC, &[index], &[], &[]);
    assert_eq!(rc(&response), 0);
    let p = params(&response);
    u32::from_be_bytes(p[8..12].try_into().unwrap())
}

fn nv_name(index: u32) -> Vec<u8> {
    let response = send(ST_NO_SESSIONS, CC_NV_READ_PUBLIC, &[index], &[], &[]);
    let p = params(&response);
    let public = u16::from_be_bytes(p[..2].try_into().unwrap()) as usize;
    let name = &p[2 + public..];
    assert_eq!(&name[..2], &34u16.to_be_bytes());
    name[2..].to_vec()
}

fn read(auth: u32, index: u32, size: u16, offset: u16, secret: &[u8]) -> Result<Vec<u8>, u32> {
    let mut p = size.to_be_bytes().to_vec();
    p.extend_from_slice(&offset.to_be_bytes());
    let response = send(ST_SESSIONS, CC_NV_READ, &[auth, index], &password(secret), &p);
    match rc(&response) {
        0 => Ok(params(&response)[2..].to_vec()),
        code => Err(code),
    }
}

fn sha256(parts: &[&[u8]]) -> Vec<u8> {
    let mut all = Vec::new();
    for p in parts {
        all.extend_from_slice(p);
    }
    tpm_sim::sha256::digest(&all).to_vec()
}

fn start_session(kind: u8) -> u32 {
    let mut p = sized(&[7; 16]);
    p.extend(sized(&[]));
    p.push(kind);
    p.extend_from_slice(&0x0010u16.to_be_bytes());
    p.extend_from_slice(&0x000bu16.to_be_bytes());
    let response = send(ST_NO_SESSIONS, CC_START_AUTH_SESSION, &[RH_NULL, RH_NULL], &[], &p);
    assert_eq!(rc(&response), 0, "start session");
    u32::from_be_bytes(response[10..14].try_into().unwrap())
}

fn digest(session: u32) -> Vec<u8> {
    let response = send(ST_NO_SESSIONS, CC_POLICY_GET_DIGEST, &[session], &[], &[]);
    assert_eq!(rc(&response), 0);
    params(&response)[2..].to_vec()
}

fn policy_nv_written(session: u32, set: bool) -> u32 {
    rc(&send(ST_NO_SESSIONS, CC_POLICY_NV_WRITTEN, &[session], &[], &[set as u8]))
}

fn policy_command_code(session: u32, code: u32) -> u32 {
    rc(&send(ST_NO_SESSIONS, CC_POLICY_COMMAND_CODE, &[session], &[], &code.to_be_bytes()))
}

fn policy_or(session: u32, branches: &[&[u8]]) -> u32 {
    let mut p = (branches.len() as u32).to_be_bytes().to_vec();
    for b in branches {
        p.extend(sized(b));
    }
    rc(&send(ST_NO_SESSIONS, CC_POLICY_OR, &[session], &[], &p))
}

fn extend(auth: u32, index: u32, authorization: &[u8], data: &[u8]) -> u32 {
    rc(&send(ST_SESSIONS, CC_NV_EXTEND, &[auth, index], authorization, &sized(data)))
}

fn handles_listed() -> Vec<u32> {
    let mut p = 1u32.to_be_bytes().to_vec();
    p.extend_from_slice(&0x0100_0000u32.to_be_bytes());
    p.extend_from_slice(&64u32.to_be_bytes());
    let response = send(ST_NO_SESSIONS, CC_GET_CAPABILITY, &[], &[], &p);
    assert_eq!(rc(&response), 0);
    let body = &response[10..];
    let count = u32::from_be_bytes(body[5..9].try_into().unwrap()) as usize;
    (0..count).map(|i| u32::from_be_bytes(body[9 + 4 * i..13 + 4 * i].try_into().unwrap())).collect()
}

#[test]
fn nv_indices_as_the_tools_use_them() {
    assert!(handles_listed().is_empty());

    // An extend index with its own authorization value.
    let ext = 0x0150_0001;
    assert_eq!(define(RH_OWNER, ext, AUTHWRITE | AUTHREAD | NT_EXTEND | NO_DA, &[], 32, b"pw"), 0);
    assert_eq!(handles_listed(), vec![ext]);
    assert_eq!(define(RH_OWNER, ext, AUTHWRITE | AUTHREAD | NT_EXTEND, &[], 32, &[]), RC_NV_DEFINED);
    assert_eq!(nv_attributes(ext) & WRITTEN, 0);
    let before = nv_name(ext);
    assert_eq!(read(ext, ext, 32, 0, b"pw"), Err(RC_NV_UNINITIALIZED));
    assert_eq!(extend(ext, ext, &password(b"nope"), b"x"), 0x0a2 | 0x800 | 0x100, "a wrong password");
    assert_eq!(extend(ext, ext, &password(b"pw"), b"hello"), 0);
    assert_eq!(read(ext, ext, 32, 0, b"pw").unwrap(), sha256(&[&[0u8; 32], b"hello"]));
    assert_eq!(extend(ext, ext, &password(b"pw"), b"again"), 0);
    let once = sha256(&[&[0u8; 32], b"hello"]);
    assert_eq!(read(ext, ext, 32, 0, b"pw").unwrap(), sha256(&[&once, b"again"]));
    assert_ne!(nv_attributes(ext) & WRITTEN, 0);
    assert_ne!(nv_name(ext), before, "the name changes once the index is written");
    assert_eq!(read(ext, ext, 40, 0, b"pw"), Err(RC_NV_RANGE));

    // The owner cannot read what only the index's own value may.
    assert_eq!(rc(&send(ST_SESSIONS, CC_NV_READ, &[RH_OWNER, ext], &password(&[]), &[0, 32, 0, 0])), RC_AUTH_UNAVAILABLE);

    // A counter, a bit field and an ordinary index.
    let counter = 0x0150_0002;
    assert_eq!(define(RH_OWNER, counter, AUTHWRITE | AUTHREAD | NT_COUNTER, &[], 8, &[]), 0);
    for expected in 1u64..=3 {
        assert_eq!(rc(&send(ST_SESSIONS, CC_NV_INCREMENT, &[counter, counter], &password(&[]), &[])), 0);
        assert_eq!(read(counter, counter, 8, 0, &[]).unwrap(), expected.to_be_bytes());
    }
    let bits = 0x0150_0003;
    assert_eq!(define(RH_OWNER, bits, AUTHWRITE | AUTHREAD | NT_BITS, &[], 8, &[]), 0);
    for set in [1u64, 4] {
        assert_eq!(rc(&send(ST_SESSIONS, CC_NV_SET_BITS, &[bits, bits], &password(&[]), &set.to_be_bytes())), 0);
    }
    assert_eq!(read(bits, bits, 8, 0, &[]).unwrap(), 5u64.to_be_bytes());
    let plain = 0x0150_0004;
    assert_eq!(define(RH_OWNER, plain, AUTHWRITE | AUTHREAD, &[], 16, &[]), 0);
    let mut write = sized(b"0123456789");
    write.extend_from_slice(&3u16.to_be_bytes());
    assert_eq!(rc(&send(ST_SESSIONS, CC_NV_WRITE, &[plain, plain], &password(&[]), &write)), 0);
    assert_eq!(read(plain, plain, 10, 3, &[]).unwrap(), b"0123456789");
    let mut too_far = sized(b"0123456789");
    too_far.extend_from_slice(&10u16.to_be_bytes());
    assert_eq!(rc(&send(ST_SESSIONS, CC_NV_WRITE, &[plain, plain], &password(&[]), &too_far)), RC_NV_RANGE);

    // The platform's indices are the platform's to remove.
    let pp = 0x01c0_0001;
    assert_eq!(define(RH_OWNER, pp, PLATFORMCREATE | PPWRITE | OWNERREAD | NT_EXTEND, &[], 32, &[]), 0x082 | 0x40 | 0x200, "owner cannot set PLATFORMCREATE");
    assert_eq!(define(RH_PLATFORM, pp, PPWRITE | OWNERREAD | NT_EXTEND, &[], 32, &[]), 0x082 | 0x40 | 0x200, "the platform must");
    assert_eq!(define(RH_PLATFORM, pp, PLATFORMCREATE | PPWRITE | OWNERREAD | NT_EXTEND, &[], 32, &[]), 0);
    assert_eq!(rc(&send(ST_SESSIONS, CC_NV_UNDEFINE_SPACE, &[RH_OWNER, pp], &password(&[]), &[])), 0x149);
    assert_eq!(rc(&send(ST_SESSIONS, CC_NV_UNDEFINE_SPACE, &[RH_PLATFORM, pp], &password(&[]), &[])), 0);

    // systemd's NvPCR: the first write needs the init policy, every later
    // one PolicyNvWritten(true), joined by PolicyOR.
    let init = start_session(3);
    assert_eq!(policy_command_code(init, CC_NV_EXTEND), 0);
    let init_policy = digest(init);
    let written = start_session(3);
    assert_eq!(policy_nv_written(written, true), 0);
    let written_policy = digest(written);
    let either = start_session(3);
    assert_eq!(policy_or(either, &[&init_policy, &written_policy]), 0);
    let write_policy = digest(either);
    let nvpcr = 0x01d1_0301;
    assert_eq!(define(RH_OWNER, nvpcr, CLEAR_STCLEAR | POLICYWRITE | OWNERREAD | AUTHREAD | NT_EXTEND, &write_policy, 32, &[]), 0);
    for s in [init, written, either] {
        assert_eq!(rc(&send(ST_NO_SESSIONS, 0x165, &[], &[], &s.to_be_bytes())), 0);
    }

    // Its own password does not write it.
    assert_eq!(extend(nvpcr, nvpcr, &password(&[]), &[1; 32]), RC_AUTH_UNAVAILABLE);

    // Through the init branch.
    let first = start_session(1);
    assert_eq!(policy_command_code(first, CC_NV_EXTEND), 0);
    assert_eq!(policy_or(first, &[&init_policy, &written_policy]), 0);
    assert_eq!(digest(first), write_policy);
    assert_eq!(extend(nvpcr, nvpcr, &policy_auth(first), &[1; 32]), 0, "the initializing write");
    assert_ne!(nv_attributes(nvpcr) & WRITTEN, 0);
    assert_eq!(read(nvpcr, nvpcr, 32, 0, &[]).unwrap(), sha256(&[&[0u8; 32], &[1u8; 32]]));

    // PolicyNvWritten(true) writes later ones, and the init branch's session
    // still names the same policy.
    let later = start_session(1);
    assert_eq!(policy_nv_written(later, true), 0);
    assert_eq!(policy_or(later, &[&init_policy, &written_policy]), 0);
    assert_eq!(digest(later), write_policy);
    let saved = send(ST_NO_SESSIONS, CC_CONTEXT_SAVE, &[later], &[], &[]);
    assert_eq!(rc(&saved), 0, "a session with PolicyNvWritten saves");
    let load = send(ST_NO_SESSIONS, CC_CONTEXT_LOAD, &[], &[], &saved[10..]);
    assert_eq!(rc(&load), 0, "and loads");
    let later = u32::from_be_bytes(load[10..14].try_into().unwrap());
    assert_eq!(extend(nvpcr, nvpcr, &policy_auth(later), &[2; 32]), 0, "a later write");

    // PolicyNvWritten(true) is refused for an index nobody has written.
    let fresh = 0x01d1_0302;
    assert_eq!(define(RH_OWNER, fresh, CLEAR_STCLEAR | POLICYWRITE | OWNERREAD | AUTHREAD | NT_EXTEND, &write_policy, 32, &[]), 0);
    let early = start_session(1);
    assert_eq!(policy_nv_written(early, true), 0);
    assert_eq!(policy_or(early, &[&init_policy, &written_policy]), 0);
    assert_eq!(extend(fresh, fresh, &policy_auth(early), &[3; 32]), RC_POLICY);
    assert_eq!(rc(&send(ST_NO_SESSIONS, CC_POLICY_RESTART, &[early], &[], &[])), 0);

    // Undefine them all, and the table is not full.
    for index in [ext, counter, bits, plain, nvpcr, fresh] {
        assert_eq!(rc(&send(ST_SESSIONS, CC_NV_UNDEFINE_SPACE, &[RH_OWNER, index], &password(&[]), &[])), 0);
    }
    assert!(handles_listed().is_empty());
    for i in 0..8 {
        assert_eq!(define(RH_OWNER, 0x0150_0100 + i, AUTHWRITE | AUTHREAD | NT_EXTEND, &[], 32, &[]), 0);
    }
    assert_eq!(define(RH_OWNER, 0x0150_0200, AUTHWRITE | AUTHREAD | NT_EXTEND, &[], 32, &[]), RC_NV_SPACE);
}

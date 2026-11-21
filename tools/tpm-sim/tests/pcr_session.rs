//! The flow of the Keylime agent: an unsalted, unbound HMAC session authorizes
//! `PCR_Reset` and `PCR_Extend` of a PCR, whose authorization value is empty.

use tpm_sim::{keystore, sha256, tpm2};

const ST_NO_SESSIONS: u16 = 0x8001;
const ST_SESSIONS: u16 = 0x8002;
const RH_NULL: u32 = 0x4000_0007;
const RS_PW: u32 = 0x4000_0009;
const CC_START_AUTH_SESSION: u32 = 0x176;
const CC_PCR_EXTEND: u32 = 0x182;
const CC_PCR_EVENT: u32 = 0x14b;
const CC_PCR_RESET: u32 = 0x13d;
const ATTR_CONTINUE: u8 = 1;
const ATTR_DECRYPT: u8 = 0x20;
const ATTR_ENCRYPT: u8 = 0x40;
const RC_AUTH_FAIL: u32 = 0x98e;
const RC_HANDLE: u32 = 0x08b;

fn sized(bytes: &[u8]) -> Vec<u8> {
    let mut out = (bytes.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(bytes);
    out
}

fn send(tag: u16, code: u32, handle: Option<u32>, auth: &[u8], params: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    if let Some(h) = handle {
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

fn password() -> Vec<u8> {
    let mut a = RS_PW.to_be_bytes().to_vec();
    a.extend(sized(&[]));
    a.push(0);
    a.extend(sized(&[]));
    a
}

struct Session {
    handle: u32,
    nonce_tpm: Vec<u8>,
}

fn start_session() -> Session {
    let mut p = sized(&[7; 32]);
    p.extend(sized(&[]));
    p.push(0);
    p.extend_from_slice(&0x0010u16.to_be_bytes());
    p.extend_from_slice(&0x000bu16.to_be_bytes());
    let mut command = Vec::new();
    command.extend_from_slice(&RH_NULL.to_be_bytes());
    command.extend_from_slice(&RH_NULL.to_be_bytes());
    command.extend(p);
    let mut raw = ST_NO_SESSIONS.to_be_bytes().to_vec();
    raw.extend_from_slice(&((10 + command.len()) as u32).to_be_bytes());
    raw.extend_from_slice(&CC_START_AUTH_SESSION.to_be_bytes());
    raw.extend(command);
    let mut response = vec![0u8; tpm2::MAX_COMMAND];
    let n = tpm2::execute(&raw, &mut response);
    assert_eq!(rc(&response[..n]), 0, "start session");
    let handle = u32::from_be_bytes(response[10..14].try_into().unwrap());
    let size = u16::from_be_bytes(response[14..16].try_into().unwrap()) as usize;
    Session { handle, nonce_tpm: response[16..16 + size].to_vec() }
}

fn command_hmac(code: u32, pcr: u32, params: &[u8], nonce_caller: &[u8], nonce_tpm: &[u8], attributes: u8) -> Vec<u8> {
    let mut cp = code.to_be_bytes().to_vec();
    cp.extend_from_slice(&pcr.to_be_bytes());
    cp.extend_from_slice(params);
    let mut message = sha256::digest(&cp).to_vec();
    message.extend_from_slice(nonce_caller);
    message.extend_from_slice(nonce_tpm);
    message.push(attributes);
    sha256::hmac(&[], &message).to_vec()
}

fn authorization(session: &Session, nonce_caller: &[u8], attributes: u8, hmac: &[u8]) -> Vec<u8> {
    let mut a = session.handle.to_be_bytes().to_vec();
    a.extend(sized(nonce_caller));
    a.push(attributes);
    a.extend(sized(hmac));
    a
}

/// Run a command through the session, with the HMAC the caller computes, and
/// check the HMAC of the response when it succeeds.
fn through(session: &mut Session, code: u32, pcr: u32, params: &[u8], attributes: u8, tamper: bool) -> Vec<u8> {
    let nonce_caller = [0x5a; 32];
    let mut hmac = command_hmac(code, pcr, params, &nonce_caller, &session.nonce_tpm, attributes);
    if tamper {
        hmac[0] ^= 1;
    }
    let auth = authorization(session, &nonce_caller, attributes, &hmac);
    let response = send(ST_SESSIONS, code, Some(pcr), &auth, params);
    if rc(&response) != 0 {
        return response;
    }
    let size = u32::from_be_bytes(response[10..14].try_into().unwrap()) as usize;
    let response_params = &response[14..14 + size];
    let mut at = 14 + size;
    let nonce_len = u16::from_be_bytes(response[at..at + 2].try_into().unwrap()) as usize;
    let nonce = response[at + 2..at + 2 + nonce_len].to_vec();
    at += 2 + nonce_len;
    let returned = response[at];
    let mac_len = u16::from_be_bytes(response[at + 1..at + 3].try_into().unwrap()) as usize;
    let mac = &response[at + 3..at + 3 + mac_len];
    let mut rp = 0u32.to_be_bytes().to_vec();
    rp.extend_from_slice(&code.to_be_bytes());
    rp.extend_from_slice(response_params);
    let mut message = sha256::digest(&rp).to_vec();
    message.extend_from_slice(&nonce);
    message.extend_from_slice(&nonce_caller);
    message.push(returned);
    assert_eq!(mac, sha256::hmac(&[], &message), "response HMAC");
    session.nonce_tpm = nonce;
    response
}

fn extend_params(digest: &[u8; 32]) -> Vec<u8> {
    let mut p = 1u32.to_be_bytes().to_vec();
    p.extend_from_slice(&0x000bu16.to_be_bytes());
    p.extend_from_slice(digest);
    p
}

#[test]
fn an_hmac_session_authorizes_pcr_commands() {
    let mut session = start_session();

    assert_eq!(rc(&through(&mut session, CC_PCR_RESET, 16, &[], ATTR_CONTINUE, false)), 0, "reset");
    assert_eq!(keystore::pcr(16).unwrap(), [0; 32]);

    let digest = [0x42; 32];
    let extend = extend_params(&digest);
    assert_eq!(rc(&through(&mut session, CC_PCR_EXTEND, 16, &extend, ATTR_CONTINUE, false)), 0, "extend");
    let mut zeros_and_digest = vec![0u8; 32];
    zeros_and_digest.extend_from_slice(&digest);
    assert_eq!(keystore::pcr(16).unwrap(), sha256::digest(&zeros_and_digest));

    let wrong = through(&mut session, CC_PCR_EXTEND, 16, &extend, ATTR_CONTINUE, true);
    assert_eq!(rc(&wrong) & 0xfff, RC_AUTH_FAIL & 0xfff, "a wrong HMAC fails: {:#x}", rc(&wrong));
    assert_eq!(keystore::pcr(16).unwrap(), sha256::digest(&zeros_and_digest), "the wrong HMAC extended nothing");

    let event = through(&mut session, CC_PCR_EVENT, 16, &sized(b"event"), ATTR_CONTINUE, false);
    assert_eq!(rc(&event), 0, "event");

    for (code, attributes) in [(CC_PCR_EXTEND, ATTR_DECRYPT), (CC_PCR_RESET, ATTR_ENCRYPT), (CC_PCR_EVENT, ATTR_ENCRYPT)] {
        let params = if code == CC_PCR_EXTEND { extend.clone() } else if code == CC_PCR_EVENT { sized(b"e") } else { vec![] };
        let refused = through(&mut session, code, 16, &params, ATTR_CONTINUE | attributes, false);
        assert_ne!(rc(&refused), 0, "{code:#x} with {attributes:#x}");
    }

    let before = keystore::pcr(16).unwrap();
    let again = extend_params(&[1; 32]);
    assert_eq!(rc(&send(ST_SESSIONS, CC_PCR_EXTEND, Some(16), &password(), &again)), 0, "password session");
    assert_ne!(keystore::pcr(16).unwrap(), before);

    let single_use = through(&mut session, CC_PCR_RESET, 16, &[], 0, false);
    assert_eq!(rc(&single_use), 0);
    let gone = send(ST_SESSIONS, CC_PCR_RESET, Some(16), &authorization(&session, &[0x5a; 32], 0, &[0; 32]), &[]);
    assert_ne!(rc(&gone), 0, "a session without continueSession is flushed");

    let mut other = start_session();
    let bad_handle = through(&mut other, CC_PCR_EXTEND, 24, &extend, ATTR_CONTINUE, false);
    assert_eq!(rc(&bad_handle) & 0xff, RC_HANDLE & 0xff);
    let not_resettable = through(&mut other, CC_PCR_RESET, 3, &[], ATTR_CONTINUE, false);
    assert_ne!(rc(&not_resettable), 0, "PCR 3 is not resettable");
    let none = send(ST_NO_SESSIONS, CC_PCR_RESET, Some(16), &[], &[]);
    assert_eq!(rc(&none), 0x125, "no session");
}

//! The flow of a client behind the kernel's resource manager (`/dev/tpmrm0`):
//! around every command the manager loads the client's objects and sessions
//! with `TPM2_ContextLoad`, and afterwards saves what the command left with
//! `TPM2_ContextSave` and flushes the loaded handles. The client is the Keylime
//! agent: an EK primary, an AK created and loaded under it with a
//! `TPM2_PolicySecret` session, and a quote.

use std::collections::HashMap;
use std::sync::Mutex;
use tpm_sim::{aes, kdf, sha256, tpm2};

static ONE_TPM: Mutex<()> = Mutex::new(());

const ST_NO_SESSIONS: u16 = 0x8001;
const ST_SESSIONS: u16 = 0x8002;
const RH_NULL: u32 = 0x4000_0007;
const RH_ENDORSEMENT: u32 = 0x4000_000b;
const RS_PW: u32 = 0x4000_0009;
const CC_CREATE_PRIMARY: u32 = 0x131;
const CC_CREATE: u32 = 0x153;
const CC_LOAD: u32 = 0x157;
const CC_QUOTE: u32 = 0x158;
const CC_READ_PUBLIC: u32 = 0x173;
const CC_CONTEXT_LOAD: u32 = 0x161;
const CC_CONTEXT_SAVE: u32 = 0x162;
const CC_FLUSH_CONTEXT: u32 = 0x165;
const CC_START_AUTH_SESSION: u32 = 0x176;
const CC_POLICY_SECRET: u32 = 0x151;
const ATTR_CONTINUE: u8 = 1;
const ATTR_DECRYPT: u8 = 0x20;
const ATTR_ENCRYPT: u8 = 0x40;

fn sized(bytes: &[u8]) -> Vec<u8> {
    let mut out = (bytes.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(bytes);
    out
}

fn raw(tag: u16, code: u32, body: &[u8]) -> Vec<u8> {
    let mut command = tag.to_be_bytes().to_vec();
    command.extend_from_slice(&((10 + body.len()) as u32).to_be_bytes());
    command.extend_from_slice(&code.to_be_bytes());
    command.extend_from_slice(body);
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

fn policy_authorization(session: u32, attributes: u8) -> Vec<u8> {
    let mut a = session.to_be_bytes().to_vec();
    a.extend(sized(&[0x11; 16]));
    a.push(attributes);
    a.extend(sized(&[]));
    a
}

struct Response {
    handle: Option<u32>,
    params: Vec<u8>,
}

/// The kernel's resource manager, as `drivers/char/tpm/tpm2-space.c` has it:
/// before each command it loads every object and session the client has saved,
/// maps the client's transient handles (`0x80ffffff - n`) to the loaded ones,
/// and after it saves everything again and flushes the loaded objects. A
/// session keeps its own handle, which a loaded context has to give back.
#[derive(Default)]
struct Manager {
    objects: Vec<Option<Vec<u8>>>,
    sessions: Vec<(u32, Vec<u8>)>,
    nonces: HashMap<u32, Vec<u8>>,
}

const CALLER_NONCE: [u8; 16] = [0x11; 16];

fn crypt_first(params: &mut [u8], newer: &[u8], older: &[u8], decrypt: bool) {
    let size = u16::from_be_bytes([params[0], params[1]]) as usize;
    let mut material = [0u8; 32];
    kdf::kdfa(&[], b"CFB", newer, older, 256, &mut material);
    let cipher = aes::Aes128::new(material[..16].try_into().unwrap());
    let iv: [u8; 16] = material[16..].try_into().unwrap();
    let body = &mut params[2..2 + size];
    if decrypt {
        cipher.cfb_decrypt(&iv, body);
    } else {
        cipher.cfb_encrypt(&iv, body);
    }
}

fn is_transient(handle: u32) -> bool {
    handle >> 24 == 0x80
}

fn vhandle(index: usize) -> u32 {
    0x80ff_ffff - index as u32
}

impl Manager {
    fn load_context(context: &[u8]) -> u32 {
        let response = raw(ST_NO_SESSIONS, CC_CONTEXT_LOAD, context);
        assert_eq!(rc(&response), 0, "ContextLoad");
        u32::from_be_bytes(response[10..14].try_into().unwrap())
    }

    fn save_context(real: u32) -> Option<Vec<u8>> {
        let response = raw(ST_NO_SESSIONS, CC_CONTEXT_SAVE, &real.to_be_bytes());
        match rc(&response) {
            0 => {
                if is_transient(real) {
                    raw(ST_NO_SESSIONS, CC_FLUSH_CONTEXT, &real.to_be_bytes());
                }
                Some(response[10..].to_vec())
            }
            0x910 => None,
            other => panic!("ContextSave of {real:08x} failed: {other:#x}"),
        }
    }

    fn run(&mut self, code: u32, handles: &[u32], auth: &[(u32, Vec<u8>)], params: &[u8], new_handle: bool) -> Response {
        self.run_encrypted(code, handles, auth, params, new_handle, None)
    }

    /// As [`Manager::run`], with the first parameter going to the TPM and the first
    /// response parameter coming back encrypted by `encrypt`'s key.
    fn run_encrypted(&mut self, code: u32, handles: &[u32], auth: &[(u32, Vec<u8>)], params: &[u8], new_handle: bool, encrypt: Option<u32>) -> Response {
        let mut params = params.to_vec();
        if let Some(session) = encrypt {
            crypt_first(&mut params, &CALLER_NONCE, &self.nonces[&session], false);
        }

        let mut loaded: Vec<(usize, u32)> = Vec::new();
        for (i, context) in self.objects.iter().enumerate() {
            if let Some(context) = context {
                loaded.push((i, Self::load_context(context)));
            }
        }
        for (handle, context) in &self.sessions {
            assert_eq!(Self::load_context(context), *handle, "a session is restored to its handle");
        }

        let real = |handle: u32| match is_transient(handle) {
            true => loaded.iter().find(|(i, _)| vhandle(*i) == handle).expect("a transient handle the client holds").1,
            false => handle,
        };
        let mut body = Vec::new();
        for &h in handles {
            body.extend_from_slice(&real(h).to_be_bytes());
        }
        let mut area = Vec::new();
        for (h, rest) in auth {
            area.extend_from_slice(&h.to_be_bytes());
            area.extend_from_slice(rest);
        }
        let tag = if auth.is_empty() { ST_NO_SESSIONS } else { ST_SESSIONS };
        if !auth.is_empty() {
            body.extend_from_slice(&(area.len() as u32).to_be_bytes());
            body.extend_from_slice(&area);
        }
        body.extend_from_slice(&params);
        let response = raw(tag, code, &body);
        let ok = rc(&response) == 0;

        let mut out = Response { handle: None, params: Vec::new() };
        if ok {
            let mut at = 10;
            if new_handle {
                let h = u32::from_be_bytes(response[10..14].try_into().unwrap());
                at = 14;
                if is_transient(h) {
                    let index = (0..).find(|i| self.objects.get(*i).is_none_or(|o| o.is_none()) && !loaded.iter().any(|(l, _)| l == i)).unwrap();
                    loaded.push((index, h));
                    if index == self.objects.len() {
                        self.objects.push(None);
                    }
                    out.handle = Some(vhandle(index));
                } else {
                    self.sessions.push((h, Vec::new()));
                    self.nonces.insert(h, sized_at(&response, 14).0.to_vec());
                    out.handle = Some(h);
                }
            }
            if tag == ST_SESSIONS {
                let size = u32::from_be_bytes(response[at..at + 4].try_into().unwrap()) as usize;
                out.params = response[at + 4..at + 4 + size].to_vec();
                let mut cursor = at + 4 + size;
                for (h, _) in auth {
                    if *h == RS_PW {
                        cursor += 2 + 1 + 2;
                        continue;
                    }
                    let (nonce, next) = sized_at(&response, cursor);
                    self.nonces.insert(*h, nonce.to_vec());
                    if encrypt == Some(*h) {
                        crypt_first(&mut out.params, nonce, &CALLER_NONCE, true);
                    }
                    cursor = sized_at(&response, next + 1).1;
                }
            } else {
                out.params = response[at..].to_vec();
            }
        }

        for (index, real) in loaded {
            self.objects[index] = Self::save_context(real);
        }
        let sessions = std::mem::take(&mut self.sessions);
        for (handle, _) in sessions {
            if let Some(context) = Self::save_context(handle) {
                self.sessions.push((handle, context));
            }
        }
        assert!(ok, "command {code:#x} failed with {:#x}", rc(&response));
        out
    }

    fn flush_session(&mut self, handle: u32) {
        self.sessions.retain(|(h, _)| *h != handle);
        let response = raw(ST_NO_SESSIONS, CC_FLUSH_CONTEXT, &handle.to_be_bytes());
        assert_eq!(rc(&response), 0, "FlushContext of the saved session");
    }
}

fn policy_secret_digest() -> [u8; 32] {
    let name = RH_ENDORSEMENT.to_be_bytes();
    let mut message = vec![0u8; 32];
    message.extend_from_slice(&CC_POLICY_SECRET.to_be_bytes());
    message.extend_from_slice(&name);
    sha256::digest(&sha256::digest(&message))
}

fn ek_template() -> Vec<u8> {
    let mut t = 0x0023u16.to_be_bytes().to_vec();
    t.extend_from_slice(&0x000bu16.to_be_bytes());
    t.extend_from_slice(&0x0003_00b2u32.to_be_bytes());
    t.extend(sized(&policy_secret_digest()));
    t.extend_from_slice(&[0x00, 0x06, 0x00, 0x80, 0x00, 0x43]);
    t.extend_from_slice(&0x0010u16.to_be_bytes());
    t.extend_from_slice(&0x0003u16.to_be_bytes());
    t.extend_from_slice(&0x0010u16.to_be_bytes());
    t.extend(sized(&[0; 32]));
    t.extend(sized(&[0; 32]));
    t
}

fn ak_template() -> Vec<u8> {
    let mut t = 0x0023u16.to_be_bytes().to_vec();
    t.extend_from_slice(&0x000bu16.to_be_bytes());
    t.extend_from_slice(&0x0005_0072u32.to_be_bytes());
    t.extend(sized(&[]));
    t.extend_from_slice(&0x0010u16.to_be_bytes());
    t.extend_from_slice(&0x0018u16.to_be_bytes());
    t.extend_from_slice(&0x000bu16.to_be_bytes());
    t.extend_from_slice(&0x0003u16.to_be_bytes());
    t.extend_from_slice(&0x0010u16.to_be_bytes());
    t.extend(sized(&[]));
    t.extend(sized(&[]));
    t
}

fn create_params(template: &[u8]) -> Vec<u8> {
    let mut p = sized(&[0, 0, 0, 0]);
    p.extend(sized(template));
    p.extend(sized(&[]));
    p.extend_from_slice(&0u32.to_be_bytes());
    p
}

fn start_policy_session(rm: &mut Manager) -> u32 {
    let mut p = sized(&[7; 16]);
    p.extend(sized(&[]));
    p.push(1);
    p.extend_from_slice(&[0x00, 0x06, 0x00, 0x80, 0x00, 0x43]);
    p.extend_from_slice(&0x000bu16.to_be_bytes());
    rm.run(CC_START_AUTH_SESSION, &[RH_NULL, RH_NULL], &[], &p, true).handle.unwrap()
}

fn policy_secret(rm: &mut Manager, session: u32) {
    let mut p = sized(&[]);
    p.extend(sized(&[]));
    p.extend(sized(&[]));
    p.extend_from_slice(&0u32.to_be_bytes());
    rm.run(CC_POLICY_SECRET, &[RH_ENDORSEMENT, session], &[(RS_PW, password()[4..].to_vec())], &p, false);
}

fn sized_at(bytes: &[u8], at: usize) -> (&[u8], usize) {
    let n = u16::from_be_bytes(bytes[at..at + 2].try_into().unwrap()) as usize;
    (&bytes[at + 2..at + 2 + n], at + 2 + n)
}

fn pcr_quote_params() -> Vec<u8> {
    let mut p = sized(&[1, 2, 3]);
    p.extend_from_slice(&0x0010u16.to_be_bytes());
    p.extend_from_slice(&1u32.to_be_bytes());
    p.extend_from_slice(&0x000bu16.to_be_bytes());
    p.extend_from_slice(&[3, 1, 0, 0]);
    p
}

#[test]
fn a_client_behind_a_resource_manager_creates_and_loads_a_key() {
    let _tpm = ONE_TPM.lock().unwrap_or_else(|e| e.into_inner());
    let mut rm = Manager::default();

    let ek = rm.run(CC_CREATE_PRIMARY, &[RH_ENDORSEMENT], &[(RS_PW, password()[4..].to_vec())], &create_params(&ek_template()), true);
    let ek_handle = ek.handle.unwrap();

    let session = start_policy_session(&mut rm);
    policy_secret(&mut rm, session);
    let created = rm.run_encrypted(CC_CREATE, &[ek_handle], &[(session, policy_authorization(session, ATTR_CONTINUE | ATTR_DECRYPT | ATTR_ENCRYPT)[4..].to_vec())], &create_params(&ak_template()), false, Some(session));
    rm.run(CC_FLUSH_CONTEXT, &[], &[], &session.to_be_bytes(), false);
    let (private, at) = sized_at(&created.params, 0);
    let (public, _) = sized_at(&created.params, at);

    let session = start_policy_session(&mut rm);
    policy_secret(&mut rm, session);
    let mut load = sized(private);
    load.extend(sized(public));
    let loaded = rm.run_encrypted(CC_LOAD, &[ek_handle], &[(session, policy_authorization(session, ATTR_DECRYPT | ATTR_ENCRYPT)[4..].to_vec())], &load, true, Some(session));
    let (name, _) = sized_at(&loaded.params, 0);
    let ak = loaded.handle.unwrap();

    let read = rm.run(CC_READ_PUBLIC, &[ak], &[], &[], false);
    let (_, at) = sized_at(&read.params, 0);
    let (read_name, _) = sized_at(&read.params, at);
    assert_eq!(read_name, name, "the loaded key keeps its name through a context");

    let quote = rm.run(CC_QUOTE, &[ak], &[(RS_PW, password()[4..].to_vec())], &pcr_quote_params(), false);
    assert!(!quote.params.is_empty(), "the key signs after the context");
}

fn start_hmac_session(rm: &mut Manager) -> u32 {
    let mut p = sized(&[7; 16]);
    p.extend(sized(&[]));
    p.push(0);
    p.extend_from_slice(&[0x00, 0x06, 0x00, 0x80, 0x00, 0x43]);
    p.extend_from_slice(&0x000bu16.to_be_bytes());
    rm.run(CC_START_AUTH_SESSION, &[RH_NULL, RH_NULL], &[], &p, true).handle.unwrap()
}

#[test]
fn a_saved_session_keeps_its_handle_until_it_is_loaded_or_flushed() {
    let _tpm = ONE_TPM.lock().unwrap_or_else(|e| e.into_inner());
    let mut rm = Manager::default();

    let first = start_hmac_session(&mut rm);
    let second = start_hmac_session(&mut rm);
    assert_ne!(first, second, "a session started while another is saved has another handle");
    let third = start_policy_session(&mut rm);
    assert_eq!(third >> 24, 3);

    let context = rm.sessions.iter().find(|(h, _)| *h == first).unwrap().1.clone();
    rm.flush_session(first);
    rm.flush_session(second);
    rm.flush_session(third);
    let replay = raw(ST_NO_SESSIONS, CC_CONTEXT_LOAD, &context);
    assert_eq!(rc(&replay) & 0x3f, 0x0b, "the context of a flushed session does not load: {:#x}", rc(&replay));
    let reused = start_hmac_session(&mut rm);
    assert_eq!(reused, first, "a flushed session's handle is free again");
}

#[test]
fn a_session_context_loads_once() {
    let _tpm = ONE_TPM.lock().unwrap_or_else(|e| e.into_inner());
    let mut rm = Manager::default();
    let handle = start_hmac_session(&mut rm);
    let context = rm.sessions[0].1.clone();
    assert_eq!(Manager::load_context(&context), handle);
    let again = raw(ST_NO_SESSIONS, CC_CONTEXT_LOAD, &context);
    assert_eq!(rc(&again) & 0x3f, 0x0b, "a saved session is loaded once: {:#x}", rc(&again));
    assert!(Manager::save_context(handle).is_some());
    rm.flush_session(handle);
}

fn start_hmac_session_raw() -> u32 {
    let mut p = RH_NULL.to_be_bytes().to_vec();
    p.extend_from_slice(&RH_NULL.to_be_bytes());
    p.extend(sized(&[7; 16]));
    p.extend(sized(&[]));
    p.push(0);
    p.extend_from_slice(&[0x00, 0x06, 0x00, 0x80, 0x00, 0x43]);
    p.extend_from_slice(&0x000bu16.to_be_bytes());
    let response = raw(ST_NO_SESSIONS, CC_START_AUTH_SESSION, &p);
    assert_eq!(rc(&response), 0, "start a session");
    u32::from_be_bytes(response[10..14].try_into().unwrap())
}

#[test]
fn a_client_that_saves_sessions_and_never_flushes_them_loses_the_oldest() {
    let _tpm = ONE_TPM.lock().unwrap_or_else(|e| e.into_inner());
    let handles: Vec<u32> = (0..4).map(|_| start_hmac_session_raw()).collect();
    let contexts: Vec<Vec<u8>> = handles.iter().map(|h| Manager::save_context(*h).unwrap()).collect();
    let newest = start_hmac_session_raw();
    assert_eq!(newest, handles[0], "the slot of the session saved longest ago is taken");
    let gone = raw(ST_NO_SESSIONS, CC_CONTEXT_LOAD, &contexts[0]);
    assert_ne!(rc(&gone), 0, "the context of the session that lost its handle does not load");
    assert_eq!(Manager::load_context(&contexts[1]), handles[1], "the others load");
    for handle in handles[1..].iter().chain([&newest]) {
        assert_eq!(rc(&raw(ST_NO_SESSIONS, CC_FLUSH_CONTEXT, &handle.to_be_bytes())), 0);
    }
}

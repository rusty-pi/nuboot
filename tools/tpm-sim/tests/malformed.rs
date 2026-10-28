//! Commands any user of the TPM device can send, shaped to run a buffer over:
//! each gets an error, and the VPU's service thread goes on.

use tpm_sim::tpm2;

/// The format-one error number for `TPM_RC_SIZE`.
const SIZE: u32 = 0x15;

fn execute(command: &[u8]) -> Vec<u8> {
    let mut response = vec![0u8; tpm2::MAX_COMMAND];
    let n = tpm2::execute(command, &mut response);
    response.truncate(n);
    response
}

fn response_code(response: &[u8]) -> u32 {
    u32::from_be_bytes(response[6..10].try_into().unwrap())
}

fn command(tag: u16, code: u32, body: &[u8]) -> Vec<u8> {
    let mut out = tag.to_be_bytes().to_vec();
    out.extend_from_slice(&((10 + body.len()) as u32).to_be_bytes());
    out.extend_from_slice(&code.to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn sized(bytes: &[u8]) -> Vec<u8> {
    let mut out = (bytes.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(bytes);
    out
}

const RH_NULL: u32 = 0x4000_0007;
const RH_OWNER: u32 = 0x4000_0001;
const CC_START_AUTH_SESSION: u32 = 0x176;
const CC_LOAD_EXTERNAL: u32 = 0x167;
const ST_NO_SESSIONS: u16 = 0x8001;
const ST_SESSIONS: u16 = 0x8002;

#[test]
fn a_public_area_longer_than_a_slot_is_refused() {
    let mut public = Vec::new();
    public.extend_from_slice(&1u16.to_be_bytes());
    public.extend_from_slice(&0x000bu16.to_be_bytes());
    public.extend_from_slice(&0x0004_0000u32.to_be_bytes());
    public.extend(sized(&[0xaa; 32]));
    public.extend_from_slice(&0x0010u16.to_be_bytes());
    public.extend_from_slice(&0x0010u16.to_be_bytes());
    public.extend_from_slice(&2048u16.to_be_bytes());
    public.extend_from_slice(&0u32.to_be_bytes());
    let mut modulus = vec![0xc3u8; 600];
    modulus[599] |= 1;
    public.extend(sized(&modulus));
    assert!(public.len() > 600);

    let mut body = sized(&[]);
    body.extend(sized(&public));
    body.extend_from_slice(&RH_OWNER.to_be_bytes());
    let response = execute(&command(ST_NO_SESSIONS, CC_LOAD_EXTERNAL, &body));
    assert_eq!(response_code(&response) & 0x3f, SIZE, "{response:02x?}");
}

#[test]
fn parameters_longer_than_the_decryption_buffer_are_refused() {
    let mut start = Vec::new();
    start.extend_from_slice(&RH_NULL.to_be_bytes());
    start.extend_from_slice(&RH_NULL.to_be_bytes());
    start.extend(sized(&[0x11; 16]));
    start.extend(sized(&[]));
    start.push(0);
    start.extend_from_slice(&0x0006u16.to_be_bytes());
    start.extend_from_slice(&128u16.to_be_bytes());
    start.extend_from_slice(&0x0043u16.to_be_bytes());
    start.extend_from_slice(&0x000bu16.to_be_bytes());
    let started = execute(&command(ST_NO_SESSIONS, CC_START_AUTH_SESSION, &start));
    assert_eq!(response_code(&started), 0, "{started:02x?}");
    let session = u32::from_be_bytes(started[10..14].try_into().unwrap());

    let mut area = session.to_be_bytes().to_vec();
    area.extend(sized(&[0x22; 16]));
    area.push(0x21);
    area.extend(sized(&[]));
    let mut body = (area.len() as u32).to_be_bytes().to_vec();
    body.extend(area);
    body.extend(sized(&[]));
    body.extend(vec![0u8; 1200]);
    let response = execute(&command(ST_SESSIONS, CC_LOAD_EXTERNAL, &body));
    assert_ne!(response_code(&response), 0, "{response:02x?}");
}

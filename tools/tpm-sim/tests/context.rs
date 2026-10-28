//! What the kernel's resource manager (`/dev/tpmrm0`) relies on when it saves
//! the sessions and objects a command left behind.

use tpm_sim::tpm2;

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

const RH_NULL: u32 = 0x4000_0007;
const ST_NO_SESSIONS: u16 = 0x8001;
const CC_START_AUTH_SESSION: u32 = 0x176;
const CC_CONTEXT_SAVE: u32 = 0x162;
const CC_FLUSH_CONTEXT: u32 = 0x165;
const RC_REFERENCE_H0: u32 = 0x910;

fn start_policy_session() -> u32 {
    let mut body = Vec::new();
    body.extend_from_slice(&RH_NULL.to_be_bytes());
    body.extend_from_slice(&RH_NULL.to_be_bytes());
    body.extend_from_slice(&16u16.to_be_bytes());
    body.extend_from_slice(&[7; 16]);
    body.extend_from_slice(&0u16.to_be_bytes());
    body.push(0x01);
    body.extend_from_slice(&0x0010u16.to_be_bytes());
    body.extend_from_slice(&0x000bu16.to_be_bytes());
    let response = execute(&command(ST_NO_SESSIONS, CC_START_AUTH_SESSION, &body));
    assert_eq!(response_code(&response), 0);
    u32::from_be_bytes(response[10..14].try_into().unwrap())
}

#[test]
fn what_the_resource_manager_reads_of_a_save_and_a_flush() {
    let handle = start_policy_session();
    let save = command(ST_NO_SESSIONS, CC_CONTEXT_SAVE, &handle.to_be_bytes());
    assert_eq!(response_code(&execute(&save)), 0, "a loaded session saves");
    assert_eq!(response_code(&execute(&save)), RC_REFERENCE_H0, "and is gone once it has been saved");

    for handle in [0x0200_0000u32, 0x0300_0001, 0x8000_0000, 0x8000_0003] {
        let save = command(ST_NO_SESSIONS, CC_CONTEXT_SAVE, &handle.to_be_bytes());
        assert_eq!(response_code(&execute(&save)), RC_REFERENCE_H0, "{handle:08x} is not loaded");
    }

    let flush = command(ST_NO_SESSIONS, CC_FLUSH_CONTEXT, &0x0300_0000u32.to_be_bytes());
    assert_eq!(response_code(&execute(&flush)), 0x08b | 0x40 | 0x100, "flushing what is not loaded is a handle error on the parameter");
}

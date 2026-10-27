//! RSA public keys of 2048, 3072 and 4096 bits as the TPM is handed them:
//! loaded, read back, verified with, saved and loaded again.

use tpm_sim::tpm2;

mod vectors;
use vectors::RSA;

const ST_NO_SESSIONS: u16 = 0x8001;
const RH_OWNER: u32 = 0x4000_0001;
const CC_LOAD_EXTERNAL: u32 = 0x167;
const CC_VERIFY_SIGNATURE: u32 = 0x177;
const CC_READ_PUBLIC: u32 = 0x173;
const CC_CONTEXT_SAVE: u32 = 0x162;
const CC_CONTEXT_LOAD: u32 = 0x161;
const CC_FLUSH_CONTEXT: u32 = 0x165;

fn sized(bytes: &[u8]) -> Vec<u8> {
    let mut out = (bytes.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(bytes);
    out
}

fn send(code: u32, handles: &[u32], params: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    for h in handles {
        body.extend_from_slice(&h.to_be_bytes());
    }
    body.extend_from_slice(params);
    let mut command = ST_NO_SESSIONS.to_be_bytes().to_vec();
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

fn load_external(modulus: &[u8]) -> Result<u32, u32> {
    let mut public = Vec::new();
    public.extend_from_slice(&1u16.to_be_bytes());
    public.extend_from_slice(&0x000bu16.to_be_bytes());
    public.extend_from_slice(&0x0004_0000u32.to_be_bytes());
    public.extend(sized(&[]));
    public.extend_from_slice(&0x0010u16.to_be_bytes());
    public.extend_from_slice(&0x0010u16.to_be_bytes());
    public.extend_from_slice(&((modulus.len() * 8) as u16).to_be_bytes());
    public.extend_from_slice(&0u32.to_be_bytes());
    public.extend(sized(modulus));
    let mut body = sized(&[]);
    body.extend(sized(&public));
    body.extend_from_slice(&RH_OWNER.to_be_bytes());
    let response = send(CC_LOAD_EXTERNAL, &[], &body);
    match rc(&response) {
        0 => Ok(u32::from_be_bytes(response[10..14].try_into().unwrap())),
        code => Err(code),
    }
}

fn verify(handle: u32, digest: &[u8; 32], signature: &[u8]) -> u32 {
    let mut p = sized(digest);
    p.extend_from_slice(&0x0014u16.to_be_bytes());
    p.extend_from_slice(&0x000bu16.to_be_bytes());
    p.extend(sized(signature));
    rc(&send(CC_VERIFY_SIGNATURE, &[handle], &p))
}

#[test]
fn rsa_keys_of_2048_3072_and_4096_bits() {
    let mut seen = [false; 3];
    for (modulus, exponent, digest, signature, valid) in RSA {
        if *exponent != 65537 || !*valid {
            continue;
        }
        let bits = modulus.len() * 8;
        let handle = load_external(modulus).unwrap_or_else(|rc| panic!("{bits}-bit key refused: {rc:#x}"));
        seen[(bits - 2048) / 1024] = true;

        let public = send(CC_READ_PUBLIC, &[handle], &[]);
        assert_eq!(rc(&public), 0, "{bits}: read public");
        assert!(public.windows(modulus.len()).any(|w| w == &modulus[..]), "{bits}: the modulus is in the public area");

        assert_eq!(verify(handle, digest, signature), 0, "{bits}: a good signature");
        let mut other = *digest;
        other[0] ^= 1;
        assert_eq!(verify(handle, &other, signature), 0x09b | 0x40 | 0x200, "{bits}: a signature of something else");
        let mut broken = signature.to_vec();
        broken[10] ^= 1;
        assert_eq!(verify(handle, digest, &broken), 0x09b | 0x40 | 0x200, "{bits}: a broken signature");
        assert_eq!(verify(handle, digest, &signature[1..]), 0x09b | 0x40 | 0x200, "{bits}: a short signature");

        let saved = send(CC_CONTEXT_SAVE, &[handle], &[]);
        assert_eq!(rc(&saved), 0, "{bits}: save");
        assert_eq!(rc(&send(CC_FLUSH_CONTEXT, &[], &handle.to_be_bytes())), 0);
        let loaded = send(CC_CONTEXT_LOAD, &[], &saved[10..]);
        assert_eq!(rc(&loaded), 0, "{bits}: load");
        let again = u32::from_be_bytes(loaded[10..14].try_into().unwrap());
        assert_eq!(verify(again, digest, signature), 0, "{bits}: verify after a save and load");
        assert_eq!(rc(&send(CC_FLUSH_CONTEXT, &[], &again.to_be_bytes())), 0);
    }
    assert_eq!(seen, [true; 3], "the vectors have each size");

    let odd = vec![0xc3u8; 320];
    assert!(load_external(&odd).is_err(), "no 2560-bit keys");
}

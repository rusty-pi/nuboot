//! The key derivation functions a TPM 2.0 uses, with SHA-256 throughout:
//! `KDFa`, NIST SP 800-108 in counter mode with HMAC, which derives every
//! symmetric key and seed, and `KDFe`, the concatenation KDF of SP 800-56A,
//! which derives the secret of an ECDH exchange.

use crate::sha256::{self, Sha256};

/// `bits` of `KDFa(key, label, context_u, context_v)`, into `out`, which is
/// `ceil(bits / 8)` bytes. The label is given without its terminating zero,
/// which the function adds.
pub fn kdfa(key: &[u8], label: &[u8], context_u: &[u8], context_v: &[u8], bits: u32, out: &mut [u8]) {
    let bytes = (bits as usize).div_ceil(8);
    let mut message = [0u8; 256];
    let mut counter = 1u32;
    let mut done = 0;
    while done < bytes {
        let mut n = 0;
        for part in [&counter.to_be_bytes()[..], label, &[0], context_u, context_v, &bits.to_be_bytes()] {
            message[n..n + part.len()].copy_from_slice(part);
            n += part.len();
        }
        let block = sha256::hmac(key, &message[..n]);
        let take = (bytes - done).min(32);
        out[done..done + take].copy_from_slice(&block[..take]);
        done += take;
        counter += 1;
    }
    if bits % 8 != 0 {
        out[0] &= 0xffu8 >> (8 - bits % 8);
    }
}

/// `bits` of `KDFe(z, label, party_u, party_v)`, into `out`.
pub fn kdfe(z: &[u8], label: &[u8], party_u: &[u8], party_v: &[u8], bits: u32, out: &mut [u8]) {
    let bytes = (bits as usize).div_ceil(8);
    let mut counter = 1u32;
    let mut done = 0;
    while done < bytes {
        let mut hash = Sha256::new();
        hash.update(&counter.to_be_bytes());
        hash.update(z);
        hash.update(label);
        hash.update(&[0]);
        hash.update(party_u);
        hash.update(party_v);
        let block = hash.finish();
        let take = (bytes - done).min(32);
        out[done..done + take].copy_from_slice(&block[..take]);
        done += take;
        counter += 1;
    }
}

//! RSA-2048 signature verification with PKCS#1 v1.5 and SHA-256: the public
//! operation only, for keys the TPM is given and signatures it checks. Not
//! constant time, which a public operation does not need.
//!
//! Numbers are 2048 bits as 64 32-bit limbs, least significant first, and
//! bytes, big endian, at the edges. Arithmetic is Montgomery's.

use crate::p256::mul_add;

const LIMBS: usize = 64;
pub const MODULUS_BYTES: usize = LIMBS * 4;

type Num = [u32; LIMBS];

/// `DigestInfo` of SHA-256, which precedes the digest in the encoded message.
const DIGEST_INFO: [u8; 19] = [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20];

/// `a >= b`.
fn geq_limbs(a: &Num, b: &Num) -> bool {
    for i in (0..LIMBS).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

/// `a - b`, for `a >= b` or with the borrow dropped.
fn sub_limbs(a: &Num, b: &Num) -> Num {
    let mut out = [0u32; LIMBS];
    let mut borrow = false;
    for i in 0..LIMBS {
        let (d, b1) = a[i].overflowing_sub(b[i]);
        let (d, b2) = d.overflowing_sub(borrow as u32);
        out[i] = d;
        borrow = b1 || b2;
    }
    out
}

fn from_bytes(bytes: &[u8]) -> Num {
    let mut n = [0u32; LIMBS];
    for (i, chunk) in bytes.rchunks(4).enumerate() {
        let mut word = [0u8; 4];
        word[4 - chunk.len()..].copy_from_slice(chunk);
        n[i] = u32::from_be_bytes(word);
    }
    n
}

fn to_bytes(n: &Num) -> [u8; MODULUS_BYTES] {
    let mut out = [0u8; MODULUS_BYTES];
    for (i, word) in n.iter().enumerate() {
        out[MODULUS_BYTES - 4 * (i + 1)..MODULUS_BYTES - 4 * i].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Montgomery product `a * b / 2^2048 mod n`.
fn mont_mul(a: &Num, b: &Num, n: &Num, n0: u32) -> Num {
    let mut t = [0u32; LIMBS + 2];
    for i in 0..LIMBS {
        let mut carry = 0u32;
        for j in 0..LIMBS {
            let (s, c) = mul_add(t[j], a[j], b[i], carry);
            t[j] = s;
            carry = c;
        }
        let (s, c) = t[LIMBS].overflowing_add(carry);
        t[LIMBS] = s;
        t[LIMBS + 1] = c as u32;
        let q = t[0].wrapping_mul(n0);
        let (_, mut carry) = mul_add(t[0], q, n[0], 0);
        for j in 1..LIMBS {
            let (s, c) = mul_add(t[j], q, n[j], carry);
            t[j - 1] = s;
            carry = c;
        }
        let (s, c) = t[LIMBS].overflowing_add(carry);
        t[LIMBS - 1] = s;
        t[LIMBS] = t[LIMBS + 1] + c as u32;
    }
    let mut out = [0u32; LIMBS];
    out.copy_from_slice(&t[..LIMBS]);
    if t[LIMBS] != 0 || geq_limbs(&out, n) {
        out = sub_limbs(&out, n);
    }
    out
}

/// `-n^-1 mod 2^32` for an odd `n`.
fn n0_inverse(n0: u32) -> u32 {
    let mut inverse = n0;
    for _ in 0..5 {
        inverse = inverse.wrapping_mul(2u32.wrapping_sub(n0.wrapping_mul(inverse)));
    }
    inverse.wrapping_neg()
}

/// `2^4096 mod n`, which turns a number into Montgomery form: 1 doubled 4096
/// times.
fn r_squared(n: &Num) -> Num {
    let mut x = [0u32; LIMBS];
    x[0] = 1;
    for _ in 0..2 * LIMBS * 32 {
        let mut carry = 0u32;
        for word in x.iter_mut() {
            let next = *word >> 31;
            *word = *word << 1 | carry;
            carry = next;
        }
        if carry != 0 || geq_limbs(&x, n) {
            x = sub_limbs(&x, n);
        }
    }
    x
}

/// Whether `signature` is `modulus`' PKCS#1 v1.5 signature of `digest`, with
/// the public exponent `exponent` (65537 when 0, as the TPM has it).
pub fn verify_sha256(modulus: &[u8], exponent: u32, digest: &[u8; 32], signature: &[u8]) -> bool {
    if modulus.len() != MODULUS_BYTES || signature.len() != MODULUS_BYTES || modulus[0] & 0x80 == 0 || modulus[MODULUS_BYTES - 1] & 1 == 0 {
        return false;
    }
    let exponent = if exponent == 0 { 65537 } else { exponent };
    if exponent < 3 || exponent & 1 == 0 {
        return false;
    }
    let n = from_bytes(modulus);
    let s = from_bytes(signature);
    if geq_limbs(&s, &n) {
        return false;
    }
    let n0 = n0_inverse(n[0]);
    let r2 = r_squared(&n);
    let base = mont_mul(&s, &r2, &n, n0);
    let mut result = base;
    for bit in (0..31 - exponent.leading_zeros()).rev() {
        result = mont_mul(&result, &result, &n, n0);
        if exponent >> bit & 1 != 0 {
            result = mont_mul(&result, &base, &n, n0);
        }
    }
    let mut one = [0u32; LIMBS];
    one[0] = 1;
    let message = to_bytes(&mont_mul(&result, &one, &n, n0));

    let mut expected = [0xffu8; MODULUS_BYTES];
    expected[0] = 0;
    expected[1] = 1;
    let digest_at = MODULUS_BYTES - 32;
    let info_at = digest_at - DIGEST_INFO.len();
    expected[info_at - 1] = 0;
    expected[info_at..digest_at].copy_from_slice(&DIGEST_INFO);
    expected[digest_at..].copy_from_slice(digest);
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(&message) {
        diff |= a ^ b;
    }
    diff == 0
}

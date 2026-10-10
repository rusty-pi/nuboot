//! RSA signature verification (PKCS #1 v1.5 with SHA-256): `s^e mod n` in
//! Montgomery form, on 32-bit limbs, least significant first.

use alloc::vec;
use alloc::vec::Vec;

/// The DER `DigestInfo` that goes before a SHA-256 hash in the padded
/// message.
const SHA256_INFO: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
];

/// The largest modulus taken, in bytes.
const MAX_BYTES: usize = 512;

fn strip(b: &[u8]) -> &[u8] {
    let zeros = b.iter().take_while(|&&x| x == 0).count();
    &b[zeros..]
}

fn limbs(bytes: &[u8], len: usize) -> Vec<u32> {
    let mut out = vec![0u32; len];
    for (i, &b) in bytes.iter().rev().enumerate() {
        out[i / 4] |= (b as u32) << (8 * (i % 4));
    }
    out
}

/// `a >= b`, both `b.len()` limbs.
fn ge(a: &[u32], b: &[u32]) -> bool {
    for i in (0..b.len()).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

/// `a -= b` over `b.len()` limbs, the borrow out dropped.
fn sub(a: &mut [u32], b: &[u32]) {
    let mut borrow = 0u64;
    for i in 0..b.len() {
        let d = (a[i] as u64).wrapping_sub(b[i] as u64).wrapping_sub(borrow);
        a[i] = d as u32;
        borrow = (d >> 63) & 1;
    }
}

struct Modulus {
    n: Vec<u32>,
    /// `-n^-1 mod 2^32`.
    n0: u32,
}

impl Modulus {
    /// `a * b / R mod n` (CIOS).
    fn mul(&self, a: &[u32], b: &[u32]) -> Vec<u32> {
        let s = self.n.len();
        let n = &self.n;
        let mut t = vec![0u32; s + 2];
        for &bi in b {
            let mut c = 0u64;
            for j in 0..s {
                let x = t[j] as u64 + a[j] as u64 * bi as u64 + c;
                t[j] = x as u32;
                c = x >> 32;
            }
            let x = t[s] as u64 + c;
            t[s] = x as u32;
            t[s + 1] = (x >> 32) as u32;
            let m = t[0].wrapping_mul(self.n0) as u64;
            let mut c = (t[0] as u64 + m * n[0] as u64) >> 32;
            for j in 1..s {
                let x = t[j] as u64 + m * n[j] as u64 + c;
                t[j - 1] = x as u32;
                c = x >> 32;
            }
            let x = t[s] as u64 + c;
            t[s - 1] = x as u32;
            t[s] = t[s + 1] + (x >> 32) as u32;
            t[s + 1] = 0;
        }
        if t[s] != 0 || ge(&t, n) {
            sub(&mut t, n);
        }
        t.truncate(s);
        t
    }

    /// `R^2 mod n`, by doubling 1 until it has been multiplied by `R^2`.
    fn r2(&self) -> Vec<u32> {
        let s = self.n.len();
        let mut r = vec![0u32; s];
        r[0] = 1;
        for _ in 0..64 * s {
            let mut carry = 0;
            for x in r.iter_mut() {
                let top = *x >> 31;
                *x = *x << 1 | carry;
                carry = top;
            }
            if carry != 0 || ge(&r, &self.n) {
                sub(&mut r, &self.n);
            }
        }
        r
    }
}

/// `sig^e mod n`, as many bytes as `n` has, or `None` for a key or
/// signature this cannot take.
fn public(n: &[u8], e: &[u8], sig: &[u8]) -> Option<Vec<u8>> {
    let (n, e) = (strip(n), strip(e));
    if n.is_empty() || n.len() > MAX_BYTES || n[n.len() - 1] & 1 == 0 || e.is_empty() || e.len() > 4 {
        return None;
    }
    let k = n.len();
    if sig.len() != k {
        return None;
    }
    let s = k.div_ceil(4);
    let m = {
        let n = limbs(n, s);
        let mut inv = 1u32;
        for _ in 0..5 {
            inv = inv.wrapping_mul(2u32.wrapping_sub(n[0].wrapping_mul(inv)));
        }
        Modulus { n0: inv.wrapping_neg(), n }
    };
    let x = limbs(sig, s);
    if ge(&x, &m.n) {
        return None;
    }
    let e = e.iter().fold(0u32, |a, &b| a << 8 | b as u32);
    let x = m.mul(&x, &m.r2());
    let mut acc = x.clone();
    for bit in (0..31 - e.leading_zeros()).rev() {
        acc = m.mul(&acc, &acc);
        if e >> bit & 1 != 0 {
            acc = m.mul(&acc, &x);
        }
    }
    let mut one = vec![0u32; s];
    one[0] = 1;
    let r = m.mul(&acc, &one);
    Some((0..k).rev().map(|i| (r[i / 4] >> (8 * (i % 4))) as u8).collect())
}

/// Whether `sig` is the RSASSA-PKCS1-v1_5 signature of the SHA-256 hash
/// `hash` under the key `(n, e)`.
pub fn verify(n: &[u8], e: &[u8], sig: &[u8], hash: &[u8; 32]) -> bool {
    let Some(em) = public(n, e, sig) else { return false };
    let tail = SHA256_INFO.len() + 32;
    if em.len() < tail + 11 || em[0] != 0 || em[1] != 1 {
        return false;
    }
    let pad = em.len() - tail - 1;
    em[2..pad].iter().all(|&b| b == 0xff)
        && em[pad] == 0
        && em[pad + 1..pad + 1 + SHA256_INFO.len()] == SHA256_INFO
        && em[em.len() - 32..] == hash[..]
}

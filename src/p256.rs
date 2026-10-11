//! NIST P-256: public keys, ECDH and ECDSA, for the TPM's keys. Not constant
//! time: nothing here is reachable but through the TPM's command interface, and
//! the VPU's timing is not something its callers can see closely.
//!
//! Numbers are 256 bits as eight 32-bit limbs, least significant first, and
//! as 32 bytes, big endian, at the edges. Arithmetic is Montgomery's, modulo
//! the field prime and the group order alike.

type Limbs = [u32; 8];

const P: Limbs = [0xffffffff, 0xffffffff, 0xffffffff, 0x00000000, 0x00000000, 0x00000000, 0x00000001, 0xffffffff];
const P_N0: u32 = 0x00000001;
const P_R2: Limbs = [0x00000003, 0x00000000, 0xffffffff, 0xfffffffb, 0xfffffffe, 0xffffffff, 0xfffffffd, 0x00000004];
const P_R: Limbs = [0x00000001, 0x00000000, 0x00000000, 0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe, 0x00000000];
const N: Limbs = [0xfc632551, 0xf3b9cac2, 0xa7179e84, 0xbce6faad, 0xffffffff, 0xffffffff, 0x00000000, 0xffffffff];
const N_N0: u32 = 0xee00bc4f;
const N_R2: Limbs = [0xbe79eea2, 0x83244c95, 0x49bd6fa6, 0x4699799c, 0x2b6bec59, 0x2845b239, 0xf3d95620, 0x66e12d94];
const N_R: Limbs = [0x039cdaaf, 0x0c46353d, 0x58e8617b, 0x43190552, 0x00000000, 0x00000000, 0xffffffff, 0x00000000];
const B_MONT: Limbs = [0x29c4bddf, 0xd89cdf62, 0x78843090, 0xacf005cd, 0xf7212ed6, 0xe5a220ab, 0x04874834, 0xdc30061d];
const GX_MONT: Limbs = [0x18a9143c, 0x79e730d4, 0x5fedb601, 0x75ba95fc, 0x77622510, 0x79fb732b, 0xa53755c6, 0x18905f76];
const GY_MONT: Limbs = [0xce95560a, 0xddf25357, 0xba19e45c, 0x8b4ab8e4, 0xdd21f325, 0xd2e88688, 0x25885d85, 0x8571ff18];

/// A prime and what Montgomery multiplication modulo it needs.
struct Modulus {
    m: Limbs,
    n0: u32,
    r2: Limbs,
    one: Limbs,
}

const FIELD: Modulus = Modulus { m: P, n0: P_N0, r2: P_R2, one: P_R };
const ORDER: Modulus = Modulus { m: N, n0: N_N0, r2: N_R2, one: N_R };

/// A point on the curve, big-endian coordinates.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Point {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

fn from_bytes(b: &[u8; 32]) -> Limbs {
    let mut l = [0u32; 8];
    for i in 0..8 {
        l[i] = u32::from_be_bytes([b[28 - 4 * i], b[29 - 4 * i], b[30 - 4 * i], b[31 - 4 * i]]);
    }
    l
}

fn to_bytes(l: &Limbs) -> [u8; 32] {
    let mut b = [0u8; 32];
    for i in 0..8 {
        b[28 - 4 * i..32 - 4 * i].copy_from_slice(&l[i].to_be_bytes());
    }
    b
}

fn is_zero(a: &Limbs) -> bool {
    a.iter().all(|&w| w == 0)
}

/// `a >= b`.
fn geq(a: &Limbs, b: &Limbs) -> bool {
    for i in (0..8).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

/// `a - b` and whether it borrowed.
fn sub_raw(a: &Limbs, b: &Limbs) -> (Limbs, bool) {
    let mut out = [0u32; 8];
    let mut borrow = 0i64;
    for i in 0..8 {
        let d = a[i] as i64 - b[i] as i64 - borrow;
        out[i] = d as u32;
        borrow = (d < 0) as i64;
    }
    (out, borrow != 0)
}

/// `a + b` and its carry.
fn add_raw(a: &Limbs, b: &Limbs) -> (Limbs, bool) {
    let mut out = [0u32; 8];
    let mut carry = 0u64;
    for i in 0..8 {
        let s = a[i] as u64 + b[i] as u64 + carry;
        out[i] = s as u32;
        carry = s >> 32;
    }
    (out, carry != 0)
}

fn add_mod(a: &Limbs, b: &Limbs, mo: &Modulus) -> Limbs {
    let (s, carry) = add_raw(a, b);
    if carry || geq(&s, &mo.m) {
        sub_raw(&s, &mo.m).0
    } else {
        s
    }
}

fn sub_mod(a: &Limbs, b: &Limbs, mo: &Modulus) -> Limbs {
    let (d, borrow) = sub_raw(a, b);
    if borrow { add_raw(&d, &mo.m).0 } else { d }
}

/// The 64-bit product of two 32-bit numbers, as its low and high words, from
/// 16-bit halves: the VPU has no widening multiply, so a `u64` product is a
/// library call there.
#[inline(always)]
pub(crate) fn mul_wide(a: u32, b: u32) -> (u32, u32) {
    let (a0, a1) = (a & 0xffff, a >> 16);
    let (b0, b1) = (b & 0xffff, b >> 16);
    let p00 = a0 * b0;
    let p01 = a0 * b1;
    let p10 = a1 * b0;
    let p11 = a1 * b1;
    let mid = (p00 >> 16) + (p01 & 0xffff) + (p10 & 0xffff);
    let lo = (p00 & 0xffff) | (mid << 16);
    let hi = p11 + (p01 >> 16) + (p10 >> 16) + (mid >> 16);
    (lo, hi)
}

/// `x + a * b + carry` as a low word and the carry out, which fits a word.
#[inline(always)]
pub(crate) fn mul_add(x: u32, a: u32, b: u32, carry: u32) -> (u32, u32) {
    let (lo, hi) = mul_wide(a, b);
    let (s, c1) = x.overflowing_add(lo);
    let (s, c2) = s.overflowing_add(carry);
    (s, hi + c1 as u32 + c2 as u32)
}

/// Montgomery product `a * b / 2^256 mod m`.
fn mont_mul(a: &Limbs, b: &Limbs, mo: &Modulus) -> Limbs {
    let mut t = [0u32; 10];
    for i in 0..8 {
        let mut carry = 0u32;
        for j in 0..8 {
            let (s, c) = mul_add(t[j], a[j], b[i], carry);
            t[j] = s;
            carry = c;
        }
        let (s, c) = t[8].overflowing_add(carry);
        t[8] = s;
        t[9] = c as u32;
        let q = t[0].wrapping_mul(mo.n0);
        let (_, mut carry) = mul_add(t[0], q, mo.m[0], 0);
        for j in 1..8 {
            let (s, c) = mul_add(t[j], q, mo.m[j], carry);
            t[j - 1] = s;
            carry = c;
        }
        let (s, c) = t[8].overflowing_add(carry);
        t[7] = s;
        t[8] = t[9] + c as u32;
    }
    let mut out = [0u32; 8];
    out.copy_from_slice(&t[..8]);
    if t[8] != 0 || geq(&out, &mo.m) {
        out = sub_raw(&out, &mo.m).0;
    }
    out
}

fn to_mont(a: &Limbs, mo: &Modulus) -> Limbs {
    mont_mul(a, &mo.r2, mo)
}

fn from_mont(a: &Limbs, mo: &Modulus) -> Limbs {
    let mut one = [0u32; 8];
    one[0] = 1;
    mont_mul(a, &one, mo)
}

/// `a^e` for a Montgomery `a` and a plain exponent.
fn pow(a: &Limbs, e: &Limbs, mo: &Modulus) -> Limbs {
    let mut result = mo.one;
    for i in (0..256).rev() {
        result = mont_mul(&result, &result, mo);
        if e[i / 32] >> (i % 32) & 1 != 0 {
            result = mont_mul(&result, a, mo);
        }
    }
    result
}

/// `a^-1` for a Montgomery, non-zero `a` (Fermat: the modulus is prime).
fn invert(a: &Limbs, mo: &Modulus) -> Limbs {
    let mut two = [0u32; 8];
    two[0] = 2;
    pow(a, &sub_raw(&mo.m, &two).0, mo)
}

/// A point with Jacobian coordinates in the field's Montgomery form: `z == 0`
/// is the point at infinity.
#[derive(Clone, Copy)]
struct Jacobian {
    x: Limbs,
    y: Limbs,
    z: Limbs,
}

const INFINITY: Jacobian = Jacobian { x: [0; 8], y: [0; 8], z: [0; 8] };

fn fmul(a: &Limbs, b: &Limbs) -> Limbs {
    mont_mul(a, b, &FIELD)
}
fn fadd(a: &Limbs, b: &Limbs) -> Limbs {
    add_mod(a, b, &FIELD)
}
fn fsub(a: &Limbs, b: &Limbs) -> Limbs {
    sub_mod(a, b, &FIELD)
}

fn double(p: &Jacobian) -> Jacobian {
    if is_zero(&p.z) || is_zero(&p.y) {
        return INFINITY;
    }
    let delta = fmul(&p.z, &p.z);
    let gamma = fmul(&p.y, &p.y);
    let beta = fmul(&p.x, &gamma);
    let t = fmul(&fsub(&p.x, &delta), &fadd(&p.x, &delta));
    let alpha = fadd(&fadd(&t, &t), &t);
    let beta4 = fadd(&fadd(&beta, &beta), &fadd(&beta, &beta));
    let x3 = fsub(&fmul(&alpha, &alpha), &fadd(&beta4, &beta4));
    let yz = fadd(&p.y, &p.z);
    let z3 = fsub(&fsub(&fmul(&yz, &yz), &gamma), &delta);
    let gamma2 = fmul(&gamma, &gamma);
    let gamma8 = {
        let g2 = fadd(&gamma2, &gamma2);
        let g4 = fadd(&g2, &g2);
        fadd(&g4, &g4)
    };
    let y3 = fsub(&fmul(&alpha, &fsub(&beta4, &x3)), &gamma8);
    Jacobian { x: x3, y: y3, z: z3 }
}

fn add(p: &Jacobian, q: &Jacobian) -> Jacobian {
    if is_zero(&p.z) {
        return *q;
    }
    if is_zero(&q.z) {
        return *p;
    }
    let z1z1 = fmul(&p.z, &p.z);
    let z2z2 = fmul(&q.z, &q.z);
    let u1 = fmul(&p.x, &z2z2);
    let u2 = fmul(&q.x, &z1z1);
    let s1 = fmul(&fmul(&p.y, &q.z), &z2z2);
    let s2 = fmul(&fmul(&q.y, &p.z), &z1z1);
    if u1 == u2 {
        return if s1 == s2 { double(p) } else { INFINITY };
    }
    let h = fsub(&u2, &u1);
    let h2 = fadd(&h, &h);
    let i = fmul(&h2, &h2);
    let j = fmul(&h, &i);
    let r = {
        let d = fsub(&s2, &s1);
        fadd(&d, &d)
    };
    let v = fmul(&u1, &i);
    let x3 = fsub(&fsub(&fmul(&r, &r), &j), &fadd(&v, &v));
    let s1j = fmul(&s1, &j);
    let y3 = fsub(&fmul(&r, &fsub(&v, &x3)), &fadd(&s1j, &s1j));
    let zz = fadd(&p.z, &q.z);
    let z3 = fmul(&fsub(&fsub(&fmul(&zz, &zz), &z1z1), &z2z2), &h);
    Jacobian { x: x3, y: y3, z: z3 }
}

fn affine(p: &Point) -> Jacobian {
    Jacobian { x: to_mont(&from_bytes(&p.x), &FIELD), y: to_mont(&from_bytes(&p.y), &FIELD), z: FIELD.one }
}

/// `k * point`, `k` a scalar of at most 256 bits.
fn multiply(point: &Jacobian, k: &Limbs) -> Jacobian {
    let mut result = INFINITY;
    for i in (0..256).rev() {
        result = double(&result);
        if k[i / 32] >> (i % 32) & 1 != 0 {
            result = add(&result, point);
        }
    }
    result
}

fn to_affine(p: &Jacobian) -> Option<Point> {
    if is_zero(&p.z) {
        return None;
    }
    let zi = invert(&p.z, &FIELD);
    let zi2 = fmul(&zi, &zi);
    let x = fmul(&p.x, &zi2);
    let y = fmul(&fmul(&p.y, &zi2), &zi);
    Some(Point { x: to_bytes(&from_mont(&x, &FIELD)), y: to_bytes(&from_mont(&y, &FIELD)) })
}

fn generator() -> Jacobian {
    Jacobian { x: GX_MONT, y: GY_MONT, z: FIELD.one }
}

/// Whether `d` is a private key: from 1 to the group order less one.
pub fn valid_scalar(d: &[u8; 32]) -> bool {
    let l = from_bytes(d);
    !is_zero(&l) && !geq(&l, &N)
}

/// Whether `p` is on the curve, with coordinates below the prime.
pub fn on_curve(p: &Point) -> bool {
    let (x, y) = (from_bytes(&p.x), from_bytes(&p.y));
    if geq(&x, &P) || geq(&y, &P) {
        return false;
    }
    let x = to_mont(&x, &FIELD);
    let y = to_mont(&y, &FIELD);
    let x3 = fmul(&fmul(&x, &x), &x);
    let three_x = fadd(&fadd(&x, &x), &x);
    let rhs = fadd(&fsub(&x3, &three_x), &B_MONT);
    fmul(&y, &y) == rhs
}

/// The public key of private key `d`.
pub fn public_key(d: &[u8; 32]) -> Option<Point> {
    if !valid_scalar(d) {
        return None;
    }
    to_affine(&multiply(&generator(), &from_bytes(d)))
}

/// The x coordinate of `d` times `peer`, which has to be on the curve.
pub fn ecdh(d: &[u8; 32], peer: &Point) -> Option<[u8; 32]> {
    if !valid_scalar(d) || !on_curve(peer) {
        return None;
    }
    to_affine(&multiply(&affine(peer), &from_bytes(d))).map(|p| p.x)
}

/// `x` reduced modulo the group order, as a hash is for a signature.
pub fn reduce_order(x: &[u8; 32]) -> [u8; 32] {
    let l = from_bytes(x);
    to_bytes(&if geq(&l, &N) { sub_raw(&l, &N).0 } else { l })
}

fn order_mul(a: &Limbs, b: &Limbs) -> Limbs {
    mont_mul(a, b, &ORDER)
}

/// An ECDSA signature `(r, s)` of `digest` by `d`, with the per-signature
/// secret `k` the caller draws: `None` for a `k` that gives a zero `r` or `s`,
/// for the caller to draw another.
pub fn sign(d: &[u8; 32], digest: &[u8; 32], k: &[u8; 32]) -> Option<([u8; 32], [u8; 32])> {
    if !valid_scalar(d) || !valid_scalar(k) {
        return None;
    }
    let point = to_affine(&multiply(&generator(), &from_bytes(k)))?;
    let r = from_bytes(&reduce_order(&point.x));
    if is_zero(&r) {
        return None;
    }
    let z = from_bytes(&reduce_order(digest));
    // s = k^-1 (z + r d) mod n, in Montgomery form throughout.
    let rm = to_mont(&r, &ORDER);
    let dm = to_mont(&from_bytes(d), &ORDER);
    let zm = to_mont(&z, &ORDER);
    let sum = add_mod(&zm, &order_mul(&rm, &dm), &ORDER);
    let km = to_mont(&from_bytes(k), &ORDER);
    let s = from_mont(&order_mul(&invert(&km, &ORDER), &sum), &ORDER);
    if is_zero(&s) {
        return None;
    }
    Some((to_bytes(&r), to_bytes(&s)))
}

/// Whether `(r, s)` is `q`'s signature of `digest`.
pub fn verify(q: &Point, digest: &[u8; 32], r: &[u8; 32], s: &[u8; 32]) -> bool {
    if !on_curve(q) || !valid_scalar(r) || !valid_scalar(s) {
        return false;
    }
    let (rl, sl) = (from_bytes(r), from_bytes(s));
    let z = from_bytes(&reduce_order(digest));
    let w = invert(&to_mont(&sl, &ORDER), &ORDER);
    let u1 = from_mont(&order_mul(&to_mont(&z, &ORDER), &w), &ORDER);
    let u2 = from_mont(&order_mul(&to_mont(&rl, &ORDER), &w), &ORDER);
    let sum = add(&multiply(&generator(), &u1), &multiply(&affine(q), &u2));
    let Some(point) = to_affine(&sum) else { return false };
    from_bytes(&reduce_order(&point.x)) == rl
}

//! NIST P-256: public keys, ECDH and ECDSA, for the TPM's keys. What takes a
//! secret (a private key, a per-signature secret) takes the same steps for
//! every value of it: the field arithmetic has no branch on its operands, a
//! scalar multiplication is a fixed number of doublings and additions with
//! complete formulas, and a table entry is picked by reading all of them.
//! Verifying a signature works on public numbers and takes the shorter way.
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

/// 1 for a word that is not zero, and 0 for one that is.
#[inline(always)]
fn nonzero(x: u32) -> u32 {
    (x | x.wrapping_neg()) >> 31
}

/// All ones for a 1 and all zeros for a 0.
#[inline(always)]
fn mask(bit: u32) -> u32 {
    bit.wrapping_neg()
}

/// `a` where `m` is all ones, and `b` where it is zero.
fn select(m: u32, a: &Limbs, b: &Limbs) -> Limbs {
    let mut out = [0u32; 8];
    for i in 0..8 {
        out[i] = (a[i] & m) | (b[i] & !m);
    }
    out
}

fn is_zero(a: &Limbs) -> bool {
    let mut any = 0u32;
    for &w in a.iter() {
        any |= w;
    }
    nonzero(any) == 0
}

/// `a >= b`.
fn geq(a: &Limbs, b: &Limbs) -> bool {
    sub_borrow(a, b).1 == 0
}

/// `a - b` and its borrow, 0 or 1.
fn sub_borrow(a: &Limbs, b: &Limbs) -> (Limbs, u32) {
    let mut out = [0u32; 8];
    let mut borrow = 0u32;
    for i in 0..8 {
        let d = (a[i] as u64).wrapping_sub(b[i] as u64).wrapping_sub(borrow as u64);
        out[i] = d as u32;
        borrow = (d >> 63) as u32;
    }
    (out, borrow)
}

/// `a + b` and its carry, 0 or 1.
fn add_carry(a: &Limbs, b: &Limbs) -> (Limbs, u32) {
    let mut out = [0u32; 8];
    let mut carry = 0u64;
    for i in 0..8 {
        let s = a[i] as u64 + b[i] as u64 + carry;
        out[i] = s as u32;
        carry = s >> 32;
    }
    (out, carry as u32)
}

fn add_mod(a: &Limbs, b: &Limbs, mo: &Modulus) -> Limbs {
    let (s, carry) = add_carry(a, b);
    let (d, borrow) = sub_borrow(&s, &mo.m);
    select(mask(carry | (borrow ^ 1)), &d, &s)
}

fn sub_mod(a: &Limbs, b: &Limbs, mo: &Modulus) -> Limbs {
    let (d, borrow) = sub_borrow(a, b);
    let (e, _) = add_carry(&d, &mo.m);
    select(mask(borrow), &e, &d)
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
    let (d, borrow) = sub_borrow(&out, &mo.m);
    select(mask(nonzero(t[8]) | (borrow ^ 1)), &d, &out)
}

/// Montgomery square `a * a / 2^256 mod m`: the 28 products of different limbs
/// once and doubled, the 8 squares, and then the reduction.
fn mont_sqr(a: &Limbs, mo: &Modulus) -> Limbs {
    let mut t = [0u32; 16];
    for i in 0..7 {
        let mut carry = 0u32;
        for j in i + 1..8 {
            let (s, c) = mul_add(t[i + j], a[i], a[j], carry);
            t[i + j] = s;
            carry = c;
        }
        t[i + 8] = carry;
    }
    let mut carry = 0u32;
    for word in t.iter_mut() {
        let next = *word >> 31;
        *word = *word << 1 | carry;
        carry = next;
    }
    let mut carry = 0u32;
    for i in 0..8 {
        let (lo, hi) = mul_wide(a[i], a[i]);
        let (s, c1) = t[2 * i].overflowing_add(lo);
        let (s, c2) = s.overflowing_add(carry);
        t[2 * i] = s;
        let (s, c3) = t[2 * i + 1].overflowing_add(hi);
        let (s, c4) = s.overflowing_add(c1 as u32 + c2 as u32);
        t[2 * i + 1] = s;
        carry = c3 as u32 + c4 as u32;
    }
    let mut top = 0u32;
    for i in 0..8 {
        let q = t[i].wrapping_mul(mo.n0);
        let mut carry = 0u32;
        for j in 0..8 {
            let (s, c) = mul_add(t[i + j], q, mo.m[j], carry);
            t[i + j] = s;
            carry = c;
        }
        for word in t[i + 8..].iter_mut() {
            let (s, c) = word.overflowing_add(carry);
            *word = s;
            carry = c as u32;
        }
        top += carry;
    }
    let mut out = [0u32; 8];
    out.copy_from_slice(&t[8..]);
    let (d, borrow) = sub_borrow(&out, &mo.m);
    select(mask(nonzero(top) | (borrow ^ 1)), &d, &out)
}

fn to_mont(a: &Limbs, mo: &Modulus) -> Limbs {
    mont_mul(a, &mo.r2, mo)
}

fn from_mont(a: &Limbs, mo: &Modulus) -> Limbs {
    let mut one = [0u32; 8];
    one[0] = 1;
    mont_mul(a, &one, mo)
}

fn sqr_times(a: &Limbs, times: u32, mo: &Modulus) -> Limbs {
    let mut r = *a;
    for _ in 0..times {
        r = mont_sqr(&r, mo);
    }
    r
}

/// `a^(2^k - 1)` for the `k` the inversion chains need: 30 and 32.
struct Runs {
    thirty: Limbs,
    thirty_two: Limbs,
}

fn runs(a: &Limbs, mo: &Modulus) -> Runs {
    let two = mont_mul(&mont_sqr(a, mo), a, mo);
    let three = mont_mul(&mont_sqr(&two, mo), a, mo);
    let six = mont_mul(&sqr_times(&three, 3, mo), &three, mo);
    let twelve = mont_mul(&sqr_times(&six, 6, mo), &six, mo);
    let fifteen = mont_mul(&sqr_times(&twelve, 3, mo), &three, mo);
    let thirty = mont_mul(&sqr_times(&fifteen, 15, mo), &fifteen, mo);
    let thirty_two = mont_mul(&sqr_times(&thirty, 2, mo), &two, mo);
    Runs { thirty, thirty_two }
}

/// `a^-1` modulo the field prime for a Montgomery, non-zero `a`: `a^(p-2)`,
/// where `p - 2` is 32 ones, 31 zeros and a one, 96 zeros, 62 ones, a zero and
/// a one.
fn invert_field(a: &Limbs) -> Limbs {
    let mo = &FIELD;
    let r = runs(a, mo);
    let mut x = mont_mul(&sqr_times(&r.thirty_two, 32, mo), a, mo);
    x = mont_mul(&sqr_times(&x, 128, mo), &r.thirty_two, mo);
    x = mont_mul(&sqr_times(&x, 32, mo), &r.thirty_two, mo);
    x = mont_mul(&sqr_times(&x, 30, mo), &r.thirty, mo);
    mont_mul(&sqr_times(&x, 2, mo), a, mo)
}

/// The low 128 bits of the group order less two.
const ORDER_TAIL: [u8; 16] = [0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x4f];

/// `a^-1` modulo the group order for a Montgomery, non-zero `a`: `a^(n-2)`,
/// where `n - 2` is 32 ones, 32 zeros, 64 ones and then 128 bits of no pattern,
/// taken a nibble at a time.
fn invert_order(a: &Limbs) -> Limbs {
    let mo = &ORDER;
    let r = runs(a, mo);
    let sixty_four = mont_mul(&sqr_times(&r.thirty_two, 32, mo), &r.thirty_two, mo);
    let mut x = sqr_times(&r.thirty_two, 32, mo);
    x = mont_mul(&sqr_times(&x, 64, mo), &sixty_four, mo);
    let mut table = [*a; 16];
    for j in 2..16 {
        table[j] = mont_mul(&table[j - 1], a, mo);
    }
    for byte in ORDER_TAIL {
        for nibble in [byte >> 4, byte & 0xf] {
            x = sqr_times(&x, 4, mo);
            if nibble != 0 {
                x = mont_mul(&x, &table[nibble as usize], mo);
            }
        }
    }
    x
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
fn fsqr(a: &Limbs) -> Limbs {
    mont_sqr(a, &FIELD)
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
    let delta = fsqr(&p.z);
    let gamma = fsqr(&p.y);
    let beta = fmul(&p.x, &gamma);
    let t = fmul(&fsub(&p.x, &delta), &fadd(&p.x, &delta));
    let alpha = fadd(&fadd(&t, &t), &t);
    let beta4 = fadd(&fadd(&beta, &beta), &fadd(&beta, &beta));
    let x3 = fsub(&fsqr(&alpha), &fadd(&beta4, &beta4));
    let yz = fadd(&p.y, &p.z);
    let z3 = fsub(&fsub(&fsqr(&yz), &gamma), &delta);
    let gamma2 = fsqr(&gamma);
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
    let z1z1 = fsqr(&p.z);
    let z2z2 = fsqr(&q.z);
    let u1 = fmul(&p.x, &z2z2);
    let u2 = fmul(&q.x, &z1z1);
    let s1 = fmul(&fmul(&p.y, &q.z), &z2z2);
    let s2 = fmul(&fmul(&q.y, &p.z), &z1z1);
    if u1 == u2 {
        return if s1 == s2 { double(p) } else { INFINITY };
    }
    let h = fsub(&u2, &u1);
    let h2 = fadd(&h, &h);
    let i = fsqr(&h2);
    let j = fmul(&h, &i);
    let r = {
        let d = fsub(&s2, &s1);
        fadd(&d, &d)
    };
    let v = fmul(&u1, &i);
    let x3 = fsub(&fsub(&fsqr(&r), &j), &fadd(&v, &v));
    let s1j = fmul(&s1, &j);
    let y3 = fsub(&fmul(&r, &fsub(&v, &x3)), &fadd(&s1j, &s1j));
    let zz = fadd(&p.z, &q.z);
    let z3 = fmul(&fsub(&fsub(&fsqr(&zz), &z1z1), &z2z2), &h);
    Jacobian { x: x3, y: y3, z: z3 }
}

fn affine(p: &Point) -> Jacobian {
    Jacobian { x: to_mont(&from_bytes(&p.x), &FIELD), y: to_mont(&from_bytes(&p.y), &FIELD), z: FIELD.one }
}

/// `p + q` for an affine `q` (`z` of one, never the point at infinity).
fn add_affine(p: &Jacobian, q: &[Limbs; 2]) -> Jacobian {
    if is_zero(&p.z) {
        return Jacobian { x: q[0], y: q[1], z: FIELD.one };
    }
    let z1z1 = fsqr(&p.z);
    let u2 = fmul(&q[0], &z1z1);
    let s2 = fmul(&fmul(&q[1], &p.z), &z1z1);
    let h = fsub(&u2, &p.x);
    let d = fsub(&s2, &p.y);
    if is_zero(&h) {
        return if is_zero(&d) { double(p) } else { INFINITY };
    }
    let hh = fsqr(&h);
    let i = fadd(&fadd(&hh, &hh), &fadd(&hh, &hh));
    let j = fmul(&h, &i);
    let r = fadd(&d, &d);
    let v = fmul(&p.x, &i);
    let x3 = fsub(&fsub(&fsqr(&r), &j), &fadd(&v, &v));
    let yj = fmul(&p.y, &j);
    let y3 = fsub(&fmul(&r, &fsub(&v, &x3)), &fadd(&yj, &yj));
    let zh = fadd(&p.z, &h);
    let z3 = fsub(&fsub(&fsqr(&zh), &z1z1), &hh);
    Jacobian { x: x3, y: y3, z: z3 }
}

/// The four bits of `k` from bit `4 * window`.
fn nibble(k: &Limbs, window: usize) -> usize {
    (k[window / 8] >> (4 * (window % 8)) & 0xf) as usize
}

/// `k * point` for a public `k`, in windows of four bits.
fn multiply_vartime(point: &Jacobian, k: &Limbs) -> Jacobian {
    let mut table = [INFINITY; 16];
    table[1] = *point;
    table[2] = double(point);
    for j in 3..16 {
        table[j] = add(&table[j - 1], point);
    }
    let mut result = INFINITY;
    for window in (0..64).rev() {
        for _ in 0..4 {
            result = double(&result);
        }
        let n = nibble(k, window);
        if n != 0 {
            result = add(&result, &table[n]);
        }
    }
    result
}

/// `k * G` from the tables: the low and the high half of `k` share their
/// doublings.
fn multiply_generator_vartime(k: &Limbs) -> Jacobian {
    let mut result = INFINITY;
    for window in (0..32).rev() {
        for _ in 0..4 {
            result = double(&result);
        }
        let low = nibble(k, window);
        if low != 0 {
            result = add_affine(&result, &LOW[low - 1]);
        }
        let high = nibble(k, window + 32);
        if high != 0 {
            result = add_affine(&result, &HIGH[high - 1]);
        }
    }
    result
}

include!("p256_tables.rs");

/// A point with homogeneous projective coordinates in the field's Montgomery
/// form, for the formulas that are complete: they hold for every pair of
/// points, the point at infinity `(0 : 1 : 0)` and a point added to itself
/// included, so a scalar multiplication needs no branch to go round them.
#[derive(Clone, Copy)]
struct Projective {
    x: Limbs,
    y: Limbs,
    z: Limbs,
}

const IDENTITY: Projective = Projective { x: [0; 8], y: P_R, z: [0; 8] };

/// `p + q`: Renes, Costello and Batina's Algorithm 4 for `a = -3`.
fn complete_add(p: &Projective, q: &Projective) -> Projective {
    let t0 = fmul(&p.x, &q.x);
    let t1 = fmul(&p.y, &q.y);
    let t2 = fmul(&p.z, &q.z);
    let t3 = fadd(&p.x, &p.y);
    let t4 = fadd(&q.x, &q.y);
    let t3 = fmul(&t3, &t4);
    let t4 = fadd(&t0, &t1);
    let t3 = fsub(&t3, &t4);
    let t4 = fadd(&p.y, &p.z);
    let x3 = fadd(&q.y, &q.z);
    let t4 = fmul(&t4, &x3);
    let x3 = fadd(&t1, &t2);
    let t4 = fsub(&t4, &x3);
    let x3 = fadd(&p.x, &p.z);
    let y3 = fadd(&q.x, &q.z);
    let x3 = fmul(&x3, &y3);
    let y3 = fadd(&t0, &t2);
    let y3 = fsub(&x3, &y3);
    let z3 = fmul(&B_MONT, &t2);
    let x3 = fsub(&y3, &z3);
    let z3 = fadd(&x3, &x3);
    let x3 = fadd(&x3, &z3);
    let z3 = fsub(&t1, &x3);
    let x3 = fadd(&t1, &x3);
    let y3 = fmul(&B_MONT, &y3);
    let t1 = fadd(&t2, &t2);
    let t2 = fadd(&t1, &t2);
    let y3 = fsub(&y3, &t2);
    let y3 = fsub(&y3, &t0);
    let t1 = fadd(&y3, &y3);
    let y3 = fadd(&t1, &y3);
    let t1 = fadd(&t0, &t0);
    let t0 = fadd(&t1, &t0);
    let t0 = fsub(&t0, &t2);
    let t1 = fmul(&t4, &y3);
    let t2 = fmul(&t0, &y3);
    let y3 = fmul(&x3, &z3);
    let y3 = fadd(&y3, &t2);
    let x3 = fmul(&t3, &x3);
    let x3 = fsub(&x3, &t1);
    let z3 = fmul(&t4, &z3);
    let t1 = fmul(&t3, &t0);
    let z3 = fadd(&z3, &t1);
    Projective { x: x3, y: y3, z: z3 }
}

/// `2 * p`: the same authors' Algorithm 6 for `a = -3`.
fn complete_double(p: &Projective) -> Projective {
    let t0 = fsqr(&p.x);
    let t1 = fsqr(&p.y);
    let t2 = fsqr(&p.z);
    let t3 = fmul(&p.x, &p.y);
    let t3 = fadd(&t3, &t3);
    let z3 = fmul(&p.x, &p.z);
    let z3 = fadd(&z3, &z3);
    let y3 = fmul(&B_MONT, &t2);
    let y3 = fsub(&y3, &z3);
    let x3 = fadd(&y3, &y3);
    let y3 = fadd(&x3, &y3);
    let x3 = fsub(&t1, &y3);
    let y3 = fadd(&t1, &y3);
    let y3 = fmul(&x3, &y3);
    let x3 = fmul(&x3, &t3);
    let t3 = fadd(&t2, &t2);
    let t2 = fadd(&t2, &t3);
    let z3 = fmul(&B_MONT, &z3);
    let z3 = fsub(&z3, &t2);
    let z3 = fsub(&z3, &t0);
    let t3 = fadd(&z3, &z3);
    let z3 = fadd(&z3, &t3);
    let t3 = fadd(&t0, &t0);
    let t0 = fadd(&t3, &t0);
    let t0 = fsub(&t0, &t2);
    let t0 = fmul(&t0, &z3);
    let y3 = fadd(&y3, &t0);
    let t0 = fmul(&p.y, &p.z);
    let t0 = fadd(&t0, &t0);
    let z3 = fmul(&t0, &z3);
    let x3 = fsub(&x3, &z3);
    let z3 = fmul(&t0, &t1);
    let z3 = fadd(&z3, &z3);
    let z3 = fadd(&z3, &z3);
    Projective { x: x3, y: y3, z: z3 }
}

/// 1 where the two numbers are equal, and 0 where they are not.
#[inline(always)]
fn equal(a: usize, b: usize) -> u32 {
    let d = (a ^ b) as u32;
    nonzero(d) ^ 1
}

/// Entry `n` of `table`, picked by looking at every entry.
fn pick(table: &[Projective; 16], n: usize) -> Projective {
    let mut out = IDENTITY;
    for (j, entry) in table.iter().enumerate() {
        let m = mask(equal(j, n));
        out.x = select(m, &entry.x, &out.x);
        out.y = select(m, &entry.y, &out.y);
        out.z = select(m, &entry.z, &out.z);
    }
    out
}

/// Entry `n` of a table of the multiples `1..=15` of a point, as affine
/// coordinates, the point at infinity for a 0, picked by looking at every
/// entry.
fn pick_affine(table: &[[Limbs; 2]; 15], n: usize) -> Projective {
    let mut x = [0u32; 8];
    let mut y = [0u32; 8];
    for (j, entry) in table.iter().enumerate() {
        let m = mask(equal(j + 1, n));
        x = select(m, &entry[0], &x);
        y = select(m, &entry[1], &y);
    }
    let live = mask(nonzero(n as u32));
    Projective { x, y: select(live, &y, &P_R), z: select(live, &P_R, &[0; 8]) }
}

/// `k * point` for a secret `k` of at most 256 bits: four doublings and one
/// addition for each of 64 windows, whatever the windows hold.
fn multiply(point: &Projective, k: &Limbs) -> Projective {
    let mut table = [IDENTITY; 16];
    table[1] = *point;
    for j in 2..16 {
        table[j] = if j % 2 == 0 { complete_double(&table[j / 2]) } else { complete_add(&table[j - 1], point) };
    }
    let mut result = IDENTITY;
    for window in (0..64).rev() {
        for _ in 0..4 {
            result = complete_double(&result);
        }
        result = complete_add(&result, &pick(&table, nibble(k, window)));
    }
    result
}

/// `k * G` for a secret `k` from the tables, with the low and the high half of
/// `k` sharing their doublings.
fn multiply_generator(k: &Limbs) -> Projective {
    let mut result = IDENTITY;
    for window in (0..32).rev() {
        for _ in 0..4 {
            result = complete_double(&result);
        }
        result = complete_add(&result, &pick_affine(&LOW, nibble(k, window)));
        result = complete_add(&result, &pick_affine(&HIGH, nibble(k, window + 32)));
    }
    result
}

fn to_affine_projective(p: &Projective) -> Option<Point> {
    if is_zero(&p.z) {
        return None;
    }
    let zi = invert_field(&p.z);
    let x = fmul(&p.x, &zi);
    let y = fmul(&p.y, &zi);
    Some(Point { x: to_bytes(&from_mont(&x, &FIELD)), y: to_bytes(&from_mont(&y, &FIELD)) })
}

fn projective(p: &Point) -> Projective {
    Projective { x: to_mont(&from_bytes(&p.x), &FIELD), y: to_mont(&from_bytes(&p.y), &FIELD), z: FIELD.one }
}

fn to_affine(p: &Jacobian) -> Option<Point> {
    if is_zero(&p.z) {
        return None;
    }
    let zi = invert_field(&p.z);
    let zi2 = fsqr(&zi);
    let x = fmul(&p.x, &zi2);
    let y = fmul(&fmul(&p.y, &zi2), &zi);
    Some(Point { x: to_bytes(&from_mont(&x, &FIELD)), y: to_bytes(&from_mont(&y, &FIELD)) })
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
    let x3 = fmul(&fsqr(&x), &x);
    let three_x = fadd(&fadd(&x, &x), &x);
    let rhs = fadd(&fsub(&x3, &three_x), &B_MONT);
    fsqr(&y) == rhs
}

/// The public key of private key `d`.
pub fn public_key(d: &[u8; 32]) -> Option<Point> {
    if !valid_scalar(d) {
        return None;
    }
    to_affine_projective(&multiply_generator(&from_bytes(d)))
}

/// The x coordinate of `d` times `peer`, which has to be on the curve.
pub fn ecdh(d: &[u8; 32], peer: &Point) -> Option<[u8; 32]> {
    if !valid_scalar(d) || !on_curve(peer) {
        return None;
    }
    to_affine_projective(&multiply(&projective(peer), &from_bytes(d))).map(|p| p.x)
}

/// `x` reduced modulo the group order, as a hash is for a signature.
pub fn reduce_order(x: &[u8; 32]) -> [u8; 32] {
    let l = from_bytes(x);
    let (d, borrow) = sub_borrow(&l, &N);
    to_bytes(&select(mask(borrow), &l, &d))
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
    let point = to_affine_projective(&multiply_generator(&from_bytes(k)))?;
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
    let s = from_mont(&order_mul(&invert_order(&km), &sum), &ORDER);
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
    let w = invert_order(&to_mont(&sl, &ORDER));
    let u1 = from_mont(&order_mul(&to_mont(&z, &ORDER), &w), &ORDER);
    let u2 = from_mont(&order_mul(&to_mont(&rl, &ORDER), &w), &ORDER);
    let sum = add(&multiply_generator_vartime(&u1), &multiply_vartime(&affine(q), &u2));
    let Some(point) = to_affine(&sum) else { return false };
    from_bytes(&reduce_order(&point.x)) == rl
}

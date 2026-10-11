//! The firmware's P-256, AES-CFB and KDFs against vectors the reference
//! implementations in `gen-vectors.py` produced.

use tpm_sim::{aes, kdf, p256, rsa};

mod vectors;
use vectors::*;

#[test]
fn public_keys() {
    for k in KEYS {
        let q = p256::public_key(&k.d).unwrap();
        assert_eq!(q.x, k.x);
        assert_eq!(q.y, k.y);
        assert!(p256::on_curve(&q));
    }
}

#[test]
fn rejects_bad_scalars_and_points() {
    assert!(p256::public_key(&[0; 32]).is_none());
    assert!(p256::public_key(&[0xff; 32]).is_none());
    let mut q = p256::public_key(&KEYS[0].d).unwrap();
    q.y[31] ^= 1;
    assert!(!p256::on_curve(&q));
    assert!(p256::ecdh(&KEYS[1].d, &q).is_none());
}

#[test]
fn ecdh_shared_x() {
    for (d, x, y, shared) in ECDH {
        let peer = p256::Point { x: *x, y: *y };
        assert_eq!(p256::ecdh(d, &peer).unwrap(), *shared);
    }
}

#[test]
fn ecdsa_signs_as_the_arithmetic_says() {
    for (d, k, digest, r, s) in SIGNATURES {
        let (got_r, got_s) = p256::sign(d, digest, k).unwrap();
        assert_eq!(got_r, *r);
        assert_eq!(got_s, *s);
        let q = p256::public_key(d).unwrap();
        assert!(p256::verify(&q, digest, r, s));
    }
}

#[test]
fn ecdsa_verifies_the_librarys_signatures() {
    for (x, y, digest, r, s) in LIBRARY_SIGNATURES {
        let q = p256::Point { x: *x, y: *y };
        assert!(p256::verify(&q, digest, r, s));
        let mut bad = *digest;
        bad[0] ^= 1;
        assert!(!p256::verify(&q, &bad, r, s));
    }
}

#[test]
fn aes_cfb() {
    for (key, iv, plain, cipher) in CFB {
        let aes = aes::Aes128::new(key);
        let mut data = plain.to_vec();
        aes.cfb_encrypt(iv, &mut data);
        assert_eq!(&data, cipher);
        aes.cfb_decrypt(iv, &mut data);
        assert_eq!(&data, plain);
    }
}

#[test]
fn kdfa_matches() {
    for (key, label, u, v, bits, want) in KDFA {
        let mut out = vec![0u8; (*bits as usize).div_ceil(8)];
        kdf::kdfa(key, label, u, v, *bits, &mut out);
        assert_eq!(&out, want);
    }
}

#[test]
fn kdfe_matches() {
    for (z, label, u, v, bits, want) in KDFE {
        let mut out = vec![0u8; (*bits as usize).div_ceil(8)];
        kdf::kdfe(z, label, u, v, *bits, &mut out);
        assert_eq!(&out, want);
    }
}

#[test]
fn rsa_pkcs1_signatures() {
    for (modulus, exponent, digest, signature, valid) in RSA {
        assert_eq!(rsa::verify_sha256(modulus, *exponent, digest, signature), *valid);
    }
}

/// Scalars that line up with the generator tables' windows and halves.
#[test]
fn public_keys_of_awkward_scalars() {
    // (d, x of d*G): 1, 2, 15, 16, 2^128, 2^128 + 1, n - 1, as Python's arithmetic has them.
    for (d, x) in EDGE_KEYS {
        assert_eq!(&p256::public_key(d).unwrap().x, x);
    }
}

#[test]
fn sign_and_verify_round_trip() {
    for k in KEYS {
        let q = p256::public_key(&k.d).unwrap();
        let (r, s) = p256::sign(&k.d, &[0x5a; 32], &[0x77; 32]).unwrap();
        assert!(p256::verify(&q, &[0x5a; 32], &r, &s));
        assert!(!p256::verify(&q, &[0x5b; 32], &r, &s));
    }
}

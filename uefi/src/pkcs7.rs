//! Just enough DER, X.509 and PKCS #7 to check an Authenticode signature:
//! RSA keys and SHA-256 throughout, as the UEFI CAs and the distributions'
//! signers use.

use alloc::vec::Vec;

use crate::rsa;
use crate::sha256;

const SHA256_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
const RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const SIGNED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
const MESSAGE_DIGEST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];
/// `id-data`.
const DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01];
/// `SPC_INDIRECT_DATA_OBJID`.
const SPC_INDIRECT_DATA: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04];
const COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];

/// The most certificates a signature may carry: building the chain checks
/// each against the others, and the signature is read before it is trusted.
const MAX_CERTS: usize = 16;

const SEQ: u8 = 0x30;
const SET: u8 = 0x31;
const INT: u8 = 0x02;
const OID: u8 = 0x06;
const OCTETS: u8 = 0x04;
const BITS: u8 = 0x03;
const CTX0: u8 = 0xa0;
const CTX1: u8 = 0xa1;

#[derive(Clone, Copy)]
struct Tlv<'a> {
    tag: u8,
    body: &'a [u8],
    whole: &'a [u8],
}

/// A run of DER values, read front to back.
struct Der<'a>(&'a [u8]);

impl<'a> Der<'a> {
    fn next(&mut self) -> Option<Tlv<'a>> {
        let d = self.0;
        let tag = *d.first()?;
        let first = *d.get(1)? as usize;
        let (len, head) = if first < 0x80 {
            (first, 2)
        } else {
            let n = first & 0x7f;
            if n == 0 || n > 4 {
                return None;
            }
            let len = d.get(2..2 + n)?.iter().fold(0usize, |a, &b| a << 8 | b as usize);
            (len, 2 + n)
        };
        let end = head.checked_add(len)?;
        let whole = d.get(..end)?;
        self.0 = &d[end..];
        Some(Tlv { tag, body: &whole[head..], whole })
    }

    fn expect(&mut self, tag: u8) -> Option<Tlv<'a>> {
        self.next().filter(|t| t.tag == tag)
    }

    fn body(&mut self, tag: u8) -> Option<&'a [u8]> {
        self.expect(tag).map(|t| t.body)
    }

    fn optional(&mut self, tag: u8) -> Option<Tlv<'a>> {
        if self.0.first() == Some(&tag) { self.next() } else { None }
    }

    /// The OID of an `AlgorithmIdentifier`.
    fn algorithm(&mut self) -> Option<&'a [u8]> {
        Der(self.body(SEQ)?).body(OID)
    }
}

/// An X.509 certificate with an RSA key.
pub struct Cert<'a> {
    pub whole: &'a [u8],
    tbs: &'a [u8],
    sig_alg: &'a [u8],
    sig: &'a [u8],
    serial: &'a [u8],
    issuer: &'a [u8],
    subject: &'a [u8],
    n: &'a [u8],
    e: &'a [u8],
}

impl<'a> Cert<'a> {
    pub fn parse(der: &'a [u8]) -> Option<Cert<'a>> {
        let top = Der(der).expect(SEQ)?;
        let mut c = Der(top.body);
        let tbs = c.expect(SEQ)?;
        let sig_alg = c.algorithm()?;
        let sig = c.body(BITS)?.split_first().filter(|(unused, _)| **unused == 0)?.1;
        let mut t = Der(tbs.body);
        t.optional(CTX0);
        let serial = t.body(INT)?;
        t.expect(SEQ)?;
        let issuer = t.expect(SEQ)?.whole;
        t.expect(SEQ)?;
        let subject = t.expect(SEQ)?.whole;
        let mut spki = Der(t.body(SEQ)?);
        if spki.algorithm()? != RSA_ENCRYPTION {
            return None;
        }
        let key = spki.body(BITS)?.split_first().filter(|(unused, _)| **unused == 0)?.1;
        let mut key = Der(Der(key).body(SEQ)?);
        let (n, e) = (key.body(INT)?, key.body(INT)?);
        Some(Cert { whole: top.whole, tbs: tbs.whole, sig_alg, sig, serial, issuer, subject, n, e })
    }

    /// Whether this certificate's key signed `child`.
    fn signed(&self, child: &Cert) -> bool {
        self.subject == child.issuer
            && child.sig_alg == SHA256_WITH_RSA
            && rsa::verify(self.n, self.e, child.sig, &sha256::digest(child.tbs))
    }

    /// The subject's common name, for the log.
    pub fn name(&self) -> &'a str {
        common_name(self.subject)
    }
}

fn common_name(name: &[u8]) -> &str {
    let mut rdns = Der(Der(name).expect(SEQ).map_or(&[][..], |t| t.body));
    while let Some(rdn) = rdns.next() {
        let mut atvs = Der(rdn.body);
        while let Some(atv) = atvs.next() {
            let mut a = Der(atv.body);
            if a.body(OID) == Some(COMMON_NAME) {
                if let Some(v) = a.next() {
                    return core::str::from_utf8(v.body).unwrap_or("?");
                }
            }
        }
    }
    "?"
}

/// What a signature says about an image, once its own signature checks out.
pub struct Signed<'a> {
    /// The Authenticode hash the signer signed.
    pub digest: &'a [u8],
    /// The certificates the signature carries, the signer first.
    pub chain: Vec<Cert<'a>>,
}

/// Check an Authenticode `SignedData`: that its signer, among the
/// certificates it carries, signed its content. What the content's hash is
/// and whether the signer is trusted is the caller's to check.
pub fn signed_data(der: &[u8]) -> Result<Signed<'_>, &'static str> {
    signed_data_inner(der, None).ok_or("signature malformed or of a kind not supported")?
}

/// Check a detached `SignedData` over `content`, as an authenticated
/// variable carries: that its signer signed exactly those bytes.
pub fn signed_content<'a>(der: &'a [u8], content: &[u8]) -> Result<Signed<'a>, &'static str> {
    signed_data_inner(der, Some(content)).ok_or("signature malformed or of a kind not supported")?
}

fn signed_data_inner<'a>(der: &'a [u8], detached: Option<&[u8]>) -> Option<Result<Signed<'a>, &'static str>> {
    let mut ci = Der(Der(der).body(SEQ)?);
    if ci.body(OID)? != SIGNED_DATA {
        return None;
    }
    let mut sd = Der(Der(ci.body(CTX0)?).body(SEQ)?);
    sd.body(INT)?;
    sd.body(SET)?;
    let mut content = Der(sd.body(SEQ)?);
    let kind = content.body(OID)?;
    let (digest, signed_bytes): (&[u8], &[u8]) = match detached {
        None => {
            if kind != SPC_INDIRECT_DATA {
                return None;
            }
            let spc = Der(content.body(CTX0)?).expect(SEQ)?;
            let mut s = Der(spc.body);
            s.expect(SEQ)?;
            let mut digest_info = Der(s.body(SEQ)?);
            if digest_info.algorithm()? != SHA256 {
                return Some(Err("image hash not SHA-256"));
            }
            (digest_info.body(OCTETS)?, spc.body)
        }
        Some(bytes) => {
            if kind != DATA {
                return None;
            }
            (&[], bytes)
        }
    };

    let mut certs = Vec::new();
    if let Some(set) = sd.optional(CTX0) {
        let mut d = Der(set.body);
        while let Some(c) = d.next() {
            // Anything that is not an RSA certificate cannot be on the chain.
            if let Some(c) = Cert::parse(c.whole) {
                if certs.len() == MAX_CERTS {
                    return None;
                }
                certs.push(c);
            }
        }
    }
    sd.optional(CTX1);
    let mut signers = Der(sd.body(SET)?);
    let mut si = Der(signers.body(SEQ)?);
    si.body(INT)?;
    let mut ias = Der(si.body(SEQ)?);
    let (issuer, serial) = (ias.expect(SEQ)?.whole, ias.body(INT)?);
    if si.algorithm()? != SHA256 {
        return Some(Err("signature not over SHA-256"));
    }
    let Some(attrs) = si.optional(CTX0) else { return Some(Err("signature without signed attributes")) };
    let enc = si.algorithm()?;
    if enc != RSA_ENCRYPTION && enc != SHA256_WITH_RSA {
        return Some(Err("signature not RSA"));
    }
    let sig = si.body(OCTETS)?;

    // The signed attributes carry the hash of the content, and the
    // signature is over them as the `SET OF` they are, not the `[0]` they are
    // tagged as here.
    let mut found = false;
    let mut a = Der(attrs.body);
    while let Some(attr) = a.next() {
        let mut attr = Der(attr.body);
        if attr.body(OID)? == MESSAGE_DIGEST {
            if Der(attr.body(SET)?).body(OCTETS)? != sha256::digest(signed_bytes) {
                return Some(Err("signed attributes do not match the content"));
            }
            found = true;
        }
    }
    if !found {
        return Some(Err("signed attributes do not match the content"));
    }
    let mut hasher = sha256::Sha256::new();
    hasher.update(&[SET]);
    hasher.update(&attrs.whole[1..]);
    let hash = hasher.finish();

    let Some(at) = certs.iter().position(|c| c.issuer == issuer && c.serial == serial) else {
        return Some(Err("signer's certificate missing"));
    };
    if !rsa::verify(certs[at].n, certs[at].e, sig, &hash) {
        return Some(Err("signature does not verify"));
    }
    certs.swap(0, at);
    Some(Ok(Signed { digest, chain: certs }))
}

/// The certificate in `trusted` the signer's chain ends at: the signer
/// itself, or one that signed it or a certificate up its chain.
pub fn anchor<'t>(signed: &Signed, trusted: &'t [Cert<'t>]) -> Option<&'t Cert<'t>> {
    let mut cur = &signed.chain[0];
    for _ in 0..signed.chain.len() {
        if let Some(t) = trusted.iter().find(|t| t.whole == cur.whole || t.signed(cur)) {
            return Some(t);
        }
        cur = signed.chain.iter().find(|c| c.whole != cur.whole && c.signed(cur))?;
    }
    None
}

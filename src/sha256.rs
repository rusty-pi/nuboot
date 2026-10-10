//! SHA-256, for the digests `pieeprom.bin` keeps after each packed section.

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub struct Sha256 {
    h: [u32; 8],
    buf: [u8; 64],
    fill: usize,
    total: u32,
}

impl Sha256 {
    pub fn new() -> Sha256 {
        Sha256 {
            h: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buf: [0; 64],
            fill: 0,
            total: 0,
        }
    }

    /// Run one 64-byte block into the state, with the message schedule kept
    /// as a rolling window of 16 words.
    ///
    /// The rounds are written out rather than looped: a round renames the
    /// eight working variables rather than moving them, so rolled up it costs
    /// six register moves a round to shuffle `a`..`h` along, and the schedule
    /// index is only a constant offset when the round number is one.
    fn compress(h: &mut [u32; 8], block: &[u8]) {
        let mut w = [0u32; 16];
        // VC4 cannot load an unaligned word, so reading four bytes and
        // putting them together costs four `ldb` and six more instructions
        // unless the compiler knows the block is aligned. Whole blocks come
        // out of the caller's buffer word aligned; when they do, one `ld` and
        // a byte swap replace all ten. Every bit pattern is a valid `u32`,
        // which is what `align_to` asks of the caller.
        let (head, words, _) = unsafe { block.align_to::<u32>() };
        if head.is_empty() && words.len() >= 16 {
            for (word, &raw) in w.iter_mut().zip(&words[..16]) {
                *word = u32::from_be(raw);
            }
        } else {
            for (i, word) in w.iter_mut().enumerate() {
                let at = i * 4;
                *word =
                    u32::from_be_bytes([block[at], block[at + 1], block[at + 2], block[at + 3]]);
            }
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = *h;

        macro_rules! round {
            ($i:expr, $j:expr, $a:ident, $b:ident, $c:ident, $d:ident,
             $e:ident, $f:ident, $g:ident, $h:ident) => {{
                if $i >= 16 {
                    let w15 = w[($j + 1) & 15];
                    let w2 = w[($j + 14) & 15];
                    let s0 = w15.rotate_right(7) ^ w15.rotate_right(18) ^ (w15 >> 3);
                    let s1 = w2.rotate_right(17) ^ w2.rotate_right(19) ^ (w2 >> 10);
                    w[$j] = w[$j]
                        .wrapping_add(s0)
                        .wrapping_add(w[($j + 9) & 15])
                        .wrapping_add(s1);
                }
                let s1 = $e.rotate_right(6) ^ $e.rotate_right(11) ^ $e.rotate_right(25);
                let ch = ($e & $f) ^ (!$e & $g);
                let t1 = $h
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(K[$i])
                    .wrapping_add(w[$j]);
                let s0 = $a.rotate_right(2) ^ $a.rotate_right(13) ^ $a.rotate_right(22);
                let maj = ($a & $b) ^ ($a & $c) ^ ($b & $c);
                $d = $d.wrapping_add(t1);
                $h = t1.wrapping_add(s0.wrapping_add(maj));
            }};
        }

        round!(0, 0, a, b, c, d, e, f, g, hh);
        round!(1, 1, hh, a, b, c, d, e, f, g);
        round!(2, 2, g, hh, a, b, c, d, e, f);
        round!(3, 3, f, g, hh, a, b, c, d, e);
        round!(4, 4, e, f, g, hh, a, b, c, d);
        round!(5, 5, d, e, f, g, hh, a, b, c);
        round!(6, 6, c, d, e, f, g, hh, a, b);
        round!(7, 7, b, c, d, e, f, g, hh, a);
        round!(8, 8, a, b, c, d, e, f, g, hh);
        round!(9, 9, hh, a, b, c, d, e, f, g);
        round!(10, 10, g, hh, a, b, c, d, e, f);
        round!(11, 11, f, g, hh, a, b, c, d, e);
        round!(12, 12, e, f, g, hh, a, b, c, d);
        round!(13, 13, d, e, f, g, hh, a, b, c);
        round!(14, 14, c, d, e, f, g, hh, a, b);
        round!(15, 15, b, c, d, e, f, g, hh, a);
        round!(16, 0, a, b, c, d, e, f, g, hh);
        round!(17, 1, hh, a, b, c, d, e, f, g);
        round!(18, 2, g, hh, a, b, c, d, e, f);
        round!(19, 3, f, g, hh, a, b, c, d, e);
        round!(20, 4, e, f, g, hh, a, b, c, d);
        round!(21, 5, d, e, f, g, hh, a, b, c);
        round!(22, 6, c, d, e, f, g, hh, a, b);
        round!(23, 7, b, c, d, e, f, g, hh, a);
        round!(24, 8, a, b, c, d, e, f, g, hh);
        round!(25, 9, hh, a, b, c, d, e, f, g);
        round!(26, 10, g, hh, a, b, c, d, e, f);
        round!(27, 11, f, g, hh, a, b, c, d, e);
        round!(28, 12, e, f, g, hh, a, b, c, d);
        round!(29, 13, d, e, f, g, hh, a, b, c);
        round!(30, 14, c, d, e, f, g, hh, a, b);
        round!(31, 15, b, c, d, e, f, g, hh, a);
        round!(32, 0, a, b, c, d, e, f, g, hh);
        round!(33, 1, hh, a, b, c, d, e, f, g);
        round!(34, 2, g, hh, a, b, c, d, e, f);
        round!(35, 3, f, g, hh, a, b, c, d, e);
        round!(36, 4, e, f, g, hh, a, b, c, d);
        round!(37, 5, d, e, f, g, hh, a, b, c);
        round!(38, 6, c, d, e, f, g, hh, a, b);
        round!(39, 7, b, c, d, e, f, g, hh, a);
        round!(40, 8, a, b, c, d, e, f, g, hh);
        round!(41, 9, hh, a, b, c, d, e, f, g);
        round!(42, 10, g, hh, a, b, c, d, e, f);
        round!(43, 11, f, g, hh, a, b, c, d, e);
        round!(44, 12, e, f, g, hh, a, b, c, d);
        round!(45, 13, d, e, f, g, hh, a, b, c);
        round!(46, 14, c, d, e, f, g, hh, a, b);
        round!(47, 15, b, c, d, e, f, g, hh, a);
        round!(48, 0, a, b, c, d, e, f, g, hh);
        round!(49, 1, hh, a, b, c, d, e, f, g);
        round!(50, 2, g, hh, a, b, c, d, e, f);
        round!(51, 3, f, g, hh, a, b, c, d, e);
        round!(52, 4, e, f, g, hh, a, b, c, d);
        round!(53, 5, d, e, f, g, hh, a, b, c);
        round!(54, 6, c, d, e, f, g, hh, a, b);
        round!(55, 7, b, c, d, e, f, g, hh, a);
        round!(56, 8, a, b, c, d, e, f, g, hh);
        round!(57, 9, hh, a, b, c, d, e, f, g);
        round!(58, 10, g, hh, a, b, c, d, e, f);
        round!(59, 11, f, g, hh, a, b, c, d, e);
        round!(60, 12, e, f, g, hh, a, b, c, d);
        round!(61, 13, d, e, f, g, hh, a, b, c);
        round!(62, 14, c, d, e, f, g, hh, a, b);
        round!(63, 15, b, c, d, e, f, g, hh, a);

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u32);
        // Top up a partial block first, then whole blocks straight from the
        // input.
        if self.fill != 0 {
            let take = (64 - self.fill).min(data.len());
            self.buf[self.fill..self.fill + take].copy_from_slice(&data[..take]);
            self.fill += take;
            data = &data[take..];
            if self.fill < 64 {
                return;
            }
            Self::compress(&mut self.h, &self.buf);
            self.fill = 0;
        }
        let mut blocks = data.chunks_exact(64);
        for block in &mut blocks {
            Self::compress(&mut self.h, block);
        }
        let rest = blocks.remainder();
        self.buf[..rest.len()].copy_from_slice(rest);
        self.fill = rest.len();
    }

    pub fn finish(mut self) -> [u8; 32] {
        // Inputs here stay well under 512 MiB, so the bit count fits 32 bits.
        let total = self.total;
        let bits = total << 3;
        let hi = total >> 29;
        let pad = if self.fill < 56 { 56 - self.fill } else { 120 - self.fill };
        let mut tail = [0u8; 72];
        tail[0] = 0x80;
        tail[pad..pad + 4].copy_from_slice(&hi.to_be_bytes());
        tail[pad + 4..pad + 8].copy_from_slice(&bits.to_be_bytes());
        self.update(&tail[..pad + 8]);
        let mut out = [0; 32];
        for (o, h) in out.chunks_exact_mut(4).zip(self.h) {
            o.copy_from_slice(&h.to_be_bytes());
        }
        out
    }
}

pub fn digest(data: &[u8]) -> [u8; 32] {
    let mut s = Sha256::new();
    s.update(data);
    s.finish()
}

/// HMAC-SHA256 (RFC 2104): the key padded out to the hash's own block, once
/// for the inner pass and once for the outer.
pub fn hmac(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut padded = [0u8; BLOCK];
    if key.len() > BLOCK {
        padded[..32].copy_from_slice(&digest(key));
    } else {
        padded[..key.len()].copy_from_slice(key);
    }

    let mut block = [0u8; BLOCK];
    for (b, k) in block.iter_mut().zip(padded.iter()) {
        *b = k ^ 0x36;
    }
    let mut inner = Sha256::new();
    inner.update(&block);
    inner.update(message);
    let inner = inner.finish();

    for (b, k) in block.iter_mut().zip(padded.iter()) {
        *b = k ^ 0x5c;
    }
    let mut outer = Sha256::new();
    outer.update(&block);
    outer.update(&inner);
    outer.finish()
}

//! A decoder for the raw LZMA1 stream `xz --format=raw --lzma1` writes, and
//! the inverse of xz's ARM64 branch filter that runs before it.
//!
//! The whole output buffer is the dictionary, so the stream decodes in one
//! call straight to where the image runs. It follows the reference decoder in
//! the LZMA SDK's `LzmaSpec.cpp`.

#[derive(Debug)]
pub struct Error;

/// `lc + lp` this decoder has room for.
const MAX_LC_LP: u32 = 3;
const LITERAL_CODER_SIZE: usize = 0x300;
const NUM_STATES: usize = 12;
const MAX_POS_STATES: usize = 16;
const NUM_LEN_TO_POS_STATES: usize = 4;
const END_POS_MODEL_INDEX: u32 = 14;
const NUM_FULL_DISTANCES: usize = 128;
const NUM_ALIGN_BITS: u32 = 4;
const PROB_INIT: u16 = 1 << 10;

struct RangeDecoder<'a> {
    data: &'a [u8],
    pos: usize,
    range: u32,
    code: u32,
}

impl<'a> RangeDecoder<'a> {
    fn new(data: &'a [u8]) -> Result<Self, Error> {
        let mut rc = Self { data, pos: 0, range: 0xFFFF_FFFF, code: 0 };
        if rc.byte() != 0 {
            return Err(Error);
        }
        for _ in 0..4 {
            rc.code = (rc.code << 8) | rc.byte() as u32;
        }
        if rc.code == rc.range {
            return Err(Error);
        }
        Ok(rc)
    }

    fn byte(&mut self) -> u8 {
        let b = self.data.get(self.pos).copied().unwrap_or(0);
        self.pos += 1;
        b
    }

    fn normalize(&mut self) {
        if self.range < 1 << 24 {
            self.range <<= 8;
            self.code = (self.code << 8) | self.byte() as u32;
        }
    }

    fn direct_bits(&mut self, count: u32) -> u32 {
        let mut res = 0u32;
        for _ in 0..count {
            self.range >>= 1;
            self.code = self.code.wrapping_sub(self.range);
            let t = 0u32.wrapping_sub(self.code >> 31);
            self.code = self.code.wrapping_add(self.range & t);
            self.normalize();
            res = (res << 1).wrapping_add(t.wrapping_add(1));
        }
        res
    }

    fn bit(&mut self, prob: &mut u16) -> u32 {
        let bound = (self.range >> 11) * *prob as u32;
        let bit = if self.code < bound {
            *prob += ((1 << 11) - *prob) >> 5;
            self.range = bound;
            0
        } else {
            *prob -= *prob >> 5;
            self.code -= bound;
            self.range -= bound;
            1
        };
        self.normalize();
        bit
    }

    fn tree(&mut self, probs: &mut [u16], bits: u32) -> u32 {
        let mut m = 1usize;
        for _ in 0..bits {
            m = (m << 1) + self.bit(&mut probs[m]) as usize;
        }
        m as u32 - (1 << bits)
    }

    fn tree_reverse(&mut self, probs: &mut [u16], bits: u32) -> u32 {
        let mut m = 1usize;
        let mut symbol = 0;
        for i in 0..bits {
            let bit = self.bit(&mut probs[m]);
            m = (m << 1) + bit as usize;
            symbol |= bit << i;
        }
        symbol
    }
}

#[repr(C)]
struct LenDecoder {
    choice: u16,
    choice2: u16,
    low: [[u16; 1 << 3]; MAX_POS_STATES],
    mid: [[u16; 1 << 3]; MAX_POS_STATES],
    high: [u16; 1 << 8],
}

impl LenDecoder {
    fn decode(&mut self, rc: &mut RangeDecoder, pos_state: usize) -> u32 {
        if rc.bit(&mut self.choice) == 0 {
            rc.tree(&mut self.low[pos_state], 3)
        } else if rc.bit(&mut self.choice2) == 0 {
            8 + rc.tree(&mut self.mid[pos_state], 3)
        } else {
            16 + rc.tree(&mut self.high, 8)
        }
    }
}

/// Every probability the decoder keeps; only `u16`s, so it can be filled as
/// one array.
#[repr(C)]
struct Model {
    literal: [u16; LITERAL_CODER_SIZE << MAX_LC_LP],
    is_match: [[u16; MAX_POS_STATES]; NUM_STATES],
    is_rep: [u16; NUM_STATES],
    is_rep_g0: [u16; NUM_STATES],
    is_rep_g1: [u16; NUM_STATES],
    is_rep_g2: [u16; NUM_STATES],
    is_rep0_long: [[u16; MAX_POS_STATES]; NUM_STATES],
    pos_slot: [[u16; 1 << 6]; NUM_LEN_TO_POS_STATES],
    pos: [u16; 1 + NUM_FULL_DISTANCES - END_POS_MODEL_INDEX as usize],
    align: [u16; 1 << NUM_ALIGN_BITS],
    len: LenDecoder,
    rep_len: LenDecoder,
}

/// Decode `src`, coded with the properties byte `props` (`(pb * 5 + lp) * 9 +
/// lc`), until `out` is full.
pub fn decode(src: &[u8], props: u8, out: &mut [u8]) -> Result<(), Error> {
    let props = props as u32;
    if props >= 9 * 5 * 5 {
        return Err(Error);
    }
    let lc = props % 9;
    let lp = props / 9 % 5;
    let pb = props / 45;
    if lc + lp > MAX_LC_LP {
        return Err(Error);
    }

    // SAFETY: `Model` is `repr(C)` and made of `u16`s only.
    let mut m: Model =
        unsafe { core::mem::transmute([PROB_INIT; core::mem::size_of::<Model>() / 2]) };
    let mut rc = RangeDecoder::new(src)?;
    let (mut rep0, mut rep1, mut rep2, mut rep3) = (0usize, 0usize, 0usize, 0usize);
    let mut state = 0usize;
    let mut pos = 0usize;

    while pos < out.len() {
        let pos_state = pos & ((1 << pb) - 1);

        if rc.bit(&mut m.is_match[state][pos_state]) == 0 {
            let prev = if pos > 0 { out[pos - 1] as usize } else { 0 };
            let lit_state = ((pos & ((1 << lp) - 1)) << lc) + (prev >> (8 - lc));
            let probs = &mut m.literal[LITERAL_CODER_SIZE * lit_state..][..LITERAL_CODER_SIZE];
            let mut symbol = 1usize;
            if state >= 7 {
                let mut match_byte = *out.get(pos.wrapping_sub(rep0 + 1)).ok_or(Error)? as usize;
                while symbol < 0x100 {
                    let match_bit = (match_byte >> 7) & 1;
                    match_byte <<= 1;
                    let bit = rc.bit(&mut probs[((1 + match_bit) << 8) + symbol]) as usize;
                    symbol = (symbol << 1) | bit;
                    if match_bit != bit {
                        break;
                    }
                }
            }
            while symbol < 0x100 {
                symbol = (symbol << 1) | rc.bit(&mut probs[symbol]) as usize;
            }
            out[pos] = symbol as u8;
            pos += 1;
            state = match state {
                0..4 => 0,
                4..10 => state - 3,
                _ => state - 6,
            };
            continue;
        }

        let len;
        if rc.bit(&mut m.is_rep[state]) != 0 {
            if pos == 0 {
                return Err(Error);
            }
            if rc.bit(&mut m.is_rep_g0[state]) == 0 {
                if rc.bit(&mut m.is_rep0_long[state][pos_state]) == 0 {
                    state = if state < 7 { 9 } else { 11 };
                    out[pos] = *out.get(pos.wrapping_sub(rep0 + 1)).ok_or(Error)?;
                    pos += 1;
                    continue;
                }
            } else {
                let dist;
                if rc.bit(&mut m.is_rep_g1[state]) == 0 {
                    dist = rep1;
                } else {
                    if rc.bit(&mut m.is_rep_g2[state]) == 0 {
                        dist = rep2;
                    } else {
                        dist = rep3;
                        rep3 = rep2;
                    }
                    rep2 = rep1;
                }
                rep1 = rep0;
                rep0 = dist;
            }
            len = m.rep_len.decode(&mut rc, pos_state);
            state = if state < 7 { 8 } else { 11 };
        } else {
            rep3 = rep2;
            rep2 = rep1;
            rep1 = rep0;
            len = m.len.decode(&mut rc, pos_state);
            state = if state < 7 { 7 } else { 10 };

            let len_state = (len as usize).min(NUM_LEN_TO_POS_STATES - 1);
            let slot = rc.tree(&mut m.pos_slot[len_state], 6);
            rep0 = if slot < 4 {
                slot as usize
            } else {
                let direct = (slot >> 1) - 1;
                let mut dist = (2 | (slot & 1)) << direct;
                if slot < END_POS_MODEL_INDEX {
                    dist += rc.tree_reverse(&mut m.pos[(dist - slot) as usize..], direct);
                } else {
                    dist += rc.direct_bits(direct - NUM_ALIGN_BITS) << NUM_ALIGN_BITS;
                    dist += rc.tree_reverse(&mut m.align, NUM_ALIGN_BITS);
                }
                dist as usize
            };
            if rep0 >= pos {
                return Err(Error);
            }
        }

        for _ in 0..len + 2 {
            if pos == out.len() {
                return Err(Error);
            }
            out[pos] = out[pos - rep0 - 1];
            pos += 1;
        }
    }

    if rc.pos > src.len() { Err(Error) } else { Ok(()) }
}

/// Undo xz's ARM64 filter: turn the absolute targets it wrote into `BL` and
/// `ADRP` instructions back into PC-relative ones.
pub fn unfilter_arm64(buf: &mut [u8]) {
    for (i, word) in buf.chunks_exact_mut(4).enumerate() {
        let pc = (i * 4) as u32;
        let mut instr = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
        if instr >> 26 == 0x25 {
            // BL
            let src = instr;
            instr = 0x9400_0000 | (src.wrapping_sub(pc >> 2) & 0x03FF_FFFF);
        } else if instr & 0x9F00_0000 == 0x9000_0000 {
            // ADRP
            let src = ((instr >> 29) & 3) | ((instr >> 3) & 0x001F_FFFC);
            if src.wrapping_add(0x0002_0000) & 0x001C_0000 != 0 {
                continue;
            }
            let dest = src.wrapping_sub(pc >> 12);
            instr &= 0x9000_001F;
            instr |= (dest & 3) << 29;
            instr |= (dest & 0x0003_FFFC) << 3;
            instr |= 0u32.wrapping_sub(dest & 0x0002_0000) & 0x00E0_0000;
        } else {
            continue;
        }
        word.copy_from_slice(&instr.to_le_bytes());
    }
}

//! LZ4 frame decoding, as `pieeprom.bin` packs `bootmain` and the SDRAM
//! firmware.

pub trait Source {
    fn byte(&mut self) -> u8;
}

impl Source for &[u8] {
    fn byte(&mut self) -> u8 {
        match self.split_first() {
            Some((&b, rest)) => {
                *self = rest;
                b
            }
            None => 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Magic,
    Corrupt,
    /// The output does not fit.
    Overflow,
}

const MAGIC: u32 = 0x184d_2204;

const FLG_BLOCK_CHECKSUM: u8 = 1 << 4;
const FLG_CONTENT_SIZE: u8 = 1 << 3;
const FLG_CONTENT_CHECKSUM: u8 = 1 << 2;
const FLG_DICT_ID: u8 = 1 << 0;

fn u32_le(src: &mut impl Source) -> u32 {
    (0..4).fold(0, |v, i| v | (src.byte() as u32) << (8 * i))
}

fn skip(src: &mut impl Source, n: usize) {
    for _ in 0..n {
        src.byte();
    }
}

/// Decode one frame into `out`; the number of bytes it held.
pub fn decode(src: &mut impl Source, out: &mut [u8]) -> Result<usize, Error> {
    if u32_le(src) != MAGIC {
        return Err(Error::Magic);
    }
    let flg = src.byte();
    let _bd = src.byte();
    if flg & FLG_CONTENT_SIZE != 0 {
        skip(src, 8);
    }
    if flg & FLG_DICT_ID != 0 {
        skip(src, 4);
    }
    let _header_checksum = src.byte();

    let mut pos = 0;
    loop {
        let size = u32_le(src);
        if size == 0 {
            break;
        }
        let len = (size & 0x7fff_ffff) as usize;
        if size & 0x8000_0000 != 0 {
            let dst = out.get_mut(pos..pos + len).ok_or(Error::Overflow)?;
            for b in dst {
                *b = src.byte();
            }
            pos += len;
        } else {
            pos = block(&mut Counted { src, used: 0 }, len, out, pos)?;
        }
        if flg & FLG_BLOCK_CHECKSUM != 0 {
            skip(src, 4);
        }
    }
    if flg & FLG_CONTENT_CHECKSUM != 0 {
        skip(src, 4);
    }
    Ok(pos)
}

struct Counted<'a, S> {
    src: &'a mut S,
    used: usize,
}

impl<S: Source> Counted<'_, S> {
    fn byte(&mut self) -> u8 {
        self.used += 1;
        self.src.byte()
    }

    /// A 4-bit length and its 255-continued extension.
    fn length(&mut self, nibble: u8) -> usize {
        let mut n = nibble as usize;
        if n == 15 {
            loop {
                let b = self.byte();
                n += b as usize;
                if b != 255 {
                    break;
                }
            }
        }
        n
    }
}

/// One compressed block of `len` input bytes, appended at `out[pos..]`.
/// Matches may reach back into earlier blocks.
fn block<S: Source>(
    src: &mut Counted<S>,
    len: usize,
    out: &mut [u8],
    mut pos: usize,
) -> Result<usize, Error> {
    loop {
        let token = src.byte();
        let lit = src.length(token >> 4);
        let dst = out.get_mut(pos..pos + lit).ok_or(Error::Overflow)?;
        for b in dst {
            *b = src.byte();
        }
        pos += lit;
        if src.used >= len {
            return Ok(pos);
        }
        let offset = src.byte() as usize | (src.byte() as usize) << 8;
        let mlen = src.length(token & 15) + 4;
        if offset == 0 || offset > pos {
            return Err(Error::Corrupt);
        }
        if pos + mlen > out.len() {
            return Err(Error::Overflow);
        }
        for i in pos..pos + mlen {
            out[i] = out[i - offset];
        }
        pos += mlen;
    }
}

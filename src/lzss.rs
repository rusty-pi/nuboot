//! The LZSS packing of the EEPROM's `0x55aaf33f` sections, the VL805's two
//! firmware images: a flag byte, then eight items, each a literal byte for a
//! clear flag bit (lowest first) or, for a set one, a match of two bytes —
//! distance minus one, then length minus one — back into the output.

use crate::lz4::Source;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A match reaches back past the start of the output.
    Corrupt,
    /// The output does not fit.
    Overflow,
}

/// Decode `len` packed bytes from `src` into `out`; the number of bytes they
/// came to.
pub fn decode(src: &mut impl Source, len: usize, out: &mut [u8]) -> Result<usize, Error> {
    let (mut used, mut pos) = (0, 0);
    while used < len {
        let flags = src.byte();
        used += 1;
        for bit in 0..8 {
            if used >= len {
                break;
            }
            if flags >> bit & 1 == 0 {
                *out.get_mut(pos).ok_or(Error::Overflow)? = src.byte();
                used += 1;
                pos += 1;
                continue;
            }
            let back = src.byte() as usize + 1;
            let count = src.byte() as usize + 1;
            used += 2;
            if back > pos {
                return Err(Error::Corrupt);
            }
            if pos + count > out.len() {
                return Err(Error::Overflow);
            }
            for i in pos..pos + count {
                out[i] = out[i - back];
            }
            pos += count;
        }
    }
    Ok(pos)
}

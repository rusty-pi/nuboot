//! The `pieeprom.bin` section chain on the SPI flash: `>u32 magic, >u32
//! length, body`, each header 8-byte aligned.

use crate::{lz4, lzss, sha256, spi_flash};

pub const SIZE: u32 = 512 * 1024;

pub const MAGIC_BOOTCODE: u32 = 0x55aa_f00f;
/// A file `rpi-eeprom-config` can replace: 16-byte name, data.
pub const MAGIC_FILE: u32 = 0x55aa_f11f;
pub const MAGIC_FILE_SIGNED: u32 = 0x55aa_f22f;
/// 16-byte name, packed data, then the SHA-256 of what it unpacks to: LZSS
/// for `A` (the VL805 images), an LZ4 frame for `B`.
pub const MAGIC_PACKED_A: u32 = 0x55aa_f33f;
pub const MAGIC_PACKED_B: u32 = 0x55aa_f44f;
const MAGIC_MASK: u32 = 0xffff_f00f;
const MAGIC_BASE: u32 = 0x55aa_f00f;

const MAX_SECTIONS: u32 = 256;

#[derive(Clone, Copy)]
pub struct Section {
    pub magic: u32,
    /// Flash offset and length of the payload (packed: the packed data).
    pub data: u32,
    pub len: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    NotFound,
    TooLarge,
    Lz4(lz4::Error),
    Lzss(lzss::Error),
    /// The digest after a packed section does not match its contents.
    Mismatch,
}

fn be32(b: &[u8]) -> u32 {
    (b[0] as u32) << 24 | (b[1] as u32) << 16 | (b[2] as u32) << 8 | b[3] as u32
}

fn name_eq(field: &[u8], name: &[u8]) -> bool {
    let end = field.iter().position(|&c| c == 0).unwrap_or(field.len());
    &field[..end] == name
}

/// Walk the chain for `name` (the bootcode section answers to
/// `bootcode.bin`).
pub fn find(name: &[u8]) -> Option<Section> {
    spi_flash::with_pins(|| {
        let mut off = 0;
        for _ in 0..MAX_SECTIONS {
            if off >= SIZE {
                return None;
            }
            let mut hdr = [0u8; 24];
            spi_flash::read(off, &mut hdr);
            let (magic, len) = (be32(&hdr[0..]), be32(&hdr[4..]));
            if magic & MAGIC_MASK != MAGIC_BASE || len & 0xff00_0000 != 0 {
                return None;
            }
            let field = &hdr[8..24];
            let found = match magic {
                MAGIC_BOOTCODE => (name == b"bootcode.bin").then(|| (off + 8, len.saturating_sub(20))),
                MAGIC_FILE => name_eq(field, name).then(|| (off + 24, len.saturating_sub(16))),
                MAGIC_FILE_SIGNED => name_eq(field, name).then(|| (off + 24, len.saturating_sub(36))),
                MAGIC_PACKED_A | MAGIC_PACKED_B => {
                    name_eq(field, name).then(|| (off + 24, len.saturating_sub(48)))
                }
                _ => None,
            };
            if let Some((data, len)) = found {
                return Some(Section { magic, data, len });
            }
            off = (off + len + 0xf) & !7;
        }
        None
    })
}

/// Read `name` into `out`, unpacking and checking it if it is packed; how many
/// bytes it came to.
pub fn load(name: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let s = find(name).ok_or(Error::NotFound)?;
    read_section(&s, out)
}

/// Read a section [`find`] found into `out`, the way [`load`] does.
pub fn read_section(s: &Section, out: &mut [u8]) -> Result<usize, Error> {
    spi_flash::with_pins(|| match s.magic {
        MAGIC_PACKED_A | MAGIC_PACKED_B => {
            // The transfer ends before the digest is read with another one.
            let n = {
                let mut t = spi_flash::fast_read(s.data);
                if s.magic == MAGIC_PACKED_A {
                    lzss::decode(&mut t, s.len as usize, out).map_err(Error::Lzss)?
                } else {
                    lz4::decode(&mut t, out).map_err(Error::Lz4)?
                }
            };
            let mut want = [0u8; 32];
            spi_flash::read(s.data + s.len, &mut want);
            if sha256::digest(&out[..n]) != want {
                return Err(Error::Mismatch);
            }
            Ok(n)
        }
        _ => {
            let dst = out.get_mut(..s.len as usize).ok_or(Error::TooLarge)?;
            spi_flash::fast_read(s.data).read(dst);
            Ok(s.len as usize)
        }
    })
}

/// What a section holds in the flash, as it is stored: where it is, how long it
/// is and its SHA-256.
pub struct Digest {
    pub at: u32,
    pub len: u32,
    pub sha256: [u8; 32],
}

/// The [`Digest`] of `name`, or `None` if there is no such section.
pub fn digest(name: &[u8]) -> Option<Digest> {
    let s = find(name)?;
    let sha256 = spi_flash::with_pins(|| {
        let mut hash = sha256::Sha256::new();
        let mut chunk = [0u8; 256];
        let mut done = 0;
        while done < s.len {
            let n = chunk.len().min((s.len - done) as usize);
            spi_flash::read(s.data + done, &mut chunk[..n]);
            hash.update(&chunk[..n]);
            done += n as u32;
        }
        hash.finish()
    });
    Some(Digest { at: s.data, len: s.len, sha256 })
}

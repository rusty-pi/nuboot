//! Device paths: building them, comparing them and showing them in the log.

use alloc::vec::Vec;
use core::fmt;

pub const HARDWARE: u8 = 1;
pub const ACPI: u8 = 2;
pub const MESSAGING: u8 = 3;
pub const MEDIA: u8 = 4;
pub const END: u8 = 0x7f;

pub const HW_PCI: u8 = 1;
pub const HW_VENDOR: u8 = 4;
pub const MSG_USB: u8 = 5;
pub const MSG_SD: u8 = 26;
pub const MEDIA_HD: u8 = 1;
pub const MEDIA_FILE: u8 = 4;

/// A device path being built: nodes, then the end node when it is done.
pub struct Builder(Vec<u8>);

impl Builder {
    pub fn new() -> Self {
        Builder(Vec::new())
    }

    /// Starting with the nodes of `path`, without its end node.
    pub fn from(path: &[u8]) -> Self {
        Builder(path[..path.len().saturating_sub(4)].to_vec())
    }

    pub fn node(mut self, ty: u8, sub: u8, data: &[u8]) -> Self {
        let len = (4 + data.len()) as u16;
        self.0.extend_from_slice(&[ty, sub]);
        self.0.extend_from_slice(&len.to_le_bytes());
        self.0.extend_from_slice(data);
        self
    }

    pub fn file(self, name: &[u16]) -> Self {
        let mut data = Vec::with_capacity(name.len() * 2 + 2);
        for &c in name.iter().chain(&[0]) {
            data.extend_from_slice(&c.to_le_bytes());
        }
        self.node(MEDIA, MEDIA_FILE, &data)
    }

    pub fn done(mut self) -> Vec<u8> {
        self.0.extend_from_slice(&[END, 0xff, 4, 0]);
        self.0
    }
}

/// One node: type, subtype, data.
pub struct Node<'a> {
    pub ty: u8,
    pub sub: u8,
    pub data: &'a [u8],
}

/// The longest device path read: one with no end node stops here.
const MAX_PATH: usize = 0x1_0000;

/// The nodes of the path at `p`, up to its first end node.
pub fn nodes<'a>(p: *const u8) -> impl Iterator<Item = Node<'a>> {
    let mut at = p;
    let mut read = 0usize;
    core::iter::from_fn(move || unsafe {
        if at.is_null() {
            return None;
        }
        let ty = *at;
        let sub = *at.add(1);
        let len = u16::from_le_bytes([*at.add(2), *at.add(3)]) as usize;
        if ty == END || len < 4 || read + len > MAX_PATH {
            return None;
        }
        read += len;
        let node = Node { ty, sub, data: core::slice::from_raw_parts(at.add(4), len - 4) };
        at = at.add(len);
        Some(node)
    })
}

/// The whole path at `p` in bytes, its end node included.
pub fn bytes<'a>(p: *const u8) -> &'a [u8] {
    if p.is_null() {
        return &[];
    }
    let len: usize = nodes(p).map(|n| n.data.len() + 4).sum::<usize>() + 4;
    unsafe { core::slice::from_raw_parts(p, len) }
}

/// How many bytes of `path` (without its end node) `prefix`'s nodes match,
/// if all of them do.
pub fn prefix_len(prefix: &[u8], path: *const u8) -> Option<usize> {
    let want = &prefix[..prefix.len().checked_sub(4)?];
    let have = bytes(path);
    (have.len() >= want.len() + 4 && &have[..want.len()] == want).then_some(want.len())
}

/// The file path nodes at `p` joined into one path, with `\` between them.
pub fn file_name(p: *const u8) -> Vec<u16> {
    const SEP: u16 = b'\\' as u16;
    let mut out: Vec<u16> = Vec::new();
    for n in nodes(p).filter(|n| n.ty == MEDIA && n.sub == MEDIA_FILE) {
        let s: Vec<u16> =
            n.data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&c| c != 0).collect();
        if !out.is_empty() && out.last() != Some(&SEP) && s.first() != Some(&SEP) {
            out.push(SEP);
        }
        out.extend(s);
    }
    out
}

/// A device path as text, for the log.
pub struct Text<'a>(pub &'a [u8]);

impl fmt::Display for Text<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.0.is_empty() {
            return f.write_str("-");
        }
        let mut first = true;
        for n in nodes(self.0.as_ptr()) {
            if !first && !(n.ty == MEDIA && n.sub == MEDIA_FILE) {
                f.write_str("/")?;
            }
            first = false;
            let u32_at = |i: usize| n.data.get(i..i + 4).map_or(0, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
            match (n.ty, n.sub) {
                (HARDWARE, HW_VENDOR) => f.write_str("VenHw")?,
                (HARDWARE, HW_PCI) => write!(f, "Pci({},{})", n.data.get(1).unwrap_or(&0), n.data.first().unwrap_or(&0))?,
                (ACPI, 1) => write!(f, "PciRoot({})", u32_at(4))?,
                (MESSAGING, MSG_USB) => write!(f, "USB({},{})", n.data.first().unwrap_or(&0), n.data.get(1).unwrap_or(&0))?,
                (MESSAGING, MSG_SD) => write!(f, "SD({})", n.data.first().unwrap_or(&0))?,
                (MEDIA, MEDIA_HD) => write!(f, "HD({})", u32_at(0))?,
                (MEDIA, MEDIA_FILE) => {
                    let name: Vec<u16> =
                        n.data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&c| c != 0).collect();
                    write!(f, "{}", crate::util::W(&name))?
                }
                (t, s) => write!(f, "Path({t},{s})")?,
            }
        }
        Ok(())
    }
}

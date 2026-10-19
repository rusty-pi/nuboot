//! Reading the device tree the VPU firmware hands over: just enough of the
//! flattened format to find the memory and what is reserved in it.

const MAGIC: u32 = 0xd00d_feed;
const HEADER: usize = 40;
const OFF_STRUCT: usize = 8;
const OFF_STRINGS: usize = 12;
const OFF_RSVMAP: usize = 16;
const SIZE_STRINGS: usize = 32;
const SIZE_STRUCT: usize = 36;
/// The most the VPU firmware sets aside for the tree it hands over.
const MAX_SIZE: usize = 0x10_0000;

const BEGIN_NODE: u32 = 1;
const END_NODE: u32 = 2;
const PROP: u32 = 3;
const NOP: u32 = 4;

pub struct Fdt {
    tree: &'static [u8],
    structs: &'static [u8],
    strings: &'static [u8],
    rsvmap: &'static [u8],
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

fn be64(b: &[u8], at: usize) -> Option<u64> {
    Some((be32(b, at)? as u64) << 32 | be32(b, at.checked_add(4)?)? as u64)
}

fn cstr(b: &[u8], at: usize) -> Option<&[u8]> {
    let rest = b.get(at..)?;
    Some(&rest[..rest.iter().position(|&c| c == 0)?])
}

/// The block whose offset and size the header fields `offset` and `size` hold.
fn block(tree: &[u8], offset: usize, size: usize) -> Option<&[u8]> {
    let at = be32(tree, offset)? as usize;
    tree.get(at..at.checked_add(be32(tree, size)? as usize)?)
}

impl Fdt {
    pub fn at(addr: u64) -> Option<Fdt> {
        let base = addr as *const u8;
        let header = unsafe { core::slice::from_raw_parts(base, HEADER) };
        if be32(header, 0)? != MAGIC {
            return None;
        }
        let size = be32(header, 4)? as usize;
        if !(HEADER..=MAX_SIZE).contains(&size) {
            return None;
        }
        let tree = unsafe { core::slice::from_raw_parts(base, size) };
        Some(Fdt {
            tree,
            structs: block(tree, OFF_STRUCT, SIZE_STRUCT)?,
            strings: block(tree, OFF_STRINGS, SIZE_STRINGS)?,
            rsvmap: tree.get(be32(tree, OFF_RSVMAP)? as usize..)?,
        })
    }

    pub fn size(&self) -> usize {
        self.tree.len()
    }

    /// The `/memreserve/` entries: (address, size).
    pub fn reservations(&self, mut f: impl FnMut(u64, u64)) {
        for entry in self.rsvmap.chunks_exact(16) {
            let (Some(addr), Some(size)) = (be64(entry, 0), be64(entry, 8)) else { return };
            if addr == 0 && size == 0 {
                return;
            }
            f(addr, size);
        }
    }

    /// Every property, with the names of the nodes above it from the root
    /// (whose name is empty) down.
    pub fn walk(&self, mut f: impl FnMut(&[&[u8]], &[u8], &[u8])) {
        let structs = self.structs;
        let mut path: [&[u8]; 16] = [&[]; 16];
        let mut depth = 0usize;
        let mut at = 0;
        while let Some(token) = be32(structs, at) {
            at += 4;
            match token {
                BEGIN_NODE => {
                    let Some(name) = cstr(structs, at) else { return };
                    if depth < path.len() {
                        path[depth] = name;
                    }
                    depth += 1;
                    at += (name.len() + 1).next_multiple_of(4);
                }
                END_NODE => depth = depth.saturating_sub(1),
                PROP => {
                    let (Some(len), Some(name_at)) = (be32(structs, at), be32(structs, at + 4)) else { return };
                    let (len, start) = (len as usize, at + 8);
                    let (Some(name), Some(value)) = (cstr(self.strings, name_at as usize), structs.get(start..start + len))
                    else {
                        return;
                    };
                    f(&path[..depth.min(path.len())], name, value);
                    at = start + len.next_multiple_of(4);
                }
                NOP => {}
                _ => return,
            }
        }
    }
}

impl Fdt {
    /// The address of the `/reserved-memory` child whose name starts with
    /// `prefix`.
    pub fn reserved_base(&self, prefix: &[u8]) -> Option<u64> {
        let (mut address_cells, mut size_cells) = (2, 1);
        let mut base = None;
        self.walk(|path, name, value| match (path, name) {
            ([_, b"reserved-memory"], b"#address-cells") => address_cells = cells(value),
            ([_, b"reserved-memory"], b"#size-cells") => size_cells = cells(value),
            ([_, b"reserved-memory", node], b"reg") if node.starts_with(prefix) => {
                reg(value, address_cells, size_cells, |at, _| base = Some(at))
            }
            _ => {}
        });
        base
    }

    /// The value of the property `name` of the node at `path`.
    pub fn property(&self, path: &[&[u8]], name: &[u8]) -> Option<alloc::vec::Vec<u8>> {
        let mut found = None;
        self.walk(|at, prop, value| {
            if at == path && prop == name {
                found = Some(value.to_vec());
            }
        });
        found
    }

    /// The first `N` bytes of the property `name` of the node at `path`.
    pub fn bytes<const N: usize>(&self, path: &[&[u8]], name: &[u8]) -> Option<[u8; N]> {
        let mut found = None;
        self.walk(|at, prop, value| {
            if at == path && prop == name {
                found = value.get(..N).and_then(|b| b.try_into().ok());
            }
        });
        found
    }
}

/// A `reg` value as (address, size) pairs.
pub fn reg(value: &[u8], address_cells: usize, size_cells: usize, mut f: impl FnMut(u64, u64)) {
    let cell = |b: &[u8]| b.chunks_exact(4).fold(0u64, |v, c| v << 32 | u32::from_be_bytes(c.try_into().unwrap()) as u64);
    let stride = 4 * (address_cells + size_cells);
    if stride == 0 {
        return;
    }
    for r in value.chunks_exact(stride) {
        f(cell(&r[..4 * address_cells]), cell(&r[4 * address_cells..]));
    }
}

pub fn cells(value: &[u8]) -> usize {
    value.get(..4).map_or(0, |b| u32::from_be_bytes(b.try_into().unwrap()) as usize)
}

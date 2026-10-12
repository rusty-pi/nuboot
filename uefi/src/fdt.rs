//! Reading the device tree the VPU firmware hands over: just enough of the
//! flattened format to find the memory and what is reserved in it.

const MAGIC: u32 = 0xd00d_feed;
const BEGIN_NODE: u32 = 1;
const END_NODE: u32 = 2;
const PROP: u32 = 3;
const NOP: u32 = 4;

pub struct Fdt {
    base: *const u8,
}

fn be32(p: *const u8) -> u32 {
    u32::from_be_bytes(unsafe { [*p, *p.add(1), *p.add(2), *p.add(3)] })
}

fn be64(p: *const u8) -> u64 {
    (be32(p) as u64) << 32 | be32(unsafe { p.add(4) }) as u64
}

fn cstr<'a>(p: *const u8) -> &'a [u8] {
    let mut n = 0;
    while unsafe { *p.add(n) } != 0 {
        n += 1;
    }
    unsafe { core::slice::from_raw_parts(p, n) }
}

impl Fdt {
    pub fn at(addr: u64) -> Option<Fdt> {
        let base = addr as *const u8;
        (be32(base) == MAGIC).then_some(Fdt { base })
    }

    pub fn size(&self) -> usize {
        be32(unsafe { self.base.add(4) }) as usize
    }

    /// The `/memreserve/` entries: (address, size).
    pub fn reservations(&self, mut f: impl FnMut(u64, u64)) {
        let mut p = unsafe { self.base.add(be32(self.base.add(16)) as usize) };
        loop {
            let (addr, size) = (be64(p), be64(unsafe { p.add(8) }));
            if addr == 0 && size == 0 {
                return;
            }
            f(addr, size);
            p = unsafe { p.add(16) };
        }
    }

    /// Every property, with the names of the nodes above it from the root
    /// (whose name is empty) down.
    pub fn walk(&self, mut f: impl FnMut(&[&[u8]], &[u8], &[u8])) {
        let structs = unsafe { self.base.add(be32(self.base.add(8)) as usize) };
        let strings = unsafe { self.base.add(be32(self.base.add(12)) as usize) };
        let mut path: [&[u8]; 16] = [&[]; 16];
        let mut depth = 0usize;
        let mut p = structs;
        loop {
            let token = be32(p);
            p = unsafe { p.add(4) };
            match token {
                BEGIN_NODE => {
                    let name = cstr(p);
                    if depth < path.len() {
                        path[depth] = name;
                    }
                    depth += 1;
                    p = unsafe { p.add((name.len() + 1).next_multiple_of(4)) };
                }
                END_NODE => depth = depth.saturating_sub(1),
                PROP => {
                    let len = be32(p) as usize;
                    let name = cstr(unsafe { strings.add(be32(p.add(4)) as usize) });
                    let value = unsafe { core::slice::from_raw_parts(p.add(8), len) };
                    f(&path[..depth.min(path.len())], name, value);
                    p = unsafe { p.add(8 + len.next_multiple_of(4)) };
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

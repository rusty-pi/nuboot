//! Just enough of the flattened device tree format to hand the ARM a tree
//! with one property's value replaced.

const MAGIC: u32 = 0xd00d_feed;
const HEADER: usize = 40;
const OFF_STRUCT: usize = 8;
const OFF_STRINGS: usize = 12;
const OFF_RSVMAP: usize = 16;
const SIZE_STRINGS: usize = 32;
const SIZE_STRUCT: usize = 36;
const TOTALSIZE: usize = 4;

const BEGIN_NODE: u32 = 1;
const END_NODE: u32 = 2;
const PROP: u32 = 3;
const NOP: u32 = 4;
const END: u32 = 9;

fn be32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn put32(b: &mut [u8], at: usize, value: u32) -> Option<()> {
    b.get_mut(at..at + 4)?.copy_from_slice(&value.to_be_bytes());
    Some(())
}

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// The NUL-terminated string at `at`, without its NUL.
fn cstr(b: &[u8], at: usize) -> Option<&[u8]> {
    let rest = b.get(at..)?;
    Some(&rest[..rest.iter().position(|&c| c == 0)?])
}

/// Copy `tree` into `out` with the property `name` of the node at `path`
/// (from the root, whose name is empty: `[b"", b"memory@0"]`) set to `value`.
/// The property has to be there already. The length of the new tree, or
/// `None` if `tree` is not one, the property is missing or `out` is too small.
pub fn copy_with_property(tree: &[u8], out: &mut [u8], path: &[&[u8]], name: &[u8], value: &[u8]) -> Option<usize> {
    if be32(tree, 0)? != MAGIC {
        return None;
    }
    let off_struct = be32(tree, OFF_STRUCT)? as usize;
    let off_strings = be32(tree, OFF_STRINGS)? as usize;
    let off_rsvmap = be32(tree, OFF_RSVMAP)? as usize;
    let size_strings = be32(tree, SIZE_STRINGS)? as usize;
    let size_struct = be32(tree, SIZE_STRUCT)? as usize;
    if !(HEADER <= off_rsvmap && off_rsvmap <= off_struct && off_struct + size_struct <= off_strings) {
        return None;
    }
    let strings = tree.get(off_strings..off_strings + size_strings)?;

    // The header and the reservation map stay where they are.
    out.get_mut(..off_struct)?.copy_from_slice(tree.get(..off_struct)?);

    let mut at = off_struct;
    let mut to = off_struct;
    let mut depth = 0usize;
    // How many of `path`'s nodes the current node and its ancestors match.
    let mut matched = 0usize;
    let mut found = false;
    loop {
        let token = be32(tree, at)?;
        let start = at;
        at += 4;
        match token {
            BEGIN_NODE => {
                let node = cstr(tree, at)?;
                at = align4(at + node.len() + 1);
                if matched == depth && path.get(depth) == Some(&node) {
                    matched += 1;
                }
                depth += 1;
            }
            END_NODE => {
                depth = depth.checked_sub(1)?;
                matched = matched.min(depth);
            }
            PROP => {
                let len = be32(tree, at)? as usize;
                let name_at = be32(tree, at + 4)? as usize;
                at = align4(at + 8 + len);
                if matched == depth && depth == path.len() && cstr(strings, name_at)? == name {
                    put32(out, to, PROP)?;
                    put32(out, to + 4, value.len() as u32)?;
                    put32(out, to + 8, name_at as u32)?;
                    let end = to + 12 + value.len();
                    out.get_mut(to + 12..end)?.copy_from_slice(value);
                    let padded = align4(end);
                    out.get_mut(end..padded)?.fill(0);
                    to = padded;
                    found = true;
                    continue;
                }
            }
            NOP => {}
            END => {}
            _ => return None,
        }
        let piece = tree.get(start..at)?;
        out.get_mut(to..to + piece.len())?.copy_from_slice(piece);
        to += piece.len();
        if token == END {
            break;
        }
    }
    if !found {
        return None;
    }

    let new_strings = to;
    out.get_mut(new_strings..new_strings + size_strings)?.copy_from_slice(strings);
    let total = new_strings + size_strings;
    put32(out, OFF_STRINGS, new_strings as u32)?;
    put32(out, SIZE_STRUCT, (new_strings - off_struct) as u32)?;
    put32(out, TOTALSIZE, total as u32)?;
    Some(total)
}

/// Copy `tree` into `out` with a node `name` added at the end of the node at
/// `parent` (from the root, as in [`copy_with_property`]), holding `props`.
/// A property name the tree's strings do not have is added to them. The
/// length of the new tree, or `None` if `tree` is not one, the parent is
/// missing or `out` is too small.
pub fn copy_with_node(tree: &[u8], out: &mut [u8], parent: &[&[u8]], name: &[u8], props: &[(&[u8], &[u8])]) -> Option<usize> {
    if be32(tree, 0)? != MAGIC {
        return None;
    }
    let off_struct = be32(tree, OFF_STRUCT)? as usize;
    let off_strings = be32(tree, OFF_STRINGS)? as usize;
    let size_strings = be32(tree, SIZE_STRINGS)? as usize;
    let size_struct = be32(tree, SIZE_STRUCT)? as usize;
    if !(HEADER <= off_struct && off_struct + size_struct <= off_strings) {
        return None;
    }
    let strings = tree.get(off_strings..off_strings + size_strings)?;

    // Where each property's name is in the strings, adding what is missing.
    let mut name_at = [0usize; 8];
    let mut extra = [0u8; 64];
    let mut extra_len = 0;
    for (i, (prop, _)) in props.iter().enumerate() {
        let mut found = None;
        let mut at = 0;
        while at < strings.len() {
            let s = cstr(strings, at)?;
            if s == *prop {
                found = Some(at);
                break;
            }
            at += s.len() + 1;
        }
        name_at[i] = match found {
            Some(at) => at,
            None => {
                let at = size_strings + extra_len;
                extra.get_mut(extra_len..extra_len + prop.len() + 1)?[..prop.len()].copy_from_slice(prop);
                extra_len += prop.len() + 1;
                at
            }
        };
    }

    out.get_mut(..off_struct)?.copy_from_slice(tree.get(..off_struct)?);
    let mut at = off_struct;
    let mut to = off_struct;
    let mut depth = 0usize;
    let mut matched = 0usize;
    let mut added = false;
    loop {
        let token = be32(tree, at)?;
        let start = at;
        at += 4;
        match token {
            BEGIN_NODE => {
                let node = cstr(tree, at)?;
                at = align4(at + node.len() + 1);
                if matched == depth && parent.get(depth) == Some(&node) {
                    matched += 1;
                }
                depth += 1;
            }
            END_NODE => {
                if !added && matched == depth && depth == parent.len() {
                    put32(out, to, BEGIN_NODE)?;
                    to += 4;
                    out.get_mut(to..to + name.len() + 1)?[..name.len()].copy_from_slice(name);
                    let end = align4(to + name.len() + 1);
                    out.get_mut(to + name.len()..end)?.fill(0);
                    to = end;
                    for (i, (_, value)) in props.iter().enumerate() {
                        put32(out, to, PROP)?;
                        put32(out, to + 4, value.len() as u32)?;
                        put32(out, to + 8, name_at[i] as u32)?;
                        let end = to + 12 + value.len();
                        out.get_mut(to + 12..end)?.copy_from_slice(value);
                        let padded = align4(end);
                        out.get_mut(end..padded)?.fill(0);
                        to = padded;
                    }
                    put32(out, to, END_NODE)?;
                    to += 4;
                    added = true;
                }
                depth = depth.checked_sub(1)?;
                matched = matched.min(depth);
            }
            PROP => {
                let len = be32(tree, at)? as usize;
                at = align4(at + 8 + len);
            }
            NOP | END => {}
            _ => return None,
        }
        let piece = tree.get(start..at)?;
        out.get_mut(to..to + piece.len())?.copy_from_slice(piece);
        to += piece.len();
        if token == END {
            break;
        }
    }
    if !added {
        return None;
    }

    let new_strings = to;
    out.get_mut(new_strings..new_strings + size_strings)?.copy_from_slice(strings);
    out.get_mut(new_strings + size_strings..new_strings + size_strings + extra_len)?.copy_from_slice(&extra[..extra_len]);
    let total = new_strings + size_strings + extra_len;
    put32(out, OFF_STRINGS, new_strings as u32)?;
    put32(out, SIZE_STRINGS, (size_strings + extra_len) as u32)?;
    put32(out, SIZE_STRUCT, (new_strings - off_struct) as u32)?;
    put32(out, TOTALSIZE, total as u32)?;
    Some(total)
}

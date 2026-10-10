//! Loading a VPU ELF image already in memory.

const EM_VIDEOCORE: u16 = 137;
const PT_LOAD: u32 = 1;

/// The SDRAM alias that bypasses the caches. A segment is written through it
/// so nothing of it is left in a cache when the image is entered.
const UNCACHED: u32 = 0xc000_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    NotElf,
    Truncated,
}

fn u16_at(b: &[u8], o: usize) -> Result<u16, Error> {
    b.get(o..o + 2).map(|s| u16::from_le_bytes([s[0], s[1]])).ok_or(Error::Truncated)
}

fn u32_at(b: &[u8], o: usize) -> Result<u32, Error> {
    b.get(o..o + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]])).ok_or(Error::Truncated)
}

/// Copy the loadable segments to their physical addresses and clear what
/// they leave to zero; the entry point.
pub fn load(image: &[u8]) -> Result<u32, Error> {
    if image.get(..6) != Some(b"\x7fELF\x01\x01") || u16_at(image, 18)? != EM_VIDEOCORE {
        return Err(Error::NotElf);
    }
    let entry = u32_at(image, 24)?;
    let phoff = u32_at(image, 28)? as usize;
    let phentsize = u16_at(image, 42)? as usize;
    let phnum = u16_at(image, 44)? as usize;
    for i in 0..phnum {
        let ph = phoff + i * phentsize;
        if u32_at(image, ph)? != PT_LOAD {
            continue;
        }
        let offset = u32_at(image, ph + 4)? as usize;
        let paddr = u32_at(image, ph + 12)?;
        let filesz = u32_at(image, ph + 16)? as usize;
        let memsz = u32_at(image, ph + 20)? as usize;
        let data = image.get(offset..offset + filesz).ok_or(Error::Truncated)?;
        let dst = (UNCACHED | (paddr & 0x3fff_ffff)) as usize as *mut u8;
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), dst, filesz);
            core::ptr::write_bytes(dst.add(filesz), 0, memsz.saturating_sub(filesz));
        }
    }
    Ok(entry)
}

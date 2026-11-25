//! The video mode a display asks for, out of the base block of its EDID: the
//! detailed timing descriptors, of which the first is the display's preferred
//! mode.

/// A progressive video mode: the pixel clock, and each direction's active
/// length, front porch, sync pulse and back porch.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Mode {
    pub pixel_khz: u32,
    pub width: u32,
    pub hfp: u32,
    pub hsync: u32,
    pub hbp: u32,
    pub height: u32,
    pub vfp: u32,
    pub vsync: u32,
    pub vbp: u32,
    pub hsync_positive: bool,
    pub vsync_positive: bool,
}

pub const BLOCK: usize = 128;
const HEADER: [u8; 8] = [0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00];
const DESCRIPTORS: usize = 54;
const DESCRIPTOR: usize = 18;
const DESCRIPTOR_COUNT: usize = 4;

const INTERLACED: u8 = 1 << 7;
const SYNC_KIND: u8 = 0b11 << 3;
const SYNC_DIGITAL_SEPARATE: u8 = 0b11 << 3;
const VSYNC_POSITIVE: u8 = 1 << 2;
const HSYNC_POSITIVE: u8 = 1 << 1;

/// Whether `block` has the EDID header and its bytes sum to zero.
pub fn valid(block: &[u8; BLOCK]) -> bool {
    block[..8] == HEADER && block.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)) == 0
}

fn detailed(d: &[u8]) -> Option<Mode> {
    let pixel_khz = u16::from_le_bytes([d[0], d[1]]) as u32 * 10;
    if pixel_khz == 0 || d[17] & INTERLACED != 0 {
        return None;
    }
    let high = |byte: u8, shift: u8| ((byte >> shift) as u32 & 0xf) << 8;
    let width = d[2] as u32 | high(d[4], 4);
    let hblank = d[3] as u32 | high(d[4], 0);
    let height = d[5] as u32 | high(d[7], 4);
    let vblank = d[6] as u32 | high(d[7], 0);
    let hfp = d[8] as u32 | (d[11] as u32 >> 6 & 3) << 8;
    let hsync = d[9] as u32 | (d[11] as u32 >> 4 & 3) << 8;
    let vfp = (d[10] as u32 >> 4) | (d[11] as u32 >> 2 & 3) << 4;
    let vsync = (d[10] as u32 & 0xf) | (d[11] as u32 & 3) << 4;
    if width == 0 || height == 0 || hsync == 0 || vsync == 0 || hfp + hsync >= hblank || vfp + vsync >= vblank {
        return None;
    }
    let separate = d[17] & SYNC_KIND == SYNC_DIGITAL_SEPARATE;
    Some(Mode {
        pixel_khz,
        width,
        hfp,
        hsync,
        hbp: hblank - hfp - hsync,
        height,
        vfp,
        vsync,
        vbp: vblank - vfp - vsync,
        hsync_positive: separate && d[17] & HSYNC_POSITIVE != 0,
        vsync_positive: separate && d[17] & VSYNC_POSITIVE != 0,
    })
}

/// The progressive detailed timings of `block`, the preferred one first.
pub fn modes(block: &[u8; BLOCK]) -> impl Iterator<Item = Mode> + '_ {
    (0..DESCRIPTOR_COUNT).filter_map(move |i| {
        let at = DESCRIPTORS + i * DESCRIPTOR;
        detailed(&block[at..at + DESCRIPTOR])
    })
}

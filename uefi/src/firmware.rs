//! Writing the firmware's own flash region, the part of the EEPROM below the
//! variable store, from a capsule's image.
//!
//! Every sector but the first is written before it, so that the sector with
//! the boot ROM's first look at the image changes last: a write that stops
//! short leaves a bootcode that is whole or gone, never half. A sector that
//! already holds what it should is left alone, and the region is read back
//! and compared before the write counts as done.

use crate::spiflash::{self, PAGE, SECTOR};
use crate::{error, info, warn};

/// What the firmware owns of the flash.
pub const REGION: usize = 0x70000;
const ATTEMPTS: usize = 3;

/// The 4 KiB sector `n` as it should be: `image` there, erased flash after it.
fn wanted(image: &[u8], n: usize) -> [u8; SECTOR] {
    let mut sector = [0xffu8; SECTOR];
    let from = (n * SECTOR).min(image.len());
    let to = ((n + 1) * SECTOR).min(image.len());
    sector[..to - from].copy_from_slice(&image[from..to]);
    sector
}

fn write_sector(n: usize, wanted: &[u8; SECTOR]) -> bool {
    let at = (n * SECTOR) as u32;
    let mut have = [0u8; SECTOR];
    spiflash::read(at, &mut have);
    if have == *wanted {
        return true;
    }
    if !spiflash::erase_sector(at) {
        return false;
    }
    wanted
        .chunks(PAGE)
        .enumerate()
        .filter(|(_, page)| page.iter().any(|&b| b != 0xff))
        .all(|(i, page)| spiflash::program(at + (i * PAGE) as u32, page))
}

fn matches(image: &[u8]) -> bool {
    let mut have = [0u8; SECTOR];
    (0..REGION / SECTOR).all(|n| {
        spiflash::read((n * SECTOR) as u32, &mut have);
        have == wanted(image, n)
    })
}

/// Make the flash region `image`. Whether it reads back as that.
pub fn write(image: &[u8]) -> bool {
    if image.len() > REGION || !spiflash::present() {
        return false;
    }
    let order = (1..REGION / SECTOR).chain(core::iter::once(0));
    for attempt in 1..=ATTEMPTS {
        let mut written = true;
        for n in order.clone() {
            if !write_sector(n, &wanted(image, n)) {
                warn!("firmware", "sector not written"; sector = n, attempt = attempt);
                written = false;
                break;
            }
        }
        if written && matches(image) {
            info!("firmware", "flash region written"; bytes = image.len(), attempt = attempt);
            return true;
        }
        warn!("firmware", "flash region does not read back as written"; attempt = attempt);
    }
    error!("firmware", "flash region could not be written");
    false
}

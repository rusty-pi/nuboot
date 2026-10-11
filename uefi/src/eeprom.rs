//! The EEPROM the stock bootloader keeps itself in: when it was last updated,
//! and the variable store in its free tail across an update.

use alloc::vec::Vec;

use crate::spiflash::{self, SECTOR};
use crate::store;

/// The last 8 bytes of the flash: after an update, the update's time and its
/// complement.
const STAMP: u32 = 0x7fff8;
const LENGTH: usize = 2 * store::BANK as usize;

/// The time of the update that wrote the EEPROM, in seconds, or 0 when the
/// flash says none.
pub fn version() -> u32 {
    if !spiflash::present() {
        return 0;
    }
    let mut stamp = [0u8; 8];
    spiflash::read(STAMP, &mut stamp);
    let (complement, time) = (u32::from_le_bytes(stamp[..4].try_into().unwrap()), u32::from_le_bytes(stamp[4..].try_into().unwrap()));
    if complement == !time { time } else { 0 }
}

/// What the variable store holds, if it holds anything.
pub fn backup() -> Option<Vec<u8>> {
    if !spiflash::present() {
        return None;
    }
    let mut bytes = alloc::vec![0u8; LENGTH];
    spiflash::read(store::BASE, &mut bytes);
    bytes.iter().any(|&b| b != 0xff).then_some(bytes)
}

/// Whether the variable store is empty.
pub fn store_is_empty() -> bool {
    let mut head = [0u8; 8];
    spiflash::read(store::BASE, &mut head);
    let mut other = [0u8; 8];
    spiflash::read(store::BASE + store::BANK, &mut other);
    head == [0xff; 8] && other == [0xff; 8]
}

/// Put a backup back as the variable store.
pub fn restore(bytes: &[u8]) -> bool {
    if bytes.len() != LENGTH || !spiflash::present() {
        return false;
    }
    (0..LENGTH).step_by(SECTOR).all(|at| {
        let sector = &bytes[at..at + SECTOR];
        spiflash::erase_sector(store::BASE + at as u32)
            && sector.chunks(spiflash::PAGE).enumerate().filter(|(_, page)| page.iter().any(|&b| b != 0xff)).all(|(i, page)| {
                spiflash::program(store::BASE + (at + i * spiflash::PAGE) as u32, page)
            })
    })
}

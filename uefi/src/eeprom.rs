//! The EEPROM the stock bootloader keeps itself in: when it was last updated.

use crate::spiflash;

/// The last 8 bytes of the flash: after an update, the update's time and its
/// complement.
const STAMP: u32 = 0x7fff8;

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

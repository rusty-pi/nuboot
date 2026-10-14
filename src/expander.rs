//! The FXL6408 GPIO expander on the board's I2C bus (`0x43`): the pins the
//! bootloader sets up for the SD card's power and signalling, the wireless
//! chip's switches and the power LED.

use crate::i2c;

const ADDR: u8 = 0x43;
const OUTPUT: u8 = 0x05;
/// The power LED's pin, which lights the LED while it is low.
const POWER_LED_OFF: u8 = 1 << 2;

/// Light the power LED, or put it out; whether the expander took it. The other
/// pins keep what the bootloader set them to.
pub fn set_power_led(lit: bool) -> bool {
    let Some(outputs) = i2c::read_reg(ADDR, OUTPUT) else {
        return false;
    };
    let outputs = if lit { outputs & !POWER_LED_OFF } else { outputs | POWER_LED_OFF };
    i2c::write_reg(ADDR, OUTPUT, outputs)
}

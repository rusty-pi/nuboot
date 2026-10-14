//! The FXL6408 GPIO expander on the board's I2C bus (`0x43`): the pins the
//! bootloader sets up for the SD card's power and signalling, the wireless
//! chip's switches and the power LED.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::i2c;

const ADDR: u8 = 0x43;
const DIRECTION: u8 = 0x03;
const OUTPUT: u8 = 0x05;
const OUTPUT_HIGH_Z: u8 = 0x07;
/// The power LED's pin, which lights the LED while it is driven low.
const POWER_LED_OFF: u8 = 1 << 2;

/// Whether [`SAVED`] holds what the power LED's pin was, and its three bits:
/// direction (1 is an output), output level and output high-Z.
const SAVED_VALID: u32 = 1 << 31;
const SAVED_DIRECTION: u32 = 1;
const SAVED_OUTPUT: u32 = 1 << 1;
const SAVED_HIGH_Z: u32 = 1 << 2;
static SAVED: AtomicU32 = AtomicU32::new(0);

/// The expander's direction, output and output high-Z registers.
#[derive(Clone, Copy)]
pub struct Registers {
    pub direction: u8,
    pub output: u8,
    pub high_z: u8,
}

fn read() -> Option<Registers> {
    Some(Registers {
        direction: i2c::read_reg(ADDR, DIRECTION)?,
        output: i2c::read_reg(ADDR, OUTPUT)?,
        high_z: i2c::read_reg(ADDR, OUTPUT_HIGH_Z)?,
    })
}

fn pin_bits(registers: Registers) -> u32 {
    let bit = |register: u8, flag: u32| if register & POWER_LED_OFF != 0 { flag } else { 0 };
    SAVED_VALID
        | bit(registers.direction, SAVED_DIRECTION)
        | bit(registers.output, SAVED_OUTPUT)
        | bit(registers.high_z, SAVED_HIGH_Z)
}

fn with_pin(register: u8, set: bool) -> u8 {
    if set { register | POWER_LED_OFF } else { register & !POWER_LED_OFF }
}

/// Drive the power LED's pin to `output`, as an output that is not high-Z if
/// `driven`, and the other pins as they are. The level is set before the pin
/// becomes an output, so the LED does not flicker. What the registers read
/// back as.
fn set_pin(registers: Registers, driven: bool, output: bool) -> Option<Registers> {
    i2c::write_reg(ADDR, OUTPUT, with_pin(registers.output, output)).then_some(())?;
    i2c::write_reg(ADDR, OUTPUT_HIGH_Z, with_pin(registers.high_z, !driven)).then_some(())?;
    i2c::write_reg(ADDR, DIRECTION, with_pin(registers.direction, driven)).then_some(())?;
    read()
}

/// Put the power LED out, the pin driven high whatever the bootloader left it
/// as; the registers as they read back, if the expander answered.
pub fn power_led_off() -> Option<Registers> {
    let before = read()?;
    SAVED.store(pin_bits(before), Ordering::Relaxed);
    set_pin(before, true, true)
}

/// Put the power LED's pin back as [`power_led_off`] found it. Without an
/// answer from the expander the pin stays driven high, as the bootloader that
/// runs next initialises it.
pub fn power_led_restore() {
    let saved = SAVED.load(Ordering::Relaxed);
    if saved & SAVED_VALID == 0 {
        return;
    }
    SAVED.store(0, Ordering::Relaxed);
    let Some(now) = read() else {
        return;
    };
    set_pin_as(now, saved);
}

fn set_pin_as(now: Registers, saved: u32) {
    let output = with_pin(now.output, saved & SAVED_OUTPUT != 0);
    let high_z = with_pin(now.high_z, saved & SAVED_HIGH_Z != 0);
    let direction = with_pin(now.direction, saved & SAVED_DIRECTION != 0);
    i2c::write_reg(ADDR, OUTPUT, output);
    i2c::write_reg(ADDR, OUTPUT_HIGH_Z, high_z);
    i2c::write_reg(ADDR, DIRECTION, direction);
}

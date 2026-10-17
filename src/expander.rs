//! The FXL6408 GPIO expander on the board's I2C bus (`0x43`): the pins the
//! bootloader sets up for the SD card's power and signalling, the wireless
//! chip's switches and the power LED.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::i2c;

const ADDR: u8 = 0x43;
const DIRECTION: u8 = 0x03;
const OUTPUT: u8 = 0x05;
const OUTPUT_HIGH_Z: u8 = 0x07;
const PULL_ENABLE: u8 = 0x0b;
const PULL_UP: u8 = 0x0d;
const INPUT_STATUS: u8 = 0x0f;
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

/// The number the property mailbox gives the expander's first pin; the pins
/// follow in order.
const FIRST_GPIO: u32 = 128;
/// The pins the OS may reach: the SD card's power switch and its signalling
/// voltage select. The radios', the power LED's, the reset's and the camera's
/// stay with this firmware.
const SD_IO_SELECT: u8 = 4;
const SD_POWER_ON: u8 = 6;

/// The expander pin the mailbox's GPIO number `gpio` names, if it names one the
/// OS may reach.
pub fn pin(gpio: u32) -> Option<u8> {
    let pin = u8::try_from(gpio.checked_sub(FIRST_GPIO)?).ok()?;
    matches!(pin, SD_IO_SELECT | SD_POWER_ON).then_some(pin)
}

/// What a pin is set up as.
#[derive(Clone, Copy)]
pub struct PinConfig {
    pub output: bool,
    pub pull: bool,
    pub pull_up: bool,
}

fn flag(register: u8, pin: u8) -> bool {
    register & 1 << pin != 0
}

fn with_flag(register: u8, pin: u8, set: bool) -> u8 {
    if set { register | 1 << pin } else { register & !(1 << pin) }
}

/// How `pin` is set up, if the expander answers.
pub fn pin_config(pin: u8) -> Option<PinConfig> {
    Some(PinConfig {
        output: flag(i2c::read_reg(ADDR, DIRECTION)?, pin),
        pull: flag(i2c::read_reg(ADDR, PULL_ENABLE)?, pin),
        pull_up: flag(i2c::read_reg(ADDR, PULL_UP)?, pin),
    })
}

/// The level of `pin`: what it is driven to if it is an output, what it reads
/// as if it is an input.
pub fn pin_level(pin: u8) -> Option<bool> {
    let register = if flag(i2c::read_reg(ADDR, DIRECTION)?, pin) { OUTPUT } else { INPUT_STATUS };
    Some(flag(i2c::read_reg(ADDR, register)?, pin))
}

/// Drive `pin` to `level`; whether the expander took it.
pub fn drive_pin(pin: u8, level: bool) -> bool {
    i2c::read_reg(ADDR, OUTPUT).is_some_and(|output| i2c::write_reg(ADDR, OUTPUT, with_flag(output, pin, level)))
}

/// Set `pin` up as `config`. An output is driven to `level` before it becomes
/// one, so it does not glitch. Whether the expander took it.
pub fn set_pin_config(pin: u8, config: PinConfig, level: bool) -> Option<()> {
    let output = i2c::read_reg(ADDR, OUTPUT)?;
    let high_z = i2c::read_reg(ADDR, OUTPUT_HIGH_Z)?;
    let direction = i2c::read_reg(ADDR, DIRECTION)?;
    let pull = i2c::read_reg(ADDR, PULL_ENABLE)?;
    let pull_up = i2c::read_reg(ADDR, PULL_UP)?;
    let writes = [
        (OUTPUT, with_flag(output, pin, level)),
        (OUTPUT_HIGH_Z, with_flag(high_z, pin, !config.output)),
        (PULL_ENABLE, with_flag(pull, pin, config.pull)),
        (PULL_UP, with_flag(pull_up, pin, config.pull_up)),
        (DIRECTION, with_flag(direction, pin, config.output)),
    ];
    writes.iter().all(|&(register, value)| i2c::write_reg(ADDR, register, value)).then_some(())
}

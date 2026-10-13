//! The on-die temperature sensor. Its channel of the AVS monitor samples only
//! while the sensor's clock generator runs, which nothing but the firmware
//! starts: without it an OS reads no temperature (Linux's `bcm2711_thermal`
//! answers `-EIO`), and an OS on the ACPI tables reads a thermal zone that
//! never has a sample.

use crate::{cm, mmio, timer};

/// The sensor's clock generator, off the oscillator and divided by 16.
const TSENS_CTL: u32 = 0x0e0;
const TSENS_DIV: u32 = 16 << 12;

/// The temperature channel's result word: the sample in the low ten bits, and
/// the two bits that say it is valid and settled.
const RESULT: u32 = 0x7d5d_2200;
const VALID: u32 = 1 << 10;
const SETTLED: u32 = 1 << 16;
const COUNT: u32 = 0x3ff;

/// How long the sensor is given for its first sample.
const SAMPLE_US: u32 = 10_000;

/// A sample's temperature in millidegrees Celsius, as Linux converts it.
const fn millicelsius(count: u32) -> i32 {
    410_040 - 487 * count as i32
}

/// Start the sensor, and read the temperature once it has a sample.
pub fn start() -> Option<i32> {
    cm::set_generator(TSENS_CTL, TSENS_DIV, cm::SRC_OSC | cm::ENAB);
    timer::wait(SAMPLE_US, || mmio::read(RESULT) & (VALID | SETTLED) == VALID | SETTLED).then(|| millicelsius(mmio::read(RESULT) & COUNT))
}

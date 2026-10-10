//! The log's lock. One core runs this firmware and nothing interrupts it, so
//! there is never anyone to wait for.

pub struct Lock;

pub struct Held;

impl Lock {
    pub const fn new() -> Self {
        Lock
    }

    pub fn lock(&self, _timeout_us: u32) -> Option<Held> {
        Some(Held)
    }
}

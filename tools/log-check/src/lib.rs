//! `src/log.rs` as the firmware has it, with stand-ins for the hardware it
//! writes to.

#[path = "../../../src/log.rs"]
pub mod log;

pub mod console {
    pub struct Console;

    impl core::fmt::Write for Console {
        fn write_str(&mut self, _: &str) -> core::fmt::Result {
            Ok(())
        }
    }
}

pub mod critical {
    pub struct Section;

    pub fn enter() -> Section {
        Section
    }
}

pub mod stc {
    pub fn now() -> u64 {
        0
    }
}

pub mod sync {
    pub struct Lock;

    pub struct Held;

    impl Lock {
        pub const fn new() -> Lock {
            Lock
        }

        pub fn lock(&self, _timeout_us: u32) -> Option<Held> {
            Some(Held)
        }
    }
}

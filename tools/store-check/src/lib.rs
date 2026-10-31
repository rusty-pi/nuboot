//! The UEFI firmware's variable store and the code that lists its window in a
//! disk's partition table, compiled for the host: the real modules, run on
//! disk images.

extern crate alloc;

#[macro_export]
macro_rules! warn {
    ($($t:tt)*) => {{}};
}
#[macro_export]
macro_rules! info {
    ($($t:tt)*) => {{}};
}
#[macro_export]
macro_rules! debug {
    ($($t:tt)*) => {{}};
}

/// What the firmware's `util` gives these modules.
pub mod util {
    use std::cell::UnsafeCell;

    pub struct Global<T>(UnsafeCell<T>);

    unsafe impl<T> Sync for Global<T> {}

    impl<T> Global<T> {
        pub const fn new(value: T) -> Self {
            Self(UnsafeCell::new(value))
        }

        #[allow(clippy::mut_from_ref)]
        pub fn get(&self) -> &mut T {
            unsafe { &mut *self.0.get() }
        }
    }

    /// The CRC-32 of the EFI tables and the GPT, bit by bit.
    pub fn crc32(data: &[u8]) -> u32 {
        let mut crc = !0u32;
        for &byte in data {
            crc ^= byte as u32;
            for _ in 0..8 {
                crc = if crc & 1 != 0 { 0xEDB8_8320 ^ (crc >> 1) } else { crc >> 1 };
            }
        }
        !crc
    }
}

#[path = "../../../src/sha256.rs"]
#[allow(dead_code)]
pub mod sha256;
#[path = "../../../uefi/src/store.rs"]
pub mod store;
#[path = "../../../uefi/src/window.rs"]
pub mod window;

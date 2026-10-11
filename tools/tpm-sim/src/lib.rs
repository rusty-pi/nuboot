//! The VPU firmware's TPM code, compiled for the host: the real modules, with
//! stand-ins for the hardware they read.

#[path = "../../../src/aes.rs"]
pub mod aes;
#[path = "../../../src/kdf.rs"]
pub mod kdf;
#[path = "../../../src/keystore.rs"]
pub mod keystore;
#[path = "../../../src/p256.rs"]
pub mod p256;
#[path = "../../../src/rsa.rs"]
pub mod rsa;
#[path = "../../../src/sha256.rs"]
pub mod sha256;
#[path = "../../../src/tpm2.rs"]
pub mod tpm2;

/// The firmware's log macros, which take their arguments and write nothing.
#[macro_export]
macro_rules! info {
    ($($t:tt)*) => {};
}
#[macro_export]
macro_rules! debug {
    ($($t:tt)*) => {};
}

pub mod cache {
    pub fn write_back_with_l2(_first: u32, _last: u32) {}
}

pub mod critical {
    pub struct Section;
    pub fn enter() -> Section {
        Section
    }
}

/// The board's OTP: private key rows 56-63 as the simulator is told.
pub mod otp {
    use std::sync::Mutex;

    pub static ROWS: Mutex<[u32; 8]> = Mutex::new([0; 8]);

    pub fn read(row: u32) -> u32 {
        match row.checked_sub(56) {
            Some(i) if i < 8 => ROWS.lock().unwrap()[i as usize],
            _ => 0,
        }
    }
}

pub mod rng {
    use std::io::Read;

    pub fn fill(buf: &mut [u8]) -> bool {
        std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(buf)).is_ok()
    }
}

pub mod stc {
    pub fn now() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_micros() as u64)
    }
}

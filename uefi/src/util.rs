//! Small things everything else uses: global state, registers, caches,
//! waiting, and UCS-2 strings.

use core::cell::UnsafeCell;
use core::fmt;

/// State shared by the whole firmware. One core runs it and nothing
/// interrupts it, so access is never concurrent; but EFI code calls back in,
/// so a caller must not hold a reference across a call that could re-enter.
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

/// Overwrite `bytes` with zeros in a way the compiler keeps.
pub fn zero(bytes: &mut [u8]) {
    for b in bytes {
        unsafe { core::ptr::write_volatile(b, 0) };
    }
}

pub fn read32(addr: u64) -> u32 {
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

pub fn write32(addr: u64, value: u32) {
    unsafe { core::ptr::write_volatile(addr as *mut u32, value) }
}

/// A field value in hex.
pub struct Hex<T>(pub T);

impl<T: fmt::LowerHex> fmt::Display for Hex<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

/// Stop for good, with interrupts masked and the timer that beats the
/// watchdog stopped: nothing reloads it, and the board resets. A timer left on
/// would keep `wfi` from sleeping.
pub fn halt() -> ! {
    unsafe { core::arch::asm!("msr daifset, #2", "msr CNTHP_CTL_EL2, xzr", "isb") };
    loop {
        unsafe { core::arch::asm!("wfi") };
    }
}

/// Microseconds on the system timer, the clock the VPU firmware logs with.
pub fn now_us() -> u64 {
    crate::stc::now()
}

/// The generic timer's count, in microseconds. Waits spin on this rather than
/// on the system timer: a loop that reads only the counter costs nothing in a
/// model that skips such loops, where one polling the system timer's
/// registers runs instruction by instruction.
pub fn counter_us() -> u64 {
    let (count, freq): (u64, u64);
    unsafe {
        core::arch::asm!("isb", "mrs {0}, CNTPCT_EL0", out(reg) count);
        core::arch::asm!("mrs {0}, CNTFRQ_EL0", out(reg) freq);
    }
    (count as u128 * 1_000_000 / freq.max(1) as u128) as u64
}

pub fn delay_us(us: u64) {
    let until = counter_us() + us;
    while counter_us() < until {
        core::hint::spin_loop();
    }
}

/// How long `wait_for` waits between checks.
pub const POLL_US: u64 = 20;

/// Wait up to `timeout_us` for `done`; whether it came true.
pub fn wait_for(timeout_us: u64, mut done: impl FnMut() -> bool) -> bool {
    let until = counter_us() + timeout_us;
    loop {
        if done() {
            return true;
        }
        let now = counter_us();
        if now >= until {
            return done();
        }
        delay_us(POLL_US.min(until - now));
    }
}

fn line_size() -> u64 {
    let ctr: u64;
    unsafe { core::arch::asm!("mrs {0}, CTR_EL0", out(reg) ctr) };
    4 << ((ctr >> 16) & 0xf)
}

/// Write `[addr, addr + len)` back to memory and drop it from the data cache.
pub fn cache_flush(addr: u64, len: usize) {
    let line = line_size();
    let mut at = addr & !(line - 1);
    while at < addr + len as u64 {
        unsafe { core::arch::asm!("dc civac, {0}", in(reg) at) };
        at += line;
    }
    unsafe { core::arch::asm!("dsb sy") };
}

/// Make code just written to `[addr, addr + len)` the code that runs.
pub fn sync_icache(addr: u64, len: usize) {
    let line = line_size();
    let mut at = addr & !(line - 1);
    while at < addr + len as u64 {
        unsafe { core::arch::asm!("dc cvau, {0}", in(reg) at) };
        at += line;
    }
    unsafe { core::arch::asm!("dsb ish", "ic iallu", "dsb ish", "isb") };
}

/// A NUL-terminated UCS-2 string's length in units.
pub unsafe fn wcslen(s: *const u16) -> usize {
    let mut n = 0;
    while unsafe { *s.add(n) } != 0 {
        n += 1;
    }
    n
}

pub unsafe fn wstr<'a>(s: *const u16) -> &'a [u16] {
    if s.is_null() {
        return &[];
    }
    unsafe { core::slice::from_raw_parts(s, wcslen(s)) }
}

/// A UCS-2 string as a log field.
pub struct W<'a>(pub &'a [u16]);

impl fmt::Display for W<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for c in char::decode_utf16(self.0.iter().copied()) {
            fmt::Write::write_char(f, c.unwrap_or('?'))?;
        }
        Ok(())
    }
}

pub fn eq_ignore_case(a: &[u16], b: &[u16]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(&x, &y)| upper(x) == upper(y))
}

pub fn upper(c: u16) -> u16 {
    if (b'a' as u16..=b'z' as u16).contains(&c) { c - 32 } else { c }
}

/// The CRC-32 the EFI tables carry.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xEDB8_8320 & (!(crc & 1)).wrapping_add(1));
        }
    }
    !crc
}

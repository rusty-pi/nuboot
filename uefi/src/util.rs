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
    let freq = frequency();
    let count = ticks();
    count / freq * 1_000_000 + count % freq * 1_000_000 / freq
}

/// The generic timer's count.
pub fn ticks() -> u64 {
    let count: u64;
    unsafe { core::arch::asm!("isb", "mrs {0}, CNTPCT_EL0", out(reg) count) };
    count
}

/// The generic timer's ticks in a second.
pub fn frequency() -> u64 {
    let freq: u64;
    unsafe { core::arch::asm!("mrs {0}, CNTFRQ_EL0", out(reg) freq) };
    freq.max(1)
}

/// The ticks of `us` microseconds.
pub fn ticks_of(us: u64) -> u64 {
    let freq = frequency();
    us / 1_000_000 * freq + us % 1_000_000 * freq / 1_000_000
}

/// A moment, in the generic timer's ticks: what a loop that waits for it
/// compares the count with and does nothing else.
#[derive(Clone, Copy)]
pub struct Deadline(u64);

impl Deadline {
    pub fn after_us(us: u64) -> Deadline {
        Deadline(ticks().saturating_add(ticks_of(us)))
    }

    pub fn passed(&self) -> bool {
        ticks() >= self.0
    }

    /// Microseconds to go, none once it has passed.
    pub fn left_us(&self) -> u64 {
        let now = ticks();
        if now >= self.0 { 0 } else { (self.0 - now) / (frequency() / 1_000_000).max(1) }
    }
}

/// Spin until the count reaches `until`. The loop's only moving register is
/// the ticks left, which falls to zero the way a timeout does: a model that
/// parks a core in a loop like that can skip the wait.
fn spin_until(until: u64) {
    unsafe {
        core::arch::asm!(
            "2:",
            "isb",
            "mrs {now}, cntpct_el0",
            "subs {left}, {until}, {now}",
            "b.hi 2b",
            until = in(reg) until,
            now = out(reg) _,
            left = out(reg) _,
            options(nomem, nostack),
        );
    }
}

pub fn delay_us(us: u64) {
    spin_until(Deadline::after_us(us).0);
}

/// How long `wait_for` waits between checks.
pub const POLL_US: u64 = 20;

/// Wait up to `timeout_us` for `done`; whether it came true.
pub fn wait_for(timeout_us: u64, mut done: impl FnMut() -> bool) -> bool {
    let until = Deadline::after_us(timeout_us);
    loop {
        if done() {
            return true;
        }
        if until.passed() {
            return done();
        }
        delay_us(POLL_US.min(until.left_us()));
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

/// The CRC-32 the EFI tables carry, a byte at a time.
pub fn crc32(data: &[u8]) -> u32 {
    const TABLE: [u32; 256] = {
        let mut table = [0u32; 256];
        let mut n = 0;
        while n < 256 {
            let mut c = n as u32;
            let mut k = 0;
            while k < 8 {
                c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
                k += 1;
            }
            table[n] = c;
            n += 1;
        }
        table
    };
    let mut crc = !0u32;
    for &b in data {
        crc = TABLE[((crc ^ b as u32) & 0xff) as usize] ^ (crc >> 8);
    }
    !crc
}

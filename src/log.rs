//! The firmware's log: one record per event, with a level, the subsystem it
//! came from, a message and named fields, rendered by every [`Sink`] that is
//! attached. The console is the first.
//!
//! ```ignore
//! info!("sd", "card ready"; capacity_mb = 30436, kind = "SDHC");
//! warn!("net", "no DHCP offer, retrying in {} s", 4; attempt = 2);
//! ```
//!
//! comes out on the serial console as
//!
//! ```text
//!    1.204518 INFO  sd       card ready  capacity_mb=30436 kind=SDHC
//!    3.981022 WARN  net      no DHCP offer, retrying in 4 s  attempt=2
//! ```
//!
//! The time is the system timer's, in seconds since it started. A field's
//! value is anything that implements [`Display`]; [`dbg`] takes one that only
//! implements [`Debug`]. A value that is empty or holds a space, `"` or `=`
//! is quoted, so a line always splits back into its fields.
//!
//! A record is built on the stack and nothing is formatted until a sink asks,
//! so a record below [`level`] costs one comparison. Records are written whole:
//! a thread that logs while another is mid-line waits for it. An interrupt
//! handler must not log.

use core::cell::Cell;
use core::fmt::{self, Debug, Display, Write};
use core::sync::atomic::{AtomicU8, Ordering};

use crate::console::Console;
use crate::{stc, sync};

/// How much a record matters; the lower, the more.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Level {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl Level {
    /// Five columns, so the subsystem lines up after it.
    pub fn name(self) -> &'static str {
        match self {
            Level::Error => "ERROR",
            Level::Warn => "WARN ",
            Level::Info => "INFO ",
            Level::Debug => "DEBUG",
            Level::Trace => "TRACE",
        }
    }

    #[cfg(feature = "color")]
    fn color(self) -> &'static str {
        match self {
            Level::Error => "\x1b[1;31m",
            Level::Warn => "\x1b[1;33m",
            Level::Info => "\x1b[32m",
            Level::Debug => "\x1b[34m",
            Level::Trace => "\x1b[2m",
        }
    }
}

/// One named value of a record.
pub struct Field<'a> {
    pub key: &'static str,
    pub value: &'a dyn Display,
}

/// One event, as every sink sees it.
pub struct Record<'a> {
    /// The system timer, in microseconds.
    pub time_us: u64,
    pub level: Level,
    /// The subsystem the record came from: `boot`, `sched`, `sd`.
    pub target: &'static str,
    pub message: fmt::Arguments<'a>,
    pub fields: &'a [Field<'a>],
}

/// Where records go.
pub trait Sink: Sync {
    fn record(&self, record: &Record);
}

/// The most sinks attached at once.
const SINKS: usize = 4;

struct Sinks([Cell<Option<&'static dyn Sink>>; SINKS]);

/// Single core, and only ever read or written inside a [`crate::critical`]
/// section or with [`LOCK`] held.
unsafe impl Sync for Sinks {}

static ATTACHED: Sinks = Sinks([const { Cell::new(None) }; SINKS]);

/// Held while a record is written, so that records from two threads do not
/// interleave.
static LOCK: sync::Lock = sync::Lock::new();

/// How long a record waits for another thread's to finish before it is
/// written anyway.
const LOCK_WAIT_US: u32 = 100_000;

static LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);

/// The least important level that is logged.
pub fn level() -> Level {
    match LEVEL.load(Ordering::Relaxed) {
        0 => Level::Error,
        1 => Level::Warn,
        2 => Level::Info,
        3 => Level::Debug,
        _ => Level::Trace,
    }
}

pub fn set_level(level: Level) {
    LEVEL.store(level as u8, Ordering::Relaxed);
}

#[inline(always)]
pub fn enabled(level: Level) -> bool {
    level as u8 <= LEVEL.load(Ordering::Relaxed)
}

/// Send every record from here on to `sink` as well. Whether there was room.
pub fn attach(sink: &'static dyn Sink) -> bool {
    let _section = crate::critical::enter();
    match ATTACHED.0.iter().find(|slot| slot.get().is_none()) {
        Some(slot) => {
            slot.set(Some(sink));
            true
        }
        None => false,
    }
}

/// Hand `record` to the console and every attached sink, whole.
pub fn emit(record: &Record) {
    let _held = LOCK.lock(LOCK_WAIT_US);
    write(record);
}

fn write(record: &Record) {
    CONSOLE.record(record);
    for slot in &ATTACHED.0 {
        if let Some(sink) = slot.get() {
            sink.record(record);
        }
    }
}

/// The last record of a core that is stopping: no lock, since whatever held
/// it will never run again, and nowhere but the console.
pub fn emergency(target: &'static str, message: fmt::Arguments) {
    let record = Record { time_us: stc::now(), level: Level::Error, target, message, fields: &[] };
    CONSOLE.record(&record);
}

/// What the panic handler logs.
pub fn panic_record(message: fmt::Arguments, file: &str, line: u32) {
    let record = Record {
        time_us: stc::now(),
        level: Level::Error,
        target: "panic",
        message,
        fields: &[Field { key: "at", value: &At(file, line) }],
    };
    CONSOLE.record(&record);
}

struct At<'a>(&'a str, u32);

impl Display for At<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.0, self.1)
    }
}

/// A field value that has [`Debug`] but no [`Display`].
pub fn dbg<T: Debug>(value: &T) -> Dbg<'_, T> {
    Dbg(value)
}

pub struct Dbg<'a, T: Debug>(&'a T);

impl<T: Debug> Display for Dbg<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Debug::fmt(self.0, f)
    }
}

/// The serial console's rendering: aligned columns, one record a line.
pub struct ConsoleSink;

static CONSOLE: ConsoleSink = ConsoleSink;

/// How wide the subsystem column is.
const TARGET_WIDTH: usize = 8;

impl Sink for ConsoleSink {
    fn record(&self, record: &Record) {
        let _ = render(&mut Console, record);
    }
}

/// Write `record` as one line of the console's format.
pub fn render(out: &mut impl Write, record: &Record) -> fmt::Result {
    let (s, us) = (record.time_us / 1_000_000, (record.time_us % 1_000_000) as u32);
    let (dim, level, reset) = styles(record.level);
    write!(out, "{dim}{s:4}.{us:06}{reset} {level}{}{reset} ", record.level.name())?;
    write!(out, "{:<width$} ", record.target, width = TARGET_WIDTH)?;
    write!(Printable(out), "{}", record.message)?;
    for (i, field) in record.fields.iter().enumerate() {
        let gap = if i == 0 { "  " } else { " " };
        write!(out, "{gap}{dim}{}={reset}", field.key)?;
        write_value(out, field.value)?;
    }
    out.write_str("\n")
}

#[cfg(feature = "color")]
fn styles(level: Level) -> (&'static str, &'static str, &'static str) {
    ("\x1b[2m", level.color(), "\x1b[0m")
}

#[cfg(not(feature = "color"))]
fn styles(_level: Level) -> (&'static str, &'static str, &'static str) {
    ("", "", "")
}

/// A value as it stands, or quoted with `"` and `\` escaped when it would
/// not read back as one field. Formatted twice rather than buffered: once to
/// look, once to write.
fn write_value(out: &mut impl Write, value: &dyn Display) -> fmt::Result {
    let mut probe = Probe { empty: true, quote: false };
    let _ = write!(probe, "{value}");
    if !probe.empty && !probe.quote {
        return write!(out, "{value}");
    }
    out.write_char('"')?;
    write!(Escape(out), "{value}")?;
    out.write_char('"')
}

struct Probe {
    empty: bool,
    quote: bool,
}

impl Write for Probe {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.empty &= s.is_empty();
        self.quote |= s.bytes().any(|b| b <= b' ' || b == b'"' || b == b'=') || s.chars().any(char::is_control);
        Ok(())
    }
}

struct Escape<'a, W: Write>(&'a mut W);

impl<W: Write> Write for Escape<'_, W> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for c in s.chars() {
            match c {
                '"' | '\\' => {
                    self.0.write_char('\\')?;
                    self.0.write_char(c)?;
                }
                '\n' => self.0.write_str("\\n")?,
                c if c.is_control() => write!(self.0, "\\x{:02x}", c as u32)?,
                _ => self.0.write_char(c)?,
            }
        }
        Ok(())
    }
}

/// Text as it is, but for control characters, which a terminal would act on
/// (an escape sequence, a carriage return that overwrites the line) and which
/// can come from a file name or a variable name: those are written as `\xNN`.
struct Printable<'a, W: Write>(&'a mut W);

impl<W: Write> Write for Printable<'_, W> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for c in s.chars() {
            if c.is_control() {
                write!(self.0, "\\x{:02x}", c as u32)?;
            } else {
                self.0.write_char(c)?;
            }
        }
        Ok(())
    }
}

/// `log!(level, "target", "message {}", arg; key = value, ...)`: what the
/// per-level macros expand to.
#[macro_export]
macro_rules! log {
    ($level:expr, $target:expr, $fmt:literal $(, $arg:expr)* $(; $($key:ident = $value:expr),* $(,)?)?) => {{
        let level = $level;
        if $crate::log::enabled(level) {
            $crate::log::emit(&$crate::log::Record {
                time_us: $crate::stc::now(),
                level,
                target: $target,
                message: format_args!($fmt $(, $arg)*),
                fields: &[$($($crate::log::Field { key: stringify!($key), value: &$value }),*)?],
            });
        }
    }};
}

#[macro_export]
macro_rules! error {
    ($($t:tt)*) => { $crate::log!($crate::log::Level::Error, $($t)*) };
}

#[macro_export]
macro_rules! warn {
    ($($t:tt)*) => { $crate::log!($crate::log::Level::Warn, $($t)*) };
}

#[macro_export]
macro_rules! info {
    ($($t:tt)*) => { $crate::log!($crate::log::Level::Info, $($t)*) };
}

#[macro_export]
macro_rules! debug {
    ($($t:tt)*) => { $crate::log!($crate::log::Level::Debug, $($t)*) };
}

#[macro_export]
macro_rules! trace {
    ($($t:tt)*) => { $crate::log!($crate::log::Level::Trace, $($t)*) };
}

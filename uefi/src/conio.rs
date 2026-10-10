//! The EFI console on the serial port: `EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL`
//! writes UTF-8 and moves the cursor with VT100 escapes, and
//! `EFI_SIMPLE_TEXT_INPUT_PROTOCOL` turns what a terminal sends into keys.

use core::ffi::c_void;

use r_efi::efi;
use r_efi::protocols::{simple_text_input as input, simple_text_output as output};

use crate::console::{Console, getc};
use crate::util::{Global, now_us};

const COLUMNS: usize = 80;
const ROWS: usize = 25;

static MODE: Global<output::Mode> = Global::new(output::Mode {
    max_mode: 1,
    mode: 0,
    attribute: 0x07,
    cursor_column: 0,
    cursor_row: 0,
    cursor_visible: efi::Boolean::TRUE,
});

static OUT: Global<output::Protocol> = Global::new(output::Protocol {
    reset: out_reset,
    output_string,
    test_string,
    query_mode,
    set_mode,
    set_attribute,
    clear_screen,
    set_cursor_position,
    enable_cursor,
    mode: core::ptr::null_mut(),
});

static IN: Global<input::Protocol> =
    Global::new(input::Protocol { reset: in_reset, read_key_stroke, wait_for_key: core::ptr::null_mut() });

/// The two protocols, ready to go in the system table.
pub fn init() -> (*mut input::Protocol, *mut output::Protocol) {
    OUT.get().mode = MODE.get();
    IN.get().wait_for_key = crate::event::create_polled(key_waiting);
    (IN.get(), OUT.get())
}

fn put(s: &str) {
    let _ = core::fmt::Write::write_str(&mut Raw, s);
}

/// The console without `\n` translation: EFI applications send `\r\n`.
struct Raw;

impl core::fmt::Write for Raw {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for b in s.bytes() {
            Console.putc(b);
        }
        Ok(())
    }
}

extern "efiapi" fn out_reset(_this: *mut output::Protocol, _extended: efi::Boolean) -> efi::Status {
    efi::Status::SUCCESS
}

extern "efiapi" fn output_string(_this: *mut output::Protocol, s: *mut efi::Char16) -> efi::Status {
    if s.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    let mode = MODE.get();
    let text = unsafe { crate::util::wstr(s) };
    for c in char::decode_utf16(text.iter().copied()) {
        let c = c.unwrap_or('?');
        let mut buf = [0u8; 4];
        put(c.encode_utf8(&mut buf));
        match c {
            '\r' => mode.cursor_column = 0,
            '\n' => mode.cursor_row = (mode.cursor_row + 1).min(ROWS as i32 - 1),
            '\u{8}' => mode.cursor_column = (mode.cursor_column - 1).max(0),
            _ => mode.cursor_column = (mode.cursor_column + 1).min(COLUMNS as i32 - 1),
        }
    }
    efi::Status::SUCCESS
}

extern "efiapi" fn test_string(_this: *mut output::Protocol, _s: *mut efi::Char16) -> efi::Status {
    efi::Status::SUCCESS
}

extern "efiapi" fn query_mode(_this: *mut output::Protocol, mode: usize, cols: *mut usize, rows: *mut usize) -> efi::Status {
    if mode != 0 {
        return efi::Status::UNSUPPORTED;
    }
    unsafe {
        *cols = COLUMNS;
        *rows = ROWS;
    }
    efi::Status::SUCCESS
}

extern "efiapi" fn set_mode(_this: *mut output::Protocol, mode: usize) -> efi::Status {
    if mode != 0 { efi::Status::UNSUPPORTED } else { efi::Status::SUCCESS }
}

extern "efiapi" fn set_attribute(_this: *mut output::Protocol, attribute: usize) -> efi::Status {
    MODE.get().attribute = attribute as i32;
    efi::Status::SUCCESS
}

extern "efiapi" fn clear_screen(_this: *mut output::Protocol) -> efi::Status {
    put("\x1b[2J\x1b[H");
    let mode = MODE.get();
    mode.cursor_column = 0;
    mode.cursor_row = 0;
    efi::Status::SUCCESS
}

extern "efiapi" fn set_cursor_position(_this: *mut output::Protocol, col: usize, row: usize) -> efi::Status {
    if col >= COLUMNS || row >= ROWS {
        return efi::Status::UNSUPPORTED;
    }
    let _ = core::fmt::Write::write_fmt(&mut Raw, format_args!("\x1b[{};{}H", row + 1, col + 1));
    let mode = MODE.get();
    mode.cursor_column = col as i32;
    mode.cursor_row = row as i32;
    efi::Status::SUCCESS
}

extern "efiapi" fn enable_cursor(_this: *mut output::Protocol, visible: efi::Boolean) -> efi::Status {
    let on = bool::from(visible);
    put(if on { "\x1b[?25h" } else { "\x1b[?25l" });
    MODE.get().cursor_visible = visible;
    efi::Status::SUCCESS
}

// --- input ---

const SCAN_UP: u16 = 0x01;
const SCAN_DOWN: u16 = 0x02;
const SCAN_RIGHT: u16 = 0x03;
const SCAN_LEFT: u16 = 0x04;
const SCAN_HOME: u16 = 0x05;
const SCAN_END: u16 = 0x06;
const SCAN_INSERT: u16 = 0x07;
const SCAN_DELETE: u16 = 0x08;
const SCAN_PAGE_UP: u16 = 0x09;
const SCAN_PAGE_DOWN: u16 = 0x0a;
const SCAN_F1: u16 = 0x0b;
const SCAN_ESC: u16 = 0x17;

/// How long the rest of an escape sequence may take to arrive.
const ESCAPE_US: u64 = 20_000;

/// A byte read ahead while looking for an escape sequence.
static PENDING: Global<Option<u8>> = Global::new(None);

fn key_waiting() -> bool {
    let pending = PENDING.get();
    if pending.is_none() {
        *pending = getc();
    }
    pending.is_some()
}

fn next_byte(wait_us: u64) -> Option<u8> {
    if let Some(b) = PENDING.get().take() {
        return Some(b);
    }
    let until = now_us() + wait_us;
    loop {
        if let Some(b) = getc() {
            return Some(b);
        }
        if now_us() >= until {
            return None;
        }
    }
}

fn read_key() -> Option<input::InputKey> {
    let key = |scan: u16, c: u16| Some(input::InputKey { scan_code: scan, unicode_char: c });
    let b = next_byte(0)?;
    match b {
        0x1b => {}
        b'\n' | b'\r' => return key(0, b'\r' as u16),
        0x7f | 0x08 => return key(0, 0x08),
        _ => return key(0, b as u16),
    }
    let Some(b1) = next_byte(ESCAPE_US) else { return key(SCAN_ESC, 0) };
    if b1 == b'O' {
        // F1..F4 as most terminals send them.
        return match next_byte(ESCAPE_US) {
            Some(c @ b'P'..=b'S') => key(SCAN_F1 + (c - b'P') as u16, 0),
            _ => key(SCAN_ESC, 0),
        };
    }
    if b1 != b'[' {
        *PENDING.get() = Some(b1);
        return key(SCAN_ESC, 0);
    }
    let mut n = 0u16;
    loop {
        match next_byte(ESCAPE_US)? {
            c @ b'0'..=b'9' => n = n * 10 + (c - b'0') as u16,
            b';' => {}
            b'A' => return key(SCAN_UP, 0),
            b'B' => return key(SCAN_DOWN, 0),
            b'C' => return key(SCAN_RIGHT, 0),
            b'D' => return key(SCAN_LEFT, 0),
            b'H' => return key(SCAN_HOME, 0),
            b'F' => return key(SCAN_END, 0),
            b'~' => {
                let scan = match n {
                    1 | 7 => SCAN_HOME,
                    2 => SCAN_INSERT,
                    3 => SCAN_DELETE,
                    4 | 8 => SCAN_END,
                    5 => SCAN_PAGE_UP,
                    6 => SCAN_PAGE_DOWN,
                    11..=15 => SCAN_F1 + n - 11,
                    17..=21 => SCAN_F1 + 5 + n - 17,
                    23 | 24 => SCAN_F1 + 10 + n - 23,
                    _ => return None,
                };
                return key(scan, 0);
            }
            _ => return None,
        }
    }
}

extern "efiapi" fn in_reset(_this: *mut input::Protocol, _extended: efi::Boolean) -> efi::Status {
    *PENDING.get() = None;
    while getc().is_some() {}
    efi::Status::SUCCESS
}

extern "efiapi" fn read_key_stroke(_this: *mut input::Protocol, key: *mut input::InputKey) -> efi::Status {
    if key.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    match read_key() {
        Some(k) => {
            unsafe { *key = k };
            efi::Status::SUCCESS
        }
        None => efi::Status::NOT_READY,
    }
}

/// The console handle's protocols.
pub fn install() -> efi::Handle {
    let (i, o) = (IN.get() as *mut input::Protocol, OUT.get() as *mut output::Protocol);
    let h = crate::proto::install(core::ptr::null_mut(), &input::PROTOCOL_GUID, i as *mut c_void).unwrap();
    crate::proto::install(h, &output::PROTOCOL_GUID, o as *mut c_void).unwrap()
}

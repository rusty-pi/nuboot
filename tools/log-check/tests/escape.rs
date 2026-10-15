//! A record is one line, and text that came from a medium or from the OS (a
//! file name, a variable name) cannot make it more, or reach the terminal the
//! console is read on as anything but text.

use log_check::log::{Field, Level, Record, render};

fn line(message: core::fmt::Arguments, fields: &[Field]) -> String {
    let mut out = String::new();
    render(&mut out, &Record { time_us: 1_000_000, level: Level::Warn, target: "capsule", message, fields }).unwrap();
    out
}

fn is_text(line: &str) -> bool {
    line.ends_with('\n') && line[..line.len() - 1].chars().all(|c| !c.is_control())
}

#[test]
fn a_field_with_control_characters_is_written_as_text() {
    let name = "x.cap\r  1.0 INFO  secboot  image verified\x1b[2J\x1b]0;owned\x07\u{85}\x7f";
    let out = line(format_args!("capsule unreadable"), &[Field { key: "path", value: &name }]);
    assert!(is_text(&out), "{out:?}");
    assert!(out.contains("\\x0d"), "{out:?}");
    assert!(out.contains("\\x1b[2J"), "{out:?}");
    assert!(out.contains("\\x85") && out.contains("\\x7f"), "{out:?}");
}

#[test]
fn a_message_with_control_characters_is_written_as_text() {
    let out = line(format_args!("variable {}", "a\nb\x1b[31m"), &[]);
    assert!(is_text(&out), "{out:?}");
    assert!(out.contains("a\\x0ab\\x1b[31m"), "{out:?}");
}

#[test]
fn ordinary_values_are_unchanged() {
    let out = line(format_args!("image refused"), &[Field { key: "reason", value: &"not signed" }, Field { key: "bytes", value: &42 }]);
    assert!(out.ends_with("capsule  image refused  reason=\"not signed\" bytes=42\n"), "{out:?}");
}

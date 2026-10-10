//! Critical sections, for the log: with one core and no interrupts, every
//! moment is one.

pub struct Section;

pub fn enter() -> Section {
    Section
}

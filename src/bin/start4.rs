//! `start4.elf`: the firmware linked where the bootloader loads it.

#![no_std]
#![no_main]

#[path = "../firmware.rs"]
mod firmware;

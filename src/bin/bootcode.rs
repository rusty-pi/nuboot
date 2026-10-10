//! `bootcode`: the first stage, which the boot ROM loads out of the EEPROM.
//!
//! The boot ROM stages it into the L2 at `0x8000_0000`, which it runs out of
//! as SRAM since there is no SDRAM yet, and enters it at `+0x200`. It starts
//! the PLLs and the clocks the rest of the boot runs on, brings up the LPDDR4
//! with the training firmware the EEPROM carries, then loads `start4.elf`
//! out of the EEPROM into SDRAM and enters it with the handover block it
//! reads.

#![no_std]
#![no_main]

use pi4_server_firmware::board::{Board, Revision};
use pi4_server_firmware::mmio::{self, PASSWD};
use pi4_server_firmware::{cache, cm, console, eeprom, elf, error, halt, handover, info, sdram, spi_flash, timer};

/// Where `start4.elf` is read to before it is loaded: SDRAM above the image
/// it loads, uncached.
const IMAGE_BUF: u32 = 0xc100_0000;
const IMAGE_MAX: usize = 4 << 20;

/// What the bank-low setting of the stock bootloader defaults to.
const BANKLOW: u32 = 3;

fn fatal() -> ! {
    console::drain();
    halt()
}

/// Two of the A2W PLLs, powered through PM and brought up at 0x37 + fraction,
/// with the VPU moved onto one of them.
fn plls() {
    let _ = cm::read(cm::A2W_1390);
    cm::write(cm::A2W_1390, 0x0030_0021);
    cm::set_plls_started();
    for (pm, ana, frac, ctrl, fb, lock, divs, chans) in [
        (0x7e10_0088, 0x1350, 0x1a40, 0x1940, 0x1f40, 0x10c,
         [(0x1d40, 4), (0x1b40, 0x10), (0x1e40, 0x10), (0x1c40, 5)], [0x1b40, 0x1e40]),
        (0x7e10_0084, 0x1330, 0x1a20, 0x1920, 0x1f20, 0x108,
         [(0x1e20, 6), (0x1c20, 6), (0x1b20, 6), (0x1d20, 5)], [0x1c20, 0x1b20]),
    ] {
        mmio::write(pm, PASSWD | 0x80_0004);
        mmio::write(pm, PASSWD | 4);
        cm::write(ana, 0x23);
        cm::write(frac, 0x0008_e390);
        cm::write(ctrl, 0x1037);
        cm::write(fb, 0);
        cm::write(lock, 0x6aa);
        timer::wait(10_000, || cm::read(0x114) != 0);
        for (off, v) in divs {
            cm::write(off, v);
        }
        cm::write(ctrl, 0x0002_1037);
        cm::write(fb, 0);
        for off in chans {
            cm::write(off, 0x100);
        }
        cm::write(fb, 0);
        cm::write(lock, 0);
    }
    cm::write(0x00c, 0x1000);
    let _ = cm::read(0x008);
    cm::write(0x008, 0x75);
}

/// Peripheral clocks and resets the SDRAM controller and the rest of the boot
/// rely on.
fn peripheral_clocks() {
    cm::set_generator(0x1d8, 0x3c00, 0x16);
    cm::set_generator(0x1e0, 0x3000, 0x16);
    cm::set_generator(0x1f8, 0x1000, 0x11);
    cm::set_generator(0x1f0, 0x2000, 0x11);
    mmio::write(0x7e00_f100, 0x200);
    mmio::write(0x7e00_f110, 2);
    mmio::write(0x7e00_f118, 3);
    let _ = cm::read(0x21c);
    for v in [0x341, 0x343, 0x347, 0x34f] {
        cm::write(0x21c, v);
    }
}

/// Read `start4.elf` out of the EEPROM and load it; its entry point.
fn load_firmware() -> u32 {
    let buf = unsafe { core::slice::from_raw_parts_mut(IMAGE_BUF as usize as *mut u8, IMAGE_MAX) };
    let image = match eeprom::load(b"start4.elf", buf) {
        Ok(n) => &buf[..n],
        Err(e) => {
            error!("boot", "no start4.elf in the EEPROM"; error = format_args!("{e:?}"));
            fatal()
        }
    };
    match elf::load(image) {
        Ok(entry) => {
            info!("boot", "start4.elf loaded"; bytes = image.len(), entry = format_args!("{entry:#x}"));
            entry
        }
        Err(e) => {
            error!("boot", "start4.elf does not load"; error = format_args!("{e:?}"));
            fatal()
        }
    }
}

#[unsafe(no_mangle)]
fn firmware_main() -> ! {
    // The stock first stage writes this before it touches the UART's clock.
    let _ = cm::read(cm::A2W_1390);
    cm::write(cm::A2W_1390, 1);
    console::init();
    let revision = Revision::read();
    info!("boot", "pi4-server-firmware bootcode {}", &env!("FIRMWARE_COMMIT")[..7];
        board = revision.model(), revision = revision, pcb = revision.pcb());

    plls();
    peripheral_clocks();
    spi_flash::set_divider(spi_flash::PLL_DIVIDER);

    let board = Board::read();
    let sd = match sdram::init(&board, BANKLOW) {
        Ok(sd) => sd,
        Err(e) => {
            error!("sdram", "SDRAM does not come up"; error = format_args!("{e:?}"));
            fatal()
        }
    };
    if sdram::verify(&sd, &board).is_err() {
        fatal();
    }

    let entry = load_firmware();
    handover::write(env!("FIRMWARE_COMMIT").as_bytes(), sd.geometry.size_gbit, handover::DEVICE_EEPROM);
    cache::enter(entry)
}

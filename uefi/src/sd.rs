//! The SD card on EMMC2, the Arasan SDHCI 3.00 the card slot is wired to.
//!
//! The controller only takes 32-bit accesses. Data moves through its buffer
//! port (PIO): no DMA addressing to get right on either stepping of the chip,
//! and fast enough for a kernel and an initrd.

use alloc::boxed::Box;

use crate::block::Disk;
use crate::devpath::{self, Builder};
use crate::util::{read32, wait_for, write32};
use crate::{debug, info, warn};

const BASE: u64 = 0xFE34_0000;
const BLKSIZECNT: u64 = BASE + 0x04;
const ARG1: u64 = BASE + 0x08;
const CMDTM: u64 = BASE + 0x0C;
const RESP0: u64 = BASE + 0x10;
const DATA: u64 = BASE + 0x20;
const STATUS: u64 = BASE + 0x24;
const CONTROL0: u64 = BASE + 0x28;
const CONTROL1: u64 = BASE + 0x2C;
const INTERRUPT: u64 = BASE + 0x30;
const IRPT_EN: u64 = BASE + 0x34;
const IRPT_SIG: u64 = BASE + 0x38;
const CAPS0: u64 = BASE + 0x40;

const STATUS_CMD_INHIBIT: u32 = 1 << 0;
const STATUS_DAT_INHIBIT: u32 = 1 << 1;

const INT_CMD_DONE: u32 = 1 << 0;
const INT_DATA_DONE: u32 = 1 << 1;
const INT_READ_READY: u32 = 1 << 5;
const INT_ERROR: u32 = 1 << 15;

const C1_CLK_INTLEN: u32 = 1 << 0;
const C1_CLK_STABLE: u32 = 1 << 1;
const C1_CLK_EN: u32 = 1 << 2;
const C1_RESET_ALL: u32 = 1 << 24;
const C1_RESET_CMD: u32 = 1 << 25;
const C1_RESET_DATA: u32 = 1 << 26;

// The command register's flags (bits 16..31 of CMDTM).
const RESP_NONE: u32 = 0;
const RESP_136: u32 = 1 << 16;
const RESP_48: u32 = 2 << 16;
const RESP_48_BUSY: u32 = 3 << 16;
const CHECK_CRC: u32 = 1 << 19;
const CHECK_INDEX: u32 = 1 << 20;
const DATA_PRESENT: u32 = 1 << 21;
// The transfer mode (bits 0..15).
const TM_BLKCNT_EN: u32 = 1 << 1;
const TM_AUTO_CMD12: u32 = 1 << 2;
const TM_READ: u32 = 1 << 4;
const TM_MULTI: u32 = 1 << 5;

const R1: u32 = RESP_48 | CHECK_CRC | CHECK_INDEX;
const R1B: u32 = RESP_48_BUSY | CHECK_CRC | CHECK_INDEX;
const R2: u32 = RESP_136 | CHECK_CRC;
const R3: u32 = RESP_48;
const R6: u32 = R1;
const R7: u32 = R1;

const BLOCK: usize = 512;
/// The most blocks one `CMD18` moves.
const MAX_RUN: usize = 1024;

pub struct Sd {
    rca: u32,
    /// SDHC and SDXC address blocks; SDSC addresses bytes.
    high_capacity: bool,
    blocks: u64,
    base_hz: u32,
}

/// Logged through `Debug`, which is all that reads the status.
#[derive(Debug)]
#[allow(dead_code)]
enum Error {
    Timeout,
    Controller(u32),
}

impl Sd {
    fn reset_lines(&self, bits: u32) {
        write32(CONTROL1, read32(CONTROL1) | bits);
        wait_for(100_000, || read32(CONTROL1) & bits == 0);
    }

    fn command(&self, index: u32, arg: u32, flags: u32) -> Result<[u32; 4], Error> {
        let busy = STATUS_CMD_INHIBIT | if flags & (DATA_PRESENT | RESP_48_BUSY) != 0 { STATUS_DAT_INHIBIT } else { 0 };
        if !wait_for(100_000, || read32(STATUS) & busy == 0) {
            self.reset_lines(C1_RESET_CMD | C1_RESET_DATA);
            return Err(Error::Timeout);
        }
        write32(INTERRUPT, 0xffff_ffff);
        write32(ARG1, arg);
        write32(CMDTM, index << 24 | flags);
        if !wait_for(500_000, || read32(INTERRUPT) & (INT_CMD_DONE | INT_ERROR) != 0) {
            self.reset_lines(C1_RESET_CMD);
            return Err(Error::Timeout);
        }
        let irq = read32(INTERRUPT);
        if irq & INT_ERROR != 0 {
            write32(INTERRUPT, irq);
            self.reset_lines(C1_RESET_CMD | C1_RESET_DATA);
            return Err(Error::Controller(irq));
        }
        write32(INTERRUPT, INT_CMD_DONE);
        let resp = [read32(RESP0), read32(RESP0 + 4), read32(RESP0 + 8), read32(RESP0 + 12)];
        if flags & 0x3_0000 == RESP_48_BUSY {
            if !wait_for(1_000_000, || read32(INTERRUPT) & (INT_DATA_DONE | INT_ERROR) != 0) {
                return Err(Error::Timeout);
            }
            write32(INTERRUPT, INT_DATA_DONE);
        }
        Ok(resp)
    }

    fn app_command(&self, index: u32, arg: u32, flags: u32) -> Result<[u32; 4], Error> {
        self.command(55, self.rca << 16, R1)?;
        self.command(index, arg, flags)
    }

    fn set_clock(&self, hz: u32) {
        write32(CONTROL1, read32(CONTROL1) & !(C1_CLK_EN));
        let div = self.base_hz.div_ceil(2 * hz).min(0x3ff);
        let c1 = read32(CONTROL1) & !0xffc7 | (div & 0xff) << 8 | ((div >> 8) & 3) << 6 | C1_CLK_INTLEN;
        // The data timeout: the longest the controller offers.
        let c1 = c1 & !(0xf << 16) | 0xe << 16;
        write32(CONTROL1, c1);
        wait_for(100_000, || read32(CONTROL1) & C1_CLK_STABLE != 0);
        write32(CONTROL1, read32(CONTROL1) | C1_CLK_EN);
        crate::util::delay_us(1000);
    }

    fn init() -> Result<Sd, Error> {
        let caps = read32(CAPS0);
        let base_mhz = (caps >> 8) & 0xff;
        let mut sd = Sd { rca: 0, high_capacity: false, blocks: 0, base_hz: if base_mhz == 0 { 100 } else { base_mhz } * 1_000_000 };

        write32(CONTROL1, C1_RESET_ALL);
        if !wait_for(100_000, || read32(CONTROL1) & C1_RESET_ALL == 0) {
            return Err(Error::Timeout);
        }
        // 3.3 V, bus power on.
        write32(CONTROL0, (read32(CONTROL0) & !0xff00) | 0x0f00);
        crate::util::delay_us(10_000);
        write32(IRPT_EN, 0xffff_feff);
        write32(IRPT_SIG, 0);
        sd.set_clock(400_000);

        sd.command(0, 0, RESP_NONE)?;
        let v2 = sd.command(8, 0x1aa, R7).is_ok_and(|r| r[0] & 0xfff == 0x1aa);
        let hcs = if v2 { 1 << 30 } else { 0 };
        // A card that does not answer ACMD41 at all is no card.
        let mut ocr = sd.app_command(41, hcs | 0x00ff_8000, R3)?[0];
        let until = crate::util::counter_us() + 1_000_000;
        while ocr & (1 << 31) == 0 {
            if crate::util::counter_us() > until {
                return Err(Error::Timeout);
            }
            crate::util::delay_us(10_000);
            ocr = sd.app_command(41, hcs | 0x00ff_8000, R3)?[0];
        }
        sd.high_capacity = ocr & (1 << 30) != 0;
        sd.command(2, 0, R2)?;
        sd.rca = sd.command(3, 0, R6)?[0] >> 16;
        let csd = sd.command(9, sd.rca << 16, R2)?;
        sd.blocks = capacity(&csd);
        sd.command(7, sd.rca << 16, R1B)?;
        sd.app_command(6, 2, R1)?;
        write32(CONTROL0, read32(CONTROL0) | 1 << 1);
        if !sd.high_capacity {
            sd.command(16, BLOCK as u32, R1)?;
        }
        sd.set_clock(25_000_000);
        Ok(sd)
    }

    fn read_run(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), Error> {
        let count = buf.len() / BLOCK;
        let addr = if self.high_capacity { lba as u32 } else { (lba * BLOCK as u64) as u32 };
        write32(BLKSIZECNT, (count as u32) << 16 | BLOCK as u32);
        let (index, mode) = if count == 1 {
            (17, TM_READ)
        } else {
            (18, TM_READ | TM_MULTI | TM_BLKCNT_EN | TM_AUTO_CMD12)
        };
        self.command(index, addr, R1 | DATA_PRESENT | mode)?;
        for block in buf.chunks_exact_mut(BLOCK) {
            if !wait_for(1_000_000, || read32(INTERRUPT) & (INT_READ_READY | INT_ERROR) != 0) {
                self.reset_lines(C1_RESET_CMD | C1_RESET_DATA);
                return Err(Error::Timeout);
            }
            let irq = read32(INTERRUPT);
            if irq & INT_ERROR != 0 {
                write32(INTERRUPT, irq);
                self.reset_lines(C1_RESET_CMD | C1_RESET_DATA);
                return Err(Error::Controller(irq));
            }
            write32(INTERRUPT, INT_READ_READY);
            for word in block.chunks_exact_mut(4) {
                word.copy_from_slice(&read32(DATA).to_le_bytes());
            }
        }
        if !wait_for(1_000_000, || read32(INTERRUPT) & (INT_DATA_DONE | INT_ERROR) != 0) {
            self.reset_lines(C1_RESET_CMD | C1_RESET_DATA);
            return Err(Error::Timeout);
        }
        write32(INTERRUPT, read32(INTERRUPT));
        Ok(())
    }
}

/// The card's size in blocks, from its CSD (bits 127..8 as the controller
/// gives them, shifted down by 8).
fn capacity(r: &[u32; 4]) -> u64 {
    let bits = |from: u32, len: u32| -> u64 {
        let mut v = 0u64;
        for i in 0..len {
            let b = from + i - 8;
            v |= ((r[(b / 32) as usize] >> (b % 32)) & 1) as u64 * (1 << i);
        }
        v
    };
    match bits(126, 2) {
        1 => (bits(48, 22) + 1) * 1024,
        _ => {
            let c_size = bits(62, 12);
            let mult = bits(47, 3);
            let read_bl_len = bits(80, 4);
            ((c_size + 1) << (mult + 2) << read_bl_len) / BLOCK as u64
        }
    }
}

impl Disk for Sd {
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), ()> {
        for (i, run) in buf.chunks_mut(MAX_RUN * BLOCK).enumerate() {
            let at = lba + (i * MAX_RUN) as u64;
            if let Err(e) = self.read_run(at, run) {
                // One retry, a block at a time.
                debug!("sd", "read failed, retrying"; lba = at, error = crate::log::dbg(&e));
                for (j, block) in run.chunks_exact_mut(BLOCK).enumerate() {
                    if let Err(e) = self.read_run(at + j as u64, block) {
                        warn!("sd", "read failed"; lba = at + j as u64, error = crate::log::dbg(&e));
                        return Err(());
                    }
                }
            }
        }
        Ok(())
    }

    fn block_size(&self) -> u32 {
        BLOCK as u32
    }

    fn blocks(&self) -> u64 {
        self.blocks
    }
}

/// `VenHw(<EMMC2>)/SD(0)`.
const EMMC2_GUID: [u8; 16] = [
    0x8d, 0x1c, 0x2e, 0x5b, 0x0e, 0x55, 0x4e, 0x5d, 0x9a, 0x3c, 0x7e, 0x34, 0x00, 0x00, 0x27, 0x11,
];

/// Find the card and publish it.
pub fn init() {
    match Sd::init() {
        Ok(sd) => {
            info!("sd", "card ready"; mib = sd.blocks * BLOCK as u64 >> 20,
                kind = if sd.high_capacity { "SDHC/SDXC" } else { "SDSC" });
            let path = Builder::new()
                .node(devpath::HARDWARE, devpath::HW_VENDOR, &EMMC2_GUID)
                .node(devpath::MESSAGING, devpath::MSG_SD, &[0])
                .done();
            crate::block::add_disk(Box::new(sd), path, "sd");
        }
        Err(e) => info!("sd", "no card"; error = crate::log::dbg(&e)),
    }
}

//! USB drives: bulk-only mass storage and SCSI commands.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::block::Disk;
use crate::util::{Hex, delay_us};
use crate::xhci::{self, Endpoint, Error};

mod uas;
use crate::{debug, info, warn};

/// The largest run one `READ(10)` moves, through the drive's DMA buffer.
const BUFFER: usize = 256 * 1024;
/// How long a drive has to answer "ready" in all: no further probe is made
/// after it.
const READY_BUDGET_US: u64 = 10_000_000;
/// How long one transfer may take before it is given up on.
const TRANSFER_US: u64 = 5_000_000;
/// Drive a drive that offers UAS through it, when the controller does streams.
pub const USE_UAS: bool = true;

pub struct UsbDisk {
    slot: u32,
    interface: u8,
    bulk_in: (u32, u32),
    bulk_out: (u32, u32),
    tag: u32,
    block_size: u32,
    blocks: u64,
    buf: u64,
    /// The pipes, on a drive driven through UAS.
    uas: Option<Pipes>,
}

/// A UAS interface's pipes: the endpoint's DCI and its max packet size each.
#[derive(Clone, Copy)]
struct Pipes {
    command: (u32, u32),
    status: (u32, u32),
    data_in: (u32, u32),
    data_out: (u32, u32),
}

impl UsbDisk {
    fn new(slot: u32, interface: u8, bulk_in: (u32, u32), bulk_out: (u32, u32), uas: Option<Pipes>, buf: u64) -> UsbDisk {
        UsbDisk { slot, interface, bulk_in, bulk_out, tag: 0, block_size: 512, blocks: 0, buf, uas }
    }
}

const CBW_SIGNATURE: u32 = 0x4342_5355;
const CSW_SIGNATURE: u32 = 0x5342_5355;

impl UsbDisk {
    fn buffer(&self) -> &'static mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.buf as *mut u8, BUFFER) }
    }

    /// One SCSI command; `len` bytes of data come back at the start of the
    /// buffer, which the command block borrows the end of.
    fn scsi(&mut self, cdb: &[u8], len: usize) -> Result<(), Error> {
        self.command(cdb, len, false)
    }

    /// One SCSI command that sends the `len` bytes at the start of the buffer.
    fn scsi_out(&mut self, cdb: &[u8], len: usize) -> Result<(), Error> {
        self.command(cdb, len, true)
    }

    fn command(&mut self, cdb: &[u8], len: usize, out: bool) -> Result<(), Error> {
        if let Some(pipes) = self.uas {
            return self.command_uas(pipes, cdb, len, out);
        }
        let x = xhci::controller();
        self.tag = self.tag.wrapping_add(1);
        let cbw_at = self.buf + (BUFFER - 64) as u64;
        let cbw = unsafe { core::slice::from_raw_parts_mut(cbw_at as *mut u8, 31) };
        cbw.fill(0);
        cbw[0..4].copy_from_slice(&CBW_SIGNATURE.to_le_bytes());
        cbw[4..8].copy_from_slice(&self.tag.to_le_bytes());
        cbw[8..12].copy_from_slice(&(len as u32).to_le_bytes());
        cbw[12] = if len > 0 && !out { 0x80 } else { 0 };
        cbw[14] = cdb.len() as u8;
        cbw[15..15 + cdb.len()].copy_from_slice(cdb);
        x.bulk(self.slot, self.bulk_out.0, cbw_at, 31, self.bulk_out.1, TRANSFER_US)?;
        if len > 0 && out {
            x.bulk(self.slot, self.bulk_out.0, self.buf, len, self.bulk_out.1, TRANSFER_US)?;
        } else if len > 0 {
            match x.bulk(self.slot, self.bulk_in.0, self.buf, len, self.bulk_in.1, TRANSFER_US) {
                Ok(_) | Err(Error::Completion(xhci::CC_STALL)) => {}
                Err(e) => return Err(e),
            }
        }
        let csw_at = self.buf + (BUFFER - 32) as u64;
        let mut r = x.bulk(self.slot, self.bulk_in.0, csw_at, 13, self.bulk_in.1, TRANSFER_US);
        if matches!(r, Err(Error::Completion(xhci::CC_STALL))) {
            r = x.bulk(self.slot, self.bulk_in.0, csw_at, 13, self.bulk_in.1, TRANSFER_US);
        }
        r?;
        let csw = unsafe { core::slice::from_raw_parts(csw_at as *const u8, 13) };
        let ok = u32::from_le_bytes(csw[0..4].try_into().unwrap()) == CSW_SIGNATURE
            && u32::from_le_bytes(csw[4..8].try_into().unwrap()) == self.tag
            && csw[12] == 0;
        if ok { Ok(()) } else { Err(Error::Completion(0x100 | csw[12] as u32)) }
    }

    fn ready(&mut self) -> bool {
        let started = crate::util::counter_us();
        for _ in 0..20 {
            if self.scsi(&[0; 6], 0).is_ok() {
                return true;
            }
            if crate::util::counter_us() - started > READY_BUDGET_US {
                break;
            }
            // REQUEST SENSE clears the unit attention a fresh drive reports.
            let _ = self.scsi(&[0x03, 0, 0, 0, 18, 0], 18);
            delay_us(50_000);
        }
        false
    }
}

impl Disk for UsbDisk {
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), ()> {
        let bs = self.block_size as usize;
        let per = BUFFER / 2 / bs;
        for (i, chunk) in buf.chunks_mut(per * bs).enumerate() {
            let at = lba + (i * per) as u64;
            let n = chunk.len() / bs;
            let cdb = if at + n as u64 > u32::MAX as u64 {
                let mut c = [0u8; 16];
                c[0] = 0x88;
                c[2..10].copy_from_slice(&at.to_be_bytes());
                c[10..14].copy_from_slice(&(n as u32).to_be_bytes());
                c.to_vec()
            } else {
                let mut c = [0u8; 10];
                c[0] = 0x28;
                c[2..6].copy_from_slice(&(at as u32).to_be_bytes());
                c[7..9].copy_from_slice(&(n as u16).to_be_bytes());
                c.to_vec()
            };
            let mut tries = 0;
            loop {
                match self.scsi(&cdb, chunk.len()) {
                    Ok(()) => break,
                    Err(e) if tries < 2 => {
                        debug!("usb", "read failed, retrying"; lba = at, error = crate::log::dbg(&e));
                        tries += 1;
                    }
                    Err(e) => {
                        warn!("usb", "read failed"; lba = at, error = crate::log::dbg(&e));
                        return Err(());
                    }
                }
            }
            chunk.copy_from_slice(&self.buffer()[..chunk.len()]);
        }
        Ok(())
    }

    fn write(&mut self, lba: u64, buf: &[u8]) -> Result<(), ()> {
        let bs = self.block_size as usize;
        let per = BUFFER / 2 / bs;
        for (i, chunk) in buf.chunks(per * bs).enumerate() {
            let at = lba + (i * per) as u64;
            let n = chunk.len() / bs;
            let cdb = if at + n as u64 > u32::MAX as u64 {
                let mut c = [0u8; 16];
                c[0] = 0x8a;
                c[2..10].copy_from_slice(&at.to_be_bytes());
                c[10..14].copy_from_slice(&(n as u32).to_be_bytes());
                c.to_vec()
            } else {
                let mut c = [0u8; 10];
                c[0] = 0x2a;
                c[2..6].copy_from_slice(&(at as u32).to_be_bytes());
                c[7..9].copy_from_slice(&(n as u16).to_be_bytes());
                c.to_vec()
            };
            self.buffer()[..chunk.len()].copy_from_slice(chunk);
            let mut tries = 0;
            loop {
                match self.scsi_out(&cdb, chunk.len()) {
                    Ok(()) => break,
                    Err(e) if tries < 2 => {
                        debug!("usb", "write failed, retrying"; lba = at, error = crate::log::dbg(&e));
                        tries += 1;
                    }
                    Err(e) => {
                        warn!("usb", "write failed"; lba = at, error = crate::log::dbg(&e));
                        return Err(());
                    }
                }
            }
        }
        // SYNCHRONIZE CACHE: what the drive holds in its own cache is on the
        // medium before this returns.
        let _ = self.scsi(&[0x35, 0, 0, 0, 0, 0, 0, 0, 0, 0], 0);
        Ok(())
    }

    fn block_size(&self) -> u32 {
        self.block_size
    }

    fn blocks(&self) -> u64 {
        self.blocks
    }
}

fn dci(address: u8) -> u32 {
    2 * (address & 0xf) as u32 + (address >> 7) as u32
}

/// Set up a bulk-only mass storage interface and publish the drive.
pub fn attach(slot: u32, interface: u8, eps: &[Endpoint], path: Vec<u8>, vendor: u16, product: u16) {
    let bulk = |dir: u8| eps.iter().find(|e| e.attributes & 3 == 2 && e.address & 0x80 == dir).copied();
    let (Some(i), Some(o)) = (bulk(0x80), bulk(0)) else {
        warn!("usb", "drive without bulk endpoints"; slot = slot);
        return;
    };
    let x = xhci::controller();
    if x.configure_endpoints(slot, &[i, o], false).is_err() {
        warn!("usb", "drive's endpoints could not be set up"; slot = slot);
        return;
    }
    let Some((buf, _)) = xhci::dma_buffer(BUFFER) else {
        warn!("usb", "no DMA memory for the drive"; slot = slot);
        return;
    };
    let disk = UsbDisk::new(slot, interface, (dci(i.address), i.max_packet as u32 & 0x7ff), (dci(o.address), o.max_packet as u32 & 0x7ff), None, buf);
    finish(disk, path, vendor, product);
}

/// Set up the UAS alternate setting of an interface and publish the drive:
/// the endpoints by their pipe IDs (1 command, 2 status, 3 data in, 4 data
/// out), the three that are not the command pipe with streams.
pub fn attach_uas(slot: u32, interface: u8, eps: &[Endpoint], path: Vec<u8>, vendor: u16, product: u16) {
    let pipe = |id: u8| eps.iter().find(|e| e.pipe == id).copied();
    let (Some(command), Some(status), Some(data_in), Some(data_out)) = (pipe(1), pipe(2), pipe(3), pipe(4)) else {
        warn!("usb", "UAS interface without its four pipes"; slot = slot);
        return;
    };
    let x = xhci::controller();
    if x.configure_endpoints(slot, &[command, status, data_in, data_out], true).is_err() {
        warn!("usb", "UAS endpoints could not be set up"; slot = slot);
        return;
    }
    let Some((buf, _)) = xhci::dma_buffer(BUFFER) else {
        warn!("usb", "no DMA memory for the drive"; slot = slot);
        return;
    };
    let mps = |e: Endpoint| (dci(e.address), e.max_packet as u32 & 0x7ff);
    let pipes = Pipes { command: mps(command), status: mps(status), data_in: mps(data_in), data_out: mps(data_out) };
    let disk = UsbDisk::new(slot, interface, mps(data_in), mps(data_out), Some(pipes), buf);
    finish(disk, path, vendor, product);
}

/// Probe a drive on whichever transport it was set up with and publish it.
fn finish(mut disk: UsbDisk, path: Vec<u8>, vendor: u16, product: u16) {
    let slot = disk.slot;
    if disk.scsi(&[0x12, 0, 0, 0, 36, 0], 36).is_err() || disk.buffer()[0] & 0x1f != 0 {
        info!("usb", "storage device is not a disk"; vendor = Hex(vendor), product = Hex(product));
        return;
    }
    if !disk.ready() {
        warn!("usb", "drive never became ready"; vendor = Hex(vendor), product = Hex(product));
        return;
    }
    if disk.scsi(&[0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0], 8).is_err() {
        warn!("usb", "drive did not say its size"; slot = slot);
        return;
    }
    let b = disk.buffer();
    let last = u32::from_be_bytes(b[0..4].try_into().unwrap()) as u64;
    disk.block_size = u32::from_be_bytes(b[4..8].try_into().unwrap());
    disk.blocks = last + 1;
    if last == u32::MAX as u64 {
        let mut cdb = [0u8; 16];
        cdb[0] = 0x9e;
        cdb[1] = 0x10;
        cdb[13] = 32;
        if disk.scsi(&cdb, 32).is_ok() {
            let b = disk.buffer();
            disk.blocks = u64::from_be_bytes(b[0..8].try_into().unwrap()).saturating_add(1);
            disk.block_size = u32::from_be_bytes(b[8..12].try_into().unwrap());
        }
    }
    if !(512..=4096).contains(&disk.block_size) || !disk.block_size.is_power_of_two() {
        warn!("usb", "drive has a block size this firmware cannot use"; block_size = disk.block_size);
        return;
    }
    crate::block::add_disk(Box::new(disk), path, "usb");
}

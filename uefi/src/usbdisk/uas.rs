//! USB Attached SCSI: one command at a time, on stream 1.
//!
//! The command goes to the command pipe as a 32-byte command IU. The device
//! answers on the status pipe, stream 1, with a read or write ready IU when
//! it wants to move data and with a sense IU at the end; the data moves on the
//! data pipe, stream 1. A write's data is queued when the write ready IU
//! arrives, a read's with the command.

use super::{BUFFER, Pipes, TRANSFER_US, UsbDisk};
use crate::util::Hex;
use crate::warn;
use crate::xhci::{self, CC_SHORT_PACKET, CC_SUCCESS, Error};

const IU_COMMAND: u8 = 0x01;
const IU_SENSE: u8 = 0x03;
const IU_READ_READY: u8 = 0x06;
const IU_WRITE_READY: u8 = 0x07;
/// The command tag, and so the stream, of every command.
const TAG: u16 = 1;
/// Room for a status IU: 16 bytes and the sense data.
const STATUS_BYTES: usize = 128;

impl UsbDisk {
    pub(super) fn command_uas(&mut self, pipes: Pipes, cdb: &[u8], len: usize, out: bool) -> Result<(), Error> {
        let result = self.run_uas(pipes, cdb, len, out);
        if matches!(result, Err(Error::Timeout)) {
            warn!("usb", "UAS command did not finish"; slot = self.slot, opcode = Hex(cdb[0]));
            self.recover_uas(pipes);
        }
        result
    }

    fn run_uas(&mut self, pipes: Pipes, cdb: &[u8], len: usize, out: bool) -> Result<(), Error> {
        let x = xhci::controller();
        let slot = self.slot;
        let command_at = self.buf + (BUFFER - 128) as u64;
        let status_at = self.buf + (BUFFER - 512) as u64;
        let iu = unsafe { core::slice::from_raw_parts_mut(command_at as *mut u8, 32) };
        iu.fill(0);
        iu[0] = IU_COMMAND;
        iu[2..4].copy_from_slice(&TAG.to_be_bytes());
        iu[16..16 + cdb.len()].copy_from_slice(cdb);

        let mut status = x.queue_stream(slot, pipes.status.0, status_at, STATUS_BYTES, pipes.status.1);
        let mut data = None;
        if len > 0 && !out {
            data = Some(x.queue_stream(slot, pipes.data_in.0, self.buf, len, pipes.data_in.1));
            x.doorbell(slot, pipes.data_in.0, TAG as u32);
        }
        x.doorbell(slot, pipes.status.0, TAG as u32);
        let command = x.queue(slot, pipes.command.0, command_at, 32, pipes.command.1);
        x.doorbell(slot, pipes.command.0, 0);

        let (mut sent, mut moved, mut sense) = (false, len == 0, None);
        while !(sent && moved && sense.is_some()) {
            let (at, code, _) = x.wait_transfer(slot, TRANSFER_US)?;
            let finished = code == CC_SUCCESS || code == CC_SHORT_PACKET;
            if at == command {
                if code != CC_SUCCESS {
                    return Err(Error::Completion(code));
                }
                sent = true;
            } else if at == status {
                if !finished {
                    return Err(Error::Completion(code));
                }
                let bytes = unsafe { core::slice::from_raw_parts(status_at as *const u8, STATUS_BYTES) };
                match bytes[0] {
                    IU_SENSE => sense = Some(bytes[6]),
                    IU_READ_READY | IU_WRITE_READY => {
                        if bytes[0] == IU_WRITE_READY && out && len > 0 && data.is_none() {
                            data = Some(x.queue_stream(slot, pipes.data_out.0, self.buf, len, pipes.data_out.1));
                            x.doorbell(slot, pipes.data_out.0, TAG as u32);
                        }
                        status = x.queue_stream(slot, pipes.status.0, status_at, STATUS_BYTES, pipes.status.1);
                        x.doorbell(slot, pipes.status.0, TAG as u32);
                    }
                    other => return Err(Error::Completion(0x200 | other as u32)),
                }
            } else if Some(at) == data {
                if !finished {
                    return Err(Error::Completion(code));
                }
                moved = true;
            }
        }
        match sense {
            Some(0) => Ok(()),
            Some(status) => Err(Error::Completion(0x100 | status as u32)),
            None => Err(Error::Timeout),
        }
    }

    /// After a command that never finished: put the streams of the status and
    /// data pipes, and the command pipe, back.
    pub(super) fn recover_uas(&mut self, pipes: Pipes) {
        let x = xhci::controller();
        for dci in [pipes.status.0, pipes.data_in.0, pipes.data_out.0] {
            x.reset_stream_endpoint(self.slot, dci);
        }
        x.reset_endpoint(self.slot, pipes.command.0);
    }
}

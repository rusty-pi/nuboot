//! The VL805's xHCI controller behind the PCIe root complex, and the USB
//! devices on it: hubs, and drives (bulk-only mass storage, `usbdisk.rs`).
//! Keyboards and everything else are left alone: the console is the serial
//! port.
//!
//! `start4.elf` has brought the PCIe link up, given the VL805 its firmware
//! and put the controller's registers in the outbound window. Everything the
//! controller reads or writes lives in the DMA arena, which no cache sits in
//! front of. One transfer is in flight at a time, and nothing interrupts:
//! every wait polls the event ring.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::devpath::{self, Builder};
use crate::util::{Global, Hex, POLL_US, counter_us, delay_us, read32, wait_for, write32};
use crate::{debug, dma, info, warn};

const PCIE: u64 = 0xFD50_0000;
const EXT_CFG_DATA: u64 = PCIE + 0x8000;
const EXT_CFG_INDEX: u64 = PCIE + 0x9000;
/// Bus addresses `0x8000_0000..0xC000_0000` are ARM physical
/// `0x6_0000_0000..`; the inbound window shows the first 3 GiB of RAM at bus
/// address 0 as it is, and the DMA arena is in it.
const WINDOW_BUS: u64 = 0x8000_0000;
const WINDOW_CPU: u64 = 0x6_0000_0000;
const WINDOW_SIZE: u64 = 0x4000_0000;

/// The buses the VL805 answers on through the config window: behind the root
/// port, which is where the model puts it, and a Raspberry Pi 4B's own
/// answer, bus 0.
const ENDPOINT_BUSES: [u32; 2] = [1, 0];

static ENDPOINT_BUS: AtomicU32 = AtomicU32::new(ENDPOINT_BUSES[0]);

/// Config space of the one function the window shows, the VL805.
fn cfg(offset: u64) -> u64 {
    write32(EXT_CFG_INDEX, ENDPOINT_BUS.load(Ordering::Relaxed) << 20);
    let _ = read32(EXT_CFG_INDEX);
    EXT_CFG_DATA + offset
}

/// The controller's registers, if the VL805 is there.
fn registers() -> Option<u64> {
    let bus = ENDPOINT_BUSES.into_iter().find(|&bus| {
        ENDPOINT_BUS.store(bus, Ordering::Relaxed);
        let id = read32(cfg(0));
        id != 0 && id != u32::MAX && read32(cfg(8)) >> 8 == 0x0c_0330
    })?;
    ENDPOINT_BUS.store(bus, Ordering::Relaxed);
    let lo = read32(cfg(0x10));
    let hi = if lo & 0x6 == 0x4 { read32(cfg(0x14)) } else { 0 };
    let bar = (hi as u64) << 32 | (lo & !0xf) as u64;
    if !(WINDOW_BUS..WINDOW_BUS + WINDOW_SIZE).contains(&bar) {
        return None;
    }
    // Memory space and bus mastering.
    write32(cfg(4), read32(cfg(4)) | 0x6);
    Some(bar - WINDOW_BUS + WINDOW_CPU)
}

// Operational registers.
const USBCMD: u64 = 0x00;
const USBSTS: u64 = 0x04;
const CRCR: u64 = 0x18;
const DCBAAP: u64 = 0x30;
const CONFIG: u64 = 0x38;
const PORTSC: u64 = 0x400;

const CMD_RS: u32 = 1 << 0;
const CMD_HCRST: u32 = 1 << 1;
const STS_HCH: u32 = 1 << 0;
const STS_CNR: u32 = 1 << 11;

const PORT_CCS: u32 = 1 << 0;
const PORT_PED: u32 = 1 << 1;
const PORT_PR: u32 = 1 << 4;
const PORT_PP: u32 = 1 << 9;
const PORT_PRC: u32 = 1 << 21;
/// The bits a write must not set back: the change bits (write 1 to clear)
/// and port enabled (write 1 to disable).
const PORT_KEEP_MASK: u32 = !(PORT_PED | 0x00fe_0000);

const TRB_NORMAL: u32 = 1;
const TRB_SETUP: u32 = 2;
const TRB_DATA: u32 = 3;
const TRB_STATUS: u32 = 4;
const TRB_LINK: u32 = 6;
const TRB_ENABLE_SLOT: u32 = 9;
const TRB_ADDRESS_DEVICE: u32 = 11;
const TRB_CONFIGURE_ENDPOINT: u32 = 12;
const TRB_EVALUATE_CONTEXT: u32 = 13;
const TRB_RESET_ENDPOINT: u32 = 14;
const TRB_SET_TR_DEQUEUE: u32 = 16;
const EVENT_TRANSFER: u32 = 32;
const EVENT_COMMAND: u32 = 33;

const TRB_ISP: u32 = 1 << 2;
const TRB_CHAIN: u32 = 1 << 4;
const TRB_IOC: u32 = 1 << 5;
const TRB_IDT: u32 = 1 << 6;
const TRB_DIR_IN: u32 = 1 << 16;

pub const CC_SUCCESS: u32 = 1;
pub const CC_STALL: u32 = 6;
pub const CC_SHORT_PACKET: u32 = 13;

pub const SPEED_FULL: u32 = 1;
pub const SPEED_LOW: u32 = 2;
pub const SPEED_HIGH: u32 = 3;
pub const SPEED_SUPER: u32 = 4;

const RING_TRBS: usize = 256;
/// How long a SuperSpeed root port may take to show its device after the
/// controller's reset: it reads empty until its link has trained.
const LINK_TRAIN_US: u64 = 400_000;

struct Ring {
    base: u64,
    index: usize,
    cycle: u32,
}

impl Ring {
    fn new() -> Option<Ring> {
        let base = dma::alloc(RING_TRBS * 16, 64)?;
        Some(Ring { base, index: 0, cycle: 1 })
    }

    fn trb(&self, i: usize) -> *mut u32 {
        (self.base + i as u64 * 16) as *mut u32
    }

    /// Put a TRB on the ring, its cycle bit last; where it went.
    fn push(&mut self, t: [u32; 4]) -> u64 {
        let p = self.trb(self.index);
        let at = p as u64;
        unsafe {
            p.write_volatile(t[0]);
            p.add(1).write_volatile(t[1]);
            p.add(2).write_volatile(t[2]);
            core::arch::asm!("dmb oshst");
            p.add(3).write_volatile(t[3] & !1 | self.cycle);
        }
        self.index += 1;
        if self.index == RING_TRBS - 1 {
            let link = self.trb(self.index);
            unsafe {
                link.write_volatile(self.base as u32);
                link.add(1).write_volatile((self.base >> 32) as u32);
                link.add(2).write_volatile(0);
                core::arch::asm!("dmb oshst");
                // Toggle cycle; chained if the TD goes on past it.
                link.add(3).write_volatile(TRB_LINK << 10 | 1 << 1 | (t[3] & TRB_CHAIN) | self.cycle);
            }
            self.index = 0;
            self.cycle ^= 1;
        }
        at
    }

    /// The dequeue pointer a `Set TR Dequeue Pointer` puts the ring back to.
    fn enqueue_pointer(&self) -> u64 {
        self.base + self.index as u64 * 16 | self.cycle as u64
    }
}

/// A USB device the controller has an address for.
pub struct Device {
    pub slot: u32,
    pub speed: u32,
    input: u64,
    output: u64,
    ep0: Ring,
    rings: [Option<Ring>; 32],
}

pub struct Xhci {
    op: u64,
    runtime: u64,
    doorbells: u64,
    max_ports: u32,
    commands: Ring,
    events: u64,
    event_index: usize,
    event_cycle: u32,
    dcbaa: u64,
    /// A buffer for control transfers' data.
    pub control_buf: u64,
    pub devices: Vec<Box<Device>>,
    started_at: u64,
}

const EVENT_TRBS: usize = 256;
const CONTROL_BUF: usize = 4096;
/// How long after the controller started a new device is still brought up: a
/// hub or a drive that answers slowly, or not at all, is not followed by more
/// of them past it. What is under way ends by its own timeouts. The boot
/// watchdog allows 300 s.
const ENUMERATION_BUDGET_US: u64 = 60_000_000;
/// The most ports of a hub that are used, however many its descriptor claims.
const MAX_HUB_PORTS: u32 = 15;

static XHCI: Global<Option<Xhci>> = Global::new(None);
static REGISTERS: Global<Option<u64>> = Global::new(None);

/// Where the controller's registers are, when the VL805 is on the bus.
pub fn registers_base() -> Option<u64> {
    *REGISTERS.get()
}

pub fn controller() -> &'static mut Xhci {
    XHCI.get().as_mut().unwrap()
}

#[derive(Debug, Clone, Copy)]
pub enum Error {
    Timeout,
    /// A completion code other than success.
    Completion(u32),
    NoMemory,
}

impl Xhci {
    fn op_read(&self, r: u64) -> u32 {
        read32(self.op + r)
    }

    fn op_write(&self, r: u64, v: u32) {
        write32(self.op + r, v)
    }

    fn portsc(&self, port: u32) -> u32 {
        self.op_read(PORTSC + 0x10 * (port as u64 - 1))
    }

    fn set_portsc(&self, port: u32, v: u32) {
        self.op_write(PORTSC + 0x10 * (port as u64 - 1), v)
    }

    fn ring_doorbell(&self, slot: u32, target: u32) {
        unsafe { core::arch::asm!("dsb sy") };
        write32(self.doorbells + 4 * slot as u64, target);
    }

    fn init(base: u64) -> Result<Xhci, Error> {
        let caplength = read32(base) & 0xff;
        let hcs1 = read32(base + 4);
        let hcs2 = read32(base + 8);
        let op = base + caplength as u64;
        let runtime = base + (read32(base + 0x18) & !0x1f) as u64;
        let doorbells = base + (read32(base + 0x14) & !0x3) as u64;
        let max_slots = (hcs1 & 0xff).min(16);
        let max_ports = (hcs1 >> 24) & 0xff;
        let scratchpads = ((hcs2 >> 21) & 0x1f) << 5 | (hcs2 >> 27) & 0x1f;

        write32(op + USBCMD, read32(op + USBCMD) & !CMD_RS);
        if !wait_for(100_000, || read32(op + USBSTS) & STS_HCH != 0) {
            return Err(Error::Timeout);
        }
        write32(op + USBCMD, CMD_HCRST);
        if !wait_for(1_000_000, || read32(op + USBCMD) & CMD_HCRST == 0 && read32(op + USBSTS) & STS_CNR == 0) {
            return Err(Error::Timeout);
        }

        let dcbaa = dma::alloc((max_slots as usize + 1) * 8, 64).ok_or(Error::NoMemory)?;
        if scratchpads > 0 {
            let array = dma::alloc(scratchpads as usize * 8, 64).ok_or(Error::NoMemory)?;
            for i in 0..scratchpads as u64 {
                let page = dma::alloc(4096, 4096).ok_or(Error::NoMemory)?;
                unsafe { ((array + 8 * i) as *mut u64).write_volatile(page) };
            }
            unsafe { (dcbaa as *mut u64).write_volatile(array) };
        }
        let commands = Ring::new().ok_or(Error::NoMemory)?;
        let events = dma::alloc(EVENT_TRBS * 16, 64).ok_or(Error::NoMemory)?;
        let erst = dma::alloc(16, 64).ok_or(Error::NoMemory)?;
        unsafe {
            (erst as *mut u64).write_volatile(events);
            ((erst + 8) as *mut u32).write_volatile(EVENT_TRBS as u32);
        }
        let control_buf = dma::alloc(CONTROL_BUF, 64).ok_or(Error::NoMemory)?;

        write32(op + CONFIG, max_slots);
        write32(op + DCBAAP, dcbaa as u32);
        write32(op + DCBAAP + 4, (dcbaa >> 32) as u32);
        write32(op + CRCR, commands.base as u32 | 1);
        write32(op + CRCR + 4, (commands.base >> 32) as u32);
        // Interrupter 0: one event ring segment, polled.
        let ir = runtime + 0x20;
        write32(ir + 0x08, 1);
        write32(ir + 0x18, events as u32);
        write32(ir + 0x1c, (events >> 32) as u32);
        write32(ir + 0x10, erst as u32);
        write32(ir + 0x14, (erst >> 32) as u32);

        write32(op + USBCMD, CMD_RS);
        if !wait_for(100_000, || read32(op + USBSTS) & STS_HCH == 0) {
            return Err(Error::Timeout);
        }
        let xhci = Xhci {
            op,
            runtime,
            doorbells,
            max_ports,
            commands,
            events,
            event_index: 0,
            event_cycle: 1,
            dcbaa,
            control_buf,
            devices: Vec::new(),
            started_at: counter_us(),
        };
        for port in 1..=max_ports {
            let sc = xhci.portsc(port);
            if sc & PORT_PP == 0 {
                xhci.set_portsc(port, sc & PORT_KEEP_MASK | PORT_PP);
            }
        }
        Ok(xhci)
    }

    fn next_event(&mut self) -> Option<[u32; 4]> {
        let p = (self.events + self.event_index as u64 * 16) as *const u32;
        let dw3 = unsafe { p.add(3).read_volatile() };
        if dw3 & 1 != self.event_cycle {
            return None;
        }
        let e = unsafe { [p.read_volatile(), p.add(1).read_volatile(), p.add(2).read_volatile(), dw3] };
        self.event_index += 1;
        if self.event_index == EVENT_TRBS {
            self.event_index = 0;
            self.event_cycle ^= 1;
        }
        let erdp = self.events + self.event_index as u64 * 16;
        let ir = self.runtime + 0x20;
        write32(ir + 0x18, erdp as u32 | 1 << 3);
        write32(ir + 0x1c, (erdp >> 32) as u32);
        Some(e)
    }

    fn wait_event(&mut self, timeout_us: u64, want: impl Fn(&[u32; 4]) -> bool) -> Result<[u32; 4], Error> {
        let until = crate::util::Deadline::after_us(timeout_us);
        loop {
            while let Some(e) = self.next_event() {
                if want(&e) {
                    return Ok(e);
                }
            }
            if until.passed() {
                return Err(Error::Timeout);
            }
            delay_us(POLL_US);
        }
    }

    /// Run a command; the completion event's last word (the slot ID is in its
    /// top byte).
    fn command(&mut self, t: [u32; 4]) -> Result<u32, Error> {
        let at = self.commands.push(t);
        self.ring_doorbell(0, 0);
        let e = self.wait_event(1_000_000, |e| {
            (e[3] >> 10) & 0x3f == EVENT_COMMAND && (e[0] as u64 | (e[1] as u64) << 32) == at
        })?;
        match e[2] >> 24 {
            CC_SUCCESS => Ok(e[3]),
            cc => Err(Error::Completion(cc)),
        }
    }

    fn device(&mut self, slot: u32) -> &mut Device {
        self.devices.iter_mut().find(|d| d.slot == slot).unwrap()
    }

    /// Wait for the transfer event of the TD on `slot`'s endpoint `dci`
    /// ending at `last`; the bytes not transferred.
    fn transfer_done(&mut self, slot: u32, dci: u32, last: u64, timeout_us: u64) -> Result<u32, Error> {
        let e = self.wait_event(timeout_us, |e| {
            (e[3] >> 10) & 0x3f == EVENT_TRANSFER && e[3] >> 24 == slot && (e[3] >> 16) & 0x1f == dci
        })?;
        let cc = e[2] >> 24;
        let residue = e[2] & 0xff_ffff;
        let at = e[0] as u64 | (e[1] as u64) << 32;
        match cc {
            CC_SUCCESS if at == last => Ok(residue),
            // A short packet ends the TD early; its IOC event never comes.
            CC_SHORT_PACKET => Ok(residue),
            CC_SUCCESS => self.transfer_done(slot, dci, last, timeout_us),
            cc => {
                if cc == CC_STALL {
                    self.recover(slot, dci);
                }
                Err(Error::Completion(cc))
            }
        }
    }

    /// Bring a halted endpoint back: reset it, and point it past the TD that
    /// stalled.
    fn recover(&mut self, slot: u32, dci: u32) {
        let _ = self.command([0, 0, 0, TRB_RESET_ENDPOINT << 10 | dci << 16 | slot << 24]);
        let deq = {
            let d = self.device(slot);
            if dci == 1 { d.ep0.enqueue_pointer() } else { d.rings[dci as usize].as_ref().unwrap().enqueue_pointer() }
        };
        let _ = self.command([deq as u32, (deq >> 32) as u32, 0, TRB_SET_TR_DEQUEUE << 10 | dci << 16 | slot << 24]);
    }

    /// A control transfer on endpoint 0, its data through `control_buf`.
    pub fn control(&mut self, slot: u32, request_type: u8, request: u8, value: u16, index: u16, len: u16) -> Result<(), Error> {
        let len = len.min(CONTROL_BUF as u16);
        let input = request_type & 0x80 != 0;
        let trt = match (len, input) {
            (0, _) => 0,
            (_, true) => 3,
            (_, false) => 2,
        };
        let buf = self.control_buf;
        let d = self.device(slot);
        d.ep0.push([
            request_type as u32 | (request as u32) << 8 | (value as u32) << 16,
            index as u32 | (len as u32) << 16,
            8,
            TRB_SETUP << 10 | TRB_IDT | trt << 16,
        ]);
        if len > 0 {
            d.ep0.push([buf as u32, (buf >> 32) as u32, len as u32, TRB_DATA << 10 | if input { TRB_DIR_IN } else { 0 }]);
        }
        let status_in = len == 0 || !input;
        let last = d.ep0.push([0, 0, 0, TRB_STATUS << 10 | TRB_IOC | if status_in { TRB_DIR_IN } else { 0 }]);
        self.ring_doorbell(slot, 1);
        self.transfer_done(slot, 1, last, 1_000_000).map(|_| ())
    }

    /// The bytes of `control_buf`.
    pub fn control_data(&self, len: usize) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.control_buf as *const u8, len) }
    }

    fn get_descriptor(&mut self, slot: u32, ty: u8, index: u8, len: u16) -> Result<Vec<u8>, Error> {
        self.control(slot, 0x80, 6, (ty as u16) << 8 | index as u16, 0, len)?;
        Ok(self.control_data((len as usize).min(CONTROL_BUF as usize)).to_vec())
    }

    /// A bulk transfer of `len` bytes at DMA address `buf` on endpoint `dci`;
    /// the bytes not transferred.
    pub fn bulk(&mut self, slot: u32, dci: u32, buf: u64, len: usize, max_packet: u32) -> Result<u32, Error> {
        let input = dci & 1 == 1;
        let ring = self.device(slot).rings[dci as usize].as_mut().unwrap();
        let mut at = 0usize;
        let last = loop {
            // A TRB must not cross a 64 KiB boundary.
            let addr = buf + at as u64;
            let n = ((0x1_0000 - (addr & 0xffff)) as usize).min(len - at);
            let end = at + n == len;
            let td_size = (((len - at - n) as u32).div_ceil(max_packet.max(1))).min(31);
            let trb = ring.push([
                addr as u32,
                (addr >> 32) as u32,
                n as u32 | td_size << 17,
                TRB_NORMAL << 10 | if input { TRB_ISP } else { 0 } | if end { TRB_IOC } else { TRB_CHAIN },
            ]);
            at += n;
            if end {
                break trb;
            }
        };
        self.ring_doorbell(slot, dci);
        self.transfer_done(slot, dci, last, 5_000_000)
    }

    /// Give a device an address, and endpoint 0 the packet size it says.
    /// `tt`: the hub a full- or low-speed device's transactions are
    /// translated by, and the port on it.
    fn address(&mut self, root_port: u32, route: u32, speed: u32, tt: (u32, u32)) -> Result<u32, Error> {
        let slot = self.command([0, 0, 0, TRB_ENABLE_SLOT << 10])? >> 24;
        let output = dma::alloc(1024, 64).ok_or(Error::NoMemory)?;
        let input = dma::alloc(1056, 64).ok_or(Error::NoMemory)?;
        unsafe { ((self.dcbaa + 8 * slot as u64) as *mut u64).write_volatile(output) };
        let ep0 = Ring::new().ok_or(Error::NoMemory)?;
        let mps = match speed {
            SPEED_SUPER => 512,
            SPEED_HIGH => 64,
            _ => 8,
        };
        let w = |off: u64, v: u32| unsafe { ((input + off) as *mut u32).write_volatile(v) };
        w(0x04, 0b11);
        w(0x20, route | speed << 20 | 1 << 27);
        w(0x24, root_port << 16);
        w(0x28, tt.0 | tt.1 << 8);
        w(0x44, 3 << 1 | 4 << 3 | mps << 16);
        w(0x48, ep0.base as u32 | 1);
        w(0x4c, (ep0.base >> 32) as u32);
        w(0x50, 8);
        self.devices.push(Box::new(Device {
            slot,
            speed,
            input,
            output,
            ep0,
            rings: [const { None }; 32],
        }));
        self.command([input as u32, (input >> 32) as u32, 0, TRB_ADDRESS_DEVICE << 10 | slot << 24])?;
        // Some hubs fail a request sent sooner than 10 ms after SET_ADDRESS.
        delay_us(10_000);
        let head = self.get_descriptor(slot, 1, 0, 8)?;
        let real = head[7] as u32;
        if speed != SPEED_SUPER && real != mps && real != 0 {
            w(0x04, 0b10);
            w(0x44, 3 << 1 | 4 << 3 | real << 16);
            self.command([input as u32, (input >> 32) as u32, 0, TRB_EVALUATE_CONTEXT << 10 | slot << 24])?;
        }
        Ok(slot)
    }

    /// Add endpoints to a configured device: (address, attributes, max
    /// packet size, interval) each.
    pub fn configure_endpoints(&mut self, slot: u32, eps: &[(u8, u8, u16, u8)]) -> Result<(), Error> {
        let (input, output, speed) = {
            let d = self.device(slot);
            (d.input, d.output, d.speed)
        };
        unsafe { core::ptr::write_bytes(input as *mut u8, 0, 1056) };
        let w = |off: u64, v: u32| unsafe { ((input + off) as *mut u32).write_volatile(v) };
        // The slot context as the device has it, with the last endpoint.
        for i in 0..8 {
            w(0x20 + 4 * i, unsafe { ((output + 4 * i) as *const u32).read_volatile() });
        }
        w(0x2c, 0);
        let mut add = 1u32;
        let mut last = 1;
        for &(addr, attrs, mps, interval) in eps {
            let dci = 2 * (addr & 0xf) as u32 + (addr >> 7) as u32;
            if dci < 2 || mps & 0x7ff == 0 {
                return Err(Error::Completion(0));
            }
            let ty = (attrs & 3) as u32 + if addr & 0x80 != 0 { 4 } else { 0 };
            let ring = Ring::new().ok_or(Error::NoMemory)?;
            let ctx = 0x20 + 0x20 * dci as u64;
            let interval = match (attrs & 3, speed) {
                (3, SPEED_HIGH | SPEED_SUPER) => (interval as u32).saturating_sub(1),
                (3, _) => 3 + (interval as u32).max(1).ilog2(),
                _ => 0,
            };
            w(ctx, interval << 16);
            w(ctx + 4, 3 << 1 | ty << 3 | (mps as u32 & 0x7ff) << 16);
            w(ctx + 8, ring.base as u32 | 1);
            w(ctx + 12, (ring.base >> 32) as u32);
            w(ctx + 16, if attrs & 3 == 3 { 8 } else { 1024 });
            self.device(slot).rings[dci as usize] = Some(ring);
            add |= 1 << dci;
            last = last.max(dci);
        }
        let dw0 = unsafe { ((input + 0x20) as *const u32).read_volatile() };
        w(0x20, dw0 & !(0x1f << 27) | last << 27);
        w(0x04, add);
        self.command([input as u32, (input >> 32) as u32, 0, TRB_CONFIGURE_ENDPOINT << 10 | slot << 24]).map(|_| ())
    }

    /// Mark a device a hub with `ports` ports, for the transaction
    /// translators of what is behind it.
    fn make_hub(&mut self, slot: u32, ports: u32, multi_tt: bool) -> Result<(), Error> {
        let (input, output) = {
            let d = self.device(slot);
            (d.input, d.output)
        };
        unsafe { core::ptr::write_bytes(input as *mut u8, 0, 1056) };
        let r = |off: u64| unsafe { ((output + off) as *const u32).read_volatile() };
        let w = |off: u64, v: u32| unsafe { ((input + off) as *mut u32).write_volatile(v) };
        w(0x04, 1);
        w(0x20, r(0) | 1 << 26 | if multi_tt { 1 << 25 } else { 0 });
        w(0x24, r(4) & 0x00ff_ffff | ports << 24);
        w(0x28, r(8));
        self.command([input as u32, (input >> 32) as u32, 0, TRB_EVALUATE_CONTEXT << 10 | slot << 24]).map(|_| ())
    }

    pub fn stop(&mut self) {
        self.op_write(USBCMD, self.op_read(USBCMD) & !CMD_RS);
        wait_for(100_000, || self.op_read(USBSTS) & STS_HCH != 0);
    }
}

/// The parts of a configuration descriptor this firmware looks at.
pub struct Config {
    pub value: u8,
    pub interfaces: Vec<Interface>,
}

pub struct Interface {
    pub class: (u8, u8, u8),
    /// (address, attributes, max packet size, interval)
    pub endpoints: Vec<(u8, u8, u16, u8)>,
}

fn parse_config(c: &[u8]) -> Config {
    let mut config = Config { value: c.get(5).copied().unwrap_or(1), interfaces: Vec::new() };
    let mut at = 0;
    while at + 2 <= c.len() {
        let len = c[at] as usize;
        if len < 2 || at + len > c.len() {
            break;
        }
        let d = &c[at..at + len];
        match d[1] {
            4 if len >= 9 => config.interfaces.push(Interface { class: (d[5], d[6], d[7]), endpoints: Vec::new() }),
            5 if len >= 7 => {
                if let Some(i) = config.interfaces.last_mut() {
                    i.endpoints.push((d[2], d[3], u16::from_le_bytes([d[4], d[5]]), d[6]));
                }
            }
            _ => {}
        }
        at += len;
    }
    config
}

fn speed_name(speed: u32) -> &'static str {
    match speed {
        SPEED_LOW => "low",
        SPEED_FULL => "full",
        SPEED_HIGH => "high",
        _ => "super",
    }
}

fn usb_node(path: &[u8], port: u32) -> Vec<u8> {
    Builder::from(path).node(devpath::MESSAGING, devpath::MSG_USB, &[port as u8 - 1, 0]).done()
}

/// Bring up the device behind `root_port` (and `route` for one behind
/// hubs), and whatever is behind it if it is a hub.
fn enumerate(root_port: u32, route: u32, depth: u32, speed: u32, tt: (u32, u32), path: Vec<u8>) {
    let x = controller();
    if counter_us() - x.started_at > ENUMERATION_BUDGET_US {
        warn!("usb", "enumeration out of time, device left alone"; root_port = root_port, route = Hex(route));
        return;
    }
    let slot = match x.address(root_port, route, speed, tt) {
        Ok(s) => s,
        Err(e) => {
            warn!("usb", "device did not take an address"; root_port = root_port, route = Hex(route),
                error = crate::log::dbg(&e));
            return;
        }
    };
    let described = x.get_descriptor(slot, 1, 0, 18).and_then(|dev| {
        let head = x.get_descriptor(slot, 2, 0, 9)?;
        let total = u16::from_le_bytes([head[2], head[3]]);
        Ok((dev, x.get_descriptor(slot, 2, 0, total)?))
    });
    let (dev, mut config) = match described {
        Ok((dev, c)) => (dev, parse_config(&c)),
        Err(e) => {
            warn!("usb", "device did not describe itself"; slot = slot, error = crate::log::dbg(&e));
            return;
        }
    };
    let (vendor, product) = (u16::from_le_bytes([dev[8], dev[9]]), u16::from_le_bytes([dev[10], dev[11]]));
    let is_hub = dev[4] == 9 || config.interfaces.first().is_some_and(|i| i.class.0 == 9);
    let storage = config.interfaces.iter().position(|i| i.class == (8, 6, 0x50));
    debug!("usb", "device found"; slot = slot, speed = speed_name(speed), vendor = Hex(vendor), product = Hex(product),
        class = Hex(dev[4]));
    if x.control(slot, 0, 9, config.value as u16, 0, 0).is_err() {
        warn!("usb", "device did not take its configuration"; slot = slot);
        return;
    }
    if is_hub {
        if speed == SPEED_SUPER {
            info!("usb", "SuperSpeed hub left alone, its USB 2 half is used"; slot = slot);
            return;
        }
        hub(slot, root_port, route, depth, speed, tt, path, dev[6] == 2);
    } else if let Some(i) = storage {
        let eps = config.interfaces.swap_remove(i).endpoints;
        crate::usbdisk::attach(slot, i as u8, &eps, path, vendor, product);
    } else {
        info!("usb", "device ignored"; vendor = Hex(vendor), product = Hex(product), class = Hex(dev[4]));
    }
}

/// The ports of a USB 2 hub.
#[allow(clippy::too_many_arguments)]
fn hub(slot: u32, root_port: u32, route: u32, depth: u32, speed: u32, tt: (u32, u32), path: Vec<u8>, multi_tt: bool) {
    let x = controller();
    let Ok(desc) = x.control(slot, 0xa0, 6, 0x2900, 0, 9).map(|_| x.control_data(9).to_vec()) else {
        warn!("usb", "hub did not describe itself"; slot = slot);
        return;
    };
    let ports = (desc[2] as u32).min(MAX_HUB_PORTS);
    let power_good_us = desc[5] as u64 * 2000;
    if x.make_hub(slot, ports, multi_tt).is_err() {
        warn!("usb", "hub could not be set up"; slot = slot);
        return;
    }
    for p in 1..=ports {
        let _ = x.control(slot, 0x23, 3, 8, p as u16, 0);
    }
    delay_us(power_good_us.max(100_000));
    debug!("usb", "hub ready"; slot = slot, ports = ports);
    if depth >= 4 {
        return;
    }
    for p in 1..=ports {
        let status = |x: &mut Xhci| -> Option<(u16, u16)> {
            x.control(slot, 0xa3, 0, 0, p as u16, 4).ok()?;
            let d = x.control_data(4);
            Some((u16::from_le_bytes([d[0], d[1]]), u16::from_le_bytes([d[2], d[3]])))
        };
        let Some((st, _)) = status(x) else { continue };
        if st & 1 == 0 {
            continue;
        }
        let _ = x.control(slot, 0x23, 3, 4, p as u16, 0);
        let mut done = None;
        wait_for(500_000, || {
            done = status(x).filter(|(st, ch)| ch & (1 << 4) != 0 && st & (1 << 4) == 0);
            if done.is_none() {
                delay_us(10_000);
            }
            done.is_some()
        });
        let _ = x.control(slot, 0x23, 1, 20, p as u16, 0);
        let _ = x.control(slot, 0x23, 1, 16, p as u16, 0);
        let Some((st, _)) = done else {
            warn!("usb", "hub port did not reset"; slot = slot, port = p);
            continue;
        };
        if st & 2 == 0 {
            continue;
        }
        delay_us(10_000);
        let child_speed = if st & (1 << 9) != 0 {
            SPEED_LOW
        } else if st & (1 << 10) != 0 {
            SPEED_HIGH
        } else {
            SPEED_FULL
        };
        let child_tt = if speed == SPEED_HIGH && child_speed != SPEED_HIGH { (slot, p) } else { tt };
        let child_route = route | p.min(15) << (4 * depth);
        enumerate(root_port, child_route, depth + 1, child_speed, child_tt, usb_node(&path, p));
    }
}

/// `PciRoot(0)/Pci(0,0)/Pci(0,0)`: the root port and the VL805 behind it.
fn controller_path() -> Vec<u8> {
    let mut acpi = [0u8; 8];
    acpi[..4].copy_from_slice(&0x0a03_41d0u32.to_le_bytes());
    Builder::new()
        .node(devpath::ACPI, 1, &acpi)
        .node(devpath::HARDWARE, devpath::HW_PCI, &[0, 0])
        .node(devpath::HARDWARE, devpath::HW_PCI, &[0, 0])
        .done()
}

const CAPABILITY_LIST: u64 = 0x34;
const MSI_CAPABILITY_ID: u32 = 0x05;
/// Bit 0 of the MSI capability's message control word, its upper half.
const MSI_ENABLE: u32 = 1 << 16;
/// The most capabilities a function's list can hold in its 192 bytes.
const CAPABILITIES_MAX: usize = 48;

fn msi_capability() -> Option<u64> {
    let mut at = (read32(cfg(CAPABILITY_LIST)) & 0xfc) as u64;
    for _ in 0..CAPABILITIES_MAX {
        if at == 0 {
            return None;
        }
        let header = read32(cfg(at));
        if header & 0xff == MSI_CAPABILITY_ID {
            return Some(at);
        }
        at = ((header >> 8) & 0xfc) as u64;
    }
    None
}

/// `start4.elf` enables the controller's MSI, and a function with MSI enabled
/// does not raise INTx, the only interrupt an OS on the ACPI tables has.
fn leave_the_interrupt_line_to_the_os() {
    if let Some(at) = msi_capability() {
        let control = cfg(at);
        write32(control, read32(control) & !MSI_ENABLE);
    }
}

/// Find the controller, reset it and bring up everything on its ports.
pub fn init() {
    let Some(base) = registers() else {
        info!("usb", "no VL805 on the PCIe bus");
        return;
    };
    *REGISTERS.get() = Some(base);
    crate::tables::on_exit_boot_services(leave_the_interrupt_line_to_the_os);
    let xhci = match Xhci::init(base) {
        Ok(x) => x,
        Err(e) => {
            warn!("usb", "xHCI controller did not start"; registers = Hex(base), error = crate::log::dbg(&e));
            return;
        }
    };
    let ports = xhci.max_ports;
    *XHCI.get() = Some(xhci);
    crate::tables::on_exit_boot_services(|| controller().stop());

    // SuperSpeed ports read empty until their links train; give them all the
    // same while, together.
    let x = controller();
    let started = x.started_at;
    wait_for(LINK_TRAIN_US.saturating_sub(counter_us() - started), || (1..=ports).all(|p| x.portsc(p) & PORT_CCS != 0));
    let path = controller_path();
    for port in 1..=ports {
        let x = controller();
        let sc = x.portsc(port);
        if sc & PORT_CCS == 0 {
            continue;
        }
        if sc & PORT_PED == 0 {
            x.set_portsc(port, sc & PORT_KEEP_MASK | PORT_PR);
            if !wait_for(500_000, || x.portsc(port) & PORT_PRC != 0) {
                warn!("usb", "root port did not reset"; port = port);
                continue;
            }
            let sc = x.portsc(port);
            x.set_portsc(port, sc & PORT_KEEP_MASK | PORT_PRC);
            delay_us(10_000);
        }
        let sc = x.portsc(port);
        if sc & PORT_PED == 0 {
            continue;
        }
        let speed = (sc >> 10) & 0xf;
        enumerate(port, 0, 0, speed, (0, 0), usb_node(&path, port));
    }
    info!("usb", "USB ready"; devices = controller().devices.len(), registers = Hex(base));
}

/// A buffer in the DMA arena, for a driver's transfers.
pub fn dma_buffer(len: usize) -> Option<(u64, &'static mut [u8])> {
    let at = dma::alloc(len, 0x1_0000)?;
    Some((at, unsafe { core::slice::from_raw_parts_mut(at as *mut u8, len) }))
}

//! LPDDR4 bring-up: the SDRAM controller (`0x7E00_1000`), the memory
//! controller (`0x7DC2_0000`) and its PHY (`0x7DC3_0000`), which runs the
//! training firmware (`memsysNN.bin`) out of the EEPROM, and the per-part
//! settings table (`mcb.bin`).
//!
//! The PHY has a small microcontroller of its own: 4096 words of instruction
//! memory at `+0x8000`, 1024 words of data memory at `+0x4000`. The host talks
//! to it through seven message words at `+0x2100` (`valid, command, param,
//! arg, arg, sum, sum`) and a doorbell at `+0x2010`; `+0x2014` reads non-zero
//! while it works.

use core::cell::UnsafeCell;

use crate::board::{Board, TYPE_4B};
use crate::{eeprom, gpio, mmio, otp, timer};

const SDC: u32 = 0x7e00_1000;
const SDC_CTRL: u32 = SDC;
const SDC_REFRESH: u32 = SDC + 0x04;
const SDC_TIMING: u32 = SDC + 0x08;
/// LPDDR4 mode-register port.
const SDC_MR: u32 = SDC + 0x9c;

const MR_DONE: u32 = 1 << 31;
const MR_ERROR: u32 = 1 << 30;
const MR_CHANNEL: u32 = 1 << 25;
const MR_DEVICE: u32 = 1 << 24;

const MC: u32 = 0x7dc2_0000;
const MC_STATUS: u32 = MC + 0x10;
const MC_CMD: u32 = MC + 0x14;
/// Per-channel registers repeat `0x600` apart.
const CHANNELS: [u32; 2] = [0, 0x600];
/// Per-byte-lane blocks.
const LANES: [u32; 4] = [0x400, 0x600, 0xa00, 0xc00];

const PHY: u32 = 0x7dc3_0000;
const PHY_HALT: u32 = PHY + 0x2000;
const PHY_DOORBELL: u32 = PHY + 0x2010;
const PHY_BUSY: u32 = PHY + 0x2014;
const PHY_MSG: u32 = PHY + 0x2100;
const PHY_DMEM: u32 = PHY + 0x4000;
const PHY_IMEM: u32 = PHY + 0x8000;
const IMEM_WORDS: usize = 0x1000;
const DMEM_WORDS: usize = 0x400;

/// How long a doorbell may take the PHY: stock's own ceiling on both waits.
const SETTLE_TIMEOUT_US: u32 = 10_000_000;

const PHY_CMD_SIGNATURE: u32 = 0x101;
const PHY_CMD_TABLE: u32 = 0x203;
const PHY_CMD_TRAIN: u32 = 0x401;

/// `memsysNN.bin`: signature, the two memories' word sums, then their images.
const MEMSYS_WORDS: usize = 3 + IMEM_WORDS + DMEM_WORDS;
const MEMSYS: [&[u8]; 9] = [
    b"memsys00.bin",
    b"memsys01.bin",
    b"memsys02.bin",
    b"memsys03.bin",
    b"memsys04.bin",
    b"memsys05.bin",
    b"memsys06.bin",
    b"memsys07.bin",
    b"memsys08.bin",
];
/// Once this pass is through, the controller gets the part's own timings.
const TIMINGS_PASS: usize = 7;

struct Words<const W: usize>(UnsafeCell<[u32; W]>);

unsafe impl<const W: usize> Sync for Words<W> {}

impl<const W: usize> Words<W> {
    const fn new() -> Self {
        Words(UnsafeCell::new([0; W]))
    }

    /// Safety: nothing else may hold on to the buffer.
    #[allow(clippy::mut_from_ref)]
    unsafe fn bytes(&self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.0.get() as *mut u8, W * 4) }
    }

    unsafe fn words(&self) -> &[u32] {
        unsafe { &*self.0.get() }
    }
}

/// Both live in the L2 with the bootcode, as there is no SDRAM yet.
#[unsafe(link_section = ".mcb")]
static MCB: Words<3072> = Words::new();
#[unsafe(link_section = ".memsys")]
static MEMSYS_BUF: Words<MEMSYS_WORDS> = Words::new();

#[derive(Debug, Clone, Copy)]
pub enum Error {
    /// `mcb.bin` or a `memsysNN.bin` is missing or does not check out.
    Firmware,
    Unsupported(u32),
    NoMcb,
    Training(u32),
    Mismatch,
}

#[derive(Clone, Copy, Default)]
pub struct Geometry {
    pub size_gbit: u32,
    pub dual_rank: bool,
    pub byte_mode: bool,
    pub part: u32,
    pub odt: u32,
}

impl Geometry {
    /// The configuration byte, in the encoding OTP row 33's `SDRAM_CONFIG`
    /// uses too.
    pub fn code(&self) -> u32 {
        let v = (self.part & 7) << 6
            | if self.dual_rank { 0x10 } else { 0 }
            | if self.byte_mode { 0x08 } else { 0 };
        match self.size_gbit {
            8 => v | 7,
            16 => v | 6,
            24 => v | 0x20 | 6,
            32 => v | 5,
            48 => v | 0x20 | 5,
            64 => v | 4,
            _ => v,
        }
    }
}

/// The size a configuration byte stands for, in gigabits.
pub fn code_size(code: u32) -> u32 {
    match code & 7 {
        3 => 0x80,
        4 => 0x40,
        5 if code & 0x20 != 0 => 0x30,
        5 => 0x20,
        6 if code & 0x20 != 0 => 0x18,
        6 => 0x10,
        7 => 8,
        _ => 0,
    }
}

pub struct Sdram {
    pub geometry: Geometry,
    /// `SDRAM_CONFIG` from OTP, 0 when unset.
    pub otp_config: u32,
    /// Controller clock, MHz, from the MCB record.
    pub clock: u32,
}

fn mc(off: u32, v: u32) {
    mmio::write(MC + off, v);
}

fn mr_ready() -> bool {
    let ready = || mmio::read(SDC_MR) & mmio::read(SDC_MR) & MR_DONE != 0;
    for _ in 0..10 {
        if ready() {
            return true;
        }
        timer::delay_us(1000);
    }
    ready()
}

/// LPDDR4 mode register `mr` of `device` (chip select) on `channel`.
pub fn mr_read(mr: u32, device: u32, channel: u32) -> Option<u32> {
    match mr_query(mr, device, channel) {
        Ok(value) => Some(value),
        Err(Some(v)) => {
            crate::warn!("sdram", "mode register read timed out";
                mr = mr, device = device, channel = channel,
                port = format_args!("{v:#010x}"), rdata = format_args!("{:#04x}", (v >> 16) & 0xff));
            None
        }
        Err(None) => None,
    }
}

/// [`mr_read`] without the log line, for once the console is the ARM's: the
/// port's word when it reports an error, nothing when it never got ready.
fn mr_query(mr: u32, device: u32, channel: u32) -> Result<u32, Option<u32>> {
    if !mr_ready() {
        return Err(None);
    }
    let cmd = (if channel != 0 { MR_CHANNEL } else { 0 })
        | (if device != 0 { MR_DEVICE } else { 0 })
        | (mr & 0xff);
    mmio::write(SDC_MR, cmd);
    for _ in 0..10 {
        if mmio::read(SDC_MR) & MR_DONE != 0 {
            break;
        }
        timer::delay_us(1000);
    }
    let v = mmio::read(SDC_MR);
    if v & MR_ERROR != 0 {
        return Err(Some(v));
    }
    Ok((v >> 16) & 0xff)
}

/// LPDDR4 `MR4`: the refresh rate the part asks for, in its low three bits.
/// 3 is the nominal rate; 1 and 2 allow refreshing 4 and 2 times less often,
/// 4 and 5 ask for 2 and 4 times more often, and anything else is out of the
/// range the stock firmware acts on.
const MR4: u32 = 4;
const MR4_RATE: u32 = 7;
const RATE_NOMINAL: u32 = 3;
/// The refresh interval's field in `SDC_REFRESH`; the low half is kept.
const REFRESH_SHIFT: u32 = 16;
const REFRESH_KEEP: u32 = 0xffff;
const REFRESH_CHECK_US: u32 = 1_000_000;

/// The SDRAM refresh check the stock start4 runs once the ARM does
/// (`0x3ED6BBA0`, from a task that calls it every 100 ms): at most once a
/// second it reads `MR4` from every rank on every channel and sets the
/// refresh interval for the highest rate any of them asks for. A read that
/// fails counts as rate 7, which leaves the interval at the one the
/// bootloader set.
pub struct Refresh {
    base: u32,
    rate: u32,
    checked: u32,
    ranks: u32,
    channels: u32,
}

impl Refresh {
    /// Start checking the SDRAM laid out as `(ranks, channels)`; the first
    /// [`Self::check`] reads the parts at once.
    pub fn new((ranks, channels): (u32, u32)) -> Refresh {
        Refresh {
            base: mmio::read(SDC_REFRESH) >> REFRESH_SHIFT,
            rate: RATE_NOMINAL,
            checked: timer::now().wrapping_sub(REFRESH_CHECK_US),
            ranks,
            channels,
        }
    }

    pub fn check(&mut self) {
        let now = timer::now();
        if now.wrapping_sub(self.checked) < REFRESH_CHECK_US {
            return;
        }
        self.checked = now;
        let mut rate = 0;
        for rank in 0..self.ranks {
            for channel in 0..self.channels {
                let code = mr_query(MR4, rank, channel).unwrap_or(u32::MAX);
                rate = rate.max(code & MR4_RATE);
            }
        }
        if rate == self.rate {
            return;
        }
        self.rate = rate;
        let interval = match rate {
            1..RATE_NOMINAL => self.base << (RATE_NOMINAL - rate),
            RATE_NOMINAL..=5 => self.base >> (rate - RATE_NOMINAL),
            _ => self.base,
        };
        let keep = mmio::read(SDC_REFRESH) & REFRESH_KEEP;
        mmio::write(SDC_REFRESH, interval << REFRESH_SHIFT | keep);
    }
}

/// The on-board ODT variant: a dual-rank part on a 4B the fuses flag for it.
fn odt(board: &Board, dual_rank: bool) -> u32 {
    (dual_rank && board.kind() == TYPE_4B && board.ext_revision & 0x8_0000 != 0 && board.maker() == 5)
        as u32
}

/// What the dies say about themselves: MR5 (vendor), MR6 (revision) and MR8
/// (density, width) of each chip select on each channel.
pub fn identify(board: &Board) -> (Geometry, &'static str) {
    let (mut mr5, mut mr6, mut mr8) = ([0u32; 4], [0u32; 4], [0u32; 4]);
    for channel in 0..2 {
        for device in 0..2 {
            let i = (channel + 2 * device) as usize;
            mr5[i] = mr_read(5, device, channel).unwrap_or(u32::MAX);
            mr6[i] = mr_read(6, device, channel).unwrap_or(u32::MAX);
            mr8[i] = mr_read(8, device, channel).unwrap_or(u32::MAX);
        }
    }
    let vendor = match mr5[0] {
        0xff => "Micron",
        1 => "Samsung",
        5 => "Nanya",
        6 => "Hynix",
        8 => "Winbond",
        0x13 => "CXMT",
        _ => "Unknown",
    };
    let die = match (mr8[0] & 0x3f) >> 2 {
        0 => 4,
        1 => 6,
        3 => 12,
        4 => 16,
        5 => 24,
        6 => 32,
        _ => 8,
    };
    // A second rank only counts if chip select 1 answers like chip select 0.
    let mut ranks = if mr8[0] == mr8[2] { 2 } else { 1 };
    let dual_rank = ranks == 2;
    let byte_mode = (mr8[0] as i32 >> 6) == 1;
    if byte_mode {
        ranks <<= 1;
    }
    let part =
        (die * ranks == 16 && mr5[0] == 0xff && dual_rank && mr6[0] == 0x87) as u32;
    let geometry = Geometry {
        size_gbit: die * ranks,
        dual_rank,
        byte_mode,
        part,
        odt: odt(board, dual_rank),
    };
    (geometry, vendor)
}

/// Controller and PHY defaults, with timings for the 1350 MHz boot clock
/// until training has settled the part's own.
fn init_1350() {
    let _ = mmio::read(SDC_CTRL);
    mmio::write(SDC_CTRL, 0);
    mmio::write(SDC_CTRL, 0x0040_00ea);
    for ch in CHANNELS {
        mc(ch + 0x2b0, 1);
    }
    for ch in CHANNELS {
        mc(ch + 0x218, 0x80e);
    }
    mc(0x14, 0x5501_0012);
    mc(0x24, 0x0010_1019);
    mc(0x28, 0);
    mc(0x1c, 0x0800_0000);
    mc(0x18, 0x1e0);
    mmio::write(MC_CMD, 0x5501_0000);
    timer::wait(10_000, || mmio::read(MC_STATUS) & 1 != 0);
    mmio::write(MC_CMD, 0x5501_0000);
    mc(0x30, 0);
    mc(0x2c, 0);
    for ch in CHANNELS {
        mc(ch + 0x2a8, 8);
    }
    mc(0x50, 0x0002_3232);
    mc(0x54, 0x0002_3232);
    for ch in CHANNELS {
        mc(ch + 0x2bc, 0x200);
    }
    for ch in CHANNELS {
        mc(ch + 0x2a8, 0);
    }
    for ch in CHANNELS {
        mc(ch + 0x2a8, 4);
    }
    for ch in CHANNELS {
        for i in 0..8 {
            mc(ch + 0x21c + 4 * i, 0x36);
        }
    }
    for lane in LANES {
        mc(lane, 0x20);
    }
    for lane in LANES {
        for i in 1..=18 {
            mc(lane + 4 * i, 0x23);
        }
    }
    for i in 0..18 {
        mc(0x45c + 4 * i, 0);
    }
    for off in [
        0x454, 0x458, 0xa54, 0xa58, 0x4a4, 0x4a8, 0xaa4, 0xaa8, 0x654, 0x658, 0xc54, 0xc58, 0x6a4,
        0x6a8, 0xca4, 0xca8,
    ] {
        mc(off, 0x36);
    }
    let per_lane: [(u32, [u32; 4]); 7] = [
        (0xf, [0x518, 0xb18, 0x718, 0xd18]),
        (0x0320_03ff, [0x540, 0xb40, 0x740, 0xd40]),
        (0x67ff, [0x544, 0xb44, 0x744, 0xd44]),
        (0x14c, [0x554, 0x754, 0xb54, 0xd54]),
        (0x11, [0x548, 0xb48, 0x748, 0xd48]),
        (0, [0x538, 0xb38, 0x738, 0xd38]),
        (6, [0x53c, 0xb3c, 0x73c, 0xd3c]),
    ];
    for off in [0x204, 0x804, 0x20c, 0x80c, 0x208, 0x808] {
        mc(off, 0x67ff);
    }
    for (v, offs) in &per_lane[..5] {
        for &off in offs {
            mc(off, *v);
        }
    }
    for ch in CHANNELS {
        mc(ch + 0x2b8, 0);
    }
    for (v, offs) in &per_lane[5..] {
        for &off in offs {
            mc(off, *v);
        }
    }
    mc(0x8b0, 0);
    mc(0x2b0, 0);
    for (off, v) in [
        (0x04, 0x0292_02f4),
        (0x08, 0x1101_3120),
        (0x0c, 0x1222),
        (0x10, 0x1040),
        (0x14, 0x1306_1c2a),
        (0x18, 0x0c03_370c),
        (0x1c, 0x0d0c_0104),
        (0x20, 0x0801_0a01),
        (0x24, 0x0002_1030),
        (0x2c, 0x502),
        (0x28, 0x0001_000a),
    ] {
        mmio::write(SDC + off, v);
    }
    mmio::write(SDC_CTRL, 0x0040_00c3);
    for ch in CHANNELS {
        mc(ch + 0x2b0, 1);
    }
    for v in [0, 0x200, 0x300] {
        for ch in CHANNELS {
            mc(ch + 0x2bc, v);
        }
    }
    // MR1..MR3 through the controller's command registers.
    for (mr, v) in [(1, 0x2e), (2, 0x12), (3, 0x31)] {
        for (reg, value) in [(0x248, 0x8000_00c6), (0x24c, 0x8000_0000 | mr), (0x250, 0x8000_00d6), (0x254, v)] {
            for ch in CHANNELS {
                mc(ch + reg, value);
            }
        }
    }
    for v in [0xf, 0x11] {
        for (reg, value) in [(0x248, 0x8000_00e0), (0x24c, v)] {
            for ch in CHANNELS {
                mc(ch + reg, value);
            }
        }
    }
    mc(0x8b0, 0);
    mc(0x2b0, 0);
    mmio::write(SDC_CTRL, 0x0040_0042);
}

/// The MCB record for `g`: nine header words (header size, clock, data rate,
/// size, dual-rank, byte-mode, part, ODT, table length), eleven SDRAM
/// controller timing words, then the PHY table.
fn find_mcb<'a>(mcb: &'a [u32], g: &Geometry) -> Option<&'a [u32]> {
    let mut i = 0;
    while i + 0x14 < mcb.len() {
        let r = &mcb[i..];
        let extra = r[8] as usize;
        if r[3] == g.size_gbit
            && r[4] == g.dual_rank as u32
            && r[5] == g.byte_mode as u32
            && r[6] == g.part
            && r[7] == g.odt
            && extra != 0
            && extra < 0x99
        {
            return r.get(..0x14 + extra);
        }
        if extra == 0 {
            break;
        }
        i += 0x14 + extra;
    }
    None
}

fn memsys_init<'a>(
    board: &Board,
    otp_config: u32,
    mcb: &'a [u32],
    mcb_len: usize,
) -> Result<(Geometry, &'a [u32]), Error> {
    let mut g = Geometry::default();
    if otp_config != 0 {
        crate::debug!("sdram", "geometry from the fuses";
            sdram_config = format_args!("{otp_config:#04x}"), maker = board.maker());
        g = Geometry {
            size_gbit: code_size(otp_config),
            dual_rank: otp_config & 0x10 != 0,
            byte_mode: otp_config & 8 != 0,
            part: (otp_config >> 6) & 7,
            odt: odt(board, otp_config & 0x10 != 0),
        };
        let expected = 2 << ((board.revision >> 20) & 7);
        if g.size_gbit != expected {
            crate::warn!("sdram", "the fuses' SDRAM size does not match the revision code";
                fuses_gbit = g.size_gbit, revision_gbit = expected,
                sdram_config = format_args!("{otp_config:#04x}"));
        }
    }
    init_1350();
    if g.size_gbit == 0 {
        g = identify(board).0;
    }
    crate::info!("sdram", "bringing up SDRAM";
        ranks = if g.dual_rank { 2 } else { 1 }, size_gbit = g.size_gbit, part = g.part,
        code = format_args!("{:#04x}", g.code()), odt = g.odt);
    if !matches!(g.size_gbit, 8 | 16 | 24 | 32 | 48 | 64) {
        crate::error!("sdram", "unsupported SDRAM size"; size_gbit = g.size_gbit);
        return Err(Error::Unsupported(g.size_gbit));
    }
    let Some(r) = find_mcb(mcb, &g) else {
        crate::error!("sdram", "no settings for this part in mcb.bin";
            size_gbit = g.size_gbit, dual_rank = g.dual_rank, part = g.part, odt = g.odt, mcb_bytes = mcb_len);
        return Err(Error::NoMcb);
    };
    crate::debug!("sdram", "settings found";
        mbps = r[2], dual_rank = r[4], byte_mode = r[5], size_gbit = r[3], part = r[6], odt = r[7]);
    Ok((g, r))
}

fn msg(i: u32) -> u32 {
    mmio::read(PHY_MSG + 4 * i)
}

fn set_msg(i: u32, v: u32) {
    mmio::write(PHY_MSG + 4 * i, v);
}

/// The sum of the first `n` message words, which the next word has to hold.
fn msg_sum(n: u32) -> u32 {
    (0..n).fold(0u32, |s, i| s.wrapping_add(msg(i)))
}

fn post(cmd: u32, param: u32, args: &[u32]) {
    set_msg(0, 1);
    set_msg(1, cmd);
    set_msg(2, param);
    let mut n = 3;
    for &a in args {
        set_msg(n, a);
        n += 1;
    }
    set_msg(n, msg_sum(n));
}

/// Training on the PHY, one `memsysNN.bin` pass at a time. A pass is started,
/// and the next firmware image is fetched from the EEPROM while it runs.
struct Phy {
    running: bool,
    err: u32,
}

impl Phy {
    /// Ring the doorbell, unless a command is already running, and wait for the
    /// PHY: busy reads the same non-zero value ten times running once it is
    /// done with the message, then the doorbell is released and busy drops. A
    /// final value of 1 is success.
    fn run(&mut self) -> u32 {
        if !self.running {
            mmio::write(PHY_DOORBELL, 1);
        }
        self.running = false;
        let (mut last, mut same) = (0, 0);
        if !timer::wait(SETTLE_TIMEOUT_US, || {
            let b = mmio::read(PHY_BUSY);
            if b == 0 || b != last {
                (last, same) = (b, 0);
            } else {
                same += 1;
            }
            same >= 10
        }) {
            return 0xd;
        }
        mmio::write(PHY_DOORBELL, 0);
        if !timer::wait(SETTLE_TIMEOUT_US, || mmio::read(PHY_BUSY) == 0) {
            return 0xd;
        }
        if last == 1 { 0 } else { last }
    }

    /// Halt the PHY, load a `memsysNN.bin` into its memories and check both
    /// against the sums the file carries, then let it go.
    fn load(&mut self, fw: &[u32]) -> u32 {
        mmio::write(PHY_HALT, 1);
        for i in 0..IMEM_WORDS as u32 {
            mmio::write(PHY_IMEM + 4 * i, 0);
        }
        for i in 0..DMEM_WORDS as u32 {
            mmio::write(PHY_DMEM + 4 * i, 0);
        }
        let imem = &fw[3..3 + IMEM_WORDS];
        let dmem = &fw[3 + IMEM_WORDS..MEMSYS_WORDS];
        for (i, &w) in imem.iter().enumerate() {
            mmio::write(PHY_IMEM + 4 * i as u32, w);
        }
        for (i, &w) in dmem.iter().enumerate() {
            mmio::write(PHY_DMEM + 4 * i as u32, w);
        }
        let sum = |base: u32, n: usize| {
            (0..n as u32).fold(0u32, |s, i| s.wrapping_add(mmio::read(base + 4 * i)))
        };
        if sum(PHY_IMEM, IMEM_WORDS) != fw[1] {
            return 9;
        }
        if sum(PHY_DMEM, DMEM_WORDS) != fw[2] {
            return 10;
        }
        mmio::write(PHY_DOORBELL, 0);
        mmio::write(PHY_HALT, 0);
        0
    }

    /// The firmware reports the memsys signature it was built for and which
    /// pass it thinks this is.
    fn check_signature(&mut self, signature: u32, pass: u32) -> u32 {
        post(PHY_CMD_SIGNATURE, 0, &[]);
        let e = self.run();
        if e != 0 {
            return e;
        }
        if msg_sum(6) != msg(6) {
            return 0xe;
        }
        if msg(3) != signature {
            return 8;
        }
        if (msg(4) >> 8) & 0xff != pass {
            return 0xc;
        }
        0
    }

    /// Ask where the part's table goes, and put it there.
    fn load_table(&mut self, table: &[u32]) -> u32 {
        post(PHY_CMD_TABLE, 0, &[]);
        let e = self.run();
        if e != 0 {
            return e;
        }
        if msg_sum(5) != msg(5) {
            return 0xe;
        }
        let (off, n) = (msg(3), msg(4) as usize);
        for (i, &w) in table.iter().take(n).enumerate() {
            mmio::write(PHY_DMEM + off + 4 * i as u32, w);
        }
        0
    }

    fn start(&mut self, pass: usize, fw: &[u32], table: &[u32]) {
        if pass == 0 {
            self.err = 0;
            mmio::write(SDC_CTRL, mmio::read(SDC_CTRL) & !2);
        }
        if self.err != 0 {
            return;
        }
        let mut e = self.load(fw);
        if e == 0 {
            e = self.check_signature(fw[0], pass as u32);
        }
        if e == 0 {
            e = self.load_table(table);
        }
        if e == 0 {
            post(PHY_CMD_TRAIN, 2, &[1, 0]);
            mmio::write(PHY_DOORBELL, 1);
            self.running = true;
        }
        self.err = e;
    }

    fn finish(&mut self) -> u32 {
        if self.err == 0 {
            self.err = self.run();
        }
        if self.err == 0 {
            if msg_sum(6) != msg(6) {
                self.err = 0xe;
            } else if msg(3) != 0 {
                self.err = 0x10;
            }
        }
        release_pads();
        self.err
    }
}

/// Training keeps the UART pads quiet; give them back.
fn release_pads() {
    mmio::write(0x7c40_4380, 0x7f);
    mmio::write(0x7c40_43a8, 0);
    mmio::write(0x7e20_00d4, 0);
    gpio::set_function(14, gpio::ALT0);
    gpio::set_function(15, gpio::ALT0);
}

/// The part's timings from its MCB record, `SDRAM_BANKLOW` applied.
fn apply_timings(t: &[u32], size: u32, banklow: u32) {
    let banklow = if size == 24 || size == 48 { 3 } else { banklow };
    let mut timing = t[1];
    if banklow < 4 {
        timing = (timing & !0x3000) | (banklow & 3) << 12;
    }
    mmio::write(SDC_REFRESH, t[0]);
    mmio::write(SDC_TIMING, timing);
    for (i, &v) in t[2..11].iter().enumerate() {
        mmio::write(SDC + 0x0c + 4 * i as u32, v);
    }
}

/// Read one of the EEPROM's SDRAM firmware files into `buf`.
fn load_firmware(name: &[u8], buf: &mut [u8]) -> Result<usize, Error> {
    eeprom::load(name, buf).map_err(|e| {
        crate::error!("sdram", "training firmware missing or corrupt";
            file = core::str::from_utf8(name).unwrap_or("?"), error = format_args!("{e:?}"));
        Error::Firmware
    })
}

pub fn init(board: &Board, banklow: u32) -> Result<Sdram, Error> {
    let mcb_len = load_firmware(b"mcb.bin", unsafe { MCB.bytes() })?;
    let mcb = unsafe { &MCB.words()[..mcb_len / 4] };
    let otp_config = (otp::read(otp::EXT_REVISION) >> 8) & 0x1ff;
    let (geometry, record) = memsys_init(board, otp_config, mcb, mcb_len)?;
    let (timings, table) = (&record[9..20], &record[20..]);

    let mut phy = Phy { running: false, err: 0 };
    let finish = |phy: &mut Phy, pass: usize| -> Result<(), Error> {
        let e = phy.finish();
        if e != 0 {
            return Err(Error::Training(e));
        }
        if pass == TIMINGS_PASS {
            apply_timings(timings, geometry.size_gbit, banklow);
            mmio::write(SDC_CTRL, 0x0020_00c3);
            mmio::write(SDC_CTRL, 0x0020_0042);
        }
        Ok(())
    };
    for (pass, name) in MEMSYS.iter().enumerate() {
        load_firmware(name, unsafe { MEMSYS_BUF.bytes() })?;
        if pass > 0 {
            finish(&mut phy, pass - 1)?;
        }
        phy.start(pass, unsafe { MEMSYS_BUF.words() }, table);
    }
    finish(&mut phy, MEMSYS.len() - 1)?;
    mr_read(5, 0, 0);

    Ok(Sdram { geometry, otp_config, clock: record[1] })
}

/// The dies again, against `SDRAM_CONFIG` if the fuses have one.
pub fn verify(s: &Sdram, board: &Board) -> Result<(), Error> {
    let actual = identify(board).0.code();
    let expected = s.otp_config;
    if expected == 0 || (expected & !0x1c0) == (actual & !0x1c0) {
        return Ok(());
    }
    crate::error!("sdram", "the parts do not match the fuses";
        expected = format_args!("{expected:#04x}"), actual = format_args!("{actual:#04x}"),
        revision = format_args!("{:06x}", board.revision), serial = format_args!("{:08x}", board.serial));
    Err(Error::Mismatch)
}

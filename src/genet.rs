//! The BCM2711's GENET Ethernet MAC and the PHY behind its MDIO bus, as far as
//! waiting for a Wake-on-LAN magic packet needs them: the MAC receives with its
//! DMA off, and its magic packet detector ([`arm_magic_packet`]) sets a status
//! bit when the packet that wakes the board arrives ([`magic_packet_seen`]).
//!
//! The clocks, the MAC's reset, the MDIO bus and the PHY's start-up follow the
//! sequence the stock bootloader runs for a network boot; the detector is the
//! one Linux's `bcmgenet` arms for a suspend with `WAKE_MAGIC`
//! (`bcmgenet_wol.c`).

use core::sync::atomic::{AtomicU32, Ordering};

use crate::{cm, gpio, mmio, timer};

const GENET: u32 = 0x7d58_0000;
const SYS_PORT_CTRL: u32 = GENET + 0x0004;
const SYS_RBUF_FLUSH_CTRL: u32 = GENET + 0x0008;
const SYS_TBUF_FLUSH_CTRL: u32 = GENET + 0x000c;
const EXT_RGMII_OOB_CTRL: u32 = GENET + 0x008c;
const EXT_GPHY_CTRL: u32 = GENET + 0x009c;
const EXT_24: u32 = GENET + 0x00a4;
const INTRL2_0: u32 = GENET + 0x0200;
const INTRL2_CLEAR: u32 = INTRL2_0 + 0x08;
const INTRL2_MASK_CLEAR: u32 = INTRL2_0 + 0x14;
const RBUF_STATUS: u32 = GENET + 0x030c;
const UMAC_CMD: u32 = GENET + 0x0808;
const UMAC_MAC0: u32 = GENET + 0x080c;
const UMAC_MAC1: u32 = GENET + 0x0810;
const UMAC_MAX_FRAME_LEN: u32 = GENET + 0x0814;
const UMAC_MIB_CTRL: u32 = GENET + 0x0d80;
const UMAC_MDIO_CMD: u32 = GENET + 0x0e14;
const UMAC_MDIO_CFG: u32 = GENET + 0x0e18;
const UMAC_MPD_CTRL: u32 = GENET + 0x0e20;
const RDMA_CTRL: u32 = GENET + 0x3044;
const TDMA_CTRL: u32 = GENET + 0x5044;
const HFB_CTRL: u32 = GENET + 0xfc00;

const CMD_RX_EN: u32 = 1 << 1;
const CMD_SPEED_SHIFT: u32 = 2;
const CMD_RX_PAUSE_IGNORE: u32 = 1 << 8;
const CMD_HD_EN: u32 = 1 << 10;
const CMD_CRC_FWD: u32 = 1 << 6;
const CMD_TX_PAUSE_IGNORE: u32 = 1 << 28;
/// What `UMAC_CMD` holds after a reset, and with the UniMAC held in reset and
/// in loopback while the rest is set up.
const CMD_RESET_VALUE: u32 = 0x0100_00d8;
const CMD_SW_RESET_LOOPBACK: u32 = 0xa000;
const MIB_RESET: u32 = 7;
const MAX_FRAME: u32 = 1536;

/// `SYS_PORT_CTRL`: an external gigabit PHY on the RGMII bus.
const PORT_EXT_GPHY: u32 = 3;
/// `EXT_RGMII_OOB_CTRL` as a 4B with Linux up and the link up reads it: RGMII
/// mode and the link bit.
const RGMII_LINK_UP: u32 = 0x00f0_0050;
const RGMII_RESET: u32 = 0x00f0_0000;
const GPHY_RESET: u32 = 0x10b;
const EXT_24_VALUE: u32 = 0xf8;

const MPD_EN: u32 = 1 << 0;
const RBUF_ACPI_EN: u32 = 1 << 2;
const RBUF_STATUS_WOL: u32 = 1 << 0;
const RBUF_STATUS_MPD_INTR_ACTIVE: u32 = 1 << 1;
/// `INTRL2_0`'s status bit for a magic packet.
const IRQ_MPD_R: u32 = 1 << 12;
const DMA_EN: u32 = 1 << 0;
const DMA_STATUS_DISABLED: u32 = 1 << 0;
const DMA_STATUS_OFFSET: u32 = 0x04;
const FLUSH_US: u32 = 10_000;
const DMA_STOP_US: u32 = 1_000_000;
const DMA_STOP_POLL_US: u32 = 100;
const DETECTOR_READY_US: u32 = 50_000;

const MDIO_START_BUSY: u32 = 1 << 29;
const MDIO_READ_FAIL: u32 = 1 << 28;
const MDIO_RD: u32 = 2 << 26;
const MDIO_WR: u32 = 1 << 26;
const MDIO_PMD_SHIFT: u32 = 21;
const MDIO_REG_SHIFT: u32 = 16;
const MDIO_TIMEOUT_US: u32 = 1000;
const MDIO_POLL_US: u32 = 100;
const MDIO_DIV: u32 = 12;
const MDIO_C22: u32 = 1;

const MII_BMCR: u32 = 0x00;
const MII_BMSR: u32 = 0x01;
const MII_PHYSID1: u32 = 0x02;
const MII_PHYSID2: u32 = 0x03;
const MII_ADVERTISE: u32 = 0x04;
const MII_LPA: u32 = 0x05;
const MII_CTRL1000: u32 = 0x09;
const MII_EXT_DATA: u32 = 0x15;
const MII_EXT_SELECT: u32 = 0x17;
const BMCR_RESET: u16 = 0x8000;
const BMCR_PDOWN: u16 = 0x0800;
const BMCR_ANEG: u16 = 0x1200;
const BMCR_RESET_US: u32 = 75_000;
const BMSR_LINK_AND_ANEG_DONE: u16 = 0x0024;
/// Auto-negotiation's technology ability field: 10 and 100 Mbit/s, half and
/// full duplex, and the selector for IEEE 802.3.
const ADVERTISE_10_100: u16 = 0x01e1;
const LPA_100FULL: u16 = 0x0100;
const LPA_100HALF: u16 = 0x0080;
const LPA_10FULL: u16 = 0x0040;
const LPA_10HALF: u16 = 0x0020;
/// The Broadcom PHYs' expansion register that holds the PHY in IDDQ.
const EXT_IDDQ: u16 = 0x0d06;
const PHY_ID_BROADCOM_OUI: u32 = 0x600d_0000;
const PHY_ID_OUI_MASK: u32 = 0xffff_0000;

/// The Broadcom PHYs' shadow register window: a read writes the shadow's number
/// in bits 14:10 and reads the value back from the low ten bits, a write sets
/// bit 15 as well.
const MII_SHADOW: u32 = 0x1c;
const SHADOW_WRITE: u16 = 1 << 15;
const SHADOW_NUMBER_SHIFT: u16 = 10;
const SHADOW_VALUE_MASK: u16 = 0x03ff;
/// The shadows that say what each of the PHY's LED pins shows: two selectors of
/// four bits each in a shadow.
const SHADOW_LED_SELECTORS: [u16; 2] = [0x0d, 0x0e];
/// A selector's source that ties the pin high, which puts its LED out.
const LED_SOURCE_OFF: u16 = 0xe;
const LEDS_OFF: u16 = LED_SOURCE_OFF << 4 | LED_SOURCE_OFF;
const NO_PHY: u32 = u32::MAX;

/// The PHY whose LED selectors [`leds_off`] changed, and what they were.
static LED_PHY: AtomicU32 = AtomicU32::new(NO_PHY);
static LED_SELECTORS_BEFORE: [AtomicU32; 2] = [AtomicU32::new(0), AtomicU32::new(0)];

/// The PHY's address on a 4B and a 400 or a CM4 without the extended
/// revision's bit 22, in the order they are looked for.
const PHY_ADDRESSES: [u32; 2] = [1, 0];

/// How long the PHY gets to negotiate a link, and how often it is looked at.
const LINK_TIMEOUT_US: u32 = 10_000_000;
const LINK_POLL_US: u32 = 100_000;

/// The GPIO block's `+0xD0`, whose bit 0 the Ethernet does not carry a frame
/// without, and the MDIO bus's two pins, `ALT5` on GPIO 28 and 29.
const SD_MUX: u32 = 0x7e20_00d0;
const SD_MUX_ETHERNET: u32 = 1 << 0;
const MDIO_PIN: u32 = 28;
const MDC_PIN: u32 = 29;
/// 250 MHz and 125 MHz off PLLD's peripheral channel, the two generators the
/// MAC runs from, in the clock manager's 12.12 fixed point.
const ETH_250_DIV: u32 = 3 << 12;
const ETH_125_DIV: u32 = 6 << 12;
/// The pull words the stock bootloader has in effect over GPIO 0..57 when it
/// brings the Ethernet up, two bits a pin.
const PULLS: [(u32, u32); 4] = [
    (0x7e20_00e4, 0x5aa9_5555),
    (0x7e20_00e8, 0xa9aa_aaaa),
    (0x7e20_00ec, 0xa0aa_a95a),
    (0x7e20_00f0, 0x000a_aaaa),
];

/// The link the PHY negotiated.
#[derive(Clone, Copy)]
pub struct Link {
    pub mbit_s: u32,
    pub full_duplex: bool,
}

pub enum Error {
    /// No PHY answers on the MDIO bus.
    NoPhy,
    /// The PHY gave no link in time: no cable, or nothing at the other end.
    NoLink,
}

/// Bring up the MAC and the PHY at 10 or 100 Mbit/s, and arm the magic packet
/// detector for `mac`.
///
/// The PHY advertises nothing faster than 100 Mbit/s, which a magic packet
/// needs no more than: the board draws less with the link at that speed. The
/// MAC receives with both DMA engines off, so no frame is written to memory.
pub fn arm_magic_packet(mac: [u8; 6]) -> Result<Link, Error> {
    clocks();
    reset();
    let phy = find_phy().ok_or(Error::NoPhy)?;
    let link = negotiate(phy).ok_or(Error::NoLink)?;
    if leds_off(phy).is_some() {
        crate::info!("wake", "the Ethernet port's LEDs are off");
    } else {
        crate::warn!("wake", "the PHY did not take the LED setting, leaving the Ethernet port's LEDs on");
    }
    receive(mac, link);
    arm_detector();
    Ok(link)
}

/// Whether a magic packet has arrived since [`arm_magic_packet`].
pub fn magic_packet_seen() -> bool {
    mmio::read(INTRL2_0) & IRQ_MPD_R != 0 || mmio::read(RBUF_STATUS) & RBUF_STATUS_MPD_INTR_ACTIVE != 0
}

/// Leave the MAC the way Linux's `bcmgenet_wol_power_up_cfg` does: the
/// detector off, the receiver off.
pub fn disarm() {
    leds_restore();
    mmio::write(UMAC_MPD_CTRL, mmio::read(UMAC_MPD_CTRL) & !MPD_EN);
    mmio::write(HFB_CTRL, mmio::read(HFB_CTRL) & !RBUF_ACPI_EN);
    mmio::write(UMAC_CMD, mmio::read(UMAC_CMD) & !CMD_RX_EN);
}

/// Nothing in the MAC answers until the Ethernet's two clock generators run,
/// the SD mux's Ethernet bit is set and the MDIO pins are on the bus: a
/// register access into a MAC without them stalls the VPU.
fn clocks() {
    mmio::write(SD_MUX, mmio::read(SD_MUX) | SD_MUX_ETHERNET);
    for (word, value) in PULLS {
        mmio::write(word, value);
    }
    gpio::set_function(MDIO_PIN, gpio::ALT5);
    gpio::set_function(MDC_PIN, gpio::ALT5);
    cm::set_generator(cm::GEN_1E8_CTL, ETH_250_DIV, cm::SRC_PLLD_PER | cm::ENAB);
    cm::set_generator(cm::GEN_210_CTL, ETH_125_DIV, cm::SRC_PLLD_PER | cm::ENAB);
}

/// Take the UniMAC out of reset, which nothing in it answers a write without
/// (Linux's `reset_umac`), and put the MAC's port back to how a stage starts.
fn reset() {
    mmio::write(SYS_RBUF_FLUSH_CTRL, 0);
    timer::delay_us(10);
    mmio::write(UMAC_CMD, 0);
    mmio::write(UMAC_CMD, CMD_SW_RESET_LOOPBACK);
    timer::delay_us(2);
    mmio::write(UMAC_CMD, 0);
    mmio::write(UMAC_CMD, CMD_RESET_VALUE);
    mmio::write(SYS_PORT_CTRL, 0);
    mmio::write(EXT_RGMII_OOB_CTRL, RGMII_RESET);
    mmio::write(EXT_GPHY_CTRL, GPHY_RESET);
    mmio::write(EXT_24, EXT_24_VALUE);
    mmio::write(UMAC_MDIO_CFG, MDIO_DIV << 4 | MDIO_C22);
}

fn mdio_read(phy: u32, reg: u32) -> Option<u16> {
    mmio::write(UMAC_MDIO_CMD, MDIO_RD | phy << MDIO_PMD_SHIFT | reg << MDIO_REG_SHIFT);
    mmio::write(UMAC_MDIO_CMD, mmio::read(UMAC_MDIO_CMD) | MDIO_START_BUSY);
    mdio_done()?;
    Some(mmio::read(UMAC_MDIO_CMD) as u16)
}

fn mdio_write(phy: u32, reg: u32, value: u16) -> Option<()> {
    let cmd = MDIO_WR | phy << MDIO_PMD_SHIFT | reg << MDIO_REG_SHIFT | value as u32;
    mmio::write(UMAC_MDIO_CMD, cmd);
    mmio::write(UMAC_MDIO_CMD, cmd | MDIO_START_BUSY);
    mdio_done()
}

fn mdio_done() -> Option<()> {
    let idle = timer::poll(MDIO_TIMEOUT_US, MDIO_POLL_US, || mmio::read(UMAC_MDIO_CMD) & MDIO_START_BUSY == 0);
    (idle && mmio::read(UMAC_MDIO_CMD) & MDIO_READ_FAIL == 0).then_some(())
}

/// A bus nobody drives reads all ones, and one whose PHY never drove it all
/// zeros.
fn answered(value: u16) -> bool {
    value != 0 && value != 0xffff
}

fn phy_id(phy: u32) -> Option<u32> {
    let high = mdio_read(phy, MII_PHYSID1).filter(|v| answered(*v))?;
    let low = mdio_read(phy, MII_PHYSID2)?;
    Some((high as u32) << 16 | low as u32)
}

fn find_phy() -> Option<u32> {
    PHY_ADDRESSES.into_iter().find(|phy| phy_id(*phy).is_some())
}

/// A Broadcom PHY keeps its analog side off while its IDDQ bit is set.
fn leave_iddq(phy: u32) -> Option<()> {
    mdio_write(phy, MII_EXT_SELECT, EXT_IDDQ)?;
    mdio_read(phy, MII_EXT_DATA)?;
    mdio_write(phy, MII_EXT_DATA, 0)?;
    mdio_write(phy, MII_EXT_SELECT, 0)
}

/// Take the PHY out of the power-down the OS left it in, reset it, offer 10
/// and 100 Mbit/s only, and wait for the link.
fn negotiate(phy: u32) -> Option<Link> {
    let id = phy_id(phy)?;
    if id & PHY_ID_OUI_MASK == PHY_ID_BROADCOM_OUI {
        leave_iddq(phy)?;
    }
    let control = mdio_read(phy, MII_BMCR)?;
    mdio_write(phy, MII_BMCR, control & !BMCR_PDOWN)?;
    mdio_write(phy, MII_BMCR, BMCR_RESET)?;
    timer::delay_us(BMCR_RESET_US);
    mdio_write(phy, MII_ADVERTISE, ADVERTISE_10_100)?;
    mdio_write(phy, MII_CTRL1000, 0)?;
    mdio_write(phy, MII_BMCR, BMCR_ANEG)?;
    let mut link = None;
    timer::poll(LINK_TIMEOUT_US, LINK_POLL_US, || {
        link = negotiated(phy);
        link.is_some()
    });
    link
}

fn shadow_read(phy: u32, shadow: u16) -> Option<u16> {
    mdio_write(phy, MII_SHADOW, shadow << SHADOW_NUMBER_SHIFT)?;
    Some(mdio_read(phy, MII_SHADOW)? & SHADOW_VALUE_MASK)
}

fn shadow_write(phy: u32, shadow: u16, value: u16) -> Option<()> {
    mdio_write(phy, MII_SHADOW, SHADOW_WRITE | shadow << SHADOW_NUMBER_SHIFT | value)
}

/// Put out the LEDs the PHY drives, the Ethernet port's, keeping what their
/// selectors were for [`leds_restore`]. The link and its negotiation do not
/// change. Only a Broadcom PHY is known to take it; whether it did.
fn leds_off(phy: u32) -> Option<()> {
    if phy_id(phy)? & PHY_ID_OUI_MASK != PHY_ID_BROADCOM_OUI {
        return None;
    }
    for (shadow, before) in SHADOW_LED_SELECTORS.into_iter().zip(&LED_SELECTORS_BEFORE) {
        before.store(shadow_read(phy, shadow)? as u32, Ordering::Relaxed);
    }
    LED_PHY.store(phy, Ordering::Relaxed);
    for shadow in SHADOW_LED_SELECTORS {
        shadow_write(phy, shadow, LEDS_OFF)?;
        (shadow_read(phy, shadow)? == LEDS_OFF).then_some(())?;
    }
    Some(())
}

/// Put the LEDs' selectors back to what [`leds_off`] found.
fn leds_restore() {
    let phy = LED_PHY.load(Ordering::Relaxed);
    if phy == NO_PHY {
        return;
    }
    for (shadow, before) in SHADOW_LED_SELECTORS.into_iter().zip(&LED_SELECTORS_BEFORE) {
        shadow_write(phy, shadow, before.load(Ordering::Relaxed) as u16);
    }
    LED_PHY.store(NO_PHY, Ordering::Relaxed);
}

/// The link the PHY has negotiated, with what the partner offers weighed
/// against what was offered it.
fn negotiated(phy: u32) -> Option<Link> {
    let status = mdio_read(phy, MII_BMSR)?;
    if status & BMSR_LINK_AND_ANEG_DONE != BMSR_LINK_AND_ANEG_DONE {
        return None;
    }
    let both = mdio_read(phy, MII_LPA)? & mdio_read(phy, MII_ADVERTISE)?;
    let (mbit_s, full_duplex) = if both & LPA_100FULL != 0 {
        (100, true)
    } else if both & LPA_100HALF != 0 {
        (100, false)
    } else if both & LPA_10FULL != 0 {
        (10, true)
    } else if both & LPA_10HALF != 0 {
        (10, false)
    } else {
        return None;
    };
    Some(Link { mbit_s, full_duplex })
}

/// Put the MAC at the link's speed with its address in and only its receiver
/// on, the DMA engines off and their status read back as off.
fn receive(mac: [u8; 6], link: Link) {
    mmio::write(SYS_RBUF_FLUSH_CTRL, 0);
    mmio::write(SYS_TBUF_FLUSH_CTRL, 0);
    mmio::write(SYS_PORT_CTRL, PORT_EXT_GPHY);
    mmio::write(EXT_RGMII_OOB_CTRL, RGMII_LINK_UP);
    mmio::write(EXT_GPHY_CTRL, 0);
    mmio::write(EXT_24, EXT_24_VALUE);
    mmio::write(UMAC_CMD, CMD_SW_RESET_LOOPBACK);
    stop_dma();
    mmio::write(INTRL2_CLEAR, u32::MAX);
    mmio::write(INTRL2_MASK_CLEAR, IRQ_MPD_R);
    mmio::write(UMAC_MAC0, u32::from_be_bytes([mac[0], mac[1], mac[2], mac[3]]));
    mmio::write(UMAC_MAC1, u32::from_be_bytes([0, 0, mac[4], mac[5]]));
    mmio::write(UMAC_MAX_FRAME_LEN, MAX_FRAME);
    mmio::write(UMAC_MIB_CTRL, mmio::read(UMAC_MIB_CTRL) | MIB_RESET);
    mmio::write(UMAC_MIB_CTRL, 0);
    let speed = if link.mbit_s == 10 { 0 } else { 1 };
    let duplex = if link.full_duplex { 0 } else { CMD_HD_EN };
    mmio::write(
        UMAC_CMD,
        CMD_TX_PAUSE_IGNORE | CMD_RX_PAUSE_IGNORE | speed << CMD_SPEED_SHIFT | duplex | CMD_CRC_FWD | CMD_RX_EN,
    );
}

/// Both DMA engines off, and the buffers behind them flushed: a frame the
/// MAC takes is not written to memory.
fn stop_dma() {
    mmio::write(RDMA_CTRL, mmio::read(RDMA_CTRL) & !DMA_EN);
    mmio::write(TDMA_CTRL, mmio::read(TDMA_CTRL) & !DMA_EN);
    timer::poll(DMA_STOP_US, DMA_STOP_POLL_US, || {
        mmio::read(RDMA_CTRL + DMA_STATUS_OFFSET) & DMA_STATUS_DISABLED != 0
            && mmio::read(TDMA_CTRL + DMA_STATUS_OFFSET) & DMA_STATUS_DISABLED != 0
    });
    mmio::write(SYS_RBUF_FLUSH_CTRL, 1);
    mmio::write(SYS_TBUF_FLUSH_CTRL, 1);
    timer::delay_us(FLUSH_US);
    mmio::write(SYS_RBUF_FLUSH_CTRL, 0);
    mmio::write(SYS_TBUF_FLUSH_CTRL, 0);
}

/// The magic packet detector on, as `bcmgenet_wol_power_down_cfg` sets it, and
/// the wait for the receive side to say it is in that mode.
fn arm_detector() {
    mmio::write(INTRL2_CLEAR, IRQ_MPD_R);
    mmio::write(UMAC_MPD_CTRL, mmio::read(UMAC_MPD_CTRL) | MPD_EN);
    mmio::write(HFB_CTRL, mmio::read(HFB_CTRL) | RBUF_ACPI_EN);
    if !timer::poll(DETECTOR_READY_US, 1000, || mmio::read(RBUF_STATUS) & RBUF_STATUS_WOL != 0) {
        crate::warn!("wake", "the receiver did not say it is in wake-on-LAN mode");
    }
}

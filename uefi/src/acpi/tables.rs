//! The ACPI tables of a Raspberry Pi 4 as a server's operating system wants
//! them: the interrupt controller, the timers, the console, the TPM on the
//! VPU, and the devices a headless server uses, laid out in one block.

use alloc::vec::Vec;

use super::aml::{self, Bytes, Value};

/// What the tables say that the board and the VPU decide.
pub struct Machine {
    /// The base of the TPM's command response buffer window, when the VPU
    /// has one.
    pub tpm: Option<u64>,
    /// The address of the network interface, when the VPU gives it one.
    pub ethernet: Option<[u8; 6]>,
    /// How many cores the tables enable.
    pub cores: u32,
}

const OEM_ID: &[u8; 6] = b"PI4FW ";
const OEM_TABLE_ID: &[u8; 8] = b"PI4SRVFW";
const CREATOR_ID: &[u8; 4] = b"RSTY";
const HEADER: usize = 36;

const GIC_DISTRIBUTOR: u64 = 0xff84_1000;
const GIC_CPU_INTERFACE: u64 = 0xff84_2000;
const GIC_HYPERVISOR: u64 = 0xff84_4000;
const GIC_VIRTUAL_CPU_INTERFACE: u64 = 0xff84_6000;
const MAINTENANCE_GSIV: u32 = 25;
const PMU_GSIV: u32 = 48;

/// Where the armstub's mailboxes for the ACPI parking protocol are, one for
/// each core, and the version of the protocol they speak.
const PARKING_MAILBOXES: u64 = 0x800;
const PARKING_MAILBOX_SIZE: u64 = 16;
const PARKING_VERSION: u32 = 1;

const SECURE_TIMER_GSIV: u32 = 29;
const NON_SECURE_TIMER_GSIV: u32 = 30;
const VIRTUAL_TIMER_GSIV: u32 = 27;
const HYPERVISOR_TIMER_GSIV: u32 = 26;

const UART0: u32 = 0xfe20_1000;
const UART0_GSIV: u32 = 153;

/// Mailbox 1's write register and status as the ARM sees them.
const MAILBOX_WRITE: u32 = 0xfe00_b8a0;
const MAILBOX_STATUS: u32 = 0xfe00_b8b8;
const MAILBOX_FULL: u64 = 1 << 31;
const MAILBOX_TPM_MESSAGE: u64 = 6;
/// How many times of 10 microseconds the start method waits for room in the
/// mailbox before it fails.
const MAILBOX_WAITS: u64 = 10_000;

pub const CRB_SIZE: u32 = 0x1000;
const CRB_CONTROL_AREA: u64 = 0x40;
const TPM_START_METHOD_CRB_WITH_ACPI: u32 = 8;
const TPM_START_UUID: &str = "6bbf6cab-5463-4714-b7cd-f0203c0368d4";

const PM: u32 = 0xfe10_0000;
const PM_SIZE: u32 = 0x114;

const EMMC2: u32 = 0xfe34_0000;
const EMMC2_SIZE: u32 = 0x100;
const EMMC2_GSIV: u32 = 158;
const EMMC2_CLOCK_HZ: u64 = 100_000_000;
/// The capabilities that say the SD host does DMA: SDMA, ADMA1 and ADMA2. The
/// addresses its DMA wants differ between steppings of the chip, and the UEFI
/// firmware's driver runs it without too.
const SDHCI_DMA_CAPABILITIES: u64 = 0x0058_0000;

const GENET: u32 = 0xfd58_0000;
const GENET_SIZE: u32 = 0x10000;
const GENET_GSIVS: [u32; 2] = [189, 190];

struct Table {
    bytes: Vec<u8>,
}

impl Table {
    fn new(signature: &[u8; 4], revision: u8, oem_revision: u32) -> Table {
        let mut table = Table { bytes: Vec::new() };
        table.bytes.extend(signature);
        table.u32(0);
        table.u8(revision);
        table.u8(0);
        table.bytes.extend(OEM_ID);
        table.bytes.extend(OEM_TABLE_ID);
        table.u32(oem_revision);
        table.bytes.extend(CREATOR_ID);
        table.u32(1);
        table
    }

    fn u8(&mut self, v: u8) {
        self.bytes.push(v);
    }

    fn u16(&mut self, v: u16) {
        self.bytes.extend(v.to_le_bytes());
    }

    fn u32(&mut self, v: u32) {
        self.bytes.extend(v.to_le_bytes());
    }

    fn u64(&mut self, v: u64) {
        self.bytes.extend(v.to_le_bytes());
    }

    fn zeros(&mut self, n: usize) {
        self.bytes.resize(self.bytes.len() + n, 0);
    }

    /// A generic address structure for a register in memory.
    fn register(&mut self, address: u64, bits: u8, access: u8) {
        self.u8(0);
        self.u8(bits);
        self.u8(0);
        self.u8(access);
        self.u64(address);
    }

    fn finish(mut self) -> Vec<u8> {
        let length = self.bytes.len() as u32;
        self.bytes[4..8].copy_from_slice(&length.to_le_bytes());
        self.bytes[9] = checksum(&self.bytes);
        self.bytes
    }
}

/// The byte that makes the sum of `bytes`, with it in place of the byte at 9
/// (or wherever the caller left a zero), zero.
fn checksum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)).wrapping_neg()
}

fn fadt(dsdt: u64) -> Vec<u8> {
    const HARDWARE_REDUCED: u32 = 1 << 20;
    const ENTERPRISE_SERVER: u8 = 4;
    let mut t = Table::new(b"FACP", 6, 1);
    t.zeros(276 - HEADER);
    t.bytes[112..116].copy_from_slice(&HARDWARE_REDUCED.to_le_bytes());
    t.bytes[131] = 3;
    t.bytes[140..148].copy_from_slice(&dsdt.to_le_bytes());
    t.bytes[45] = ENTERPRISE_SERVER;
    t.finish()
}

fn madt(cores: u32) -> Vec<u8> {
    const GICC: u8 = 0xb;
    const GICD: u8 = 0xc;
    const ENABLED: u32 = 1;
    let mut t = Table::new(b"APIC", 5, 1);
    t.u32(0);
    t.u32(0);
    for core in 0..4 {
        t.u8(GICC);
        t.u8(80);
        t.u16(0);
        t.u32(core);
        t.u32(core);
        t.u32(if core < cores { ENABLED } else { 0 });
        let parked = core > 0;
        t.u32(if parked { PARKING_VERSION } else { 0 });
        t.u32(PMU_GSIV + core);
        t.u64(if parked { PARKING_MAILBOXES + PARKING_MAILBOX_SIZE * core as u64 } else { 0 });
        t.u64(GIC_CPU_INTERFACE);
        t.u64(GIC_VIRTUAL_CPU_INTERFACE);
        t.u64(GIC_HYPERVISOR);
        t.u32(MAINTENANCE_GSIV);
        t.u64(0);
        t.u64(core as u64);
        t.u8(0);
        t.u8(0);
        t.u16(0);
    }
    t.u8(GICD);
    t.u8(24);
    t.u16(0);
    t.u32(0);
    t.u64(GIC_DISTRIBUTOR);
    t.u32(0);
    t.u8(2);
    t.zeros(3);
    t.finish()
}

fn gtdt() -> Vec<u8> {
    const ACTIVE_LOW: u32 = 1 << 1;
    let mut t = Table::new(b"GTDT", 3, 1);
    t.u64(u64::MAX);
    t.u32(0);
    for gsiv in [SECURE_TIMER_GSIV, NON_SECURE_TIMER_GSIV, VIRTUAL_TIMER_GSIV, HYPERVISOR_TIMER_GSIV] {
        t.u32(gsiv);
        t.u32(ACTIVE_LOW);
    }
    t.u64(u64::MAX);
    t.u32(0);
    t.u32(0);
    t.u32(0);
    t.u32(0);
    t.finish()
}

fn spcr() -> Vec<u8> {
    const PL011: u8 = 3;
    const GIC: u8 = 1 << 3;
    const BAUD_115200: u8 = 7;
    const DWORD_ACCESS: u8 = 3;
    const NO_PARITY: u8 = 0;
    const ONE_STOP_BIT: u8 = 1;
    const NO_FLOW_CONTROL: u8 = 0;
    const TERMINAL_VT100: u8 = 0;
    const NOT_PCI: u16 = 0xffff;
    let mut t = Table::new(b"SPCR", 2, 1);
    t.u8(PL011);
    t.zeros(3);
    t.register(UART0 as u64, 32, DWORD_ACCESS);
    t.u8(GIC);
    t.u8(0);
    t.u32(UART0_GSIV);
    t.u8(BAUD_115200);
    t.u8(NO_PARITY);
    t.u8(ONE_STOP_BIT);
    t.u8(NO_FLOW_CONTROL);
    t.u8(TERMINAL_VT100);
    t.u8(0);
    t.u16(NOT_PCI);
    t.u16(NOT_PCI);
    t.zeros(3);
    t.u32(0);
    t.u8(0);
    t.u32(0);
    t.finish()
}

/// Cortex-A72 as the BCM2711 has it: 48 KiB instruction and 32 KiB data
/// caches in each core, and 1 MiB of unified cache for all of them.
fn pptt(cores: u32) -> Vec<u8> {
    const CACHE: u8 = 1;
    const PROCESSOR: u8 = 0;
    const CACHE_FLAGS_ALL_VALID: u32 = 0x7f;
    const PACKAGE_FLAGS: u32 = 1;
    const CORE_FLAGS: u32 = 0b11010;
    const READ_WRITE_ALLOCATE: u8 = 3;
    const DATA: u8 = 0;
    const INSTRUCTION: u8 = 1 << 2;
    const UNIFIED: u8 = 2 << 2;
    let mut t = Table::new(b"PPTT", 2, 1);

    let cache = |t: &mut Table, next: u32, size: u32, sets: u32, ways: u8, kind: u8| -> u32 {
        let at = t.bytes.len() as u32;
        t.u8(CACHE);
        t.u8(24);
        t.u16(0);
        t.u32(CACHE_FLAGS_ALL_VALID);
        t.u32(next);
        t.u32(size);
        t.u32(sets);
        t.u8(ways);
        t.u8(READ_WRITE_ALLOCATE | kind);
        t.u16(64);
        at
    };
    let processor = |t: &mut Table, flags: u32, parent: u32, id: u32, resources: &[u32]| -> u32 {
        let at = t.bytes.len() as u32;
        t.u8(PROCESSOR);
        t.u8(20 + 4 * resources.len() as u8);
        t.u16(0);
        t.u32(flags);
        t.u32(parent);
        t.u32(id);
        t.u32(resources.len() as u32);
        for resource in resources {
            t.u32(*resource);
        }
        at
    };

    let l2 = cache(&mut t, 0, 1 << 20, 1024, 16, UNIFIED);
    let package = processor(&mut t, PACKAGE_FLAGS, 0, 0, &[l2]);
    for core in 0..cores {
        let data = cache(&mut t, l2, 32 << 10, 256, 2, DATA);
        let instruction = cache(&mut t, l2, 48 << 10, 256, 3, INSTRUCTION);
        processor(&mut t, CORE_FLAGS, package, core, &[data, instruction]);
    }
    t.finish()
}

fn tpm2(crb: u64) -> Vec<u8> {
    const SERVER_PLATFORM: u16 = 1;
    let mut t = Table::new(b"TPM2", 3, 1);
    t.u16(SERVER_PLATFORM);
    t.u16(0);
    t.u64(crb + CRB_CONTROL_AREA);
    t.u32(TPM_START_METHOD_CRB_WITH_ACPI);
    t.zeros(12);
    t.finish()
}

fn processor(core: u32) -> Bytes {
    const NAMES: [&str; 4] = ["CPU0", "CPU1", "CPU2", "CPU3"];
    aml::device(NAMES[core as usize], &[
        aml::name("_HID", &aml::string("ACPI0007")),
        aml::name("_UID", &aml::integer(core as u64)),
    ])
}

fn console() -> Bytes {
    aml::device("URT0", &[
        aml::name("_HID", &aml::string("ARMH0011")),
        aml::name("_UID", &aml::integer(0)),
        aml::name("_CRS", &aml::resources(&[
            aml::memory32(UART0, 0x1000),
            aml::interrupts(&[UART0_GSIV], false),
        ])),
    ])
}

/// The TPM's start method: with the command in the buffer and `START` set,
/// ring the VPU's mailbox.
fn tpm_start() -> Bytes {
    let is_start_uuid = aml::equal(&aml::arg0(), &aml::uuid(TPM_START_UUID));
    let function = |n: u64| aml::equal(&aml::arg2(), &aml::integer(n));
    aml::method("_DSM", 4, true, &[
        aml::when(&is_start_uuid, &[
            aml::when(&function(0), &[aml::ret(&aml::buffer(&[0x03]))]),
            aml::when(&function(1), &[
                aml::store(&aml::integer(0), &aml::local0()),
                aml::repeat_while(&aml::bit_and(&aml::named("STA_"), &aml::integer(MAILBOX_FULL)), &[
                    aml::when(&aml::greater(&aml::local0(), &aml::integer(MAILBOX_WAITS)), &[aml::ret(&aml::integer(1))]),
                    aml::increment(&aml::local0()),
                    aml::stall(10),
                ]),
                aml::store(&aml::integer(MAILBOX_TPM_MESSAGE), &aml::named("WRT_")),
                aml::ret(&aml::integer(0)),
            ]),
        ]),
        aml::ret(&aml::buffer(&[0x00])),
    ])
}

fn tpm(crb: u64) -> Bytes {
    let mailbox = aml::operation_region("MBOX", MAILBOX_WRITE, 0x20);
    let registers = aml::dword_fields("MBOX", &[("WRT_", 0), ("STA_", MAILBOX_STATUS - MAILBOX_WRITE)]);
    aml::device("TPM0", &[
        aml::name("_HID", &aml::string("MSFT0101")),
        aml::name("_UID", &aml::integer(0)),
        aml::name("_CRS", &aml::resources(&[aml::memory32(crb as u32, CRB_SIZE)])),
        mailbox,
        registers,
        tpm_start(),
    ])
}

/// The power manager: the watchdog, and the reset the OS asks for, are the
/// driver the device tree's `compatible` names.
fn power_manager() -> Bytes {
    aml::device("PM00", &[
        aml::name("_HID", &aml::string("PRP0001")),
        aml::name("_UID", &aml::integer(0)),
        aml::name("_CRS", &aml::resources(&[aml::memory32(PM, PM_SIZE)])),
        aml::properties(&[("compatible", Value::Text("brcm,bcm2835-pm-wdt"))]),
    ])
}

/// The SD host: the regulator that would switch the card to 1.8 V is behind
/// the VPU, so the card stays at 3.3 V, and a slot has no card-detect line
/// to wait for.
fn sd_host() -> Bytes {
    aml::device("SDC0", &[
        aml::name("_HID", &aml::string("BRCME88C")),
        aml::name("_UID", &aml::integer(0)),
        aml::name("_CCA", &aml::integer(0)),
        aml::name("_CRS", &aml::resources(&[aml::memory32(EMMC2, EMMC2_SIZE), aml::interrupts(&[EMMC2_GSIV], true)])),
        aml::properties(&[
            ("clock-frequency", Value::Integer(EMMC2_CLOCK_HZ)),
            ("sdhci-caps-mask", Value::Integer(SDHCI_DMA_CAPABILITIES)),
            ("broken-cd", Value::Integer(1)),
            ("no-1-8-v", Value::Integer(1)),
        ]),
    ])
}

fn ethernet(address: Option<[u8; 6]>) -> Bytes {
    let mut properties = alloc::vec![("phy-mode", Value::Text("rgmii-rxid"))];
    if let Some(address) = address {
        properties.push(("mac-address", Value::Integers(address.iter().map(|b| *b as u64).collect())));
    }
    aml::device("ETH0", &[
        aml::name("_HID", &aml::string("BCM6E4E")),
        aml::name("_UID", &aml::integer(0)),
        aml::name("_CCA", &aml::integer(0)),
        aml::name("_CRS", &aml::resources(&[aml::memory32(GENET, GENET_SIZE), aml::interrupts(&GENET_GSIVS, false)])),
        aml::properties(&properties),
    ])
}

fn dsdt(machine: &Machine) -> Vec<u8> {
    let mut devices: Vec<Bytes> = (0..machine.cores).map(processor).collect();
    devices.extend([console(), power_manager(), sd_host(), ethernet(machine.ethernet)]);
    if let Some(crb) = machine.tpm {
        devices.push(tpm(crb));
    }
    let mut t = Table::new(b"DSDT", 2, 1);
    t.bytes.extend(aml::root_scope("_SB", &devices));
    t.finish()
}

fn rsdp(xsdt: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend(b"RSD PTR ");
    bytes.push(0);
    bytes.extend(OEM_ID);
    bytes.push(2);
    bytes.extend(0u32.to_le_bytes());
    bytes.extend(36u32.to_le_bytes());
    bytes.extend(xsdt.to_le_bytes());
    bytes.push(0);
    bytes.extend([0; 3]);
    bytes[8] = checksum(&bytes[..20]);
    bytes[32] = checksum(&bytes);
    bytes
}

fn xsdt(tables: &[u64]) -> Vec<u8> {
    let mut t = Table::new(b"XSDT", 1, 1);
    for address in tables {
        t.u64(*address);
    }
    t.finish()
}

/// What `assemble` hands back: the block the tables are in, and where in it
/// the RSDP is.
pub struct Block {
    pub bytes: Vec<u8>,
    pub rsdp: usize,
}

const ALIGN: usize = 16;

fn place(block: &mut Vec<u8>, bytes: &[u8]) -> usize {
    let at = block.len().next_multiple_of(ALIGN);
    block.resize(at, 0);
    block.extend(bytes);
    at
}

fn replace(block: &mut [u8], at: usize, bytes: &[u8]) {
    block[at..at + bytes.len()].copy_from_slice(bytes);
}

/// The tables for `machine` as one block that starts at physical address
/// `base`, with the RSDP first. A table's length does not depend on where it
/// is, so the tables that point at others go in first and are written again
/// once the others have their places.
pub fn assemble(machine: &Machine, base: u64) -> Block {
    let count = 5 + machine.tpm.is_some() as usize;
    let mut block = Vec::new();
    let rsdp_at = place(&mut block, &rsdp(0));
    let xsdt_at = place(&mut block, &xsdt(&alloc::vec![0; count]));
    let fadt_at = place(&mut block, &fadt(0));
    let dsdt_at = place(&mut block, &dsdt(machine));
    let mut entries = alloc::vec![fadt_at];
    entries.push(place(&mut block, &madt(machine.cores)));
    entries.push(place(&mut block, &gtdt()));
    entries.push(place(&mut block, &spcr()));
    entries.push(place(&mut block, &pptt(machine.cores)));
    if let Some(crb) = machine.tpm {
        entries.push(place(&mut block, &tpm2(crb)));
    }
    let address = |at: usize| base + at as u64;

    replace(&mut block, fadt_at, &fadt(address(dsdt_at)));
    let addresses: Vec<u64> = entries.iter().map(|at| address(*at)).collect();
    replace(&mut block, xsdt_at, &xsdt(&addresses));
    replace(&mut block, rsdp_at, &rsdp(address(xsdt_at)));
    Block { bytes: block, rsdp: rsdp_at }
}

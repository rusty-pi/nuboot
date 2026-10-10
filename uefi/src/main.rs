//! CrabEFI on the Raspberry Pi 4.
//!
//! The VPU firmware has already brought the board up: DRAM, clocks, the PL011
//! and the device tree. This payload turns what that tree says into CrabEFI's
//! platform description, hands it the SD card on EMMC2 and the PCIe root
//! complex the VL805's xHCI controller is behind, and lets the UEFI boot
//! manager take it from there.

#![no_std]
#![no_main]

mod entry;
mod pcie;

use core::panic::PanicInfo;

/// The ARM's view of the peripheral window (`0x7E00_0000` on the VPU's bus).
const PERIPHERALS: u64 = 0xFC00_0000;
const PERIPHERALS_END: u64 = 0x1_0000_0000;

/// PL011 (`uart0`).
const UART0: u64 = 0xFE20_1000;
/// EMMC2, the Arasan SDHCI the SD slot is on.
const EMMC2: u64 = 0xFE34_0000;
/// Power manager: the watchdog the board resets through.
const PM_RSTC: u64 = 0xFE10_001C;
const PM_WDOG: u64 = 0xFE10_0024;
const PM_PASSWORD: u32 = 0x5A00_0000;
const PM_RSTC_WRCFG_FULL_RESET: u32 = 0x20;
const PM_RSTC_WRCFG_CLR: u32 = 0xFFFF_FFCF;
/// `PM_RSTS` partition bits; 63 means halt to the bootloader.
const PM_RSTS: u64 = 0xFE10_0020;
const PM_RSTS_HALT: u32 = 0x555;

/// The word in the armstub's page (`uefi/stub/src/armstub.rs`) the VPU
/// firmware reads this firmware's watchdog requests from: a sequence number
/// in bits 31:24, what happened in 23:20 (1: `SetWatchdogTimer`, its seconds
/// in 19:0; 2: `ExitBootServices`). The VPU firmware beats the board's
/// watchdog until the span asked for runs out.
const WATCHDOG_WORD: u64 = 0xfc;
const WATCHDOG_SET: u32 = 1;
const WATCHDOG_EXIT: u32 = 2;

/// RNG200, which the bootcode left running.
const RNG_FIFO_DATA: u64 = 0xFE10_4020;
const RNG_FIFO_COUNT: u64 = 0xFE10_4024;

const MAX_REGIONS: usize = 32;
const PAGE: u64 = 4096;

struct GenericTimer;

impl crabefi::Timer for GenericTimer {
    fn current_ticks(&self) -> u64 {
        crabefi::time::read_counter()
    }

    fn ticks_per_second(&self) -> u64 {
        crabefi::time::counter_frequency()
    }
}

/// Resets through the power manager's watchdog, as `bcm2835-wdt` does.
struct WatchdogReset;

impl crabefi::ResetHandler for WatchdogReset {
    fn reset(&self, reset_type: crabefi::ResetType) -> ! {
        unsafe {
            if matches!(reset_type, crabefi::ResetType::Shutdown) {
                let rsts = mmio_read(PM_RSTS);
                mmio_write(PM_RSTS, PM_PASSWORD | (rsts & !0xFFF) | PM_RSTS_HALT);
            }
            mmio_write(PM_WDOG, PM_PASSWORD | 10);
            let rstc = mmio_read(PM_RSTC);
            mmio_write(
                PM_RSTC,
                PM_PASSWORD | (rstc & PM_RSTC_WRCFG_CLR) | PM_RSTC_WRCFG_FULL_RESET,
            );
        }
        loop {
            unsafe { core::arch::asm!("wfi") };
        }
    }
}

/// Hands `SetWatchdogTimer` and `ExitBootServices` to the VPU firmware, which
/// has the watchdog.
struct Hooks {
    seq: core::sync::atomic::AtomicU32,
}

impl Hooks {
    fn tell_vpu(&self, what: u32, seconds: u32) {
        use core::sync::atomic::Ordering;
        let seq = self.seq.load(Ordering::Relaxed).wrapping_add(1) & 0xff;
        self.seq.store(seq, Ordering::Relaxed);
        unsafe {
            mmio_write(WATCHDOG_WORD, seq << 24 | what << 20 | seconds.min(0xf_ffff));
            // The VPU reads memory past the ARM's caches.
            core::arch::asm!("dc civac, {0}", "dsb sy", in(reg) WATCHDOG_WORD);
        }
    }
}

impl crabefi::PlatformHooks for Hooks {
    fn set_watchdog_timer(&self, timeout_s: usize) {
        self.tell_vpu(WATCHDOG_SET, timeout_s.min(u32::MAX as usize) as u32);
    }

    fn on_exit_boot_services(&self) {
        self.tell_vpu(WATCHDOG_EXIT, 0);
    }
}

static HOOKS: Hooks = Hooks { seq: core::sync::atomic::AtomicU32::new(0) };

/// `EFI_RNG_PROTOCOL`'s source: words out of RNG200's FIFO.
fn rng200(buffer: &mut [u8]) -> bool {
    for chunk in buffer.chunks_mut(4) {
        let mut tries = 0u32;
        while unsafe { mmio_read(RNG_FIFO_COUNT) } & 0xff == 0 {
            tries += 1;
            if tries > 1_000_000 {
                return false;
            }
            core::hint::spin_loop();
        }
        let word = unsafe { mmio_read(RNG_FIFO_DATA) }.to_le_bytes();
        chunk.copy_from_slice(&word[..chunk.len()]);
    }
    true
}

unsafe fn mmio_read(addr: u64) -> u32 {
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

unsafe fn mmio_write(addr: u64, value: u32) {
    unsafe { core::ptr::write_volatile(addr as *mut u32, value) }
}

/// The memory map: RAM from the tree's `/memory`, less every range the tree
/// reserves (`/memreserve/`, `/reserved-memory`) and the tree itself, plus the
/// peripheral window.
struct MemoryMap {
    regions: [crabefi::MemoryRegion; MAX_REGIONS],
    len: usize,
}

impl MemoryMap {
    const fn new() -> Self {
        Self {
            regions: [crabefi::MemoryRegion {
                base: 0,
                size: 0,
                region_type: crabefi::MemoryType::Reserved,
            }; MAX_REGIONS],
            len: 0,
        }
    }

    fn push(&mut self, base: u64, size: u64, region_type: crabefi::MemoryType) {
        if size == 0 || self.len == MAX_REGIONS {
            return;
        }
        self.regions[self.len] = crabefi::MemoryRegion { base, size, region_type };
        self.len += 1;
    }

    /// Take `[base, base + size)` out of every RAM region and record it as
    /// reserved.
    fn reserve(&mut self, base: u64, size: u64) {
        let start = base & !(PAGE - 1);
        let end = (base + size).next_multiple_of(PAGE);
        let mut i = 0;
        while i < self.len {
            let r = self.regions[i];
            let r_end = r.base + r.size;
            if r.region_type != crabefi::MemoryType::Ram || end <= r.base || start >= r_end {
                i += 1;
                continue;
            }
            self.regions[i].size = start.saturating_sub(r.base).min(r.size);
            if end < r_end {
                self.push(end, r_end - end, crabefi::MemoryType::Ram);
            }
            i += 1;
        }
        self.push(start, end - start, crabefi::MemoryType::Reserved);
        self.compact();
    }

    fn compact(&mut self) {
        let mut out = 0;
        for i in 0..self.len {
            if self.regions[i].size != 0 {
                self.regions[out] = self.regions[i];
                out += 1;
            }
        }
        self.len = out;
        self.regions[..out].sort_unstable_by_key(|r| r.base);
    }

    fn as_slice(&self) -> &[crabefi::MemoryRegion] {
        &self.regions[..self.len]
    }
}

fn memory_map(tree: &fdt::Fdt, tree_addr: u64) -> MemoryMap {
    let mut map = MemoryMap::new();
    for region in tree.memory().regions() {
        let base = region.starting_address as u64;
        let size = region.size.unwrap_or(0) as u64;
        // Only RAM the identity map covers as normal memory.
        let end = (base + size).min(PERIPHERALS);
        if end > base {
            map.push(base, end - base, crabefi::MemoryType::Ram);
        }
    }
    for reservation in tree.memory_reservations() {
        map.reserve(reservation.address() as u64, reservation.size() as u64);
    }
    if let Some(reserved) = tree.find_node("/reserved-memory") {
        for child in reserved.children() {
            for reg in child.reg().into_iter().flatten() {
                map.reserve(reg.starting_address as u64, reg.size.unwrap_or(0) as u64);
            }
        }
    }
    // The spin table the secondary cores wait in.
    map.reserve(0, PAGE);
    map.reserve(tree_addr, tree.total_size() as u64);
    map.push(PERIPHERALS, PERIPHERALS_END - PERIPHERALS, crabefi::MemoryType::Mmio);
    map.compact();
    map
}

fn runtime_config() -> crabefi::RuntimePlatformConfig<'static> {
    unsafe extern "C" {
        static _deferred_buffer_start: u8;
        static _deferred_buffer_end: u8;
    }
    let start = core::ptr::addr_of!(_deferred_buffer_start) as u64;
    let end = core::ptr::addr_of!(_deferred_buffer_end) as u64;
    crabefi::RuntimePlatformConfig {
        time: crabefi::RuntimeTimeConfig {
            mechanism: crabefi::time_mechanism::UNSUPPORTED,
            reserved: 0,
            io_or_mmio_base: 0,
        },
        // Nothing answers PSCI on this board: after ExitBootServices the OS
        // resets through its own watchdog driver.
        reset: crabefi::RuntimeResetConfig {
            mechanism: crabefi::reset_mechanism::PSCI_SMC,
            reserved: 0,
            io_or_mmio_base: 0,
        },
        external_ranges: &[],
        deferred_buffer: crabefi::DeferredBufferConfig {
            base: start,
            size: (end - start) as usize,
        },
    }
}

/// EMMC2 as CrabEFI's MMIO SDHCI path wants it described.
fn emmc2() -> crabefi::fdt::DsdtDevice {
    let mut dev = crabefi::fdt::DsdtDevice::empty();
    dev.name = *b"EMC2";
    dev.hid[..8].copy_from_slice(b"BCM2711E");
    dev.hid_len = 8;
    dev.mmio_base = EMMC2;
    dev.mmio_size = 0x100;
    dev
}

static mut MAP: MemoryMap = MemoryMap::new();

#[unsafe(no_mangle)]
extern "C" fn pi4_main(tree_addr: u64) -> ! {
    crabefi::drivers::serial::init_from_config(&crabefi::drivers::serial::SerialConfig {
        mmio: true,
        baseaddr: UART0,
        baud: 115_200,
        regwidth: 4,
        input_hertz: 48_000_000,
    });
    crabefi::logger::init();
    log::info!("pi4-uefi: device tree at {:#x}", tree_addr);

    crabefi::time::init(None);
    crabefi::arch::aarch64::rng::set_platform_source(rng200);

    let tree = match unsafe { fdt::Fdt::from_ptr(tree_addr as *const u8) } {
        Ok(tree) => tree,
        Err(e) => panic!("no device tree at {tree_addr:#x}: {e:?}"),
    };
    let tree_bytes =
        unsafe { core::slice::from_raw_parts(tree_addr as *const u8, tree.total_size()) };

    let map = unsafe { &mut *(&raw mut MAP) };
    *map = memory_map(&tree, tree_addr);
    for r in map.as_slice() {
        log::info!(
            "  {:#011x}..{:#011x} {:?}",
            r.base,
            r.base + r.size,
            r.region_type
        );
    }

    let timer = GenericTimer;
    let reset = WatchdogReset;
    let mut config = crabefi::PlatformConfig {
        memory_map: map.as_slice(),
        timer: &timer,
        timestamp_recorder: None,
        reset: &reset,
        block_devices: &mut [],
        variable_storage: crabefi::VariableStorage::None,
        debug_output: None,
        console_input: None,
        framebuffer: None,
        acpi_rsdp: None,
        smbios: None,
        fdt: Some(tree_bytes),
        acpi_info: None,
        discover_mmio: false,
        firmware_info: None,
        capsule_regions: &[],
        capsule_backend: None,
        hooks: Some(&HOOKS),
        rng: None,
        ecam_regions: &[],
        runtime_image: crabefi::BUNDLED_RUNTIME_IMAGE,
        runtime: runtime_config(),
        heap_pre_initialized: false,
    };

    crabefi::efi::allocator::init_from_platform(config.memory_map);
    match crabefi::heap::init() {
        Ok(()) | Err(crabefi::heap::HeapInitError::AlreadyInitialized) => {
            config.heap_pre_initialized = true;
        }
        Err(e) => panic!("heap: {e}"),
    }

    if crabefi::drivers::sdhci::init_mmio_device(&emmc2(), crabefi::drivers::sdhci::SdhciMedia::Sd)
        .is_err()
    {
        log::warn!("pi4-uefi: no SD card on EMMC2");
    }

    crabefi::drivers::pci::set_platform_pci(&pcie::ROOT_COMPLEX);
    crabefi::init_platform(config)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    crabefi::drivers::serial::write_fmt(format_args!("\npi4-uefi: panic: {info}\n"));
    loop {
        unsafe { core::arch::asm!("wfe") };
    }
}

//! The UEFI firmware the ARM starts in: just what a headless server needs to
//! boot an operating system with Secure Boot, logging the way the rest of
//! the firmware does.
//!
//! The VPU firmware has already brought the board up: SDRAM, clocks, the
//! PL011, the PCIe link and the VL805, and the device tree. This builds the
//! memory map from that tree, finds the SD card and any USB drive, and boots
//! `\EFI\BOOT\BOOTAA64.EFI` from the first that has one.

#![no_std]
#![no_main]

extern crate alloc;

#[path = "../../src/log.rs"]
pub mod log;

mod acpi;
mod block;
mod bundle;
mod capsule;
mod conio;
mod console;
mod critical;
mod devpath;
mod diskstore;
mod dma;
mod eeprom;
mod entry;
mod esrt;
mod event;
mod fat;
mod fdt;
mod image;
mod mailbox;
mod mem;
mod nvstore;
mod proto;
mod pkcs7;
mod rng;
mod rsa;
mod rtmode;
mod rtusb;
mod rtvar;
mod sd;
mod secure;
mod setup;
#[path = "../../src/sha256.rs"]
#[allow(dead_code)]
mod sha256;
mod smbios;
mod spiflash;
mod stc;
mod store;
mod tcg2;
mod sync;
mod tables;
mod usbdisk;
mod util;
mod var;
mod watchdog;
mod window;
mod xhci;

use alloc::vec::Vec;
use core::ffi::c_void;
use core::panic::PanicInfo;

use r_efi::efi;
use r_efi::protocols::{loaded_image, simple_file_system};

use crate::devpath::{Builder, Text};
use crate::util::Hex;

#[global_allocator]
static HEAP: mem::FirmwareHeap = mem::FirmwareHeap;

/// The RAM the identity map in `entry.rs` maps as normal memory: below the
/// peripherals, and from 4 GiB to 8 GiB.
const PERIPHERALS: u64 = 0xFC00_0000;
const HIGH_RAM: (u64, u64) = (0x1_0000_0000, 0x2_0000_0000);
/// The 2 MiB `entry.rs` maps non-cacheable, for DMA.
pub const DMA_ARENA: (u64, u64) = (0x20_0000, 0x40_0000);

/// The commit this was built from, as the VPU firmware reports its own.
pub const COMMIT: &str = match option_env!("FIRMWARE_COMMIT") {
    Some(c) => c,
    None => "0000000",
};

/// The system table's `FirmwareRevision`: the release's major number in the
/// upper half and its minor number in the lower, 0 for a build that is no
/// release. `bootctl` shows it as `nuboot <major>.<minor>`.
pub const REVISION: u32 = match u32::from_str_radix(env!("FIRMWARE_REVISION"), 10) {
    Ok(revision) => revision,
    Err(_) => 0,
};

fn memory_map(tree: &fdt::Fdt, tree_addr: u64) {
    let map = mem::map();
    let (mut ac, mut sc) = (2, 1);
    let (mut rac, mut rsc) = (2, 1);
    tree.walk(|path, name, value| match (path, name) {
        ([_], b"#address-cells") => ac = fdt::cells(value),
        ([_], b"#size-cells") => sc = fdt::cells(value),
        ([_, n], b"reg") if n.starts_with(b"memory") => fdt::reg(value, ac, sc, |base, size| {
            let end = base + size;
            map.add_ram(base, end.min(PERIPHERALS));
            map.add_ram(base.max(HIGH_RAM.0), end.min(HIGH_RAM.1));
        }),
        _ => {}
    });
    let reserve = |base: u64, size: u64| mem::map().mark(base, base + size, efi::RESERVED_MEMORY_TYPE);
    tree.reservations(reserve);
    tree.walk(|path, name, value| match (path, name) {
        ([_, b"reserved-memory"], b"#address-cells") => rac = fdt::cells(value),
        ([_, b"reserved-memory"], b"#size-cells") => rsc = fdt::cells(value),
        ([_, b"reserved-memory", _], b"reg") => fdt::reg(value, rac, rsc, reserve),
        _ => {}
    });
    unsafe extern "C" {
        static _image_start: u8;
        static _rt_end: u8;
        static _end: u8;
    }
    let (start, runtime_end, end) = (&raw const _image_start as u64, &raw const _rt_end as u64, &raw const _end as u64);
    // The armstub's page: the spin table the secondary cores wait on, and the
    // watchdog word.
    map.mark(0, mem::PAGE, efi::RESERVED_MEMORY_TYPE);
    // What the runtime services reach the board through: the mailbox to the VPU,
    // and the power manager, which resets it.
    map.add_mmio(rtvar::MAILBOX_PAGE, rtvar::MAILBOX_PAGE + mem::PAGE);
    map.add_mmio(watchdog::PM_PAGE, watchdog::PM_PAGE + mem::PAGE);
    map.add_mmio(sd::EMMC2_PAGE, sd::EMMC2_PAGE + mem::PAGE);
    // The DMA arena stays for the runtime services, which bring the USB
    // controller up again to write the variable store to a drive.
    map.mark(DMA_ARENA.0, DMA_ARENA.1, efi::RUNTIME_SERVICES_DATA);
    for (start, end) in xhci::RUNTIME_MMIO {
        map.add_mmio(start, end);
    }
    map.mark(tree_addr, tree_addr + tree.size() as u64, efi::BOOT_SERVICES_DATA);
    map.mark(start, runtime_end, efi::RUNTIME_SERVICES_CODE);
    map.mark(runtime_end, end, efi::BOOT_SERVICES_CODE);
}

/// A handle for this firmware itself, the parent of what it loads.
fn firmware_handle() -> efi::Handle {
    let li = alloc::boxed::Box::leak(alloc::boxed::Box::new(loaded_image::Protocol {
        revision: loaded_image::REVISION,
        parent_handle: core::ptr::null_mut(),
        system_table: tables::system_table(),
        device_handle: core::ptr::null_mut(),
        file_path: core::ptr::null_mut(),
        reserved: core::ptr::null_mut(),
        load_options_size: 0,
        load_options: core::ptr::null_mut(),
        image_base: core::ptr::null_mut(),
        image_size: 0,
        image_code_type: efi::BOOT_SERVICES_CODE,
        image_data_type: efi::BOOT_SERVICES_DATA,
        unload: None,
    }));
    proto::install(core::ptr::null_mut(), &loaded_image::PROTOCOL_GUID, li as *mut _ as *mut c_void).unwrap()
}

pub const REMOVABLE_PATH: &str = "\\EFI\\BOOT\\BOOTAA64.EFI";

/// Boot the removable-media path of each file system in turn, in the order
/// the drivers found them: the SD card, then USB.
fn boot(parent: efi::Handle) {
    let name: Vec<u16> = REMOVABLE_PATH.encode_utf16().collect();
    for fs in proto::with(Some(&simple_file_system::PROTOCOL_GUID)) {
        let Some(dp) = proto::get(fs, &r_efi::protocols::device_path::PROTOCOL_GUID) else { continue };
        let path = Builder::from(devpath::bytes(dp as *const u8)).file(&name).done();
        tcg2::boot_option(Some(&path));
        let loaded = image::load(parent, path.as_ptr(), None);
        tcg2::boot_option(None);
        let handle = match loaded {
            Ok(h) => h,
            Err(efi::Status::NOT_FOUND) => continue,
            Err(s) => {
                warn!("boot", "boot option did not load"; path = Text(&path), status = Hex(s.as_usize()));
                continue;
            }
        };
        info!("boot", "booting"; path = Text(&path));
        let status = image::start(handle, core::ptr::null_mut(), core::ptr::null_mut());
        warn!("boot", "boot option returned"; path = Text(&path), status = Hex(status.as_usize()));
    }
}

#[unsafe(no_mangle)]
extern "C" fn pi4_main(tree_addr: u64) -> ! {
    info!("uefi", "UEFI firmware started"; commit = COMMIT, version = esrt::VERSION, tree = Hex(tree_addr));
    watchdog::start();
    let Some(tree) = fdt::Fdt::at(tree_addr) else {
        error!("uefi", "no device tree, stopping"; at = Hex(tree_addr));
        util::halt()
    };
    memory_map(&tree, tree_addr);
    let map = mem::map();
    info!("mem", "memory map ready"; ram_mib = map.total_mib(), free_mib = map.total_free_mib(), regions = map.len());

    let (con_in, con_out) = conio::init();
    let console = conio::install();
    tables::init(console, con_in, con_out);
    tables::install_table(tables::DTB_GUID, tree_addr as *mut c_void);
    rng::install();
    tcg2::init();
    esrt::init();
    sd::init();
    xhci::init();
    diskstore::choose();
    secure::init();
    let parent = firmware_handle();

    acpi::init(&tree, xhci::registers_base());
    smbios::init(&tree);

    tcg2::measure_handoff_tables(&[acpi::ACPI_20_TABLE_GUID, smbios::SMBIOS3_TABLE_GUID]);
    tcg2::separators();
    capsule::scan();
    setup::show_if_asked(&tree);
    boot(parent);
    error!("boot", "nothing to boot, the boot watchdog will reset the board"; looked_for = REMOVABLE_PATH);
    util::halt()
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    let (file, line) = info.location().map_or(("?", 0), |l| (l.file(), l.line()));
    log::panic_record(format_args!("{}", info.message()), file, line);
    util::halt()
}

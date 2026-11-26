//! After `ExitBootServices`, an OS that moves the runtime regions hands the
//! firmware a map with new virtual addresses at `SetVirtualAddressMap` and
//! then calls the runtime services there, with no identity mapping of the
//! registers they use: a write that goes through a physical address faults.
//!
//! Like Windows, the application takes the service addresses from the table
//! before the call and moves them itself.
//!
//! The application builds the translation tables such an OS would: the
//! first 4 GiB of memory where it is and again at an offset, and the devices
//! as device memory at the offset only.

#![no_std]
#![no_main]

use core::arch::asm;
use core::ffi::c_void;
use core::ptr::addr_of_mut;

use r_efi::efi::{self, Guid, Handle, MemoryDescriptor, Status, SystemTable};
use runtime_efi::{check, exit_boot_services, final_map, name, say};

const OFFSET: u64 = 1 << 40;
const BS_RT_NV: u32 = efi::VARIABLE_BOOTSERVICE_ACCESS | efi::VARIABLE_RUNTIME_ACCESS | efi::VARIABLE_NON_VOLATILE;
const OURS: Guid = Guid::from_fields(0x6b1c0a52, 0x3a7e, 0x4d1f, 0x9a, 0x0b, &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);

const BLOCK: u64 = 1;
const TABLE: u64 = 3;
const ACCESS: u64 = 1 << 10;
const INNER_SHAREABLE: u64 = 3 << 8;
const DEVICE: u64 = 0 << 2;
const NORMAL: u64 = (1 << 2) | INNER_SHAREABLE;
const GIB: u64 = 1 << 30;
const MIB2: u64 = 2 << 20;
const PERIPHERALS: u64 = 0xfc00_0000;

#[repr(C, align(4096))]
struct Table([u64; 512]);

static mut L0: Table = Table([0; 512]);
static mut L1_IDENTITY: Table = Table([0; 512]);
static mut L1_RELOCATED: Table = Table([0; 512]);
static mut L2_IDENTITY: Table = Table([0; 512]);
static mut L2_RELOCATED: Table = Table([0; 512]);

fn build_tables() -> u64 {
    unsafe {
        let identity = &mut (*addr_of_mut!(L2_IDENTITY)).0;
        let relocated = &mut (*addr_of_mut!(L2_RELOCATED)).0;
        for n in 0..512 {
            let pa = 3 * GIB + n as u64 * MIB2;
            if pa >= PERIPHERALS {
                relocated[n] = pa | BLOCK | ACCESS | DEVICE;
            } else {
                identity[n] = pa | BLOCK | ACCESS | NORMAL;
                relocated[n] = pa | BLOCK | ACCESS | NORMAL;
            }
        }
        for (l1, l2) in [(addr_of_mut!(L1_IDENTITY), addr_of_mut!(L2_IDENTITY)), (addr_of_mut!(L1_RELOCATED), addr_of_mut!(L2_RELOCATED))] {
            let l1 = &mut (*l1).0;
            for gib in 0..3u64 {
                l1[gib as usize] = gib * GIB | BLOCK | ACCESS | NORMAL;
            }
            l1[3] = l2 as u64 | TABLE;
        }
        let l0 = &mut (*addr_of_mut!(L0)).0;
        l0[0] = addr_of_mut!(L1_IDENTITY) as u64 | TABLE;
        l0[(OFFSET >> 39) as usize] = addr_of_mut!(L1_RELOCATED) as u64 | TABLE;
        addr_of_mut!(L0) as u64
    }
}

fn switch_tables(root: u64) {
    let range: u64;
    unsafe { asm!("mrs {0}, ID_AA64MMFR0_EL1", out(reg) range) };
    let tcr = 16 | (1 << 8) | (1 << 10) | (3 << 12) | ((range & 0xf) << 16) | (1 << 23) | (1 << 31);
    let mair: u64 = 0xff << 8;
    unsafe {
        asm!(
            "dsb sy",
            "msr MAIR_EL2, {mair}",
            "msr TCR_EL2, {tcr}",
            "msr TTBR0_EL2, {root}",
            "isb",
            "tlbi alle2",
            "dsb sy",
            "isb",
            mair = in(reg) mair,
            tcr = in(reg) tcr,
            root = in(reg) root,
        );
    }
}

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(image: Handle, system_table: *mut SystemTable) -> Status {
    let rt = exit_boot_services(image, system_table);
    runtime_efi::settle();
    let (set_variable, get_variable) = unsafe { ((*rt).set_variable as u64, (*rt).get_variable as u64) };
    let (map, size, desc_size, version) = final_map();
    for i in 0..size / desc_size {
        let d = unsafe { &mut *((map as *mut u8).add(i * desc_size) as *mut MemoryDescriptor) };
        if d.attribute & efi::MEMORY_RUNTIME != 0 {
            d.virtual_start = d.physical_start + OFFSET;
        }
    }
    let status = unsafe { ((*rt).set_virtual_address_map)(size, desc_size, version, map) };
    check("SetVirtualAddressMap takes the moved map", status == Status::SUCCESS);
    switch_tables(build_tables());
    runtime_efi::use_uart_at(runtime_efi::UART0 + OFFSET as usize);
    say("runtime test: the tables with the runtime regions moved are in use\r\n");

    type SetVariable = extern "efiapi" fn(*mut u16, *mut Guid, u32, usize, *mut c_void) -> Status;
    type GetVariable = extern "efiapi" fn(*mut u16, *mut Guid, *mut u32, *mut usize, *mut c_void) -> Status;
    let set_variable: SetVariable = unsafe { core::mem::transmute(set_variable + OFFSET) };
    let get_variable: GetVariable = unsafe { core::mem::transmute(get_variable + OFFSET) };
    let mut buf = [0u16; 32];
    let var = name("Relocated", &mut buf);
    let mut guid = OURS;
    let data = [7u8, 8, 9];
    let status = set_variable(var, &mut guid, BS_RT_NV, data.len(), data.as_ptr() as *mut c_void);
    check("a variable is set through the moved runtime services", status == Status::SUCCESS);
    let (mut out, mut length, mut attributes) = ([0u8; 8], 8usize, 0u32);
    let status = get_variable(var, &mut guid, &mut attributes, &mut length, out.as_mut_ptr() as *mut c_void);
    check("it reads back", status == Status::SUCCESS && out[..length] == data);
    say("runtime test: done\r\n");
    runtime_efi::hang()
}

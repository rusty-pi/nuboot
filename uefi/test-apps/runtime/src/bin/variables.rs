//! After `ExitBootServices`, the variable services answer from the runtime
//! table: reads of the firmware's own variables, writes of new ones, and the
//! protection of the keys.

#![no_std]
#![no_main]

use core::ffi::c_void;

use r_efi::efi::{self, Guid, Handle, RuntimeServices, Status, SystemTable};
use runtime_efi::{check, exit_boot_services, name, say};

const BS_RT: u32 = efi::VARIABLE_BOOTSERVICE_ACCESS | efi::VARIABLE_RUNTIME_ACCESS;
const NV: u32 = efi::VARIABLE_NON_VOLATILE;
const APPEND: u32 = efi::VARIABLE_APPEND_WRITE;
const GLOBAL: Guid = Guid::from_fields(0x8be4df61, 0x93ca, 0x11d2, 0xaa, 0x0d, &[0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c]);
const SECURITY_DB: Guid = Guid::from_fields(0xd719b2cb, 0x3d3a, 0x4596, 0xa3, 0xbc, &[0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f]);
const OURS: Guid = Guid::from_fields(0x6b1c0a52, 0x3a7e, 0x4d1f, 0x9a, 0x0b, &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);

fn set(rt: *mut RuntimeServices, var: &str, guid: &Guid, attributes: u32, data: &[u8]) -> Status {
    let mut buf = [0u16; 32];
    let n = name(var, &mut buf);
    let mut guid = *guid;
    unsafe { ((*rt).set_variable)(n, &mut guid, attributes, data.len(), data.as_ptr() as *mut c_void) }
}

fn get(rt: *mut RuntimeServices, var: &str, guid: &Guid, out: &mut [u8]) -> (Status, usize, u32) {
    let mut buf = [0u16; 32];
    let n = name(var, &mut buf);
    let mut guid = *guid;
    let (mut size, mut attributes) = (out.len(), 0u32);
    let status = unsafe { ((*rt).get_variable)(n, &mut guid, &mut attributes, &mut size, out.as_mut_ptr() as *mut c_void) };
    (status, size, attributes)
}

const ESRT: Guid = Guid::from_fields(0xb122a263, 0x3661, 0x4f68, 0x99, 0x29, &[0x78, 0xf8, 0xb0, 0xd6, 0x21, 0x80]);

fn check_esrt(system_table: *mut SystemTable) {
    let tables = unsafe { core::slice::from_raw_parts((*system_table).configuration_table, (*system_table).number_of_table_entries) };
    let Some(table) = tables.iter().find(|t| t.vendor_guid == ESRT) else {
        check("the ESRT is installed", false);
        return;
    };
    let words = table.vendor_table as *const u32;
    let word = |i: usize| unsafe { *words.add(i) };
    let (count, version) = (word(0), word(2));
    let (kind, firmware_version, status) = (word(8), word(9), word(13));
    check(
        "the ESRT has the firmware, the update and the EEPROM bootloader",
        count == 3 && version == 1 && kind == 1 && word(18) == 1 && word(28) == 2,
    );
    check("the ESRT carries a version and no failed attempt", firmware_version > 0 && status == 0);
}

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(image: Handle, system_table: *mut SystemTable) -> Status {
    let boot_rt = unsafe { (*system_table).runtime_services };
    check("a boot-time volatile variable is made", set(boot_rt, "BootMade", &OURS, BS_RT, &[1, 2, 3]) == Status::SUCCESS);
    let rt = exit_boot_services(image, system_table);
    runtime_efi::settle();
    check_esrt(system_table);
    let mut out = [0u8; 4096];

    let (status, size, attributes) = get(rt, "SecureBoot", &GLOBAL, &mut out);
    check("SecureBoot is read", status == Status::SUCCESS && size == 1 && out[0] == 1 && attributes & BS_RT == BS_RT);
    let (status, size, _) = get(rt, "OsIndicationsSupported", &GLOBAL, &mut out);
    check("file capsule delivery is supported", status == Status::SUCCESS && size == 8 && out[0] & 4 != 0);
    check("OsIndications is set", set(rt, "OsIndications", &GLOBAL, BS_RT | NV, &[4, 0, 0, 0, 0, 0, 0, 0]) == Status::SUCCESS);
    let (status, size, _) = get(rt, "OsIndications", &GLOBAL, &mut out);
    check("OsIndications reads back", status == Status::SUCCESS && out[..size] == [4, 0, 0, 0, 0, 0, 0, 0]);
    check("SecureBoot is not writable", set(rt, "SecureBoot", &GLOBAL, BS_RT, &[0]) == Status::WRITE_PROTECTED);
    check("PK is not writable", set(rt, "PK", &GLOBAL, BS_RT | NV, &[0]) == Status::WRITE_PROTECTED);
    check("PK is not deleted", set(rt, "PK", &GLOBAL, 0, &[]) == Status::WRITE_PROTECTED);
    check("db refuses a write without a signature", set(rt, "db", &SECURITY_DB, BS_RT | NV, &[0]) == Status::INVALID_PARAMETER);

    check("a new variable is set", set(rt, "RtTest", &OURS, BS_RT | NV, &[1, 2, 3]) == Status::SUCCESS);
    let (status, size, _) = get(rt, "RtTest", &OURS, &mut out);
    check("it reads back", status == Status::SUCCESS && out[..size] == [1, 2, 3]);
    check("it appends", set(rt, "RtTest", &OURS, BS_RT | NV | APPEND, &[4, 5]) == Status::SUCCESS);
    let (_, size, _) = get(rt, "RtTest", &OURS, &mut out);
    check("the append reads back", out[..size] == [1, 2, 3, 4, 5]);
    check("it is replaced", set(rt, "RtTest", &OURS, BS_RT | NV, &[9]) == Status::SUCCESS);
    let (_, size, _) = get(rt, "RtTest", &OURS, &mut out);
    check("the replacement reads back", out[..size] == [9]);
    check("other attributes are refused", set(rt, "RtTest", &OURS, BS_RT, &[1]) == Status::INVALID_PARAMETER);
    check("a volatile variable is not created at runtime", set(rt, "RtVolatile", &OURS, BS_RT, &[1]) == Status::INVALID_PARAMETER);
    check("a volatile variable of the boot chain is read", get(rt, "BootMade", &OURS, &mut out).1 == 3);
    check("it is not overwritten", set(rt, "BootMade", &OURS, BS_RT, &[9]) == Status::WRITE_PROTECTED);
    check("it is not deleted", set(rt, "BootMade", &OURS, 0, &[]) == Status::WRITE_PROTECTED);
    check("it is not replaced by a non-volatile one", set(rt, "BootMade", &OURS, BS_RT | NV, &[9]) == Status::WRITE_PROTECTED);
    check("no runtime access is refused", set(rt, "RtOther", &OURS, efi::VARIABLE_BOOTSERVICE_ACCESS, &[1]) == Status::INVALID_PARAMETER);

    let (status, size, _) = get(rt, "RtTest", &OURS, &mut out[..0]);
    check("a short buffer is told the size", status == Status::BUFFER_TOO_SMALL && size == 1);
    let (status, _, _) = get(rt, "RtMissing", &OURS, &mut out);
    check("a missing variable is not found", status == Status::NOT_FOUND);

    let (mut seen, mut found) = (0, false);
    let mut next_name = [0u16; 32];
    let mut next_guid = Guid::from_fields(0, 0, 0, 0, 0, &[0; 6]);
    loop {
        let mut size = core::mem::size_of_val(&next_name);
        let status = unsafe { ((*rt).get_next_variable_name)(&mut size, next_name.as_mut_ptr(), &mut next_guid) };
        if status != Status::SUCCESS {
            check("the walk ends", status == Status::NOT_FOUND);
            break;
        }
        seen += 1;
        found |= next_guid == OURS && next_name[..6] == [b'R' as u16, b't' as u16, b'T' as u16, b'e' as u16, b's' as u16, b't' as u16];
        if seen > 64 {
            break;
        }
    }
    check("the walk finds the new variable among the firmware's", found && seen >= 6);

    check("it is deleted", set(rt, "RtTest", &OURS, 0, &[]) == Status::SUCCESS);
    let (status, _, _) = get(rt, "RtTest", &OURS, &mut out);
    check("the deleted variable is gone", status == Status::NOT_FOUND);

    let block = [0xa5u8; 3000];
    let mut churned = true;
    for round in 0..200u32 {
        churned &= set(rt, "RtChurn", &OURS, BS_RT | NV, &block[..1000 + (round as usize % 2000)]) == Status::SUCCESS;
    }
    let (status, size, _) = get(rt, "RtChurn", &OURS, &mut out[..]);
    check("rewriting a variable reuses the table", churned && status == Status::SUCCESS && size == 1000 + (199 % 2000));
    let (status, size, _) = get(rt, "SecureBoot", &GLOBAL, &mut out);
    check("the firmware's variables survive it", status == Status::SUCCESS && size == 1);

    let (mut max, mut remaining, mut largest) = (0u64, 0u64, 0u64);
    let status = unsafe { ((*rt).query_variable_info)(BS_RT, &mut max, &mut remaining, &mut largest) };
    check("the table's size is reported", status == Status::SUCCESS && remaining < max && largest > 0);

    say("runtime test: done\r\n");
    runtime_efi::hang()
}

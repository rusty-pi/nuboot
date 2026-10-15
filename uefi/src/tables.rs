//! The EFI system table, boot services and runtime services, and
//! `ExitBootServices`.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::arch::global_asm;
use core::ffi::c_void;

use r_efi::efi;
use r_efi::protocols::device_path;

use crate::util::{Global, Hex};
use crate::{event, image, info, mem, proto, rtvar, var, warn};

static ST: Global<*mut efi::SystemTable> = Global::new(core::ptr::null_mut());
static TPL: Global<efi::Tpl> = Global::new(efi::TPL_APPLICATION);
static MONOTONIC: Global<u64> = Global::new(0);
/// Called on `ExitBootServices`, before anything else, to stop DMA.
static QUIESCE: Global<Vec<fn()>> = Global::new(Vec::new());
static BEFORE_EXIT: Global<Vec<fn()>> = Global::new(Vec::new());

/// The runtime data page: the system table, the runtime services, the
/// configuration tables and the vendor string, which the OS reads after
/// `ExitBootServices`.
#[repr(C)]
struct RuntimeData {
    st: efi::SystemTable,
    rt: efi::RuntimeServices,
    rt_properties: RtProperties,
    config: [efi::ConfigurationTable; MAX_CONFIG],
    vendor: [u16; 20],
}

const MAX_CONFIG: usize = 16;

/// `EFI_RT_PROPERTIES_TABLE`: which runtime services work after
/// `ExitBootServices`: the variable services, from [`crate::rtvar`], and
/// `ResetSystem`, from [`crate::watchdog`]. The OS does not call
/// `SetVirtualAddressMap`, so it maps the runtime regions where they are.
#[repr(C)]
struct RtProperties {
    version: u16,
    length: u16,
    supported: u32,
}

const RT_VARIABLE_SERVICES: u32 = 0x10 | 0x20 | 0x40 | 0x2000;
const RT_RESET_SYSTEM: u32 = 0x400;

const RT_PROPERTIES_GUID: efi::Guid =
    efi::Guid::from_fields(0xeb66918a, 0x7eef, 0x402a, 0x84, 0x2e, &[0x93, 0x1d, 0x21, 0xc3, 0x8a, 0xe9]);
/// `EFI_DTB_TABLE_GUID`.
pub const DTB_GUID: efi::Guid =
    efi::Guid::from_fields(0xb1b621d5, 0xf19c, 0x41a5, 0x83, 0x0b, &[0xd9, 0x15, 0x2c, 0x69, 0xaa, 0xe0]);

/// What every runtime service is after `ExitBootServices`, copied into a
/// runtime code page: `mov x0, #EFI_UNSUPPORTED; ret`.
const UNSUPPORTED_CODE: [u32; 3] = [0xD280_0060, 0xF2F0_0000, 0xD65F_03C0];

pub fn system_table() -> *mut efi::SystemTable {
    *ST.get()
}

fn rt_data() -> &'static mut RuntimeData {
    unsafe { &mut *(*ST.get() as *mut RuntimeData) }
}

fn seal(hdr: &mut efi::TableHeader, size: usize) {
    hdr.crc32 = 0;
    let bytes = unsafe { core::slice::from_raw_parts(hdr as *const _ as *const u8, size) };
    hdr.crc32 = crate::util::crc32(bytes);
}

fn reseal() {
    let d = rt_data();
    seal(&mut d.st.hdr, core::mem::size_of::<efi::SystemTable>());
    seal(&mut d.rt.hdr, core::mem::size_of::<efi::RuntimeServices>());
    let bs = d.st.boot_services;
    if !bs.is_null() {
        unsafe { seal(&mut (*bs).hdr, core::mem::size_of::<efi::BootServices>()) };
    }
}

pub fn on_exit_boot_services(f: fn()) {
    QUIESCE.get().push(f);
}

/// Called once on the first `ExitBootServices`, before anything else, while
/// the variables can still be sealed.
pub fn before_exit_boot_services(f: fn()) {
    BEFORE_EXIT.get().push(f);
}

// --- boot services ---

extern "efiapi" fn raise_tpl(new: efi::Tpl) -> efi::Tpl {
    core::mem::replace(TPL.get(), new)
}

extern "efiapi" fn restore_tpl(old: efi::Tpl) {
    *TPL.get() = old;
}

extern "efiapi" fn allocate_pages(kind: efi::AllocateType, ty: efi::MemoryType, pages: usize, memory: *mut efi::PhysicalAddress) -> efi::Status {
    if memory.is_null() || (ty >= 15 && ty < 0x7000_0000) || ty == efi::CONVENTIONAL_MEMORY {
        return efi::Status::INVALID_PARAMETER;
    }
    match mem::map().allocate(kind, ty, pages as u64, unsafe { *memory }, mem::PAGE) {
        Ok(at) => {
            unsafe { *memory = at };
            efi::Status::SUCCESS
        }
        Err(s) => s,
    }
}

extern "efiapi" fn free_pages(memory: efi::PhysicalAddress, pages: usize) -> efi::Status {
    match mem::map().free(memory, pages as u64) {
        Ok(()) => efi::Status::SUCCESS,
        Err(s) => s,
    }
}

extern "efiapi" fn get_memory_map(
    size: *mut usize,
    map: *mut efi::MemoryDescriptor,
    key: *mut usize,
    desc_size: *mut usize,
    desc_version: *mut u32,
) -> efi::Status {
    if size.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    let m = mem::map();
    let need = m.len() * mem::DESCRIPTOR_SIZE;
    unsafe {
        if !desc_size.is_null() {
            *desc_size = mem::DESCRIPTOR_SIZE;
        }
        if !desc_version.is_null() {
            *desc_version = efi::MEMORY_DESCRIPTOR_VERSION;
        }
        let room = *size;
        *size = need;
        if room < need {
            return efi::Status::BUFFER_TOO_SMALL;
        }
        if map.is_null() {
            return efi::Status::INVALID_PARAMETER;
        }
        m.write(map as *mut u8);
        if !key.is_null() {
            *key = m.key;
        }
    }
    efi::Status::SUCCESS
}

extern "efiapi" fn allocate_pool(ty: efi::MemoryType, size: usize, buffer: *mut *mut c_void) -> efi::Status {
    if buffer.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    match mem::pool_alloc(ty, size) {
        Ok(p) => {
            unsafe { *buffer = p as *mut c_void };
            efi::Status::SUCCESS
        }
        Err(s) => {
            warn!("uefi", "AllocatePool failed"; kind = ty, bytes = size, status = Hex(s.as_usize()));
            s
        }
    }
}

extern "efiapi" fn free_pool(buffer: *mut c_void) -> efi::Status {
    mem::pool_free(buffer as *mut u8)
}

extern "efiapi" fn create_event(
    ty: u32,
    _tpl: efi::Tpl,
    notify: Option<efi::EventNotify>,
    context: *mut c_void,
    event: *mut efi::Event,
) -> efi::Status {
    if event.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    unsafe { *event = event::create(ty, notify, context, None) };
    efi::Status::SUCCESS
}

extern "efiapi" fn create_event_ex(
    ty: u32,
    _tpl: efi::Tpl,
    notify: Option<efi::EventNotify>,
    context: *const c_void,
    group: *const efi::Guid,
    event: *mut efi::Event,
) -> efi::Status {
    if event.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    let group = (!group.is_null()).then(|| unsafe { *group });
    unsafe { *event = event::create(ty, notify, context as *mut c_void, group) };
    efi::Status::SUCCESS
}

extern "efiapi" fn set_timer(e: efi::Event, kind: efi::TimerDelay, trigger: u64) -> efi::Status {
    event::set_timer(e, kind, trigger)
}

extern "efiapi" fn wait_for_event(n: usize, events: *mut efi::Event, index: *mut usize) -> efi::Status {
    if n == 0 || events.is_null() || index.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    let list = unsafe { core::slice::from_raw_parts(events, n) };
    match event::wait(list) {
        Ok(i) => {
            unsafe { *index = i };
            efi::Status::SUCCESS
        }
        Err((s, i)) => {
            unsafe { *index = i };
            s
        }
    }
}

extern "efiapi" fn signal_event(e: efi::Event) -> efi::Status {
    event::signal(e)
}

extern "efiapi" fn close_event(e: efi::Event) -> efi::Status {
    event::close(e)
}

extern "efiapi" fn check_event(e: efi::Event) -> efi::Status {
    event::run_timers();
    event::check(e)
}

extern "efiapi" fn install_protocol_interface(
    handle: *mut efi::Handle,
    guid: *mut efi::Guid,
    _ty: efi::InterfaceType,
    iface: *mut c_void,
) -> efi::Status {
    if handle.is_null() || guid.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    match proto::install(unsafe { *handle }, unsafe { &*guid }, iface) {
        Ok(h) => {
            unsafe { *handle = h };
            efi::Status::SUCCESS
        }
        Err(s) => s,
    }
}

extern "efiapi" fn reinstall_protocol_interface(handle: efi::Handle, guid: *mut efi::Guid, old: *mut c_void, new: *mut c_void) -> efi::Status {
    if guid.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    proto::set(handle, unsafe { &*guid }, old, new)
}

extern "efiapi" fn uninstall_protocol_interface(handle: efi::Handle, guid: *mut efi::Guid, iface: *mut c_void) -> efi::Status {
    if guid.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    proto::uninstall(handle, unsafe { &*guid }, iface)
}

extern "efiapi" fn handle_protocol(handle: efi::Handle, guid: *mut efi::Guid, iface: *mut *mut c_void) -> efi::Status {
    if guid.is_null() || iface.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    match proto::get(handle, unsafe { &*guid }) {
        Some(p) => {
            unsafe { *iface = p };
            efi::Status::SUCCESS
        }
        None => {
            unsafe { *iface = core::ptr::null_mut() };
            efi::Status::UNSUPPORTED
        }
    }
}

extern "efiapi" fn register_protocol_notify(guid: *mut efi::Guid, e: efi::Event, registration: *mut *mut c_void) -> efi::Status {
    if guid.is_null() || registration.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    unsafe { *registration = proto::register_notify(&*guid, e) };
    efi::Status::SUCCESS
}

/// The handles a `LocateHandle` search finds.
fn search(kind: efi::LocateSearchType, guid: *mut efi::Guid, key: *mut c_void) -> Result<Vec<efi::Handle>, efi::Status> {
    let found = match kind {
        efi::ALL_HANDLES => proto::with(None),
        efi::BY_REGISTER_NOTIFY => proto::next_notified(key).into_iter().collect(),
        efi::BY_PROTOCOL if !guid.is_null() => proto::with(Some(unsafe { &*guid })),
        _ => return Err(efi::Status::INVALID_PARAMETER),
    };
    if found.is_empty() { Err(efi::Status::NOT_FOUND) } else { Ok(found) }
}

extern "efiapi" fn locate_handle(
    kind: efi::LocateSearchType,
    guid: *mut efi::Guid,
    key: *mut c_void,
    size: *mut usize,
    buffer: *mut efi::Handle,
) -> efi::Status {
    if size.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    let found = match search(kind, guid, key) {
        Ok(f) => f,
        Err(s) => return s,
    };
    let need = found.len() * core::mem::size_of::<efi::Handle>();
    let room = unsafe { *size };
    unsafe { *size = need };
    if room < need {
        return efi::Status::BUFFER_TOO_SMALL;
    }
    if buffer.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    unsafe { core::ptr::copy_nonoverlapping(found.as_ptr(), buffer, found.len()) };
    efi::Status::SUCCESS
}

extern "efiapi" fn locate_handle_buffer(
    kind: efi::LocateSearchType,
    guid: *mut efi::Guid,
    key: *mut c_void,
    count: *mut usize,
    buffer: *mut *mut efi::Handle,
) -> efi::Status {
    if count.is_null() || buffer.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    let found = match search(kind, guid, key) {
        Ok(f) => f,
        Err(s) => return s,
    };
    let Ok(p) = mem::pool_alloc(efi::BOOT_SERVICES_DATA, found.len() * core::mem::size_of::<efi::Handle>()) else {
        return efi::Status::OUT_OF_RESOURCES;
    };
    unsafe {
        core::ptr::copy_nonoverlapping(found.as_ptr(), p as *mut efi::Handle, found.len());
        *buffer = p as *mut efi::Handle;
        *count = found.len();
    }
    efi::Status::SUCCESS
}

extern "efiapi" fn locate_device_path(guid: *mut efi::Guid, path: *mut *mut device_path::Protocol, device: *mut efi::Handle) -> efi::Status {
    if guid.is_null() || path.is_null() || device.is_null() || unsafe { (*path).is_null() } {
        return efi::Status::INVALID_PARAMETER;
    }
    let p = unsafe { *path } as *const u8;
    match image::locate(unsafe { &*guid }, p) {
        Some((h, n)) => unsafe {
            *device = h;
            *path = p.add(n) as *mut device_path::Protocol;
            efi::Status::SUCCESS
        },
        None => efi::Status::NOT_FOUND,
    }
}

extern "efiapi" fn install_configuration_table(guid: *mut efi::Guid, table: *mut c_void) -> efi::Status {
    if guid.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    install_table(unsafe { *guid }, table)
}

pub fn install_table(guid: efi::Guid, table: *mut c_void) -> efi::Status {
    let d = rt_data();
    let n = d.st.number_of_table_entries;
    let at = d.config[..n].iter().position(|c| c.vendor_guid == guid);
    match (at, table.is_null()) {
        (Some(i), false) => d.config[i].vendor_table = table,
        (Some(i), true) => {
            d.config.copy_within(i + 1..n, i);
            d.st.number_of_table_entries -= 1;
        }
        (None, true) => return efi::Status::NOT_FOUND,
        (None, false) if n == MAX_CONFIG => return efi::Status::OUT_OF_RESOURCES,
        (None, false) => {
            d.config[n] = efi::ConfigurationTable { vendor_guid: guid, vendor_table: table };
            d.st.number_of_table_entries += 1;
        }
    }
    reseal();
    efi::Status::SUCCESS
}

extern "efiapi" fn load_image(
    _boot_policy: efi::Boolean,
    parent: efi::Handle,
    path: *mut device_path::Protocol,
    source: *mut c_void,
    size: usize,
    handle: *mut efi::Handle,
) -> efi::Status {
    if handle.is_null() || !proto::valid(parent) {
        return efi::Status::INVALID_PARAMETER;
    }
    let source = (!source.is_null()).then(|| unsafe { core::slice::from_raw_parts(source as *const u8, size) });
    match image::load(parent, path as *const u8, source) {
        Ok(h) => {
            unsafe { *handle = h };
            efi::Status::SUCCESS
        }
        Err(s) => s,
    }
}

extern "efiapi" fn start_image(handle: efi::Handle, exit_size: *mut usize, exit_data: *mut *mut efi::Char16) -> efi::Status {
    image::start(handle, exit_size, exit_data)
}

extern "efiapi" fn exit(handle: efi::Handle, status: efi::Status, size: usize, data: *mut efi::Char16) -> efi::Status {
    image::exit(handle, status, size, data)
}

extern "efiapi" fn unload_image(handle: efi::Handle) -> efi::Status {
    image::unload(handle)
}

extern "efiapi" fn exit_boot_services(_handle: efi::Handle, key: usize) -> efi::Status {
    if key != mem::map().key {
        warn!("uefi", "ExitBootServices: the map key is stale"; asked = key, current = mem::map().key);
        return efi::Status::INVALID_PARAMETER;
    }
    for f in core::mem::take(BEFORE_EXIT.get()) {
        f();
    }
    event::signal_group(&BEFORE_EXIT_BOOT_SERVICES);
    event::signal_group(&efi::EVENT_GROUP_EXIT_BOOT_SERVICES);
    // A notification function that allocated has changed the map.
    if key != mem::map().key {
        warn!("uefi", "ExitBootServices: a notification changed the map"; asked = key, current = mem::map().key);
        return efi::Status::INVALID_PARAMETER;
    }
    for f in QUIESCE.get().iter() {
        f();
    }
    info!("uefi", "boot services exited, the OS has the board");
    crate::watchdog::exit_boot_services();

    let d = rt_data();
    let stub = unsafe { core::mem::transmute::<u64, extern "efiapi" fn()>(*RT_CODE.get()) };
    let rt = &mut d.rt;
    unsafe {
        let all = core::slice::from_raw_parts_mut(
            (rt as *mut efi::RuntimeServices as *mut u8).add(core::mem::size_of::<efi::TableHeader>()) as *mut usize,
            (core::mem::size_of::<efi::RuntimeServices>() - core::mem::size_of::<efi::TableHeader>()) / 8,
        );
        all.fill(stub as usize);
    }
    var::export_runtime();
    d.rt.get_variable = rtvar::get_variable;
    d.rt.get_next_variable_name = rtvar::get_next_variable_name;
    d.rt.set_variable = rtvar::set_variable;
    d.rt.query_variable_info = rtvar::query_variable_info;
    d.rt.reset_system = crate::watchdog::runtime_reset_system;
    d.st.boot_services = core::ptr::null_mut();
    d.st.con_in = core::ptr::null_mut();
    d.st.console_in_handle = core::ptr::null_mut();
    d.st.con_out = core::ptr::null_mut();
    d.st.console_out_handle = core::ptr::null_mut();
    d.st.std_err = core::ptr::null_mut();
    d.st.standard_error_handle = core::ptr::null_mut();
    reseal();
    efi::Status::SUCCESS
}

const BEFORE_EXIT_BOOT_SERVICES: efi::Guid =
    efi::Guid::from_fields(0x8be0e274, 0x3970, 0x4b44, 0x80, 0xc5, &[0x1a, 0xb9, 0x50, 0x2f, 0x3b, 0xfc]);

extern "efiapi" fn get_next_monotonic_count(count: *mut u64) -> efi::Status {
    if count.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    let c = MONOTONIC.get();
    *c += 1;
    unsafe { *count = *c };
    efi::Status::SUCCESS
}

extern "efiapi" fn stall(us: usize) -> efi::Status {
    let until = crate::util::Deadline::after_us(us as u64);
    loop {
        event::run_timers();
        if until.passed() {
            break;
        }
        crate::util::delay_us(crate::util::POLL_US.min(until.left_us()));
    }
    efi::Status::SUCCESS
}

extern "efiapi" fn set_watchdog_timer(seconds: usize, _code: u64, _size: usize, _data: *mut efi::Char16) -> efi::Status {
    crate::watchdog::set(seconds);
    efi::Status::SUCCESS
}

extern "efiapi" fn connect_controller(_c: efi::Handle, _d: *mut efi::Handle, _p: *mut device_path::Protocol, _r: efi::Boolean) -> efi::Status {
    efi::Status::SUCCESS
}

extern "efiapi" fn disconnect_controller(_c: efi::Handle, _d: efi::Handle, _child: efi::Handle) -> efi::Status {
    efi::Status::SUCCESS
}

extern "efiapi" fn open_protocol(
    handle: efi::Handle,
    guid: *mut efi::Guid,
    iface: *mut *mut c_void,
    _agent: efi::Handle,
    _controller: efi::Handle,
    attributes: u32,
) -> efi::Status {
    if guid.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    if !proto::valid(handle) {
        return efi::Status::INVALID_PARAMETER;
    }
    let found = proto::get(handle, unsafe { &*guid });
    if attributes != efi::OPEN_PROTOCOL_TEST_PROTOCOL {
        if iface.is_null() {
            return efi::Status::INVALID_PARAMETER;
        }
        unsafe { *iface = found.unwrap_or(core::ptr::null_mut()) };
    }
    if found.is_some() { efi::Status::SUCCESS } else { efi::Status::UNSUPPORTED }
}

extern "efiapi" fn close_protocol(handle: efi::Handle, guid: *mut efi::Guid, _agent: efi::Handle, _controller: efi::Handle) -> efi::Status {
    if guid.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    if proto::get(handle, unsafe { &*guid }).is_some() { efi::Status::SUCCESS } else { efi::Status::NOT_FOUND }
}

extern "efiapi" fn open_protocol_information(
    handle: efi::Handle,
    guid: *mut efi::Guid,
    entries: *mut *mut efi::OpenProtocolInformationEntry,
    count: *mut usize,
) -> efi::Status {
    if guid.is_null() || entries.is_null() || count.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    if proto::get(handle, unsafe { &*guid }).is_none() {
        return efi::Status::NOT_FOUND;
    }
    let Ok(p) = mem::pool_alloc(efi::BOOT_SERVICES_DATA, 0) else { return efi::Status::OUT_OF_RESOURCES };
    unsafe {
        *entries = p as *mut efi::OpenProtocolInformationEntry;
        *count = 0;
    }
    efi::Status::SUCCESS
}

extern "efiapi" fn protocols_per_handle(handle: efi::Handle, guids: *mut *mut *mut efi::Guid, count: *mut usize) -> efi::Status {
    if guids.is_null() || count.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    let Some(list) = proto::protocols(handle) else { return efi::Status::INVALID_PARAMETER };
    let n = list.len();
    // The pointers, then the GUIDs they point at, in one pool.
    let Ok(p) = mem::pool_alloc(efi::BOOT_SERVICES_DATA, n * (8 + 16)) else { return efi::Status::OUT_OF_RESOURCES };
    unsafe {
        let ptrs = p as *mut *mut efi::Guid;
        let copies = p.add(n * 8) as *mut efi::Guid;
        for (i, g) in list.iter().enumerate() {
            copies.add(i).write_unaligned(*g);
            *ptrs.add(i) = copies.add(i);
        }
        *guids = ptrs;
        *count = n;
    }
    efi::Status::SUCCESS
}

extern "efiapi" fn locate_protocol(guid: *mut efi::Guid, registration: *mut c_void, iface: *mut *mut c_void) -> efi::Status {
    if guid.is_null() || iface.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    let guid = unsafe { &*guid };
    let handle = if registration.is_null() {
        proto::with(Some(guid)).first().copied()
    } else {
        proto::next_notified(registration)
    };
    match handle.and_then(|h| proto::get(h, guid)) {
        Some(p) => {
            unsafe { *iface = p };
            efi::Status::SUCCESS
        }
        None => {
            unsafe { *iface = core::ptr::null_mut() };
            efi::Status::NOT_FOUND
        }
    }
}

// The two variadic services: x1..x7 go into an array next to where the
// caller's stacked arguments start, and the Rust side walks (GUID,
// interface) pairs until a null GUID.
global_asm!(
    r#"
.text
.global install_multiple
install_multiple:
    stp x29, x30, [sp, #-80]!
    mov x29, sp
    stp x1, x2, [sp, #16]
    stp x3, x4, [sp, #32]
    stp x5, x6, [sp, #48]
    str x7, [sp, #64]
    add x1, sp, #16
    add x2, sp, #80
    bl install_multiple_rust
    ldp x29, x30, [sp], #80
    ret

.global uninstall_multiple
uninstall_multiple:
    stp x29, x30, [sp, #-80]!
    mov x29, sp
    stp x1, x2, [sp, #16]
    stp x3, x4, [sp, #32]
    stp x5, x6, [sp, #48]
    str x7, [sp, #64]
    add x1, sp, #16
    add x2, sp, #80
    bl uninstall_multiple_rust
    ldp x29, x30, [sp], #80
    ret
"#
);

unsafe extern "C" {
    fn install_multiple();
    fn uninstall_multiple();
}

/// The variadic arguments after the first: seven in registers, then the stack.
fn varargs(regs: *const u64, stack: *const u64) -> Vec<(*const efi::Guid, *mut c_void)> {
    let arg = |i: usize| unsafe { if i < 7 { *regs.add(i) } else { *stack.add(i - 7) } };
    let mut out = Vec::new();
    let mut i = 0;
    loop {
        let guid = arg(i) as *const efi::Guid;
        if guid.is_null() || out.len() > 64 {
            return out;
        }
        out.push((guid, arg(i + 1) as *mut c_void));
        i += 2;
    }
}

#[unsafe(no_mangle)]
extern "C" fn install_multiple_rust(handle: *mut efi::Handle, regs: *const u64, stack: *const u64) -> efi::Status {
    if handle.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    let pairs = varargs(regs, stack);
    // A device path already on another handle is refused.
    let dp = &device_path::PROTOCOL_GUID;
    for &(g, iface) in &pairs {
        if unsafe { &*g } == dp {
            let path = crate::devpath::bytes(iface as *const u8);
            let taken = proto::with(Some(dp)).into_iter().any(|h| {
                proto::get(h, dp).is_some_and(|p| crate::devpath::bytes(p as *const u8) == path)
            });
            if taken {
                return efi::Status::ALREADY_STARTED;
            }
        }
    }
    let mut h = unsafe { *handle };
    for (n, &(g, iface)) in pairs.iter().enumerate() {
        match proto::install(h, unsafe { &*g }, iface) {
            Ok(new) => h = new,
            Err(s) => {
                for &(g, iface) in &pairs[..n] {
                    proto::uninstall(h, unsafe { &*g }, iface);
                }
                return s;
            }
        }
    }
    unsafe { *handle = h };
    efi::Status::SUCCESS
}

#[unsafe(no_mangle)]
extern "C" fn uninstall_multiple_rust(handle: efi::Handle, regs: *const u64, stack: *const u64) -> efi::Status {
    let pairs = varargs(regs, stack);
    if !pairs.iter().all(|&(g, iface)| proto::get(handle, unsafe { &*g }) == Some(iface)) {
        return efi::Status::INVALID_PARAMETER;
    }
    for &(g, iface) in &pairs {
        proto::uninstall(handle, unsafe { &*g }, iface);
    }
    efi::Status::SUCCESS
}

extern "efiapi" fn calculate_crc32(data: *mut c_void, size: usize, crc: *mut u32) -> efi::Status {
    if data.is_null() || size == 0 || crc.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    unsafe { *crc = crate::util::crc32(core::slice::from_raw_parts(data as *const u8, size)) };
    efi::Status::SUCCESS
}

extern "efiapi" fn copy_mem(dst: *mut c_void, src: *mut c_void, len: usize) {
    unsafe { core::ptr::copy(src as *const u8, dst as *mut u8, len) };
}

extern "efiapi" fn set_mem(buf: *mut c_void, len: usize, value: u8) {
    unsafe { core::ptr::write_bytes(buf as *mut u8, value, len) };
}

// --- runtime services, as they are before ExitBootServices ---

extern "efiapi" fn get_time(_time: *mut efi::Time, _caps: *mut efi::TimeCapabilities) -> efi::Status {
    efi::Status::UNSUPPORTED
}

extern "efiapi" fn set_time(_time: *mut efi::Time) -> efi::Status {
    efi::Status::UNSUPPORTED
}

extern "efiapi" fn get_wakeup_time(_e: *mut efi::Boolean, _p: *mut efi::Boolean, _t: *mut efi::Time) -> efi::Status {
    efi::Status::UNSUPPORTED
}

extern "efiapi" fn set_wakeup_time(_e: efi::Boolean, _t: *mut efi::Time) -> efi::Status {
    efi::Status::UNSUPPORTED
}

extern "efiapi" fn set_virtual_address_map(_size: usize, _desc_size: usize, _version: u32, _map: *mut efi::MemoryDescriptor) -> efi::Status {
    efi::Status::UNSUPPORTED
}

extern "efiapi" fn convert_pointer(_debug: usize, _addr: *mut *mut c_void) -> efi::Status {
    efi::Status::UNSUPPORTED
}

extern "efiapi" fn get_next_high_mono_count(count: *mut u32) -> efi::Status {
    if count.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    let c = MONOTONIC.get();
    *c = (*c & 0xffff_ffff) + (1 << 32);
    unsafe { *count = (*c >> 32) as u32 };
    efi::Status::SUCCESS
}

extern "efiapi" fn reset_system(kind: efi::ResetType, status: efi::Status, _size: usize, _data: *mut c_void) {
    let halt = kind == efi::RESET_SHUTDOWN;
    info!("uefi", "resetting the board"; kind = if halt { "shutdown" } else { "reset" }, status = Hex(status.as_usize()));
    crate::watchdog::reset(halt)
}

extern "efiapi" fn update_capsule(_c: *mut *mut efi::CapsuleHeader, _n: usize, _s: efi::PhysicalAddress) -> efi::Status {
    efi::Status::UNSUPPORTED
}

extern "efiapi" fn query_capsule_capabilities(
    _c: *mut *mut efi::CapsuleHeader,
    _n: usize,
    _max: *mut u64,
    _reset: *mut efi::ResetType,
) -> efi::Status {
    efi::Status::UNSUPPORTED
}

static RT_CODE: Global<u64> = Global::new(0);

/// Build the tables, with the console handle and protocols.
pub fn init(console: efi::Handle, con_in: *mut r_efi::protocols::simple_text_input::Protocol, con_out: *mut r_efi::protocols::simple_text_output::Protocol) {
    let code = mem::alloc_pages(efi::RUNTIME_SERVICES_CODE, 1).expect("runtime code page");
    unsafe { core::ptr::copy_nonoverlapping(UNSUPPORTED_CODE.as_ptr(), code as *mut u32, UNSUPPORTED_CODE.len()) };
    crate::util::sync_icache(code, 12);
    *RT_CODE.get() = code;

    let pages = core::mem::size_of::<RuntimeData>().div_ceil(mem::PAGE as usize) as u64;
    let data = mem::alloc_pages(efi::RUNTIME_SERVICES_DATA, pages).expect("runtime data page") as *mut RuntimeData;
    unsafe { core::ptr::write_bytes(data as *mut u8, 0, (pages * mem::PAGE) as usize) };
    let d = unsafe { &mut *data };
    for (i, c) in "nuboot".encode_utf16().enumerate() {
        d.vendor[i] = c;
    }
    d.rt_properties = RtProperties { version: 1, length: 8, supported: RT_VARIABLE_SERVICES | RT_RESET_SYSTEM };
    d.rt = efi::RuntimeServices {
        hdr: header(efi::RUNTIME_SERVICES_SIGNATURE, core::mem::size_of::<efi::RuntimeServices>()),
        get_time,
        set_time,
        get_wakeup_time,
        set_wakeup_time,
        set_virtual_address_map,
        convert_pointer,
        get_variable: var::get_variable,
        get_next_variable_name: var::get_next_variable_name,
        set_variable: var::set_variable,
        get_next_high_mono_count,
        reset_system,
        update_capsule,
        query_capsule_capabilities,
        query_variable_info: var::query_variable_info,
    };
    let bs = Box::leak(Box::new(efi::BootServices {
        hdr: header(efi::BOOT_SERVICES_SIGNATURE, core::mem::size_of::<efi::BootServices>()),
        raise_tpl,
        restore_tpl,
        allocate_pages,
        free_pages,
        get_memory_map,
        allocate_pool,
        free_pool,
        create_event,
        set_timer,
        wait_for_event,
        signal_event,
        close_event,
        check_event,
        install_protocol_interface,
        reinstall_protocol_interface,
        uninstall_protocol_interface,
        handle_protocol,
        reserved: core::ptr::null_mut(),
        register_protocol_notify,
        locate_handle,
        locate_device_path,
        install_configuration_table,
        load_image,
        start_image,
        exit,
        unload_image,
        exit_boot_services,
        get_next_monotonic_count,
        stall,
        set_watchdog_timer,
        connect_controller,
        disconnect_controller,
        open_protocol,
        close_protocol,
        open_protocol_information,
        protocols_per_handle,
        locate_handle_buffer,
        locate_protocol,
        install_multiple_protocol_interfaces: unsafe { core::mem::transmute::<unsafe extern "C" fn(), _>(install_multiple) },
        uninstall_multiple_protocol_interfaces: unsafe { core::mem::transmute::<unsafe extern "C" fn(), _>(uninstall_multiple) },
        calculate_crc32,
        copy_mem,
        set_mem,
        create_event_ex,
    }));
    d.st = efi::SystemTable {
        hdr: header(efi::SYSTEM_TABLE_SIGNATURE, core::mem::size_of::<efi::SystemTable>()),
        firmware_vendor: d.vendor.as_mut_ptr(),
        firmware_revision: 0x0001_0000,
        console_in_handle: console,
        con_in,
        console_out_handle: console,
        con_out,
        standard_error_handle: console,
        std_err: con_out,
        runtime_services: &mut d.rt,
        boot_services: bs,
        number_of_table_entries: 0,
        configuration_table: d.config.as_mut_ptr(),
    };
    *ST.get() = data as *mut efi::SystemTable;
    install_table(RT_PROPERTIES_GUID, &mut d.rt_properties as *mut RtProperties as *mut c_void);
    reseal();
    if !proto::valid(console) {
        warn!("uefi", "no console handle");
    }
}

fn header(signature: u64, size: usize) -> efi::TableHeader {
    efi::TableHeader { signature, revision: efi::SYSTEM_TABLE_REVISION_2_70, header_size: size as u32, crc32: 0, reserved: 0 }
}

//! The handle database: which protocols each handle carries, and who asked
//! to hear about new ones.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ffi::c_void;

use r_efi::efi;

use crate::util::Global;

pub struct HandleData {
    pub protocols: Vec<(efi::Guid, *mut c_void)>,
}

struct Notify {
    guid: efi::Guid,
    event: efi::Event,
    /// Handles that gained the protocol since `LocateHandle` last asked.
    pending: Vec<efi::Handle>,
}

struct Db {
    handles: Vec<*mut HandleData>,
    notifies: Vec<Box<Notify>>,
}

static DB: Global<Db> = Global::new(Db { handles: Vec::new(), notifies: Vec::new() });

pub fn valid(handle: efi::Handle) -> bool {
    !handle.is_null() && DB.get().handles.contains(&(handle as *mut HandleData))
}

fn data(handle: efi::Handle) -> Option<&'static mut HandleData> {
    valid(handle).then(|| unsafe { &mut *(handle as *mut HandleData) })
}

/// Put `iface` on `handle`, or on a new handle when it is null.
pub fn install(handle: efi::Handle, guid: &efi::Guid, iface: *mut c_void) -> Result<efi::Handle, efi::Status> {
    let handle = if handle.is_null() {
        let h = Box::into_raw(Box::new(HandleData { protocols: Vec::new() }));
        DB.get().handles.push(h);
        h as efi::Handle
    } else {
        handle
    };
    let d = data(handle).ok_or(efi::Status::INVALID_PARAMETER)?;
    if d.protocols.iter().any(|(g, _)| g == guid) {
        return Err(efi::Status::INVALID_PARAMETER);
    }
    d.protocols.push((*guid, iface));
    let mut events = Vec::new();
    for n in DB.get().notifies.iter_mut().filter(|n| n.guid == *guid) {
        n.pending.push(handle);
        events.push(n.event);
    }
    for e in events {
        crate::event::signal(e);
    }
    Ok(handle)
}

pub fn uninstall(handle: efi::Handle, guid: &efi::Guid, iface: *mut c_void) -> efi::Status {
    let Some(d) = data(handle) else { return efi::Status::INVALID_PARAMETER };
    let Some(i) = d.protocols.iter().position(|(g, p)| g == guid && *p == iface) else {
        return efi::Status::NOT_FOUND;
    };
    d.protocols.remove(i);
    if d.protocols.is_empty() {
        let db = DB.get();
        db.handles.retain(|&h| h != handle as *mut HandleData);
        for n in db.notifies.iter_mut() {
            n.pending.retain(|&h| h != handle);
        }
        drop(unsafe { Box::from_raw(handle as *mut HandleData) });
    }
    efi::Status::SUCCESS
}

pub fn get(handle: efi::Handle, guid: &efi::Guid) -> Option<*mut c_void> {
    data(handle)?.protocols.iter().find(|(g, _)| g == guid).map(|&(_, p)| p)
}

pub fn set(handle: efi::Handle, guid: &efi::Guid, old: *mut c_void, new: *mut c_void) -> efi::Status {
    let Some(d) = data(handle) else { return efi::Status::INVALID_PARAMETER };
    match d.protocols.iter_mut().find(|(g, p)| g == guid && *p == old) {
        Some(entry) => {
            entry.1 = new;
            efi::Status::SUCCESS
        }
        None => efi::Status::NOT_FOUND,
    }
}

/// Every handle that carries `guid`, or every handle at all.
pub fn with(guid: Option<&efi::Guid>) -> Vec<efi::Handle> {
    DB.get()
        .handles
        .iter()
        .filter(|&&h| guid.is_none_or(|g| unsafe { (*h).protocols.iter().any(|(p, _)| p == g) }))
        .map(|&h| h as efi::Handle)
        .collect()
}

pub fn protocols(handle: efi::Handle) -> Option<Vec<efi::Guid>> {
    Some(data(handle)?.protocols.iter().map(|(g, _)| *g).collect())
}

/// `RegisterProtocolNotify`: the registration is the [`Notify`] itself.
pub fn register_notify(guid: &efi::Guid, event: efi::Event) -> *mut c_void {
    let n = Box::new(Notify { guid: *guid, event, pending: Vec::new() });
    let p = &*n as *const Notify as *mut c_void;
    DB.get().notifies.push(n);
    p
}

/// The next handle a registration has not been told of yet.
pub fn next_notified(registration: *mut c_void) -> Option<efi::Handle> {
    let n = DB.get().notifies.iter_mut().find(|n| &***n as *const Notify as *mut c_void == registration)?;
    (!n.pending.is_empty()).then(|| n.pending.remove(0))
}

pub fn unregister_event(event: efi::Event) {
    DB.get().notifies.retain(|n| n.event != event);
}

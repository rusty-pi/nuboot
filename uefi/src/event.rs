//! Events and timers. Nothing interrupts this firmware, so timers fire when
//! someone waits: in `WaitForEvent`, `CheckEvent` and `Stall`.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ffi::c_void;

use r_efi::efi;

use crate::util::{Global, now_us};

pub struct Event {
    ty: u32,
    notify: Option<efi::EventNotify>,
    context: *mut c_void,
    group: Option<efi::Guid>,
    signaled: bool,
    /// When the timer fires next, and how often after that (0: once).
    timer: Option<(u64, u64)>,
    /// For an event something outside the event system decides, such as a
    /// key waiting: asked whenever the event is checked.
    poll: Option<fn() -> bool>,
}

static EVENTS: Global<Vec<*mut Event>> = Global::new(Vec::new());

fn get(e: efi::Event) -> Option<&'static mut Event> {
    EVENTS.get().contains(&(e as *mut Event)).then(|| unsafe { &mut *(e as *mut Event) })
}

pub fn create(
    ty: u32,
    notify: Option<efi::EventNotify>,
    context: *mut c_void,
    group: Option<efi::Guid>,
) -> efi::Event {
    let group = match ty {
        efi::EVT_SIGNAL_EXIT_BOOT_SERVICES => Some(efi::EVENT_GROUP_EXIT_BOOT_SERVICES),
        efi::EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE => Some(efi::EVENT_GROUP_VIRTUAL_ADDRESS_CHANGE),
        _ => group,
    };
    let e = Box::into_raw(Box::new(Event { ty, notify, context, group, signaled: false, timer: None, poll: None }));
    EVENTS.get().push(e);
    e as efi::Event
}

/// An event that is signaled whenever `poll` says so.
pub fn create_polled(poll: fn() -> bool) -> efi::Event {
    let e = create(0, None, core::ptr::null_mut(), None);
    get(e).unwrap().poll = Some(poll);
    e
}

pub fn close(e: efi::Event) -> efi::Status {
    let list = EVENTS.get();
    let Some(i) = list.iter().position(|&p| p == e as *mut Event) else { return efi::Status::INVALID_PARAMETER };
    list.remove(i);
    crate::proto::unregister_event(e);
    drop(unsafe { Box::from_raw(e as *mut Event) });
    efi::Status::SUCCESS
}

fn fire(e: efi::Event) {
    let Some(ev) = get(e) else { return };
    if ev.ty & efi::EVT_NOTIFY_SIGNAL != 0 {
        if let Some(f) = ev.notify {
            let ctx = ev.context;
            f(e, ctx);
        }
    } else {
        ev.signaled = true;
    }
}

pub fn signal(e: efi::Event) -> efi::Status {
    let Some(ev) = get(e) else { return efi::Status::INVALID_PARAMETER };
    match ev.group {
        Some(group) => signal_group(&group),
        None => fire(e),
    }
    efi::Status::SUCCESS
}

pub fn signal_group(group: &efi::Guid) {
    let members: Vec<efi::Event> = EVENTS
        .get()
        .iter()
        .filter(|&&e| unsafe { (*e).group.as_ref() } == Some(group))
        .map(|&e| e as efi::Event)
        .collect();
    for e in members {
        fire(e);
    }
}

pub fn set_timer(e: efi::Event, kind: efi::TimerDelay, trigger_100ns: u64) -> efi::Status {
    let Some(ev) = get(e) else { return efi::Status::INVALID_PARAMETER };
    if ev.ty & efi::EVT_TIMER == 0 {
        return efi::Status::INVALID_PARAMETER;
    }
    let us = trigger_100ns / 10;
    ev.timer = match kind {
        efi::TIMER_CANCEL => None,
        efi::TIMER_PERIODIC => Some((now_us() + us, us.max(1))),
        efi::TIMER_RELATIVE => Some((now_us() + us, 0)),
        _ => return efi::Status::INVALID_PARAMETER,
    };
    efi::Status::SUCCESS
}

/// Fire every timer that is due.
pub fn run_timers() {
    let now = now_us();
    let due: Vec<efi::Event> = EVENTS
        .get()
        .iter()
        .filter(|&&e| unsafe { (*e).timer.is_some_and(|(at, _)| at <= now) })
        .map(|&e| e as efi::Event)
        .collect();
    for e in due {
        if let Some(ev) = get(e) {
            ev.timer = match ev.timer {
                Some((_, period)) if period > 0 => Some((now + period, period)),
                _ => None,
            };
            fire(e);
        }
    }
}

pub fn check(e: efi::Event) -> efi::Status {
    let Some(ev) = get(e) else { return efi::Status::INVALID_PARAMETER };
    if ev.ty & efi::EVT_NOTIFY_SIGNAL != 0 {
        return efi::Status::INVALID_PARAMETER;
    }
    if ev.poll.is_some_and(|p| p()) {
        ev.signaled = true;
    }
    if !ev.signaled && ev.ty & efi::EVT_NOTIFY_WAIT != 0 {
        if let Some(f) = ev.notify {
            let ctx = ev.context;
            f(e, ctx);
        }
    }
    let Some(ev) = get(e) else { return efi::Status::NOT_READY };
    if ev.signaled {
        ev.signaled = false;
        efi::Status::SUCCESS
    } else {
        efi::Status::NOT_READY
    }
}

pub fn wait(events: &[efi::Event]) -> Result<usize, (efi::Status, usize)> {
    loop {
        run_timers();
        for (i, &e) in events.iter().enumerate() {
            match check(e) {
                efi::Status::SUCCESS => return Ok(i),
                efi::Status::NOT_READY => {}
                s => return Err((s, i)),
            }
        }
        core::hint::spin_loop();
    }
}

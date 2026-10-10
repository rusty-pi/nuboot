//! Threads for the resident phase, the part of `start4.elf` that runs for as
//! long as the board does.
//!
//! The boot path is one flow and stays one: nothing here is armed until the
//! ARM is out of reset. What follows is not one flow -- the property mailbox
//! has to be answered while the PMICs are read over a bus whose transfers
//! take milliseconds -- and the stock firmware runs those as ThreadX threads.
//!
//! Every read or write of the round's state is a [`critical`] section:
//! [`spawn`], [`start`], a yield, [`park`] and a block each run as one, and
//! the switch happens inside it. Its depth is the thread's own, so the switch
//! keeps the outgoing thread's and puts back the incoming thread's, which then
//! closes the section it switched out in. [`running`] reads one word and needs
//! none. Once [`start`] has run, a thread runs with interrupts enabled outside
//! its sections, so a handler can wake a thread whenever it fires rather than
//! only while the core sleeps, and the tick can take the core off it.
//!
//! A thread gives the core up in three ways. [`crate::timer::wait`] and
//! [`crate::timer::poll`] yield on every miss, so a driver that waits on a
//! register lets the other threads run without knowing they exist. [`park`]
//! says a thread has run out of work. And a thread blocks on [`Waiters`] --
//! what [`crate::sync`]'s semaphore, queue and lock wait on -- until another
//! thread or an interrupt handler wakes it, or its timeout passes.
//!
//! A thread that does none of these is taken off the core by the tick: the
//! system timer's first compare, which the idle sleep wakes on too, fires
//! every [`TICK_US`] while the threads run, and a thread that has had the
//! core for a whole tick has had its turn, as if it had yielded. The tick
//! switches from inside its handler, and never inside a section: interrupts
//! are masked there, so a tick that falls in one is taken when the outermost
//! one closes. The one exception is the idle sleep, which wakes on its
//! interrupt masked or not, and switches anyway once it has.
//!
//! Each thread has a [`Priority`], and a switch goes to the highest thread
//! that has not given the core up since a lower one last did, round-robin
//! among equals. A thread that yielded or parked is waiting on something only
//! it can check, so it is asked again as soon as any lower thread has had a
//! turn. A blocked thread is never asked: it runs again once it is woken, or
//! at the first switch after its timeout, and until then it costs a compare
//! against the clock per switch. A high thread is therefore run between every
//! two turns of the threads below it, and first after every sleep. A low
//! thread's turn ends at its next wait or its second tick, whichever comes
//! first, and a thread a handler woke runs at that switch.
//!
//! When every thread has parked or blocked the core sleeps until the nearest
//! of their timeouts, or until an interrupt, the way the single-threaded loop
//! did.
//!
//! A switched-out thread leaves one frame on its stack, whichever way it
//! left: what the core pushes on the way into an interrupt (`sr`, and above it
//! the address to resume at), then `r0`-`r5` and the link register, which is
//! what a handler saves first, then `r6`-`r23`. `rti` takes the last two words
//! back up, so a thread that gave the core up at a call and one taken off it
//! at an arbitrary instruction resume the same way, with every register and
//! flag as they were. The core pushes onto whichever stack is current -- in
//! supervisor mode, which every stage runs in, it does not switch to one of
//! its own for a handler, as measured on a board -- so each thread's stack
//! carries a handler's frame as well as its own calls.
//!
//! Every switch checks both threads' [`Stack`] guards and that the stack
//! pointers are inside their stacks, and every [`park`] that no critical
//! section is still open, and stops the core over the UART if not: a thread
//! that ran off its stack has already written over whatever lies below it,
//! and carrying on only moves the failure somewhere harder to find.

use core::cell::Cell;
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::critical::{self, Nesting, Section};
use crate::stack::{self, Fault, Stack};

/// How many threads the resident phase runs, the one it starts on included.
pub const THREADS: usize = 4;

/// How much a thread's turns matter against the others'; higher runs first.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Priority(pub u8);

/// The longest a block waits: half the clock's wrap, so that a deadline is
/// always told apart from one that has passed.
pub const MAX_TIMEOUT_US: u32 = u32::MAX / 2;

/// The shortest sleep: a compare set closer than this could be passed before
/// the core gets to `sleep`, and then only the clock's wrap would wake it.
const MIN_SLEEP_US: u32 = 20;

/// The words a switched-out thread leaves on its stack, lowest first:
/// `r6`-`r23`, `r0`-`r5` and the link register, then `sr` and the address
/// `rti` resumes at. Which of the first 25 words holds which register is up to
/// the order `stm` stores in, so a fresh thread's frame puts the same value in
/// every one of them.
const FRAME_WORDS: usize = 27;
const FRAME_REGISTERS: usize = 25;
const FRAME_SR: usize = 25;
const FRAME_PC: usize = 26;

core::arch::global_asm!(
    ".pushsection .text.sched, \"ax\"",
    // r0: where to store the outgoing stack pointer. r1: the incoming one.
    // The frame is the one an interrupt leaves, with the return address where
    // the interrupted `pc` goes, so `rti` resumes a thread that switched here
    // and one that was interrupted alike.
    ".globl sched_switch",
    "sched_switch:",
    "    mov.m r2, sr",
    "    sub sp, sp, #8",
    "    st r2, (sp)",
    "    st lr, (sp+4)",
    "    stm r0-r5,lr,(--sp)",
    "    stm r6-r23,(--sp)",
    "    st sp, (r0)",
    "    mov sp, r1",
    "sched_resume:",
    "    ldm r6-r23,(sp++)",
    "    ldm r0-r5,(sp++)",
    "    ld lr, (sp)",
    "    add sp, sp, #4",
    "    rti",
    // Where the first compare's handler goes on to once the threads run, with
    // the interrupted thread's frame saved as far as `r0`-`r5` and `lr`: the
    // rest of it, then whichever thread the tick resumes.
    ".globl sched_preempt",
    "sched_preempt:",
    "    stm r6-r23,(--sp)",
    "    mov r0, sp",
    "    bl sched_tick",
    "    mov sp, r0",
    "    b sched_resume",
    ".popsection",
);

unsafe extern "C" {
    fn sched_switch(save: *mut u32, load: u32);
    fn sched_preempt() -> !;
}

/// How often the tick comes while the threads run. A thread keeps the core
/// for between one and two of these unless it gives it up sooner.
pub const TICK_US: u32 = 1_000;

/// A thread's first run, with its entry point in `r0` like in every other
/// register of its first frame. It starts inside the section the switch into
/// it ran in, at the depth its spawner had, and closes that section before its
/// entry point runs, with interrupts enabled as every thread runs once
/// [`start`] has.
extern "C" fn first_run(entry: extern "C" fn() -> !) -> ! {
    drop(unsafe { Section::adopt() });
    critical::enable();
    entry()
}

/// The status register as it stands: what a fresh thread's first frame has
/// `rti` restore.
fn status() -> u32 {
    let sr: u32;
    unsafe { core::arch::asm!("mov.m {}, sr", out(reg) sr, options(nomem, nostack)) };
    sr
}

/// What a yield runs once [`start`] has set it. Read on every wait in the
/// firmware, including the whole boot path, where it is null and a yield
/// costs one load, and a stage that never starts the threads links none of
/// the switching.
static SWITCH: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
/// What [`Waiters::wake`] runs once [`start`] has set it, for the same reason:
/// an interrupt handler every stage links wakes through it.
static WAKE: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

struct Threads {
    /// Where each thread's switch left its stack pointer. The running
    /// thread's entry is stale until it switches out.
    sp: [Cell<u32>; THREADS],
    /// How deep each thread is in [`critical`] sections, kept while it is
    /// switched out. Stale for the running thread, like its `sp`.
    nesting: [Cell<Nesting>; THREADS],
    /// Whether each thread has said it has nothing left to do, and for how
    /// long at most it would have the core sleep.
    parked: [Cell<bool>; THREADS],
    nap_us: [Cell<u32>; THREADS],
    /// What each thread runs at: its own priority, or a higher one a lock it
    /// holds has lent it.
    priority: [Cell<Priority>; THREADS],
    own_priority: [Cell<Priority>; THREADS],
    /// Whether each thread has given the core up since a lower thread last
    /// did, and so waits for a lower one's turn before its own next one.
    waited: [Cell<bool>; THREADS],
    /// Whether each thread is blocked, until when, and whether what woke it
    /// was [`Waiters::wake`] rather than the time running out.
    blocked: [Cell<bool>; THREADS],
    deadline: [Cell<u32>; THREADS],
    woken: [Cell<bool>; THREADS],
    /// Each thread's stack, whose guard every switch checks.
    stack: [Cell<Stack>; THREADS],
    current: Cell<usize>,
    count: Cell<usize>,
    /// Whether a tick has come since the running thread was switched in: the
    /// next one ends its turn.
    ticked: Cell<bool>,
    /// Whether a wake has made a thread runnable that outranks the running
    /// one, which then gives the core up as the interrupt returns.
    outranked: Cell<bool>,
}

/// Single core, and every access is inside a [`critical`] section or the
/// tick's handler, which never runs inside one.
unsafe impl Sync for Threads {}

static THREADS_STATE: Threads = Threads {
    sp: [const { Cell::new(0) }; THREADS],
    nesting: [const { Cell::new(Nesting::OUTSIDE) }; THREADS],
    parked: [const { Cell::new(false) }; THREADS],
    nap_us: [const { Cell::new(0) }; THREADS],
    priority: [const { Cell::new(Priority(0)) }; THREADS],
    own_priority: [const { Cell::new(Priority(0)) }; THREADS],
    waited: [const { Cell::new(false) }; THREADS],
    blocked: [const { Cell::new(false) }; THREADS],
    deadline: [const { Cell::new(0) }; THREADS],
    woken: [const { Cell::new(false) }; THREADS],
    stack: [const { Cell::new(Stack::NONE) }; THREADS],
    current: Cell::new(0),
    count: Cell::new(1),
    ticked: Cell::new(false),
    outranked: Cell::new(false),
};

/// Whether the threads are running, and so whether a wait yields.
#[inline(always)]
pub fn running() -> bool {
    !SWITCH.load(Ordering::Relaxed).is_null()
}

/// Paint `stack`, lay a thread's first frame out at its top so that switching
/// to it returns into `entry`, and add it to the round at `priority`.
///
/// The stack is this thread's alone from here on, and `entry` never returns:
/// there is no frame under it to return to.
pub fn spawn(stack: &'static mut [u32], priority: Priority, entry: extern "C" fn() -> !) {
    let _section = critical::enter();
    let state = &THREADS_STATE;
    let index = state.count.get();
    assert!(index < THREADS, "more threads than the table holds");
    assert!(stack.len() > FRAME_WORDS, "thread stack smaller than a frame");
    let top = stack.len() - FRAME_WORDS;
    state.stack[index].set(Stack::paint(stack));
    let frame = &mut stack[top..];
    frame[..FRAME_REGISTERS].fill(entry as usize as u32);
    frame[FRAME_SR] = status();
    frame[FRAME_PC] = first_run as *const () as u32;
    state.sp[index].set(frame.as_ptr() as u32);
    state.nesting[index].set(critical::nesting());
    state.priority[index].set(priority);
    state.own_priority[index].set(priority);
    state.count.set(index + 1);
}

/// Hand the core to the next thread.
pub fn yield_now() {
    let switch = SWITCH.load(Ordering::Relaxed);
    if !switch.is_null() {
        let switch: fn() = unsafe { core::mem::transmute(switch) };
        switch();
    }
}

fn yield_running() {
    let section = critical::enter();
    let state = &THREADS_STATE;
    let current = state.current.get();
    state.parked[current].set(false);
    give_up(state, current);
    switch_to_next(state, &section);
}

/// Say this thread has run out of work and hand the core on. Once every
/// thread has parked or blocked the core sleeps for up to `idle_us`, which is
/// where the firmware spends nearly all of its time, and the highest thread
/// runs first when it wakes.
pub fn park(idle_us: u32) {
    if !running() {
        crate::idle::sleep_us(idle_us);
        return;
    }
    if critical::nesting().depth() != 0 {
        fault(Fault::SectionOpen, THREADS_STATE.current.get(), stack::current_sp());
    }
    let section = critical::enter();
    let state = &THREADS_STATE;
    let current = state.current.get();
    state.parked[current].set(true);
    state.nap_us[current].set(idle_us);
    give_up(state, current);
    switch_to_next(state, &section);
}

/// Start the round: the caller becomes thread 0, on `stack` and at
/// `priority`, and the spawned threads run for the first time as soon as it
/// yields or the tick takes the core off it. Interrupts are enabled from here
/// on outside sections.
pub fn start(stack: Stack, priority: Priority) {
    let _section = critical::enter();
    THREADS_STATE.stack[0].set(stack);
    THREADS_STATE.priority[0].set(priority);
    THREADS_STATE.own_priority[0].set(priority);
    WAKE.store(wake_highest as fn(&Waiters) -> bool as *mut (), Ordering::Relaxed);
    SWITCH.store(yield_running as fn() as *mut (), Ordering::Relaxed);
    crate::idle::tick_every(TICK_US, sched_preempt);
    critical::enable();
}

/// The tick, from inside the first compare's handler with the interrupted
/// code's whole frame at `sp`, or from the mailbox's once its signal has woken
/// a thread that outranks the running one. Ends the running thread's turn
/// once it has had the core for a whole tick, or at once for such a wake,
/// unless the interrupt woke a sleep inside a section. Returns the frame to
/// resume.
#[unsafe(no_mangle)]
extern "C" fn sched_tick(sp: u32) -> u32 {
    let state = &THREADS_STATE;
    let outranked = state.outranked.replace(false);
    if critical::nesting().depth() != 0 || !state.ticked.replace(true) && !outranked {
        return sp;
    }
    let from = state.current.get();
    state.parked[from].set(false);
    give_up(state, from);
    expire(state);
    let Some(to) = next(state, from) else { return sp };
    if to == from {
        return sp;
    }
    check_switch(state, from, to);
    unsafe { *state.hand_over(from, to) = sp };
    state.sp[to].get()
}

/// Each thread's stack, the one [`start`] was called on first.
pub fn stacks() -> impl Iterator<Item = Stack> {
    let _section = critical::enter();
    let state = &THREADS_STATE;
    let count = state.count.get();
    let stacks: [Stack; THREADS] = core::array::from_fn(|i| state.stack[i].get());
    stacks.into_iter().take(count)
}

/// Stop switching and the core with it: see [`stack::fault`].
#[cold]
#[inline(never)]
fn fault(fault: Fault, thread: usize, at: u32) -> ! {
    SWITCH.store(core::ptr::null_mut(), Ordering::Relaxed);
    stack::fault(fault, thread, at)
}

/// What has to hold for a switch from `from` to `to` to be safe: both stacks'
/// guards intact, room above the outgoing thread's guard for the frame the
/// switch pushes, and a saved stack pointer inside the incoming one's stack.
#[inline(always)]
fn check_switch(state: &Threads, from: usize, to: usize) {
    let (out, into) = (state.stack[from].get(), state.stack[to].get());
    let sp = stack::current_sp();
    if !out.intact() {
        fault(Fault::Overflow, from, sp);
    }
    if !out.has_room(sp, FRAME_WORDS as u32) {
        fault(Fault::StackPointer, from, sp);
    }
    if to >= state.count.get() {
        fault(Fault::NotRunnable, to, 0);
    }
    let resume = state.sp[to].get();
    if !into.intact() {
        fault(Fault::Overflow, to, resume);
    }
    if !into.holds(resume, FRAME_WORDS as u32) {
        fault(Fault::StackPointer, to, resume);
    }
}

/// Mark `thread` as having had its turn, and every thread above it as due
/// another.
fn give_up(state: &Threads, thread: usize) {
    let priority = state.priority[thread].get();
    for i in 0..state.count.get() {
        if state.priority[i].get() > priority {
            state.waited[i].set(false);
        }
    }
    state.waited[thread].set(true);
}

/// The highest thread still due a turn, looking from the one after `from` so
/// that equals take turns. Nothing is due once the lowest threads that can
/// run have all had theirs, and then they start over.
fn next(state: &Threads, from: usize) -> Option<usize> {
    if let Some(to) = highest_due(state, from) {
        return Some(to);
    }
    let count = state.count.get();
    let can_run = |i: &usize| !state.blocked[*i].get();
    let lowest = (0..count).filter(can_run).map(|i| state.priority[i].get()).min()?;
    for i in (0..count).filter(can_run) {
        if state.priority[i].get() == lowest {
            state.waited[i].set(false);
        }
    }
    highest_due(state, from)
}

fn highest_due(state: &Threads, from: usize) -> Option<usize> {
    let count = state.count.get();
    (1..=count)
        .map(|step| if from + step < count { from + step } else { from + step - count })
        .filter(|&i| !state.waited[i].get() && !state.blocked[i].get())
        .reduce(|best, i| if state.priority[i].get() > state.priority[best].get() { i } else { best })
}

/// Unblock every thread whose timeout has passed. One read of the clock, and
/// none while nothing is blocked.
fn expire(state: &Threads) {
    let count = state.count.get();
    if !(0..count).any(|i| state.blocked[i].get()) {
        return;
    }
    let now = crate::timer::now();
    for i in 0..count {
        if state.blocked[i].get() && now.wrapping_sub(state.deadline[i].get()) <= MAX_TIMEOUT_US {
            state.blocked[i].set(false);
            state.waited[i].set(false);
        }
    }
}

/// Whether no thread has anything to do: each has parked or is blocked.
fn all_idle(state: &Threads) -> bool {
    (0..state.count.get()).all(|i| state.parked[i].get() || state.blocked[i].get())
}

/// Sleep until the nearest thing any thread waits for: the shortest nap a
/// parked thread asked for, the nearest timeout of a blocked one, or an
/// interrupt. Every thread is asked again afterwards, highest first.
fn idle(state: &Threads) {
    let count = state.count.get();
    let now = crate::timer::now();
    let us = (0..count)
        .filter_map(|i| {
            if state.blocked[i].get() {
                Some(state.deadline[i].get().wrapping_sub(now).min(MAX_TIMEOUT_US))
            } else if state.parked[i].get() {
                Some(state.nap_us[i].get())
            } else {
                None
            }
        })
        .min()
        .unwrap_or(MAX_TIMEOUT_US);
    crate::idle::sleep_us(us.max(MIN_SLEEP_US));
    for i in 0..count {
        state.parked[i].set(false);
        state.waited[i].set(false);
    }
}

fn switch_to_next(state: &Threads, _section: &Section) {
    let from = state.current.get();
    let to = loop {
        expire(state);
        if !all_idle(state)
            && let Some(to) = next(state, from)
        {
            break to;
        }
        idle(state);
    };
    if to == from {
        return;
    }
    check_switch(state, from, to);
    let save = state.hand_over(from, to);
    unsafe { sched_switch(save, state.sp[to].get()) };
}

impl Threads {
    /// Make `to` the running thread, at its own depth in sections, and keep
    /// `from`'s for when it runs again. Returns where `from`'s stack pointer
    /// goes.
    fn hand_over(&self, from: usize, to: usize) -> *mut u32 {
        self.nesting[from].set(critical::nesting());
        unsafe { critical::restore(self.nesting[to].get()) };
        self.current.set(to);
        self.ticked.set(false);
        self.outranked.set(false);
        crate::idle::preempted();
        self.sp[from].as_ptr()
    }
}

/// A thread, as [`current`] names it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Thread(usize);

/// The running thread.
pub fn current() -> Thread {
    Thread(THREADS_STATE.current.get())
}

/// Have `thread` run at least at the running thread's priority until it
/// calls [`reclaim`]: what a lock's holder is lent by a thread that blocks on
/// it, so that nothing between the two keeps the holder from letting go.
pub fn lend(thread: Thread, _section: &Section) {
    let state = &THREADS_STATE;
    let priority = state.priority[state.current.get()].get();
    if state.priority[thread.0].get() < priority {
        state.priority[thread.0].set(priority);
    }
}

/// Put the running thread back at its own priority.
pub fn reclaim(_section: &Section) {
    let state = &THREADS_STATE;
    let current = state.current.get();
    state.priority[current].set(state.own_priority[current].get());
}

/// The threads blocked on one thing -- a semaphore's count, a lock -- and
/// what wakes them. A thread only ever blocks on one at a time.
pub struct Waiters {
    threads: Cell<u32>,
}

/// Single core, and only ever read or written inside a [`critical`] section.
unsafe impl Sync for Waiters {}

impl Waiters {
    pub const fn new() -> Waiters {
        Waiters { threads: Cell::new(0) }
    }

    /// Block the running thread here until [`Waiters::wake`] picks it or
    /// `timeout_us` passes, and say which it was. The thread is not asked
    /// again in between, and the section it blocks in is the one it comes
    /// back in, so whatever it checked before blocking still holds against an
    /// interrupt handler that wakes it.
    ///
    /// Only once the threads are running.
    pub fn block(&self, section: &Section, timeout_us: u32) -> bool {
        let state = &THREADS_STATE;
        let current = state.current.get();
        let deadline = crate::timer::now().wrapping_add(timeout_us.min(MAX_TIMEOUT_US));
        self.threads.set(self.threads.get() | 1 << current);
        state.blocked[current].set(true);
        state.deadline[current].set(deadline);
        state.woken[current].set(false);
        state.parked[current].set(false);
        give_up(state, current);
        switch_to_next(state, section);
        if state.woken[current].get() {
            return true;
        }
        self.threads.set(self.threads.get() & !(1 << current));
        false
    }

    /// Wake the highest thread blocked here, and say whether there was one.
    /// It runs at the next switch, as soon as it is the highest due. Safe from
    /// an interrupt handler.
    #[inline]
    pub fn wake(&self, _section: &Section) -> bool {
        let wake = WAKE.load(Ordering::Relaxed);
        if self.threads.get() == 0 || wake.is_null() {
            return false;
        }
        let wake: fn(&Waiters) -> bool = unsafe { core::mem::transmute(wake) };
        wake(self)
    }
}

impl Default for Waiters {
    fn default() -> Waiters {
        Waiters::new()
    }
}

fn wake_highest(waiters: &Waiters) -> bool {
    let state = &THREADS_STATE;
    let threads = waiters.threads.get();
    let Some(thread) = (0..state.count.get())
        .filter(|&i| threads & 1 << i != 0)
        .reduce(|best, i| if state.priority[i].get() > state.priority[best].get() { i } else { best })
    else {
        return false;
    };
    waiters.threads.set(threads & !(1 << thread));
    state.blocked[thread].set(false);
    state.woken[thread].set(true);
    state.waited[thread].set(false);
    if state.priority[thread].get() > state.priority[state.current.get()].get() {
        state.outranked.set(true);
        crate::idle::preempt();
    }
    true
}

//! What threads wait on besides the hardware: a counting [`Semaphore`] an
//! interrupt handler can signal, a [`Queue`] for handing work from one thread
//! to another, and a [`Lock`] over what one thread may hold while another
//! waits for it.
//!
//! Every wait takes a timeout in microseconds, and a thread waiting blocks in
//! [`crate::sched`] rather than asking again: nothing runs on its behalf until
//! it is woken or the time is up. Before the threads start there is nothing to
//! block in, and a wait polls instead, the way [`crate::timer::wait`] does.

use core::cell::Cell;
use core::mem::MaybeUninit;

use crate::critical::{self, Section};
use crate::sched::{self, Thread, Waiters};

/// A count threads take from and threads or interrupt handlers give back.
pub struct Semaphore {
    count: Cell<u32>,
    waiters: Waiters,
}

/// Single core, and the count is only ever read or written inside a
/// [`critical`] section.
unsafe impl Sync for Semaphore {}

impl Semaphore {
    pub const fn new(count: u32) -> Semaphore {
        Semaphore { count: Cell::new(count), waiters: Waiters::new() }
    }

    /// Take one, blocking for up to `timeout_us` while there is none; whether
    /// one was taken.
    pub fn wait(&self, timeout_us: u32) -> bool {
        if !sched::running() {
            return crate::timer::wait(timeout_us, || self.try_wait());
        }
        let section = critical::enter();
        self.take(&section) || timeout_us != 0 && self.waiters.block(&section, timeout_us)
    }

    /// Take one if there is one, without waiting. Safe from an interrupt
    /// handler.
    pub fn try_wait(&self) -> bool {
        self.take(&critical::enter())
    }

    /// Give one back: to the highest thread waiting, if one is, and to the
    /// count otherwise. Safe from an interrupt handler, and the thread it
    /// wakes runs at the next switch.
    pub fn signal(&self) {
        let section = critical::enter();
        if !self.waiters.wake(&section) {
            self.count.set(self.count.get().saturating_add(1));
        }
    }

    fn take(&self, _section: &Section) -> bool {
        let count = self.count.get();
        if count == 0 {
            return false;
        }
        self.count.set(count - 1);
        true
    }
}

/// Up to `N` items of `T` in the order they were sent.
pub struct Queue<T: Copy, const N: usize> {
    items: Semaphore,
    free: Semaphore,
    slots: [Cell<MaybeUninit<T>>; N],
    head: Cell<usize>,
    len: Cell<usize>,
}

/// Single core, and the slots are only ever read or written inside a
/// [`critical`] section.
unsafe impl<T: Copy + Send, const N: usize> Sync for Queue<T, N> {}

impl<T: Copy, const N: usize> Queue<T, N> {
    pub const fn new() -> Queue<T, N> {
        const { assert!(N > 0, "a queue holds at least one item") };
        Queue {
            items: Semaphore::new(0),
            free: Semaphore::new(N as u32),
            slots: [const { Cell::new(MaybeUninit::uninit()) }; N],
            head: Cell::new(0),
            len: Cell::new(0),
        }
    }

    /// Add `item` at the back, blocking for up to `timeout_us` while the
    /// queue is full; whether it went in. With a timeout of 0, safe from an
    /// interrupt handler.
    pub fn send(&self, item: T, timeout_us: u32) -> bool {
        if !self.free.wait(timeout_us) {
            return false;
        }
        {
            let _section = critical::enter();
            let len = self.len.get();
            self.slots[(self.head.get() + len) % N].set(MaybeUninit::new(item));
            self.len.set(len + 1);
        }
        self.items.signal();
        true
    }

    /// Take the item at the front, blocking for up to `timeout_us` while the
    /// queue is empty. With a timeout of 0, safe from an interrupt handler.
    pub fn receive(&self, timeout_us: u32) -> Option<T> {
        if !self.items.wait(timeout_us) {
            return None;
        }
        let item = {
            let _section = critical::enter();
            let head = self.head.get();
            let item = unsafe { self.slots[head].get().assume_init() };
            self.head.set((head + 1) % N);
            self.len.set(self.len.get() - 1);
            item
        };
        self.free.signal();
        Some(item)
    }
}

impl<T: Copy, const N: usize> Default for Queue<T, N> {
    fn default() -> Queue<T, N> {
        Queue::new()
    }
}

/// What one thread may hold while another waits for it: a bus session, or
/// anything else whose transfer must not be cut in half by a switch.
///
/// A thread holding this is still free to wait on hardware -- that is the
/// point of holding it -- so the wait inside yields and the lock is what
/// keeps the other thread out of the transfer. A thread that has to wait for
/// it blocks, and lends the holder its priority until the holder lets go, so
/// that no thread between the two keeps the holder from finishing.
pub struct Lock {
    free: Semaphore,
    holder: Cell<Option<Thread>>,
}

/// Single core, and the holder is only ever read or written inside a
/// [`critical`] section.
unsafe impl Sync for Lock {}

/// A held [`Lock`], let go when dropped.
pub struct Held<'a> {
    lock: &'a Lock,
}

impl Lock {
    pub const fn new() -> Lock {
        Lock { free: Semaphore::new(1), holder: Cell::new(None) }
    }

    /// Take the lock, blocking for up to `timeout_us` while another thread
    /// holds it.
    pub fn lock(&self, timeout_us: u32) -> Option<Held<'_>> {
        if !sched::running() {
            return self.free.wait(timeout_us).then_some(Held { lock: self });
        }
        let section = critical::enter();
        if !self.free.take(&section) {
            if let Some(holder) = self.holder.get() {
                sched::lend(holder, &section);
            }
            if timeout_us == 0 || !self.free.waiters.block(&section, timeout_us) {
                return None;
            }
        }
        self.holder.set(Some(sched::current()));
        Some(Held { lock: self })
    }
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        let section = critical::enter();
        if self.lock.holder.take().is_some() {
            sched::reclaim(&section);
        }
        self.lock.free.signal();
    }
}

impl Default for Lock {
    fn default() -> Lock {
        Lock::new()
    }
}

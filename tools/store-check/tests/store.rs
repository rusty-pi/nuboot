//! The variable store on a medium of RAM: what comes back after it is written,
//! what is stepped over, and how it moves from one bank to the other.

use std::cell::RefCell;
use std::rc::Rc;

use store_check::store::{self, DELETE, Medium, Record, SET};

const BANK: usize = 0x40000;

struct Ram(Rc<RefCell<Vec<u8>>>);

impl Medium for Ram {
    fn len(&self) -> u32 {
        (2 * BANK) as u32
    }

    fn read(&mut self, at: u32, buf: &mut [u8]) -> bool {
        buf.copy_from_slice(&self.0.borrow()[at as usize..at as usize + buf.len()]);
        true
    }

    fn write(&mut self, at: u32, data: &[u8]) -> bool {
        self.0.borrow_mut()[at as usize..at as usize + data.len()].copy_from_slice(data);
        true
    }
}

fn record(name: &str, size: usize, fill: u8) -> Record {
    Record {
        kind: SET,
        attributes: 7,
        guid: [3; 16],
        time: [0; 16],
        name: name.encode_utf16().collect(),
        data: vec![fill; size],
        auth: vec![9; 32],
    }
}

fn names(records: &[Record]) -> Vec<String> {
    records.iter().map(|r| String::from_utf16(&r.name).unwrap()).collect()
}

#[test]
fn the_store_is_a_log_that_survives_a_new_boot_and_moves_banks() {
    let ram = Rc::new(RefCell::new(vec![0u8; 2 * BANK]));
    store::attach(Box::new(Ram(ram.clone())));

    // A blank window is an empty store, which gets a first bank to append to.
    assert!(store::load().is_empty());
    assert!(store::available());
    store::start_if_empty();
    let (tail, end) = store::tail();
    assert_eq!((tail, end), (8, BANK as u32));

    // What is appended comes back, oldest first, at the next boot.
    assert!(store::append(&record("One", 100, 1), Vec::new));
    assert!(store::append(&record("Two", 200, 2), Vec::new));
    assert_eq!(names(&store::load()), ["One", "Two"]);

    // A record the log cannot read is stepped over, and the store moves to the
    // other bank without it.
    let second = ram.borrow().iter().position(|w| *w == 2).unwrap();
    ram.borrow_mut()[second] ^= 0xff;
    assert_eq!(names(&store::load()), ["One"]);
    let (tail, end) = store::tail();
    assert!(tail > BANK as u32 && end == 2 * BANK as u32, "the other bank: {tail} {end}");
    assert_eq!(names(&store::load()), ["One"]);

    // A bank that is full is replaced by the other, started with what is live.
    for n in 0..30 {
        let write = record("Big", 16 * 1024, n);
        let live = vec![record("One", 100, 1), write.clone()];
        assert!(store::append(&write, move || live));
    }
    let loaded = store::load();
    assert_eq!(names(&loaded)[0], "One");
    assert_eq!(loaded.last().unwrap().data[0], 29);
    assert!(loaded.len() < 31, "the log started over: {}", loaded.len());

    // More than half full at boot: the other bank is started with what is still
    // needed, and the rest of the log is left behind.
    let (tail, end) = store::tail();
    let bank = end - BANK as u32;
    let mut used = tail - bank - 8;
    while used <= (BANK as u32 - 8) / 2 {
        let write = record("Big", 16 * 1024, 99);
        let live = vec![record("One", 100, 1), write.clone()];
        assert!(store::append(&write, move || live));
        used = store::tail().0 - bank - 8;
    }
    let (before, _) = store::tail();
    store::compact_when_crowded(|| vec![record("One", 100, 1)]);
    let (after, now) = store::tail();
    assert!(now != end && after != before, "moved to the other bank");
    assert_eq!(names(&store::load()), ["One"]);

    // A deletion is a record like another.
    let mut gone = record("One", 0, 0);
    gone.kind = DELETE;
    assert!(store::append(&gone, Vec::new));
    let loaded = store::load();
    assert_eq!(loaded.len(), 2);
    assert_eq!(loaded[1].kind, DELETE);
}

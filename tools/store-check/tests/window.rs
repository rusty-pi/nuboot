//! Listing the store's window in a disk's partition table: when it is done,
//! when it is refused, and that what is written is a table other tools read.

use store_check::util::crc32;
use store_check::window::{self, Blocks, GPT_TYPE, Plan, Range};

struct Image {
    bytes: Vec<u8>,
    block_size: usize,
}

impl Image {
    fn new(block_size: usize, mib: usize) -> Image {
        Image { bytes: vec![0; mib << 20], block_size }
    }

    fn apply(&mut self, writes: &[window::Write]) {
        for w in writes {
            let at = w.lba as usize * self.block_size;
            self.bytes[at..at + w.data.len()].copy_from_slice(&w.data);
        }
    }

    fn block(&mut self, lba: usize) -> &mut [u8] {
        let at = lba * self.block_size;
        &mut self.bytes[at..at + self.block_size]
    }
}

impl Blocks for Image {
    fn block_size(&self) -> u32 {
        self.block_size as u32
    }

    fn blocks(&self) -> u64 {
        (self.bytes.len() / self.block_size) as u64
    }

    fn read(&mut self, lba: u64, buf: &mut [u8]) -> bool {
        let at = lba as usize * self.block_size;
        match self.bytes.get(at..at + buf.len()) {
            Some(src) => {
                buf.copy_from_slice(src);
                true
            }
            None => false,
        }
    }
}

const UNIQUE: [u8; 16] = [7; 16];

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

#[test]
fn the_window_is_where_the_gap_is() {
    assert_eq!(window::range(512), Some(Range { first: 1024, blocks: 1024 }));
    assert_eq!(window::range(4096), Some(Range { first: 128, blocks: 128 }));
    assert_eq!(window::range(256), None);
}

/// A GPT disk the way `sgdisk` makes it, with one partition at `first`.
fn gpt_disk(block_size: usize, first: u64) -> Image {
    let mut image = Image::new(block_size, 32);
    let total = (image.bytes.len() / block_size) as u64;
    let mbr = image.block(0);
    mbr[446 + 4] = 0xee;
    mbr[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes());
    mbr[446 + 12..446 + 16].copy_from_slice(&((total - 1) as u32).to_le_bytes());
    mbr[510] = 0x55;
    mbr[511] = 0xaa;
    let (count, size) = (128usize, 128usize);
    let table_blocks = (count * size).div_ceil(block_size) as u64;
    let mut table = vec![0u8; count * size];
    table[0..16].copy_from_slice(&[0xaf, 0x3d, 0xc6, 0x0f, 0x83, 0x84, 0x72, 0x47, 0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4]);
    table[16..32].copy_from_slice(&[9; 16]);
    table[32..40].copy_from_slice(&first.to_le_bytes());
    table[40..48].copy_from_slice(&(total - 1 - table_blocks - 1).to_le_bytes());
    let table_crc = crc32(&table);
    let usable = (2 + table_blocks, total - 2 - table_blocks);
    let header = |this: u64, other: u64, entries: u64| {
        let mut h = vec![0u8; block_size];
        h[0..8].copy_from_slice(b"EFI PART");
        h[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
        h[12..16].copy_from_slice(&92u32.to_le_bytes());
        h[24..32].copy_from_slice(&this.to_le_bytes());
        h[32..40].copy_from_slice(&other.to_le_bytes());
        h[40..48].copy_from_slice(&usable.0.to_le_bytes());
        h[48..56].copy_from_slice(&usable.1.to_le_bytes());
        h[56..72].copy_from_slice(&[5; 16]);
        h[72..80].copy_from_slice(&entries.to_le_bytes());
        h[80..84].copy_from_slice(&(count as u32).to_le_bytes());
        h[84..88].copy_from_slice(&(size as u32).to_le_bytes());
        h[88..92].copy_from_slice(&table_crc.to_le_bytes());
        let crc = crc32(&h[..92]);
        h[16..20].copy_from_slice(&crc.to_le_bytes());
        h
    };
    let (primary, backup) = (header(1, total - 1, 2), header(total - 1, 1, total - 1 - table_blocks));
    image.apply(&[
        window::Write { lba: 1, data: primary },
        window::Write { lba: 2, data: table.clone() },
        window::Write { lba: total - 1 - table_blocks, data: table },
        window::Write { lba: total - 1, data: backup },
    ]);
    image
}

#[test]
fn a_gpt_disk_gets_an_entry_in_both_tables_and_then_has_one() {
    for (block_size, first) in [(512, 2048), (4096, 256)] {
        let mut image = gpt_disk(block_size, first);
        let Plan::List(range, writes) = window::plan(&mut image, UNIQUE) else { panic!("not listed at {block_size}") };
        assert_eq!(writes.len(), 4, "table block and header, in both");
        image.apply(&writes);
        assert_eq!(window::plan(&mut image, UNIQUE), Plan::Found(range));

        let total = (image.bytes.len() / block_size) as u64;
        let bs = block_size;
        let table_blocks = (128 * 128usize).div_ceil(bs) as u64;
        assert_eq!(le64(&image.bytes[bs..], 40), 2 + table_blocks.min(range.first - 2), "first usable block");
        let primary_table = image.bytes[2 * bs..2 * bs + 128 * 128].to_vec();
        let backup_at = (total - 1 - table_blocks) as usize * bs;
        assert_eq!(primary_table, image.bytes[backup_at..backup_at + 128 * 128]);
        let entry = &primary_table[128..256];
        assert_eq!(entry[0..16], GPT_TYPE);
        assert_eq!(entry[16..32], UNIQUE);
        assert_eq!(le64(entry, 32), range.first);
        assert_eq!(le64(entry, 40), range.first + range.blocks - 1);
        for header_lba in [1, total - 1] {
            let at = header_lba as usize * bs;
            let mut h = image.bytes[at..at + 92].to_vec();
            assert_eq!(le32(&h, 88), crc32(&primary_table));
            let crc = le32(&h, 16);
            h[16..20].fill(0);
            assert_eq!(crc, crc32(&h));
        }
    }
}

#[test]
fn a_gpt_partition_in_the_way_refuses() {
    let mut image = gpt_disk(512, 800);
    assert!(matches!(window::plan(&mut image, UNIQUE), Plan::Refuse(_)));
}

#[test]
fn a_gpt_that_is_not_intact_refuses() {
    let mut image = gpt_disk(512, 2048);
    image.block(2)[40] ^= 1;
    assert!(matches!(window::plan(&mut image, UNIQUE), Plan::Refuse(_)), "table");

    let mut image = gpt_disk(512, 2048);
    image.block(1)[56] ^= 1;
    assert!(matches!(window::plan(&mut image, UNIQUE), Plan::Refuse(_)), "header");

    let mut image = gpt_disk(512, 2048);
    let last = image.bytes.len() / 512 - 1;
    image.block(last)[56] ^= 1;
    assert!(matches!(window::plan(&mut image, UNIQUE), Plan::Refuse(_)), "backup");
}

#[test]
fn a_gpt_with_no_free_entry_refuses() {
    let mut image = gpt_disk(512, 2048);
    let mut table = image.bytes[2 * 512..2 * 512 + 128 * 128].to_vec();
    for slot in 1..128 {
        table[slot * 128..slot * 128 + 16].copy_from_slice(&[1; 16]);
        table[slot * 128 + 32..slot * 128 + 40].copy_from_slice(&(9000u64 + slot as u64).to_le_bytes());
        table[slot * 128 + 40..slot * 128 + 48].copy_from_slice(&(9000u64 + slot as u64).to_le_bytes());
    }
    let crc = crc32(&table);
    let total = image.bytes.len() / 512;
    for (header, at) in [(1usize, 2usize), (total - 1, total - 1 - 32)] {
        image.bytes[at * 512..at * 512 + table.len()].copy_from_slice(&table);
        let h = image.block(header);
        h[88..92].copy_from_slice(&crc.to_le_bytes());
        h[16..20].fill(0);
        let sum = crc32(&h[..92]);
        h[16..20].copy_from_slice(&sum.to_le_bytes());
    }
    assert!(matches!(window::plan(&mut image, UNIQUE), Plan::Refuse(_)));
}

/// What `sfdisk` says of a table is what other tools will: it checks both
/// headers' checksums and that the backup matches. Skipped without it.
#[test]
fn sfdisk_reads_the_tables_that_are_written() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let dir = std::env::temp_dir().join(format!("store-check-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for label in ["gpt"] {
        let path = dir.join(format!("{label}.img"));
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(64 << 20).unwrap();
        let script = format!("label: {label}\nstart=2048, size=8MiB, type=L\n");
        let made = Command::new("sfdisk").arg(&path).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn();
        let Ok(mut made) = made else {
            eprintln!("skipped: no sfdisk");
            return;
        };
        made.stdin.take().unwrap().write_all(script.as_bytes()).unwrap();
        assert!(made.wait().unwrap().success());

        let mut image = Image { bytes: std::fs::read(&path).unwrap(), block_size: 512 };
        let Plan::List(range, writes) = window::plan(&mut image, UNIQUE) else { panic!("{label} not listed") };
        image.apply(&writes);
        assert_eq!(window::plan(&mut image, UNIQUE), Plan::Found(range));
        std::fs::write(&path, &image.bytes).unwrap();

        let verify = Command::new("sfdisk").arg("--verify").arg(&path).output().unwrap();
        assert!(verify.status.success(), "{label}: {}", String::from_utf8_lossy(&verify.stderr));
        let dump = Command::new("sfdisk").arg("-d").arg(&path).output().unwrap();
        let dump = String::from_utf8_lossy(&dump.stdout);
        assert!(dump.contains("start=        1024, size=        1024"), "{label}: {dump}");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_window_with_data_in_it_refuses() {
    let mut image = gpt_disk(512, 2048);
    image.block(1500)[3] = 1;
    assert!(matches!(window::plan(&mut image, UNIQUE), Plan::Refuse(_)));
}

#[test]
fn a_window_of_ones_is_free() {
    let mut image = gpt_disk(512, 2048);
    image.bytes[512 * 1024..1024 * 1024].fill(0xff);
    assert!(matches!(window::plan(&mut image, UNIQUE), Plan::List(..)));
}

#[test]
fn a_disk_that_is_not_a_gpt_refuses() {
    let mut blank = Image::new(512, 32);
    assert!(matches!(window::plan(&mut blank, UNIQUE), Plan::Refuse(_)));
    let mut mbr = Image::new(512, 32);
    mbr.block(0)[446 + 4] = 0x0c;
    mbr.block(0)[510] = 0x55;
    mbr.block(0)[511] = 0xaa;
    assert!(matches!(window::plan(&mut mbr, UNIQUE), Plan::Refuse(_)));
}

#[test]
fn a_small_disk_refuses() {
    let mut image = Image::new(512, 1);
    assert!(matches!(window::plan(&mut image, UNIQUE), Plan::Refuse(_)));
}

#[test]
fn a_first_usable_block_above_the_window_is_moved_down() {
    let mut image = gpt_disk(512, 2048);
    for header in [1usize, image.bytes.len() / 512 - 1] {
        let h = image.block(header);
        h[40..48].copy_from_slice(&2048u64.to_le_bytes());
        h[16..20].fill(0);
        let crc = crc32(&h[..92]);
        h[16..20].copy_from_slice(&crc.to_le_bytes());
    }
    let Plan::List(range, writes) = window::plan(&mut image, UNIQUE) else { panic!("not listed") };
    image.apply(&writes);
    assert_eq!(window::plan(&mut image, UNIQUE), Plan::Found(range));
    assert_eq!(le64(&image.bytes[512..], 40), range.first);
}

//! NV indices outlast a restart as records the VPU seals: the first process is
//! a boot that defines and changes indices and exports the records, the second
//! a boot that imports them.

use tpm_sim::{otp, tpm2};
use tpm2::{NvExportError as ExportError, NvImportError as ImportError};

mod nv {
    pub use tpm_sim::tpm2::{NV_RECORD_MAX as RECORD_MAX, nv_export as export, nv_import as import};
}

const ST_NO_SESSIONS: u16 = 0x8001;
const ST_SESSIONS: u16 = 0x8002;
const RH_OWNER: u32 = 0x4000_0001;
const RS_PW: u32 = 0x4000_0009;

const CC_NV_UNDEFINE_SPACE: u32 = 0x122;
const CC_NV_DEFINE_SPACE: u32 = 0x12a;
const CC_NV_INCREMENT: u32 = 0x134;
const CC_NV_EXTEND: u32 = 0x136;
const CC_NV_WRITE: u32 = 0x137;
const CC_NV_READ: u32 = 0x14e;
const CC_NV_READ_PUBLIC: u32 = 0x169;

const AUTHWRITE: u32 = 1 << 2;
const NT_COUNTER: u32 = 1 << 4;
const NT_EXTEND: u32 = 4 << 4;
const AUTHREAD: u32 = 1 << 18;
const CLEAR_STCLEAR: u32 = 1 << 27;
const WRITTEN: u32 = 1 << 29;

const RC_BAD_AUTH: u32 = 0x9a2;
const RC_HANDLE: u32 = 0x18b;

const PLAIN: u32 = 0x0150_0001;
const COUNTER: u32 = 0x0150_0002;
const BOOT_BOUND: u32 = 0x01d1_0301;
const GONE: u32 = 0x0150_0003;

fn sized(bytes: &[u8]) -> Vec<u8> {
    let mut out = (bytes.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(bytes);
    out
}

fn send(tag: u16, code: u32, handles: &[u32], auth: &[u8], params: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    for h in handles {
        body.extend_from_slice(&h.to_be_bytes());
    }
    if tag == ST_SESSIONS {
        body.extend_from_slice(&(auth.len() as u32).to_be_bytes());
        body.extend_from_slice(auth);
    }
    body.extend_from_slice(params);
    let mut command = tag.to_be_bytes().to_vec();
    command.extend_from_slice(&((10 + body.len()) as u32).to_be_bytes());
    command.extend_from_slice(&code.to_be_bytes());
    command.extend_from_slice(&body);
    let mut response = vec![0u8; tpm2::MAX_COMMAND];
    let n = tpm2::execute(&command, &mut response);
    response.truncate(n);
    response
}

fn rc(response: &[u8]) -> u32 {
    u32::from_be_bytes(response[6..10].try_into().unwrap())
}

fn password(secret: &[u8]) -> Vec<u8> {
    let mut a = RS_PW.to_be_bytes().to_vec();
    a.extend(sized(&[]));
    a.push(0);
    a.extend(sized(secret));
    a
}

fn define(index: u32, attributes: u32, size: u16, auth: &[u8]) {
    let mut public = index.to_be_bytes().to_vec();
    public.extend_from_slice(&0x000bu16.to_be_bytes());
    public.extend_from_slice(&attributes.to_be_bytes());
    public.extend(sized(&[]));
    public.extend_from_slice(&size.to_be_bytes());
    let mut p = sized(auth);
    p.extend(sized(&public));
    assert_eq!(rc(&send(ST_SESSIONS, CC_NV_DEFINE_SPACE, &[RH_OWNER], &password(&[]), &p)), 0);
}

fn attributes(index: u32) -> u32 {
    let response = send(ST_NO_SESSIONS, CC_NV_READ_PUBLIC, &[index], &[], &[]);
    assert_eq!(rc(&response), 0);
    u32::from_be_bytes(response[10 + 2 + 6..10 + 2 + 10].try_into().unwrap())
}

fn read(index: u32, size: u16, secret: &[u8]) -> Result<Vec<u8>, u32> {
    let mut p = size.to_be_bytes().to_vec();
    p.extend_from_slice(&0u16.to_be_bytes());
    let response = send(ST_SESSIONS, CC_NV_READ, &[index, index], &password(secret), &p);
    match rc(&response) {
        0 => {
            let size = u32::from_be_bytes(response[10..14].try_into().unwrap()) as usize;
            Ok(response[16..14 + size].to_vec())
        }
        code => Err(code),
    }
}

fn write(index: u32, data: &[u8]) {
    let mut p = sized(data);
    p.extend_from_slice(&0u16.to_be_bytes());
    assert_eq!(rc(&send(ST_SESSIONS, CC_NV_WRITE, &[index, index], &password(b"pw"), &p)), 0);
}

fn export_all() -> Vec<Vec<u8>> {
    let mut records = Vec::new();
    loop {
        let mut record = [0u8; nv::RECORD_MAX];
        match nv::export(&mut record) {
            Ok(n) => records.push(record[..n].to_vec()),
            Err(ExportError::Nothing) => return records,
            Err(e) => panic!("{e:?}"),
        }
    }
}

fn fuse() {
    let mut rows = otp::ROWS.lock().unwrap();
    for (i, row) in rows.iter_mut().enumerate() {
        *row = 0xc0de_2001 + 0x1111 * i as u32;
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn a_restart_keeps_the_indices() {
    let mut record = [0u8; nv::RECORD_MAX];
    assert_eq!(nv::export(&mut record), Err(ExportError::NoDeviceKey), "no key, no records");
    fuse();
    assert_eq!(nv::export(&mut record), Err(ExportError::Nothing));

    define(PLAIN, AUTHWRITE | AUTHREAD, 16, b"pw");
    write(PLAIN, b"first");
    write(PLAIN, b"second and last");
    define(COUNTER, AUTHWRITE | AUTHREAD | NT_COUNTER, 8, b"pw");
    for _ in 0..3 {
        assert_eq!(rc(&send(ST_SESSIONS, CC_NV_INCREMENT, &[COUNTER, COUNTER], &password(b"pw"), &[])), 0);
    }
    define(BOOT_BOUND, AUTHWRITE | AUTHREAD | NT_EXTEND | CLEAR_STCLEAR, 32, b"pw");
    assert_eq!(rc(&send(ST_SESSIONS, CC_NV_EXTEND, &[BOOT_BOUND, BOOT_BOUND], &password(b"pw"), &sized(&[1; 32]))), 0);
    define(GONE, AUTHWRITE | AUTHREAD, 4, b"pw");
    assert_eq!(rc(&send(ST_SESSIONS, CC_NV_UNDEFINE_SPACE, &[RH_OWNER, GONE], &password(&[]), &[])), 0);

    let records = export_all();
    assert_eq!(records.len(), 4, "three indices and the removal of one");
    assert!(export_all().is_empty(), "each change is exported once");

    let plain = records[0].windows(15).any(|w| w == b"second and last");
    assert!(!plain, "the data is not in the clear");
    assert!(records.iter().all(|r| !r.windows(2).any(|w| w == b"pw")), "nor is the authorization value");

    write(PLAIN, b"third");
    assert_eq!(export_all().len(), 1, "a later change is a record of its own");

    let mut forged = records[1].clone();
    forged[40] ^= 1;
    assert_eq!(nv::import(&forged), Err(ImportError::Malformed), "a record the VPU did not make");
    assert_eq!(nv::import(&records[1][..records[1].len() - 1]), Err(ImportError::Malformed));

    let dir = std::env::temp_dir().join(format!("nv-persist-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("records");
    let mut all = records.clone();
    all.push(export_changed_again());
    std::fs::write(&file, all.iter().map(|r| hex(r)).collect::<Vec<_>>().join("\n")).unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "the_next_boot", "--nocapture", "--test-threads=1"])
        .env("NV_RECORDS", &file)
        .status()
        .unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(status.success(), "the second boot");
}

fn export_changed_again() -> Vec<u8> {
    write(PLAIN, b"fourth");
    let mut out = export_all();
    assert_eq!(out.len(), 1);
    out.remove(0)
}

#[test]
fn the_next_boot() {
    let Some(path) = std::env::var_os("NV_RECORDS") else { return };
    let text = std::fs::read_to_string(path).unwrap();
    let records: Vec<Vec<u8>> = text.lines().map(unhex).collect();
    assert_eq!(records.len(), 5);

    let mut record = [0u8; nv::RECORD_MAX];
    assert_eq!(nv::export(&mut record), Err(ExportError::NoDeviceKey), "this boot has no key yet");
    assert_eq!(nv::import(&records[0]), Err(ImportError::NoDeviceKey));
    fuse();
    assert_eq!(rc(&send(ST_NO_SESSIONS, CC_NV_READ_PUBLIC, &[PLAIN], &[], &[])), RC_HANDLE | 1);

    for r in &records {
        let imported = nv::import(r);
        assert_eq!(imported, Ok(()));
    }
    assert!(nv::import(&records[0]).is_err(), "an older record is not taken after a newer one");
    assert_eq!(read(PLAIN, 16, b"pw").unwrap()[..6], *b"fourth", "the newest record of an index wins");
    assert_eq!(read(PLAIN, 16, b"wrong"), Err(RC_BAD_AUTH), "the authorization value came back");
    assert_eq!(read(COUNTER, 8, b"pw").unwrap(), 3u64.to_be_bytes());
    assert_ne!(attributes(PLAIN) & WRITTEN, 0);
    assert_eq!(attributes(BOOT_BOUND) & WRITTEN, 0, "an index that clears at a restart is empty");
    assert_eq!(rc(&send(ST_NO_SESSIONS, CC_NV_READ_PUBLIC, &[GONE], &[], &[])), RC_HANDLE | 1, "the removed one stays removed");
    assert_eq!(nv::export(&mut record), Err(ExportError::Nothing), "what was imported is not exported again");

    assert_eq!(rc(&send(ST_SESSIONS, CC_NV_UNDEFINE_SPACE, &[RH_OWNER, COUNTER], &password(&[]), &[])), 0);
    assert_eq!(export_all().len(), 1);
}

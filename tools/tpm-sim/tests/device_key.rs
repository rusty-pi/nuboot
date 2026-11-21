use tpm_sim::{keystore, otp};

const ROWS: [u32; 8] = [0xc0de2001, 0xc0de3112, 0xc0de4223, 0xc0de5334, 0xc0de6445, 0xc0de7556, 0xc0de8667, 0xc0de9778];
const STOCK_X: &str = "ea21404f3cade9c0cc70351a4fd2772b6bf1ed5600133182aa34b6ca13dfe1dd";
const STOCK_Y: &str = "c293679a1a0876542afe26ed8fbd6f00a65f7c7294420df987e4c48c8cd8eaab";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn rows_read_as_stock_reads_them() {
    *otp::ROWS.lock().unwrap() = ROWS;
    let public = keystore::device_public().ok().unwrap();
    assert_eq!(hex(&public.x), STOCK_X);
    assert_eq!(hex(&public.y), STOCK_Y);
}

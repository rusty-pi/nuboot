//! Fusing the device key on a board's first boot.
//!
//! A release image's `bootconf.txt` carries `NUBOOT_PROVISION_DEVICE_KEY=1` in
//! its `[all]` section. The firmware honours it only on a board with signed boot
//! programmed in the OTP, where the bootloader has already checked
//! `bootconf.txt` against `bootconf.sig` and the owner's key, and only while
//! rows 56-63 are blank. Otherwise it fuses nothing.

use crate::keystore::{self, ProvisionFault, Provisioned};
use crate::{eeprom, error, info, otp, warn};

const FLAG: &[u8] = b"NUBOOT_PROVISION_DEVICE_KEY";

/// Fuse the device key if the board asks for it and may. Never stops the boot:
/// whatever goes wrong is logged. With no row fused the TPM's seeds come from a
/// key drawn for this boot alone, as on any board without one.
pub fn run() {
    match eeprom::bootconf_flag(FLAG) {
        Ok(false) => return,
        Ok(true) => {}
        Err(_) => {
            warn!("provision", "bootconf.txt could not be read, no device key is fused");
            return;
        }
    }
    if !otp::signed_boot() {
        warn!("provision", "NUBOOT_PROVISION_DEVICE_KEY ignored, the board has no signed boot in the OTP";
            bootmode = format_args!("{:08x}", otp::read(otp::BOOTMODE)));
        return;
    }
    match keystore::provision_device_key() {
        Ok(Provisioned::Fused { rows }) => info!("provision", "device key fused"; rows = rows),
        Ok(Provisioned::Present { blank_rows: 0, valid: true }) => {
            info!("provision", "device key already fused, nothing written")
        }
        Ok(Provisioned::Present { blank_rows, valid }) => warn!("provision",
            "device key rows are fused but do not form a whole key, nothing written";
            blank_rows = blank_rows, valid = valid),
        Err(failed) => error!("provision", "device key not fused whole";
            reason = match failed.fault {
                ProvisionFault::NoRandom => "no random numbers",
                ProvisionFault::NotEnabled => "programming not enabled",
                ProvisionFault::Command => "program command failed",
                ProvisionFault::Mismatch => "rows read back differently",
            },
            rows_fused = failed.rows_fused),
    }
}

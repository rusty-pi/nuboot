//! Fusing the device key on a board's first boot.
//!
//! A release image's `bootconf.txt` carries `NUBOOT_PROVISION_DEVICE_KEY=1` and
//! `SIGNED_BOOT=1` in its `[all]` section. The firmware honours the request only
//! with both, and only while rows 56-63 are blank. With signed boot programmed
//! in the OTP the bootloader has checked `bootconf.txt` against `bootconf.sig`,
//! so the request is authenticated; without it the request is the word of
//! whoever can write the EEPROM, and the firmware says so.

use crate::keystore::{self, ProvisionFault, Provisioned};
use crate::{eeprom, error, info, otp, warn};

const FLAG: &[u8] = b"NUBOOT_PROVISION_DEVICE_KEY";
const OWNER_INTENT: &[u8] = b"SIGNED_BOOT";

/// Fuse the device key if the board asks for it and may. Never stops the boot:
/// whatever goes wrong is logged. With no row fused the TPM's seeds come from a
/// key drawn for this boot alone, as on any board without one.
pub fn run() {
    let signed_boot_set = match eeprom::bootconf_flags([FLAG, OWNER_INTENT]) {
        Ok([false, _]) => return,
        Ok([true, signed_boot_set]) => signed_boot_set,
        Err(_) => {
            warn!("provision", "bootconf.txt could not be read, no device key is fused");
            return;
        }
    };
    if !signed_boot_set {
        warn!("provision", "NUBOOT_PROVISION_DEVICE_KEY ignored, bootconf.txt does not set SIGNED_BOOT=1";
            bootmode = format_args!("{:08x}", otp::read(otp::BOOTMODE)));
        return;
    }
    if !otp::signed_boot() {
        warn!("provision", "NUBOOT_PROVISION_DEVICE_KEY is not authenticated, the OTP has no signed boot";
            bootmode = format_args!("{:08x}", otp::read(otp::BOOTMODE)));
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

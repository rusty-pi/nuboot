//! Asks for the GPIO expander's pins over the property mailbox, as the OS's
//! regulators do: the SD card's two are answered, and the others are not.

#![no_std]
#![no_main]

use r_efi::efi::{Handle, Status, SystemTable};

#[path = "boot_key_common.rs"]
mod common;

const TAG_GET_GPIO_STATE: u32 = 0x0003_0041;
const TAG_SET_GPIO_STATE: u32 = 0x0003_8041;
const TAG_GET_GPIO_CONFIG: u32 = 0x0003_0043;
const TAG_SET_GPIO_CONFIG: u32 = 0x0003_8043;
const FIRST_GPIO: u32 = 128;
const SD_IO_SELECT: u32 = FIRST_GPIO + 4;
const SD_POWER_ON: u32 = FIRST_GPIO + 6;
const WIFI_ON: u32 = FIRST_GPIO + 1;
const POWER_LED: u32 = FIRST_GPIO + 2;
const CAMERA: u32 = FIRST_GPIO + 5;

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(_image: Handle, system_table: *mut SystemTable) -> Status {
    let Some(buf) = common::page_below_1gib(system_table) else {
        common::say(system_table, "gpio test: no page below 1 GiB\r\n");
        return Status::OUT_OF_RESOURCES;
    };
    let say = |text: &str| common::say(system_table, text);

    let power = common::call(buf, TAG_GET_GPIO_CONFIG, &[SD_POWER_ON]);
    say(match power {
        Some(config) if config[0] == 0 && config[1] == 1 => "gpio test: SD power pin is an output\r\n",
        Some(_) => "gpio test: SD power pin is not an output\r\n",
        None => "gpio test: SD power pin config not answered\r\n",
    });
    let level = common::call(buf, TAG_GET_GPIO_STATE, &[SD_POWER_ON]).map(|state| state[1]);
    say(if level == Some(1) { "gpio test: SD power is on\r\n" } else { "gpio test: SD power is not on\r\n" });
    let select = common::call(buf, TAG_GET_GPIO_STATE, &[SD_IO_SELECT]).map(|state| state[1]);
    let same = select.map(|level| common::call(buf, TAG_SET_GPIO_STATE, &[SD_IO_SELECT, level]).map(|state| state[1]));
    say(if same == Some(select) && select.is_some() { "gpio test: SD signalling level set and read back\r\n" } else { "gpio test: SD signalling level not set\r\n" });
    let config = common::call(buf, TAG_GET_GPIO_CONFIG, &[SD_IO_SELECT]).is_some();
    let set_config = common::call(buf, TAG_SET_GPIO_CONFIG, &[SD_IO_SELECT, 1, 0, 0, 0, select.unwrap_or(0)]).is_some();
    say(if config && set_config { "gpio test: SD signalling pin configured\r\n" } else { "gpio test: SD signalling pin not configured\r\n" });

    let refused = [WIFI_ON, POWER_LED, CAMERA, FIRST_GPIO, FIRST_GPIO + 3, FIRST_GPIO + 7, FIRST_GPIO + 8, 0].iter().all(|&gpio| {
        common::call(buf, TAG_GET_GPIO_CONFIG, &[gpio]).is_none()
            && common::call(buf, TAG_GET_GPIO_STATE, &[gpio]).is_none()
            && common::call(buf, TAG_SET_GPIO_STATE, &[gpio, 1]).is_none()
            && common::call(buf, TAG_SET_GPIO_CONFIG, &[gpio, 1, 0, 0, 0, 1]).is_none()
    });
    say(if refused { "gpio test: the other pins are refused\r\n" } else { "gpio test: another pin was answered\r\n" });
    say("gpio test: done\r\n");
    Status::SUCCESS
}

//! `EFI_GRAPHICS_OUTPUT_PROTOCOL` for the framebuffer the VPU lit on HDMI0: one
//! mode, which an OS draws in directly (`efifb`, `simpledrm`). `Blt` is not
//! implemented.

use core::ffi::c_void;

use r_efi::efi;
use r_efi::protocols::graphics_output as gop;

use crate::util::{Global, Hex};
use crate::{info, mailbox};

static MODE_INFO: Global<gop::ModeInformation> = Global::new(gop::ModeInformation {
    version: 0,
    horizontal_resolution: 0,
    vertical_resolution: 0,
    pixel_format: gop::PIXEL_BLUE_GREEN_RED_RESERVED_8_BIT_PER_COLOR,
    pixel_information: gop::PixelBitmask { red_mask: 0, green_mask: 0, blue_mask: 0, reserved_mask: 0 },
    pixels_per_scan_line: 0,
});

static MODE: Global<gop::Mode> = Global::new(gop::Mode {
    max_mode: 1,
    mode: 0,
    info: core::ptr::null_mut(),
    size_of_info: core::mem::size_of::<gop::ModeInformation>(),
    frame_buffer_base: 0,
    frame_buffer_size: 0,
});

static PROTOCOL: Global<gop::Protocol> =
    Global::new(gop::Protocol { query_mode, set_mode, blt, mode: core::ptr::null_mut() });

extern "efiapi" fn query_mode(
    _this: *mut gop::Protocol,
    mode: u32,
    size: *mut usize,
    info: *mut *mut gop::ModeInformation,
) -> efi::Status {
    if size.is_null() || info.is_null() || mode != 0 {
        return efi::Status::INVALID_PARAMETER;
    }
    unsafe {
        *size = core::mem::size_of::<gop::ModeInformation>();
        *info = MODE_INFO.get();
    }
    efi::Status::SUCCESS
}

extern "efiapi" fn set_mode(_this: *mut gop::Protocol, mode: u32) -> efi::Status {
    if mode == 0 { efi::Status::SUCCESS } else { efi::Status::UNSUPPORTED }
}

extern "efiapi" fn blt(
    _this: *mut gop::Protocol,
    _buffer: *mut gop::BltPixel,
    _operation: gop::BltOperation,
    _sx: usize,
    _sy: usize,
    _dx: usize,
    _dy: usize,
    _width: usize,
    _height: usize,
    _delta: usize,
) -> efi::Status {
    efi::Status::UNSUPPORTED
}

/// Install the protocol when the VPU has lit HDMI0.
pub fn install() {
    let Some(fb) = mailbox::framebuffer() else { return };
    let mode_info = MODE_INFO.get();
    mode_info.horizontal_resolution = fb.width;
    mode_info.vertical_resolution = fb.height;
    mode_info.pixels_per_scan_line = fb.pitch / 4;
    let mode = MODE.get();
    mode.info = mode_info;
    mode.frame_buffer_base = fb.base;
    mode.frame_buffer_size = fb.pitch as usize * fb.height as usize;
    let protocol = PROTOCOL.get();
    protocol.mode = mode;
    let p = protocol as *mut gop::Protocol as *mut c_void;
    if crate::proto::install(core::ptr::null_mut(), &gop::PROTOCOL_GUID, p).is_ok() {
        info!("gop", "framebuffer"; at = Hex(fb.base), width = fb.width, height = fb.height);
    }
}

# The boot measurement and the boot key

The firmware keeps the device private key (OTP rows 56-63) in the VPU and
gives the payload a key derived from it and from what was booted. A payload
that was not the one the key was meant for gets a different key.

## What the firmware does

1. UEFI loads each image only if Secure Boot accepts it ([uefi.md](uefi.md)).
   It sends the image's Authenticode SHA-256 to the VPU over the property
   mailbox (tag `0x000300a1`), and `start4.elf` folds it into the boot
   measurement: `SHA-256(measurement || digest)`, from 32 zero bytes. Every
   `LoadImage` counts, so shim, GRUB and anything they load through UEFI
   extend it. An application can extend it too, until it is closed.
2. The measurement is closed when UEFI exits boot services (tag
   `0x000300a2`, sent before the OS has the board), or when the key is taken.
   After that every extend is refused.
3. Whatever runs last asks for the key (tag `0x000300a0`, 32 bytes of room).
   The VPU reads rows 56-63 then, computes
   `HMAC-SHA256(private key, "pi4-server-firmware boot key v1" || measurement)`,
   overwrites everything the computation touched and writes the zeros out of
   the VPU's caches to SDRAM. It answers once. A board without a fused
   private key answers nothing.

The firmware answers no tag that returns a fuse, and the ARM cannot reach the
OTP block, so the private key itself never reaches the ARM, whatever
`config.txt` says. Stock `start4.elf` answers such tags unless `config.txt`
sets `lock_device_private_key=1`: without it Linux reads rows 56-63 through
`nvmem_priv0`, with it they read as blank. Measured on a Raspberry Pi 4
Model B d03115.

## What it does not protect

- The VPU's memory is readable and writable from the ARM through `/dev/mem`
  and the ARM's DMA engines, which also see the VPU's L2 (bus aliases `0x0`
  and `0x8` return lines the VPU holds dirty there, which the CPU's path does
  not show). A payload with raw memory access can read what the VPU has not
  scrubbed, change the measurement, or overwrite the VPU's own code, and the
  VPU can read OTP. The firmware cannot stop that.
- What stops it is the payload. Secure Boot is always on, so a distribution
  kernel booted through shim and GRUB enters lockdown, which refuses
  `/dev/mem` and unsigned modules. A payload that is signed by a trusted key
  and does not enforce lockdown is not held back; its measurement still
  differs from the one a key was meant for.
- The key is for the payload that asked. The root key is not used for
  anything after boot: any computation with it leaves intermediate values in
  registers, on the stack or in the cache while it runs.

## Checks

`scenarios/boot-key.yaml` boots a board with a test key fused. The EFI
application in `uefi/test-apps/mailbox` (`boot_key.rs`) asks for the key,
tries to extend the measurement and asks again: the key comes once and
nothing is measured after it. `scenarios/late-extend.yaml` exits boot
services and then tries to extend: the VPU refuses.

`scripts/check-key-scrub.py` boots the first scenario, computes the key from
the rows and the application's Authenticode hash, and checks it is the one
the application got. It then reads 2 MiB of the VPU's memory through the
cached and the uncached alias and looks for the rows, the pads, every hash
state and the digest. It finds none. With the scrub left out of the firmware
it finds the inner digest.

# Measured boot and the device key

The firmware keeps the device private key (OTP rows 56-63) in the VPU. The
TPM's seeds, UEFI's variable seals and the firmware cryptography service's
signatures and HMACs are computed from it, and the key itself is never
answered.

## The PCRs

The PCRs are the TPM's ([tpm2.md](tpm2.md)): 24 SHA-256 registers on the VPU,
extended by UEFI as it boots and by shim, GRUB, systemd-boot and the Linux EFI
stub through `EFI_TCG2_PROTOCOL`, and by the OS through the TPM commands.

## The firmware cryptography service

The VPU answers the mailbox tags Raspberry Pi's `rpi-fw-crypto` speaks
(`0x0003008e` to `0x00030095`, `0x0003009c`), for key id 1, the device private
key in OTP rows 56-63, read as a P-256 private key, most significant byte
first: an ECDSA signature of a SHA-256 hash (in DER), an HMAC-SHA256 with the
key's 32 raw bytes, and the public key (`SubjectPublicKeyInfo`). The key itself
is never answered, nor is a key generated or its usage set.

The P-256 arithmetic takes the same steps for every secret scalar, so the
time of a signature or a key agreement says nothing of the key or of the
per-signature secret. The AES the TPM uses for its blobs and for parameter
encryption looks its S-box up by secret bytes, and is not yet as careful.

A key's status says what it may no longer be asked, and a lock holds until the
next boot. Reading, generating and setting the usage are locked from the start.
UEFI seals the records of its variable store with the key's HMAC ([uefi.md](uefi.md#the-variable-store)),
and locks signing and HMAC at `ExitBootServices`, because an OS that could HMAC
any message could seal a record. The VPU's own tag for the runtime services
seals for the OS in a domain UEFI takes only for the OS's own variables
([uefi.md](uefi.md#variables-the-os-writes)). A board without a fused private key answers
`KEY_NOT_SET`, and its variables stay in memory.

## The device key and the ARM

The firmware answers no tag that returns a fuse.
Stock `start4.elf` answers such tags unless `config.txt` sets
`lock_device_private_key=1`: without it Linux reads rows 56-63 through
`nvmem_priv0`, with it they read as blank. Measured on a Raspberry Pi 4
Model B d03115.

That does not keep privileged ARM code from the fuses. The OTP block at
`0x7E20_F000` (`0xFE20_F000` to the ARM) answers the VPU's own read sequence
from ARM code at EL1 and EL2, and no firmware locks it. On a Raspberry Pi 4B
d03115 started by this firmware, `uefi/test-apps/otp-probe` reads row 17 as
`vcgencmd otp_dump` shows it, row 30 as the revision code `0x00d03115`, and
rows 56 and 57, the first of the device private key, as non-zero and different
from those. A bare-metal program at EL2 under Raspberry Pi's `start4.elf` reads
rows 17 and 30 the same way. The hardware answers every unprivileged (EL0) access to the page
with `0xec0de000` instead, under either firmware, which is why root's `mmap` of
`/dev/mem` under Raspberry Pi OS reads that constant for every register and row.
Code that runs privileged on the ARM (a loader before `ExitBootServices`, a
kernel without lockdown that loads a module, a kernel exploit) reads the key
itself, not only what the VPU computes with it.

## What it does not protect

- The VPU's memory is readable and writable from the ARM through `/dev/mem`
  and the ARM's DMA engines, which also see the VPU's L2 (bus aliases `0x0`
  and `0x8` return lines the VPU holds dirty there, which the CPU's path does
  not show). A payload with raw memory access can read what the VPU has not
  scrubbed, change the PCRs, or overwrite the VPU's own code, and the VPU can
  read OTP. The firmware cannot stop that.
- What stops it is the payload. Secure Boot is always on, so a distribution
  kernel booted through shim and GRUB enters lockdown, which refuses
  `/dev/mem` and unsigned modules. A payload that is signed by a trusted key
  and does not enforce lockdown is not held back; its measurements still
  differ from those a policy was bound to.
- A computation with the device key leaves intermediate values in registers,
  on the stack or in the cache while it runs; the firmware overwrites what it
  can reach afterwards.
- The event log is not handed to the OS in the final events table, and
  `GetEventLog` is the only way to read it.

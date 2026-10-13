# Measured boot and the boot key

The firmware keeps the device private key (OTP rows 56-63) in the VPU and
gives the payload a key derived from it and from what was booted. A payload
that was not the one the key was meant for gets a different key.

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

## The boot key

Whatever runs last asks for the key with tag `0x000300a0`: a mask of the PCRs
to bind it to goes in, 32 bytes of key come out. The VPU reads rows 56-63
then, computes

```text
HMAC-SHA256(private key, "pi4-server-firmware boot key v1" || mask || the selected PCRs)
```

overwrites everything the computation touched and writes the zeros out of the
VPU's caches to SDRAM. It answers once. A board without a fused private key
answers nothing, and so does an empty mask.

- An empty mask binds it to nothing: the key is
  `HMAC-SHA256(private key, label || 0)`, one stable key per board, whatever
  was booted and however it is updated. This is the one to use when the key
  has to outlast updates.
- Binding adds what the loaders reported. PCR 4 (`0x10`) changes with every
  update of an image. PCR 7 (`0x80`) changes when Secure Boot's keys do: the
  firmware's `db`, and the certificate that verified shim, which moves from
  Microsoft's 2011 CA to its 2023 one as distributions re-sign. A key bound
  to either has to be re-wrapped by the payload then.

The firmware does not decide which payload may have the key; it releases it
once, to whichever asks first. A payload that must not be impersonated
cannot rely on the binding: loaders report their own measurements, so a
hostile loader that Secure Boot accepts can report whatever it likes. What
keeps the key from such a payload is the same as for anything else on this
board (see below).

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
  scrubbed, change the PCRs, or overwrite the VPU's own code, and the VPU can
  read OTP. The firmware cannot stop that.
- What stops it is the payload. Secure Boot is always on, so a distribution
  kernel booted through shim and GRUB enters lockdown, which refuses
  `/dev/mem` and unsigned modules. A payload that is signed by a trusted key
  and does not enforce lockdown is not held back; its measurements still
  differ from those a key was meant for.
- The root key is not used for anything after boot: any computation with it
  leaves intermediate values in registers, on the stack or in the cache while
  it runs.
- The event log is not handed to the OS in the final events table, and
  `GetEventLog` is the only way to read it.

## Checks

`scenarios/boot-key.yaml` boots a board with a test key fused. The EFI
application in `uefi/test-apps/mailbox` asks for the key bound to PCR 4, extends
a PCR and asks again: the key comes once, and a PCR can still be extended. `boot-key-unbound` and `boot-key-unbound-b` ask for the unbound key
from two different images signed by the same key. 

`scripts/check-key-scrub.py` boots them. It computes the PCR 4 key from the
rows and the application's Authenticode hash and checks it is the one the
application got, reads 2 MiB of the VPU's memory through the cached and the
uncached alias and looks for the rows, the pads, every hash state and the
digest (it finds none; with the scrub left out of the firmware it finds the
inner digest), and checks that the two images got the same unbound key, which
the rows alone make.

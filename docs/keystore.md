# Measured boot and the device key

The firmware keeps the device private key (OTP rows 56-63) in the VPU. The
TPM's seeds, the records that keep its NV indices on the boot disk, UEFI's
variable seals and the firmware cryptography service's signatures and HMACs are
computed from it, and the key itself is never answered.

## The PCRs

The PCRs are the TPM's ([tpm2.md](tpm2.md)): 24 SHA-256 registers on the VPU,
extended by UEFI as it boots and by shim, GRUB, systemd-boot and the Linux EFI
stub through `EFI_TCG2_PROTOCOL`, and by the OS through the TPM commands or
mailbox tag `0x000300a1`. PCRs 17-22 start at all ones and cannot be extended;
the rest start at zero.

## The firmware cryptography service

The VPU answers the mailbox tags Raspberry Pi's `rpi-fw-crypto` speaks
(`0x0003008e` to `0x00030095`, `0x00038090`, `0x0003009c`, `0x0003809c`), for
key id 1, the device private key in OTP rows 56-63, read as a P-256 private key,
most significant byte first, row 56 holding the first four bytes (the layout of
stock `start4.elf`): an ECDSA signature of a SHA-256 hash (in DER), an
HMAC-SHA256 of up to 2048 bytes with the key's 32 raw bytes, and the public key
(`SubjectPublicKeyInfo`). The key itself is never answered, nor is a key
generated or its usage set.

The P-256 arithmetic takes the same steps for every secret scalar, so the
time of a signature or a key agreement says nothing of the key or of the
per-signature secret. The AES the TPM uses for its blobs and for parameter
encryption looks its S-box up by secret bytes, so its timing depends on them.

A key's status says what it may no longer be asked, and a lock holds until the
next boot. Reading, generating and setting the usage are locked from the start.
UEFI seals the records of its variable store with the key's HMAC
([uefi.md](uefi.md#the-variable-store)), and locks signing and HMAC at
`ExitBootServices`, because an OS that could HMAC any message could seal a
record. The VPU's own tag for the runtime services seals for the OS in a domain
UEFI takes only for the OS's own variables
([uefi.md](uefi.md#variables-the-os-writes)). A board without a fused private
key answers `KEY_NOT_SET`, and its variables stay in memory.

## Fusing the device key

The firmware can fuse its device key at the first boot. The EEPROM's
`bootconf.txt` asks for it with keys in its `[all]` section:

```text
[all]
SIGNED_BOOT=1
NUBOOT_PROVISION_DEVICE_KEY=1
```

The stock bootloader ignores the second key. The firmware acts on the request
only when all of this holds, and otherwise writes nothing:

1. **Both keys are set.** `SIGNED_BOOT=1` is the owner's marker that the board
   boots only a signed `boot.img`. Without it the firmware logs a warning and
   writes nothing.
2. **Rows 56-63 are all blank.** A board with any of them fused is left alone,
   and the log says whether the rows hold a whole key or only part of one.

**The request is authenticated only with signed boot programmed in the OTP**:
bit 14 and a bit of 18:15 of the boot mode row (17) set, and a customer key hash
in rows 47-54. The bootloader of such a board runs only if `bootconf.sig`,
signed by the key whose hash is fused, covers `bootconf.txt`, so the request is
the owner's; the firmware does not check the signature again. Without it, the
firmware still fuses the key and logs a warning that the request is not
authenticated: whoever can write the EEPROM or the boot medium decides what
runs, and can run firmware that reads the key. The device key is readable from
privileged ARM code ([below](#the-device-key-and-the-arm)), so on such a board a
physical-access attacker who boots a medium of their own can read it. What the
key protects, the TPM and a root sealed to it, holds only once signed boot is
fused.

The key is drawn from the SoC's random number generator by rejection sampling:
a non-zero value below the P-256 group order, none of whose rows is zero. Row
56 + *i* holds bytes 4*i* to 4*i*+3 of the 32-byte scalar, most significant byte
first, as big-endian words: row 56 holds the most significant four bytes,
which is how Raspberry Pi's stock `start4.elf` and `rpi-otp-private-key` take
them, so a key fused by either reads the same under the other. It
is programmed with the sequence of Raspberry Pi's own firmware (the block's four
enable words, then each row OR-ed with what it held), read back row by row and
used in the same boot, before the TPM's seeds and the records' keys are first
derived, so the first boot of the OS already has a TPM that outlasts a reboot.
The key stays in the VPU: it is never logged or answered, and the stack and
registers that held it are overwritten as for any other use of it.

A fuse cannot be cleared, so a failed programming leaves what it blew. It is
logged as an error and the boot goes on: with no row fused the TPM's seeds are
drawn for the boot, as on a board without a key; with some fused the next boot
finds them, counts them as a key already there, leaves them and warns how many
rows are blank. A board whose key is part-written is not repaired.

```text
INFO  provision device key fused  rows=8
INFO  provision device key already fused, nothing written
WARN  provision device key rows are fused but do not form a whole key, nothing written  blank_rows=1  valid=true
ERROR provision device key not fused whole  reason="rows read back differently"  rows_fused=7
WARN  provision NUBOOT_PROVISION_DEVICE_KEY is not authenticated, the OTP has no signed boot  bootmode=000008b0
WARN  provision NUBOOT_PROVISION_DEVICE_KEY ignored, bootconf.txt does not set SIGNED_BOOT=1  bootmode=000008b0
```

`scenarios/device-key-provision*.yaml` run each case in pimu, whose OTP model
only ever sets bits.

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

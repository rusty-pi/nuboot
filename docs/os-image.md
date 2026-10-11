# Giving the OS the TPM

The firmware's device tree has a `vpu-tpm` node, and the kernel module in
`tools/tpm-vpu` binds to it and registers a TPM 2.0 chip that sends each
command to the VPU over the firmware mailbox. The OS then has `/dev/tpm0` and
`/dev/tpmrm0`, and `/sys/kernel/security/tpm0/binary_bios_measurements` holds
the event log UEFI kept. Nothing needs configuring: the node's `compatible`
string loads the module when it is installed for the running kernel.

The module uses the kernel's `rpi_firmware` interface, which both upstream and
Raspberry Pi's kernels have, and the TPM core's `send` operation of Linux 6.12
and of 6.13 and later. It is `GPL-2.0` and builds out of tree against the
headers of the kernel it is for:

```bash
make -C tools/tpm-vpu KDIR=/lib/modules/$(uname -r)/build
```

## In an mkosi image

Build it with DKMS when the image is made, so it follows the image's kernel.
`tools/tpm-vpu` is the DKMS source (`dkms.conf` is there):

```ini
# mkosi.conf
[Content]
Packages=dkms
         linux-headers-generic
ExtraTrees=tools/tpm-vpu:/usr/src/tpm-vpu-0.1
PostInstallationScripts=mkosi.postinst
KernelModulesInitrdInclude=tpm_vpu
```

```bash
#!/bin/sh
# mkosi.postinst
for kernel in /usr/lib/modules/*; do
    dkms install tpm-vpu/0.1 -k "$(basename "$kernel")"
done
```

The package names for the headers differ by distribution
(`kernel-devel` on Fedora, `linux-headers-$(dpkg --print-architecture)` on
Debian). `KernelModulesInitrdInclude` puts the module in the initrd, which a
unit that unlocks a disk with the TPM there needs.

With Secure Boot on, a kernel in lockdown loads only signed modules. DKMS
signs what it builds with the key in `/etc/dkms/framework.conf` (`mok_signing_key`
and `mok_certificate`), and the kernel has to trust that certificate: enrol it
as a MOK, or sign with a key the image's kernel already trusts.

`scenarios/linux.yaml` boots Debian's 6.12 arm64 kernel under Secure Boot with
the module built by `scripts/build-linux-test.sh` and signed with a key in `db`:
the kernel, in lockdown, loads it, registers `/dev/tpm0` and `/dev/tpmrm0`, and
shows the PCRs the firmware, the board, the initrd and the unified kernel image
were measured into, and the event log.

## Unlocking the root volume

With the module in the initrd, a LUKS2 volume's key is sealed to the TPM
with `systemd-cryptenroll`, as on a PC. Sealing it to PCR 7 binds it to the
Secure Boot state: the keys in `db` and `dbx` and the certificate that
verified each image.

```bash
systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7 /dev/disk/by-partlabel/root
```

A key that survives a kernel update is bound to a policy the image's builder
signs instead: `ukify build` signs the PCR 11 values the unified kernel image
will measure, and `--tpm2-public-key` seals to that key.

```bash
systemd-cryptenroll --tpm2-device=auto --tpm2-public-key=pcr-public.pem \
    --tpm2-public-key-pcrs=11 /dev/disk/by-partlabel/root
```

The key is derived from the board's device private key, so it unseals again
after a reboot and a firmware update on a board that has the key fused
([tpm2.md](tpm2.md#keys)).

## What works

The TPM answers what `docs/tpm2.md` lists: PCR reads, extends and events,
`TPM2_GetCapability`, `TPM2_GetRandom`, `TPM2_Hash`, and ECC primary keys with
secrets sealed under them and unsealed against a PCR policy. So `tpm2_pcrread`,
`tpm2_pcrextend`, `tpm2_getcap`, `tpm2_getrandom`, `tpm2_eventlog`,
`tpm2_createprimary -G ecc`, `tpm2_create`, `tpm2_load` and `tpm2_unseal` work,
and so do `systemd-analyze pcrs`, `systemd-pcrextend` and the units that extend
PCR 11 and 15 at boot. The kernel's hardware random number generator takes
bytes from the TPM.

`systemd-cryptenroll --tpm2-device=auto` seals a disk key under an ECC primary
key to a PCR policy, and `systemd-cryptsetup` unseals it, the same way. On a
board with the device private key fused the key survives reboots and firmware
updates; on one without, it is gone at the next boot.

Keys that sign work too: `tpm2_create` makes an ECDSA key, `tpm2_sign` and
`tpm2_verifysignature` use it, and `tpm2_createek`, `tpm2_createak`, `tpm2_quote`
and `tpm2_checkquote` attest the PCRs. A policy signed by an RSA-2048 key
(`PolicyAuthorize`, which `systemd-measure` and signed PCR 11 policies use) is
checked with that key's public part, loaded with `TPM2_LoadExternal`. The TPM
has no RSA keys of its own.

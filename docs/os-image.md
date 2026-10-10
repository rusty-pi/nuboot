# Giving the OS the TPM

The firmware's device tree has a `vpu-tpm` node, and the kernel module in
`tools/tpm-vpu` binds to it and registers a TPM 2.0 chip that sends each
command to the VPU over the firmware mailbox. The OS then has `/dev/tpm0` and
`/dev/tpmrm0`, and `/sys/kernel/security/tpm0/binary_bios_measurements` holds
the event log UEFI kept. Nothing needs configuring: the node's `compatible`
string loads the module when it is installed for the running kernel.

The module uses the kernel's `rpi_firmware` interface, which both upstream and
Raspberry Pi's kernels have. It is `GPL-2.0` and builds out of tree against
the headers of the kernel it is for:

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

## What works

The TPM answers what `docs/tpm2.md` lists: PCR reads, extends and events,
`TPM2_GetCapability`, `TPM2_GetRandom`, `TPM2_Hash`. So `tpm2_pcrread`,
`tpm2_pcrextend`, `tpm2_getcap`, `tpm2_getrandom`, `tpm2_eventlog` and
`systemd-analyze pcrs` work, `systemd-pcrextend` and the units that extend
PCR 11 and 15 at boot do their job, and the kernel's hardware random number
generator takes bytes from the TPM.

There are no keys or sessions yet, so anything that creates or loads an
object, such as `systemd-cryptenroll --tpm2-device=auto`, `tpm2_createprimary`
or a quote, gets `TPM_RC_COMMAND_CODE`.

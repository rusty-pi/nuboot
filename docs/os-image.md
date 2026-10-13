# Giving the OS the TPM

The TPM on the VPU reaches an operating system in one of two ways, by what the
OS describes the board with. Either way the OS has `/dev/tpm0` and
`/dev/tpmrm0`, and `/sys/kernel/security/tpm0/binary_bios_measurements` holds
the event log UEFI kept.

- **The ACPI tables** (`acpi=on` on the kernel's command line): the TPM is a
  TPM 2.0 device that the kernel's own driver takes. Nothing is built or
  installed.
- **The device tree**, which a kernel uses unless it is told otherwise: a
  kernel module, built for the kernel it is for.

## With the ACPI tables

The firmware gives the OS ACPI tables next to its device tree
([uefi.md](uefi.md#acpi)). A kernel that is given both uses the device tree,
and uses the tables when its command line says so:

```text
acpi=on
```

In a unified kernel image that is the `.cmdline` section; with GRUB, the
`linux` line.

A kernel that is given a device tree with nothing in it has nothing else to
describe the board with, and takes the tables without the option. A unified
kernel image's `.dtb` section replaces the device tree the firmware gives the
kernel, so one that holds a root node and nothing else leaves the kernel with no
device tree at all.

The tables name the TPM as a command response buffer device
(`MSFT0101`, with the ACPI start method), which `tpm_crb` takes
([tpm2.md](tpm2.md#the-command-response-buffer)): an interface the TCG
defines and the kernel has long had a driver for (`CONFIG_TCG_CRB`, built in on
Debian), so there is no module to build, sign or keep in step with a kernel.

What else the tables describe is in [uefi.md](uefi.md#acpi): the four cores, the
interrupt controller and timers, the SBSA UART console, the SD host, the network
interface, the USB controller, the random number generator, the temperature
sensor (as the thermal zone `acpitz`) and the power manager, whose watchdog the
kernel's `bcm2835-pm` driver provides through the `compatible` property the
table gives it. Reset and power off need no driver: the kernel calls the
firmware's `ResetSystem`, with the tables or the device tree. The USB controller is a platform xHCI device, which the kernel's
generic driver (`CONFIG_USB_XHCI_PLATFORM`) takes; `lspci` does not list it.

An OS on the tables has no device tree to read the board's model and serial
number from: the SMBIOS tables the firmware offers give them
(`/sys/class/dmi/id`, `dmidecode`, `hostnamectl`), whichever way the OS
describes the board.

`scenarios/linux-acpi.yaml` boots Debian's 6.12 arm64 kernel with `acpi=on`
under Secure Boot: `tpm_crb` registers the TPM, the PCRs and the event log are
there, and so are the SD card, the network interface and a USB stick.

## With the device tree

The firmware's device tree has a `vpu-tpm` node, and the kernel module in
`tools/tpm-vpu` binds to it and registers a TPM 2.0 chip that sends each
command to the VPU over the firmware mailbox. Nothing needs configuring: the
node's `compatible` string loads the module when it is installed for the
running kernel.

The module uses the kernel's `rpi_firmware` interface, which both upstream and
Raspberry Pi's kernels have, and the TPM core's `send` operation of Linux 6.12
and of 6.13 and later. It is `GPL-2.0` and builds out of tree against the
headers of the kernel it is for:

```bash
make -C tools/tpm-vpu KDIR=/lib/modules/$(uname -r)/build
```

### In an mkosi image

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
as a MOK, sign with a key the image's kernel already trusts, or, when the image
boots without shim, so that there is no MOK, put the certificate in `db`
([uefi.md](uefi.md#updating-the-keys)): the kernel takes the certificates of
`db` into its platform keyring and loads a module signed by one of them.

`scenarios/linux.yaml` boots Debian's 6.12 arm64 kernel under Secure Boot with
the module built by `scripts/build-linux-test.sh` and signed with a key in `db`:
the kernel, in lockdown, loads it, registers `/dev/tpm0` and `/dev/tpmrm0`, and
shows the PCRs the firmware, the board, the initrd and the unified kernel image
were measured into, and the event log.

## Unlocking the root volume

With the TPM's driver in the initrd (the module, or the kernel's own), a
LUKS2 volume's key is sealed to the TPM with
`systemd-cryptenroll`, as on a PC. Sealing it to PCR 7 binds it to the
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

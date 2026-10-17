# The TPM on the VPU

`start4.elf` carries a TPM 2.0 (`src/tpm2.rs`). UEFI measures into it as it
boots and offers it as `EFI_TCG2_PROTOCOL`; shim, GRUB, systemd-boot and the
Linux EFI stub measure into the protocol as they do on a PC. The OS reaches
the TPM in one of two ways, by what it describes the board with:

- through the ACPI tables, as a TPM 2.0 device with a command response buffer
  ([below](#the-command-response-buffer)), which the kernel's own driver takes;
- over the property mailbox: tag `0x000300a3`, with the command in the tag's
  value and its length in the length word, and the response coming back the
  same way, which the module in `tools/tpm-vpu` uses
  ([os-image.md](os-image.md)).

Both end in the same TPM: the commands, the PCRs and the keys are the same.

The TPM is started when the firmware is. A `TPM2_Startup` from a payload gets
`TPM_RC_INITIALIZE`.

## What is measured

`start4.elf` measures the firmware and the board before it starts the ARM, and
UEFI starts its event log with those events (tag `0x000300a4`), so the log
replays to the PCRs as a TPM's does. UEFI and the loaders add the rest, in
this order:

| PCR | event | holds |
|---|---|---|
| 0 | `EV_S_CRTM_VERSION` | `nuboot-loader`, the commit and the version of the firmware that started an update, in UTF-16; only on a board that runs an update |
| 0 | `EV_EFI_PLATFORM_FIRMWARE_BLOB2` | the update's own VPU image, `start4-update`, as the SHA-256 the loader took of it before it ran it; only on a board that runs an update |
| 0 | `EV_S_CRTM_VERSION` | `nuboot` and the commit, in UTF-16 |
| 0 | `EV_EFI_PLATFORM_FIRMWARE_BLOB2` | the UEFI image, and the device tree it starts the ARM with |
| 1 | `EV_PLATFORM_CONFIG_FLAGS` | `board.revision`, `board.ext_revision`, `board.serial`, `board.mac_rows`, `otp.bootmode` and `sdram.mib`, one event each, as `name=value` |
| 1 | `EV_PLATFORM_CONFIG_FLAGS` | `eeprom.bootconf=`, the SHA-256 of `bootconf.txt` in the EEPROM as it is stored, or `none` |
| 0 | `EV_EFI_PLATFORM_FIRMWARE_BLOB2` | the EEPROM's bootloader (`eeprom-bootcode`), as the SHA-256 of the `bootcode.bin` section as the flash stores it, and where in the flash it is |
| 0 | `EV_EFI_PLATFORM_FIRMWARE_BLOB2` | the VL805's hub and MCU images (`vl805-hub`, `vl805-mcu`), when the VPU loads them into the chip, which the 4B revisions without a flash of their own for it need |
| 7 | `EV_EFI_VARIABLE_DRIVER_CONFIG` | the Secure Boot configuration: `SecureBoot`, `PK`, `KEK`, `db` and `dbx` |
| 1 | `EV_EFI_HANDOFF_TABLES2` | the pointers to the ACPI and SMBIOS tables handed to the OS |
| 0-7 | `EV_SEPARATOR` | one in each PCR, once the configuration is measured |
| 5 | `EV_EFI_GPT_EVENT` | the GPT of the disk the boot option is on, when it has one |
| 4 | `EV_EFI_ACTION` | `Calling EFI Application from Boot Option`, ahead of the boot option's image |
| 4 | `EV_EFI_BOOT_SERVICES_APPLICATION` | each image UEFI loads |
| 7 | `EV_EFI_VARIABLE_AUTHORITY` | the `db` certificate that verified each image |

Shim, GRUB, systemd-boot and systemd-stub measure the rest through
`HashLogExtendEvent`: systemd-boot puts `loader.conf` in PCR 5, systemd-stub
the sections of a unified kernel image in PCR 11, shim the MOK list in PCR 14,
GRUB its commands and files in PCRs 8 and 9.

Nothing is measured into PCRs 2, 3 and 6: there are no option ROMs and no
suspend. The ExitBootServices actions are not logged.

## What it implements

One bank, SHA-256, of 24 PCRs. Every PCR can be extended from locality 0 but
17-22 (DRTM, which nothing here does), and PCRs 16 and 23 can be reset.

| command | |
|---|---|
| `TPM2_Startup`, `Shutdown`, `SelfTest`, `IncrementalSelfTest`, `GetTestResult`, `StirRandom` | accepted; there is no non-volatile state to save |
| `TPM2_GetCapability` | algorithms, handles, commands, PCRs, ECC curves and the TPM properties; the other capabilities are empty lists |
| `TPM2_GetRandom` | from the SoC's RNG200, up to 32 bytes |
| `TPM2_PCR_Read`, `PCR_Extend`, `PCR_Event`, `PCR_Reset` | with a password session with an empty password; no other session. `PCR_Read` answers with the first eight registers of a selection and says which it read, and a caller asks again for the rest |
| `TPM2_Hash` | SHA-256, with the null, owner, endorsement or platform hierarchy for the ticket |
| `TPM2_ReadClock`, `TestParms` | |
| `TPM2_CreatePrimary` | an ECC P-256 storage key under the owner, endorsement, platform or null hierarchy |
| `TPM2_Create`, `Load`, `ReadPublic`, `Unseal` | sealed data and ECDSA signing keys under a primary storage key |
| `TPM2_LoadExternal` | a public key, ECC P-256 or RSA-2048, under the owner, endorsement, platform or null hierarchy; no private part |
| `TPM2_Sign`, `Quote`, `VerifySignature` | ECDSA over P-256 and SHA-256, with a key that signs; a restricted key (an attestation key) signs only what the TPM attested or a digest that `Hash` ticketed; `VerifySignature` also checks RSASSA (PKCS#1 v1.5) with SHA-256 by a loaded RSA public key |
| `TPM2_ContextSave`, `ContextLoad`, `FlushContext` | objects and sessions |
| `TPM2_EvictControl` | a primary key made persistent at a handle in the owner's or the platform's range, two at most, and removed again; they last until the TPM restarts, and a tool that finds none makes the primary again |
| `TPM2_StartAuthSession` | HMAC, policy and trial sessions, unsalted or salted to a primary key with ECDH, bound to nothing or to an object, with AES-128-CFB for parameter encryption or none |
| `TPM2_PolicyPCR`, `PolicyOR`, `PolicyAuthValue`, `PolicyPassword`, `PolicySecret`, `PolicyAuthorize`, `PolicyCommandCode`, `PolicyGetDigest`, `PolicyRestart` | |

Anything else gets `TPM_RC_COMMAND_CODE`. There are no RSA keys of the TPM's own
(an RSA public key can be loaded to verify with), no NV storage, no persistent handles (`EvictControl`) and no
`HierarchyChangeAuth`: the hierarchies' authorization values are empty.

An endorsement key (`tpm2_createek`, the TCG template with a `PolicySecret` on
the endorsement hierarchy) is a primary like any other, so its public key is the
same at every boot on a board with the device key fused, and `tpm2_createak`
makes an attestation key under it. `tpm2_quote` signs the PCRs with that key and
`tpm2_checkquote` checks the result without the TPM.

A policy that a key authorizes works as `systemd-measure` and
`systemd-cryptenroll --tpm2-public-key` use it: the policy of the sealed object
names an RSA-2048 key, and the unsealing session proves a PCR policy that the
key signed (`VerifySignature` on the loaded public key, then `PolicyAuthorize`
with its ticket).

## Keys

A hierarchy's seed is the board's device private key hashed with the hierarchy's
name (`keystore::tpm_secret`), so on a board with the key fused the primary
keys are the same at every boot and after every firmware update, and a secret
sealed under one unseals later. The seeds are derived when a command needs them
and the stack they touched is overwritten before the command returns; the TPM
holds no seed. The null hierarchy, and every hierarchy on a board with no
fused key, has a seed that is random for the boot, so what is sealed there
unseals only until the next reboot.

A primary key is a function of its hierarchy and its template, so a tool that
asks for the same primary twice gets the same key. What the TPM keeps of one is
the hierarchy and the hash of the template. A sealed object is kept as the blob
`TPM2_Create` returned (AES-128-CFB under a key from the parent's seed and the
object's name, with an HMAC), and is plaintext only inside `Unseal`.

The TPM has four object slots and four sessions. A tool that runs one
command per process, such as `tpm2-tools`, leaves its objects loaded, so
the kernel's resource manager (`/dev/tpmrm0`) is what to use: it saves and
loads around each command, with `ContextSave`, `ContextLoad` and
`FlushContext`.

Saved contexts are encrypted under keys that last for the boot, so they
load again until the TPM restarts.

The primary keys and the sealed blobs are the same kind of secret as the OTP
key they derive from: nothing here stops a payload that can read the VPU's
memory ([keystore.md](keystore.md)), and anyone who can send the TPM
commands can unseal what the PCRs and policy of an object allow, as with any
TPM.

## The command response buffer

The `TPM2` table names the TPM as a command response buffer with the ACPI
start method (start method 8), and the `MSFT0101` device in the DSDT is what
the kernel's `tpm_crb` takes. The buffer is one page of the ARM's memory, the
last below the VPU's own (`0x3EBF_F000`), which the device tree reserves:

| offset | |
|---|---|
| `0x40` | the control area: the status, `START`, the sizes and addresses of the command and response buffers |
| `0x80` | one buffer of 2048 bytes, for the command and then the response |

The OS writes a command in the buffer and sets `START`, and the device's
start method (`_DSM` function 1 of the TPM start UUID,
`6bbf6cab-5463-4714-b7cd-f0203c0368d4`) writes the doorbell to the mailbox, on
channel 6, where the VPU's service thread answers it. The VPU copies the command
out of the page, runs it, writes the response in the buffer and clears `START`.
Where the buffer is and how long it is are the VPU's own, whatever the control
area says when the doorbell rings; a command whose length does not fit the
buffer gets `TPM_RC_COMMAND_SIZE`. The interface has locality 0 only, and
nothing to cancel: a command that has started runs to its end, and writes its
response and clears `START` then. A command that outlasts the kernel's timeout
(750 ms, or 2 s for the longest ones) has the kernel cancel it and send the next
one, which that late response overwrites.

## Checks

`scenarios/tpm2-commands.yaml` boots an EFI application that sends the TPM a
series of commands through `SubmitCommand` and prints the responses, among
them a primary key, a secret sealed under it with a password, and its unsealing.
`scenarios/systemd-boot.yaml` boots Debian's systemd-boot, signed with the test
key, which finds a unified kernel image (`scripts/mkuki.py` puts a kernel, a
command line and an `os-release` on Debian's systemd-stub) and starts it;
the scenario checks that systemd-boot and the stub measured into PCRs 5 and
11 on the way.

`scripts/check-tpm2.py` checks the first: that the event log replays to the
PCRs, with the board's identity and the EEPROM's configuration in PCR 1, a
separator in each of PCRs 0 to 7, the handoff tables and the call to the boot
option, the properties, that the PCRs read back
are what SHA-256 makes of what was extended, the update counter, the error
codes of the commands the TPM refuses, and what the key, the sealed data and the
sessions answer and refuse.

`scenarios/linux-acpi.yaml` boots Debian's arm64 kernel with `acpi=on` and no
module of this firmware's: `tpm_crb` registers `/dev/tpm0`, and the PCRs and the
event log are there as they are over the mailbox
([os-image.md](os-image.md)). `tools/tpm-sim/tests/crb.rs` runs the buffer's
code on the host.

`scripts/test-tpm.sh` builds the TPM's code for the host (`tools/tpm-sim`) and
runs two things. Its unit tests compare P-256 (public keys, ECDH, ECDSA),
AES-CFB, `KDFa` and `KDFe` with vectors from Python's `cryptography`
(`tools/tpm-sim/gen-vectors.py`), and run the command response buffer's code.
With `tpm2-tools` installed it also serves
the TPM over the TPM simulator's socket protocol and drives it with the real
tools (`tools/tpm-sim/tpm2-tools-test.sh`): the primary key, sealing and
unsealing, a PCR policy built by a trial session and refused once a PCR has
changed, a salted HMAC session that also encrypts the secret on its way in, a
signing key whose signature OpenSSL accepts, an endorsement key, an
attestation key and a quote that `tpm2_checkquote` accepts, and a secret sealed
under a policy that an RSA key authorizes and unsealed with that key's
signature of a PCR policy, a primary key made persistent and removed, and,
with `systemd-cryptenroll` and `cryptsetup` installed, a LUKS2 volume whose key
is sealed to PCR 7 and unsealed to unlock it, which stops working once the PCR
has changed.

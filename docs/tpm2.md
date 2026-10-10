# The TPM on the VPU

`start4.elf` carries a TPM 2.0 (`src/tpm2.rs`). UEFI measures into it as it
boots and offers it as `EFI_TCG2_PROTOCOL`; shim, GRUB, systemd-boot and the
Linux EFI stub measure into the protocol as they do on a PC. The OS reaches
the TPM over the property mailbox: tag `0x000300a3`, with the command in the
tag's value and its length in the length word, and the response coming back
the same way.

The TPM is started when the firmware is. A `TPM2_Startup` from a payload gets
`TPM_RC_INITIALIZE`.

## What is measured

`start4.elf` measures the firmware and the board before it starts the ARM, and
UEFI starts its event log with those events (tag `0x000300a4`), so the log
replays to the PCRs as a TPM's does:

| PCR | event | holds |
|---|---|---|
| 0 | `EV_S_CRTM_VERSION` | `pi4-server-firmware` and the commit, in UTF-16 |
| 0 | `EV_EFI_PLATFORM_FIRMWARE_BLOB2` | the UEFI image, and the device tree it starts the ARM with |
| 1 | `EV_PLATFORM_CONFIG_FLAGS` | `board.revision`, `board.ext_revision`, `board.serial`, `board.mac_rows`, `otp.bootmode` and `sdram.mib`, one event each, as `name=value` |
| 7 | | the Secure Boot configuration, and the certificate that verified each image |
| 4 | | each image UEFI loads |

Shim, GRUB, systemd-boot and systemd-stub measure the rest through
`HashLogExtendEvent`: systemd-boot puts `loader.conf` in PCR 5, systemd-stub
the sections of a unified kernel image in PCR 11, shim the MOK list in PCR 14,
GRUB its commands and files in PCRs 8 and 9.

## What it implements

One bank, SHA-256, of 24 PCRs. Every PCR can be extended from locality 0 but
17-22 (DRTM, which nothing here does), and PCRs 16 and 23 can be reset.

| command | |
|---|---|
| `TPM2_Startup`, `Shutdown`, `SelfTest`, `IncrementalSelfTest`, `GetTestResult`, `StirRandom` | accepted; there is no non-volatile state to save |
| `TPM2_GetCapability` | algorithms, handles, commands, PCRs and the TPM properties; the other capabilities are empty lists |
| `TPM2_GetRandom` | from the SoC's RNG200, up to 32 bytes |
| `TPM2_PCR_Read`, `PCR_Extend`, `PCR_Event`, `PCR_Reset` | with a password session with an empty password; no other session |
| `TPM2_Hash` | SHA-256, with the null hierarchy |
| `TPM2_ReadClock` | |

Anything else gets `TPM_RC_COMMAND_CODE`. There is no hierarchy, so no keys,
sessions, NV storage or quotes yet.

## Checks

`scenarios/tpm2-commands.yaml` boots an EFI application that sends the TPM a
series of commands through `SubmitCommand` and prints the responses.
`scenarios/systemd-boot.yaml` boots Debian's systemd-boot, signed with the test
key, which finds a unified kernel image (`scripts/mkuki.py` puts a kernel, a
command line and an `os-release` on Debian's systemd-stub) and starts it;
the scenario checks that systemd-boot and the stub measured into PCRs 5 and
11 on the way.

`scripts/check-tpm2.py` checks them: that the event log replays to the PCRs, with the board's identity in PCR 1, the properties, that the PCRs read back
are what SHA-256 makes of what was extended, the update counter, and the
error codes of the commands the TPM refuses.

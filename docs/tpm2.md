# The TPM on the VPU

`start4.elf` carries a TPM 2.0 (`src/tpm2.rs`). UEFI measures into it as it
boots and offers it as `EFI_TCG2_PROTOCOL`; shim, GRUB, systemd-boot and the
Linux EFI stub measure into the protocol as they do on a PC. The OS reaches
the TPM over the property mailbox: tag `0x000300a3`, with the command in the
tag's value and its length in the length word, and the response coming back
the same way.

The TPM is started when the firmware is. A `TPM2_Startup` from a payload gets
`TPM_RC_INITIALIZE`.

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
`scripts/check-tpm2.py` checks them: the properties, that the PCRs read back
are what SHA-256 makes of what was extended, the update counter, and the
error codes of the commands the TPM refuses.

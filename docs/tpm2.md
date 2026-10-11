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
| `TPM2_GetCapability` | algorithms, handles, commands, PCRs, ECC curves and the TPM properties; the other capabilities are empty lists |
| `TPM2_GetRandom` | from the SoC's RNG200, up to 32 bytes |
| `TPM2_PCR_Read`, `PCR_Extend`, `PCR_Event`, `PCR_Reset` | with a password session with an empty password; no other session |
| `TPM2_Hash` | SHA-256, with the null hierarchy |
| `TPM2_ReadClock`, `TestParms` | |
| `TPM2_CreatePrimary` | an ECC P-256 storage key under the owner, endorsement, platform or null hierarchy |
| `TPM2_Create`, `Load`, `ReadPublic`, `Unseal` | sealed data under a primary storage key |
| `TPM2_ContextSave`, `ContextLoad`, `FlushContext` | objects and sessions |
| `TPM2_StartAuthSession` | HMAC, policy and trial sessions, unsalted or salted to a primary key with ECDH, bound to nothing or to an object, with AES-128-CFB for parameter encryption or none |
| `TPM2_PolicyPCR`, `PolicyOR`, `PolicyAuthValue`, `PolicyPassword`, `PolicyCommandCode`, `PolicyGetDigest`, `PolicyRestart` | |

Anything else gets `TPM_RC_COMMAND_CODE`. There is no RSA, no signing key and so no
`Sign`, `Quote` or `PolicyAuthorize`, no NV storage, no persistent handles
(`EvictControl`) and no `HierarchyChangeAuth`: the hierarchies' authorization
values are empty.

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
PCRs, with the board's identity in PCR 1, the properties, that the PCRs read back
are what SHA-256 makes of what was extended, the update counter, the error
codes of the commands the TPM refuses, and what the key, the sealed data and the
sessions answer and refuse.

`scripts/test-tpm.sh` builds the TPM's code for the host (`tools/tpm-sim`) and
runs two things. Its unit tests compare P-256 (public keys, ECDH, ECDSA),
AES-CFB, `KDFa` and `KDFe` with vectors from Python's `cryptography`
(`tools/tpm-sim/gen-vectors.py`). With `tpm2-tools` installed it also serves
the TPM over the TPM simulator's socket protocol and drives it with the real
tools (`tools/tpm-sim/tpm2-tools-test.sh`): the primary key, sealing and
unsealing, a PCR policy built by a trial session and refused once a PCR has
changed, and a salted HMAC session that also encrypts the secret on its way in.

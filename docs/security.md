# Security design

What this firmware protects, from whom, by what, and what it takes to break
it. It is for someone who has to decide whether to trust a board running it.

## The hardware sets the terms

The BCM2711 has no memory separation. The VPU, which runs `start4.elf` and
reads the device private key, and the ARM cores share the SDRAM, and nothing
stands between them: no IOMMU, no TrustZone-style carve-out, no firewall on the
VPU's memory. Code that can read and write memory on the ARM
side can read and write the VPU's code, stacks and the TPM's PCRs by their bus
addresses, and so can any bus master (a DMA engine, the VL805) that is given a
bad address. The VPU is not a vault.

So the firmware does not try to hide the VPU from the ARM. It rests on four
things instead, which every mechanism below serves:

1. **Only images signed by a key in `db` run on the ARM**, and the kernel they
   start locks itself down. Secure Boot is always on and cannot be switched off.
2. **Everything that reads bytes before it has authenticated them is small,
   written in Rust over checked slices, and capped in what a medium can make it
   allocate, read or wait for.**
3. **What a locked-down OS can reach on the VPU is a short list of messages,
   each bounded, none of which returns a fuse or the device key or lets the OS
   write state it could not have written itself.**
4. **State that outlasts a boot is either sealed by a key the ARM never reads
   while the OS runs, or is a signed write that is checked again at every
   boot.**

Nothing here claims more than that. A kernel exploit in a running OS, or any
code on the ARM that is not held back by lockdown, owns the board
([What it takes to break it](#what-it-takes-to-break-it)).

## Who it defends against

| attacker | can do | wants |
|---|---|---|
| **media**: controls the SD card or USB drive | any bytes there: partition tables, FAT, EFI files, a capsule in `\EFI\UpdateCapsule`, a malformed PE or PKCS #7 | to run unsigned code in UEFI, to corrupt UEFI's memory before it has checked anything, to plant an update |
| **device**: a hostile USB device or hub | descriptors, lengths and timing on the VL805's ports | the same, through the xHCI and mass-storage drivers |
| **OS**: root, or any user of `/dev/tpm*` or `efivarfs`, on an OS that booted under Secure Boot and is locked down (no `/dev/mem`, no unsigned modules) | TPM commands, the runtime variable services, the mailbox the kernel's drivers use | VPU code execution, the device key or the TPM's seeds, forged or rolled-back stored state, a boot that skips Secure Boot |
| **LAN** | an Ethernet frame while the board is off | anything beyond booting the board |
| **old signed code**: a shim, GRUB or kernel that is signed and not in `dbx` | whatever its bugs give it | to be booted in place of the current one |

Out of scope, because the hardware decides it: an attacker with a hardware
probe on the board, and code on the ARM that has arbitrary memory access (see
above).

## What is trusted

| root | held by | what it guarantees |
|---|---|---|
| the boot ROM, and the customer key hash fused in the OTP | Raspberry Pi, and the board's owner | the bootloader in the EEPROM is Raspberry Pi's, and the public key it checks `boot.img` against is the owner's |
| the EEPROM bootloader, with the owner's public key | the owner | `start4.elf` comes out of a `boot.img` whose `boot.sig` the owner's key made |
| `start4.elf` | the firmware's builder | everything below |
| the update keys, which `start4.elf` carries | the firmware's builder | which firmware replaces it at the next boot, with no signature by the owner |
| `PK`, `KEK`, `db` | the firmware's builder | which images UEFI runs, and which updates it takes |

**The guarantees need signed boot programmed in the OTP.** On a board without
it the bootloader runs whatever `start4.elf` is on the boot medium, and an
attacker who can write the medium replaces this firmware and everything it
protects. The firmware cannot check this about itself. The OTP's boot mode word
is measured into PCR 1 (`otp.bootmode`), so a TPM policy that includes PCR 1
sees it.

## The chain, and what each link checks

```text
boot ROM        bootloader in the EEPROM, against the OTP's key hash
bootloader      boot.img, against boot.sig and the EEPROM's public key
start4.elf      measures UEFI, the board, the EEPROM's bootconf.txt and the VL805's firmware into PCRs 0 and 1; starts the ARM
UEFI            LoadImage: Authenticode signature chained to db, hash not in dbx
shim, GRUB      their own keys and the MOK list; each measured into the TPM
kernel          lockdown, because UEFI says Secure Boot is on
```

From `start4.elf` on, each link measures what it starts into the TPM on the VPU
([tpm2.md](tpm2.md#what-is-measured)): the firmware, the board, the EEPROM's
configuration and the VL805's firmware into PCRs 0 and 1, the Secure Boot keys
into PCR 7, every image UEFI loads into PCR 4 with the certificate that
verified it into PCR 7, the boot disk's GPT into PCR 5, and what shim, GRUB,
systemd-boot and the kernel's stub add into PCRs 5, 8, 9, 11 and 14. A PCR only moves by
extension, and the registers the TPM refuses to extend (17-22) are refused on
the mailbox too.

## Secure Boot

`LoadImage` is the only way an image starts, and it verifies first:

- **Verify, then parse.** `secure::check` reads only the headers it needs to
  compute the Authenticode hash, with bounds-checked access throughout, and
  checks the signature. `LoadImage` lays the image out only after it has passed.
  There is no Security Architecture protocol to bypass, and the `source buffer`
  form of `LoadImage` goes through the same check.
- **The hash covers what is loaded.** It covers the headers (less the checksum
  and the certificate table's directory entry), every section's raw bytes in
  file order, and what follows them up to the certificate table. The loader
  copies only the headers and the sections, and reads the optional header, its
  data directories and the section table only where the headers are, so
  everything it uses is hashed. An image whose section table runs past its
  headers, or whose sections together are longer than the file, is refused.
- **The signature is checked strictly.** RSA PKCS #1 v1.5 with SHA-256 only:
  the whole encoded message is rebuilt and compared, so a forgery with
  garbage after the digest, or with the digest's parameters missing, is
  refused; the modulus is odd and at most 4096 bits, the exponent fits 32
  bits, and the signature is the modulus's length and below it. The signed
  attributes' `messageDigest` has to equal the SHA-256 of the signed content,
  and the signed hash has to equal the image's own. The certificate that
  verified the signature is the one that is looked up in `db`, so the chain
  ends at what was checked. No SHA-1 or MD5 path exists.
- **Trust is membership of `db`.** The chain has to end at a certificate that is
  in `db`, byte for byte or by a signature of one that is, and the image's hash
  must not be in `dbx`. A signature carries at most 16 certificates. The
  firmware does not read validity dates, `basicConstraints`, key usage or path
  lengths: the board has no clock, and `db` is short and signed in. A
  certificate in `db` can therefore issue others; whoever holds its key could
  sign the image directly anyway.
- **No setup mode.** `PK` is built in and no write replaces it; `SecureBoot`,
  `SetupMode`, `AuditMode` and `DeployedMode` are fixed. `KEK`, `db` and
  `dbx` change only through authenticated writes with a timestamp newer than the
  variable's last, signed over its name, GUID, attributes, time and value, by
  the platform key (for `KEK`) or by it or a `KEK` key (for `db` and `dbx`),
  whose certificate has to be the one built in or enrolled, byte for byte.
- **Revocation.** `dbx` starts from Microsoft's aarch64 hash list as a build
  includes it, and grows through signed updates. A list shipped with the
  firmware is a snapshot: it is as fresh as the build.
- **Where it applies.** UEFI boots only `\EFI\BOOT\BOOTAA64.EFI`, from the SD
  card first and then any USB drive. There is no boot menu, shell, setup screen
  or variable that changes that. The serial console is the PL011 on GPIO 14 and
  15; UEFI reads it only for the images it runs (GRUB's prompt is the one
  interactive surface, and is shipped by whoever builds the OS image).

## Updates

A firmware update is a capsule in `\EFI\UpdateCapsule` that a `db` key signed
(Microsoft's keys do not count: their CAs sign for anyone) over an image that
names its own class GUID, so a capsule made for the EEPROM bootloader is not
accepted as one for the firmware. The version has to be newer than the running
one's. A capsule that passes is written as `tryboot.img` and `tryboot.sig`,
read back, and booted once; the bootloader checks it against the owner's key,
the new firmware proves itself at `ExitBootServices`, and only then does the
next boot make it the boot pair ([uefi.md](uefi.md#firmware-capsules)). A
firmware that never reaches the OS is not kept.

The gate on a board with signed boot is the owner's key, not `db`: the firmware
does not verify the RSA signature of `boot.sig` itself, it hands the pair to the
bootloader, which does. A `db` key can stage an update that the bootloader then
refuses. Where signed boot is absent, the boot medium is writable by whoever
holds it, and a capsule adds nothing to that.

### Updates the owner does not sign

A board's owner does not have to sign each firmware image. The `start4.elf` the
owner signs, the loader, carries the update keys: P-256 public keys, built in
from `PI4_UPDATE_PUB` or `keys/update.pub`. A capsule for the update resource
(a `db` key signs it, as every capsule) carries a bundle, a whole firmware
image linked for the update slot and signed by an update key
([updates.md](updates.md#updates-the-owner-does-not-sign)).

UEFI keeps the bundle and leaves it in RAM across a reset; it is never trusted
for anything else. The loader checks the signature itself, over a digest of a
fixed label, the header and the image, before it copies a byte to the update
slot, and it runs a bundle only when its version is newer than its own. The
bundle's image runs on the VPU with the same rights as the loader, so the update
keys are as strong as the owner's key for what they can sign: a leaked update
key lets its holder run firmware of their choice on every board whose loader
carries it, and a replacement key needs a new `start4.elf` the owner signs.

Three things hold the loader's side together:

- **The signature is the only gate.** UEFI's checks (the version, the class, the
  `db` signature of the capsule) keep a bad update from being tried, and decide
  nothing: the loader checks the bundle after the reset as if no check had run.
- **A failed update is tried three times, and the one before it comes back.** A
  bundle's file name carries its tries left and tries done, and UEFI spends one
  before it stages the bundle. A bundle that reaches `ExitBootServices` is
  blessed, by dropping the counter from its name, and the older bundles are
  removed; one with no tries left is removed, and the next newest bundle on the
  disk, the one that ran before, is staged. The loader itself runs only when no
  bundle works. The counter is a limit on retries and nothing more: whoever can
  write the medium can reset or remove it, and can still only run what an update
  key signed.
- **A bundle does not go backwards.** The flash store holds the version of the
  newest bundle that has reached the OS, which is all of the update's state it
  keeps, and a capsule or a kept bundle below it is refused. The store is sealed by the device key, so an attacker who can
  only write the boot medium cannot lower it.

The loader's own code is not updated this way. What reads the medium before the
bundle is staged (the file system, the capsule scan) stays as the owner signed
it, so a flaw there stays until the owner signs a new `start4.elf`. It runs at
every power-up, ahead of the update.

The image the bundle carries measures the loader's commit and version into PCR 0
ahead of its own events, and with them the SHA-256 of its own image, which the
loader took when it checked the signature and left for the image. The image does
not hash itself: what is measured is what the owner-signed code ran. A policy
bound to PCR 0 therefore tells a board running an update from one running the
loader, and one update build from another, by the hash of the VPU image.

## The device key and the TPM's secrets

OTP rows 56-63 hold a per-board P-256 private key. The VPU uses it on the OS's
and UEFI's behalf and never gives it out, but the OTP block is not hidden from
privileged ARM code ([below](#what-is-not-protected)).

- **No tag returns a fuse**, and the private-key tag answers refusal. The key
  reaches the ARM only if ARM code reads the OTP block itself.
- **Uses of the key** are signing and HMAC-SHA256 for UEFI, the boot key (once
  per boot), and the TPM's hierarchy seeds, each derived on use from the key and a
  distinct label, then overwritten along with the stack they touched and the
  cache lines that held them. Read, generate and set-usage are locked from the
  start of the VPU's run. **Signing and HMAC are locked at `ExitBootServices`**
  by UEFI, which re-reads the status and halts the board if the lock is not
  confirmed; locks are only ever added, and a lock lives in VPU memory, so only a
  SoC reset (after which UEFI runs again) clears it.
- **Each use has its own label** in what the key HMACs. The store's seals for
  the firmware's writes and for the OS's cover different labels
  (`variable store record v4` and `runtime variable record v2`), the boot key's
  message begins `nuboot boot key v1` and the TPM's seeds'
  `nuboot TPM secret v1`, so an HMAC made for one use is not valid
  for another.
- **The boot key is released once per boot**: the first request with a valid mask
  of PCRs gets it, and a request that names a register that does not exist does
  not use the release up. The copy of the request the mailbox parsed from is
  zeroed after every answer.
- **No secret is logged.** Logs carry PCR numbers, counts and the first four
  bytes of an extended digest.

### What is not protected

**The OTP block is readable from privileged ARM code.** The block at
`0xFE20_F000` answers every unprivileged (EL0) access with the constant
`0xec0de000`, whichever firmware runs, so root's `mmap` of `/dev/mem` reads
nothing from it. It answers EL1 and EL2 accesses with the VPU's own read
sequence, and no firmware sets a lock on it. On a Raspberry Pi 4B d03115,
`uefi/test-apps/otp-probe` reads row 17 as `vcgencmd otp_dump` shows it from EL1
and EL2 under this firmware and gets the constant from EL0; from EL2 it also reads
row 30 as the revision code and finds rows 56 and 57 of the device key non-zero.
A bare-metal program at EL2 under Raspberry Pi's `start4.elf` reads rows 17 and
30 the same way ([keystore.md](keystore.md#the-boot-key)). ARM code that runs privileged, a
loader before `ExitBootServices`, a kernel module on a kernel without lockdown,
or a kernel exploit, reads the key itself. A stolen key is stolen for good: with
it the boot key, the TPM's seeds and the store's seals can be computed off the
board. The locks at `ExitBootServices` and the mailbox's refusals bind what the
OS can ask the VPU, not privileged ARM code that reads the block; what binds
that is Secure Boot and lockdown, which refuse unsigned modules and `/dev/mem`.

Before `ExitBootServices`, any code that runs in UEFI can also ask the VPU for
signatures and HMACs, and so compute the boot key for any PCR values and the
TPM's seeds. That code is every loader the keys in `db` have signed. `db` holds
Microsoft's UEFI CAs so that a distribution boots unmodified: Microsoft signs
each distribution's shim, a small first-stage loader that then checks GRUB and
the kernel against the distribution's own keys, which this firmware never sees.
What runs before `ExitBootServices` is therefore not only what the firmware's
builder signed but any shim, GRUB or other loader Microsoft has signed for
anyone and `dbx` does not list. A build whose `db` held only its builder's key
would run only what the builder signs, and would boot no distribution's stock
image. This is why the boot key's PCR binding is no defence against a hostile
loader ([keystore.md](keystore.md#the-boot-key)): bind what must outlast an OS to
a policy that a key authorizes (PCR 11 signed by the image's builder) rather than
to PCR 7 alone, which every Microsoft-signed shim OS reproduces.

## State that outlasts a boot

The variable store is a log in the EEPROM's tail, in two banks. Writes of
`KEK`, `db` and `dbx` are stored as the signed writes themselves and checked
again at every boot against the keys as they stood when each was made; other
non-volatile variables are sealed with the device key's HMAC over their
attributes, name, value and a counter, which the VPU computes. A record whose
seal fails, or whose counter does not rise, is ignored, as is one that is not
intact; the store steps over it. The OS can write the flash only as far as some
driver gives it a way to, and cannot make a record: the VPU seals for the OS
only in the runtime domain, and UEFI accepts such a record only for a variable
that is absent or has exactly the attributes non-volatile, boot services and
runtime, and never under the firmware's own class GUID. The VPU seals a write
only with those attributes, a name of 1 to 256 UCS-2 units with no NUL, and at
most 16 KiB.

The runtime variable services follow the same rule from the OS's side. After
`ExitBootServices` the OS can create and change **only non-volatile** variables
with attributes non-volatile, boot services and runtime. A volatile variable
the boot chain made (shim's `MokListRT`, from which a kexec'd kernel takes keys)
is read-only to the OS. The keys, `SecureBoot`, `PK` and the Secure Boot state
refuse writes; `KEK`, `db` and `dbx` take only a signed one, which the runtime
services cannot check and so append for the next boot to check.

What an attacker who can write the EEPROM from the OS can do, and the firmware
cannot prevent: **drop records**, which returns a variable to an older value (for
`dbx`, to revoke less), and **erase both banks**, which returns the keys the
firmware was built with. Nothing outside the flash counts how many records there
should be. The keys are measured into PCR 7 and the MOK lists into PCR 14, so a
TPM policy that includes them notices; and the bootloader's own sections lie below the store and are covered
by the boot ROM's signature on a board with signed boot, so tampering there
only prevents a boot. A store bank is 20 KiB and a signed update is a few KiB, so a few updates fill
one.

## The OS's way in

What a locked-down OS reaches:

| path | what it carries | bound |
|---|---|---|
| TPM commands, over the ACPI command buffer or the mailbox tag | the TPM 2.0 subset in [tpm2.md](tpm2.md) | a parser over checked reads, every size field bounded; a command that would overrun a slot or a buffer gets `TPM_RC_SIZE`; a command is at most 2048 bytes and none runs long |
| the property mailbox, channel 8 | the tags in [boot.md](boot.md#known-limitations) | the request is copied once, from a buffer that must lie wholly below the VPU's memory, and parsed from the copy; no tag returns a fuse or the device key, and the one secret it gives, the boot key, it gives once |
| the mailbox, channel 7 | the runtime services' two store tags | the OS's own mailbox driver does not use it, and the channel-8 path ignores these tags |
| `GetVariable`, `GetNextVariableName`, `SetVariable`, `QueryVariableInfo`, `ResetSystem` | the runtime services | the rules above; every other runtime service returns `EFI_UNSUPPORTED` |
| the TPM's command buffer page | one page the OS shares | the VPU takes the length from one read of the header, copies the command out and runs the copy; the buffer's place and size are the VPU's own |

The ARM is given memory below `0x3EC0_0000` and above 1 GiB. The VPU's own
memory is not in the device tree, the EFI memory map or the reservations the OS
sees; hardware does not enforce that (see the first section).

What a command can change in the VPU is small: the PCRs (extend-only, but for 16 and 23, which can be reset), a handful
of TPM objects and sessions, and the boot-key and lock flags. A panic in the VPU
stops its service thread (the mailbox, the TPM and the watchdog's beats), so a
TPM command that panics is a denial of service for everyone with `/dev/tpm0`;
the parser answers an error for each shape of command that was found to
([Checks](#checks)).

## Availability

A hang, a fault or a panic in UEFI ends in a reset by the board's watchdog, which
this firmware arms at its start and no setting turns off: 300 s from the start
of the ARM to `ExitBootServices`, then 120 s while the OS loads its watchdog
driver, and an ARM that stops is reset within 16 s. A panic in the VPU before
the OS has the watchdog ends in a reset as well; after it, the mailbox, the TPM
and the wake-up stop answering and the board runs on. So a medium or a device
that makes UEFI hang or fault makes a reset loop for as long as it is attached.
What the firmware does to make that hard:

- a file's size from a directory entry is checked against the volume and a
  per-use cap before any memory is asked for, and the memory is asked for without
  aborting; a directory is read at most 1 MiB, listing it reads it once and not
  once per entry, and a chain that loops cannot run longer than that
- a boot reads at most 8 capsules of at most 16 MiB each, in at most 30 s, and checks them after; a signature carries at most
  16 certificates, and the hash of an image covers at most the file's length
- no USB device is brought up more than 60 s after the controller started, no
  readiness probe of a drive starts after its first 10 s, and a hub is used for at
  most 15 ports; what is under way ends by its own timeouts (1 s for a control
  transfer, 5 s for a bulk one)
- the control-transfer buffer a device describes itself in is bounded by its
  size, not by what the device says

Anyone on the LAN who knows the board's address can boot it with a magic packet
while it waits after an OS power off, by design; no frame is parsed in software,
the MAC's detector sets one status bit, and a wake is a reset that boots as from
power on.

## Memory safety

Both programs are `no_std` Rust. The VPU firmware has no dependencies; UEFI has
one, `r-efi`, a crate of type definitions and constants with no dependencies of
its own. `unsafe` is for hardware registers, the identity map, raw buffers the
firmware hands to protocols, and the context switch; the parsers that see
attacker bytes (FAT, GPT and MBR, USB descriptors, the PE headers, PKCS #7 and
DER, the store's records, the mailbox's tags, the TPM's commands) take slices and
use checked access. Release builds do not check arithmetic, so a length that comes from the outside is
combined with checked or saturating operations, or with bounds that rule overflow
out.

What the firmware does not have: the identity map is read, write and execute
for all of RAM; there is no address randomisation and there are no stack
canaries; the stack guard of the VPU's threads fires at a context switch, not
at the access. A memory-corruption bug in UEFI would be exploitable, which is
why the code that reads attacker bytes before authentication is kept small and
bounded.

## Building it

- The VPU crate has no dependencies and the UEFI crate one; both lock files are
  committed and the images are built with `--locked`, and build inputs are fetched with a SHA-256 checked in the same
  step (the device tree, the stock EEPROM image, the test applications'
  third-party binaries).
- The platform key, the `KEK` and the `db` key are made by `scripts/genkeys.sh`
  and kept out of the repository and out of CI, which gets the certificates only.
  A build that is given some of the three certificates and not all refuses to
  run, one that is given a PEM file or the same certificate twice refuses, and a
  build that is not a test build refuses a certificate named `test key`. The
  build prints the SHA-256 of each. `genkeys.sh` never replaces a key whose
  certificate is there, and refuses a key with no certificate.
- The test build's own certificate in `db` and `KEK` is compiled in only by
  `--test-keys`, which writes different files, and logs a warning at every
  boot.
- The UEFI image does not carry the builder's paths: they are remapped to the
  names of the prebuilt standard library's.
- The update version is the release `FIRMWARE_VERSION` (`X.Y.Z`, packed as
  `X<<24 | Y<<16 | Z`), else `FIRMWARE_TIME`, else the commit's time, which no
  release is above; a build outside a git checkout must set one, or its version
  is zero.
- CI holds `contents: read`, pins its third-party actions by commit (pimu is
  taken from its main branch), and uploads no private key. The VC4 compiler (`rusty-pi/gcc-vc4` and `binutils-vc4`) is
  installed from the latest release of its repositories with no checksum, which is
  the weakest input of the build: a compromised compiler can put anything in the
  VPU's code.

## What it takes to break it

Roughly from the cheapest to the dearest, for a board with signed boot
programmed and an OS that keeps lockdown on:

| to | needs | gets |
|---|---|---|
| replace the firmware | write access to the boot medium **on a board without signed boot in the OTP** | the VPU, the device key's HMAC, everything |
| replace the firmware with an older signed one | write access to the boot medium; the bootloader has no anti-rollback for `boot.img` | the old firmware's bugs |
| run firmware of one's choice on every board whose loader carries an update key | the update private key and a `db` key to sign the capsule, or write access to the medium and a bundle the key signed | the VPU, the device key's HMAC, everything |
| sign what UEFI runs | the `db` private key, or `KEK`, or `PK` (each can add a `db` entry), or any key already in `db`; for firmware, also the owner's boot key | whatever it signs |
| run a signed loader's bug | a signed shim, GRUB or kernel that is not in `dbx` and has a flaw (a bug in a loader before `ExitBootServices`, or a kernel with lockdown off) | code on the ARM, so the VPU and the key's HMAC |
| take the VPU from a locked-down OS | a kernel exploit that gives arbitrary physical memory access; then the VPU's code or the mailbox's buffers are writable | the same |
| take it from a bus master | a flaw in the VL805's firmware (loaded from the EEPROM) or a hostile PCIe device: the inbound window covers all RAM, the VPU's included | the same |
| roll the store back | a way to write the EEPROM: a programmer, or an OS driver that reaches the SPI pins | an older `dbx`, no MOK list, no update record; detectable in PCR 7 and PCR 14 |
| unseal what a policy guards | the PCR values the policy names, or a key the policy names, and for a TPM password as many guesses as it takes: no lockout slows them | the secret |
| learn the device key | privileged ARM code (a loader before `ExitBootServices`, a kernel module on a kernel without lockdown, a kernel exploit), or a probe on the board | the key, for good, and with it every boot key, TPM seed and seal of the board |
| deny service | a USB stick, a hub, a medium, a TPM user with a command that panics (none known), or a magic packet | a reset loop, a stall, a wake |

Not defended, and not claimed:

- A loader Secure Boot accepts that is hostile or buggy. Shim's `SBAT`
  revocations and `dbx` are the mitigation, as on any machine.
- Anything once code has arbitrary memory access on the ARM.
- Rollback of the store, or of `boot.img`, by anyone who can write the media. The
  flash's write protection is not used: the firmware clears the protect bits of
  the flash's status register when it writes the store.
- The VPU's own code is not measured as a hash when it is the loader the
  bootloader started: `EV_S_CRTM_VERSION` names the commit, and PCR 0 holds the
  hashes of the UEFI image and the device tree it starts. An update's VPU image
  is measured, by the loader that ran it.
- The EEPROM's bootloader (`bootcode.bin`) is not measured, and neither is the
  VL805's firmware on a board that keeps it in a flash of its own: the VPU
  loads no image there, and there is nothing to hash.
- The device key against privileged ARM code (above).
- A kernel with a raw mailbox device for users (Raspberry Pi's `/dev/vcio`) lets
  the OS's users send any channel-8 tag, the boot key's among them. Use a
  kernel without it.
- Other keys in `db` can sign firmware capsules. The module-signing key an OS
  image enrols in `db` is one of them; on a board with signed boot the owner's
  key is still needed for a capsule to run.

## Operating it

1. Program signed boot in the OTP and fuse a device key; check PCR 1.
2. Keep `PK` and `KEK`'s private keys offline, and `db`'s apart from the machine
   that builds OS images; build with `PI4_PK_CERT`, `PI4_KEK_CERT` and
   `PI4_DB_CERT`.
3. Boot an OS that locks itself down under Secure Boot, without a raw mailbox
   device, and without `/dev/gpiomem`, `/dev/mem` or a way to drive the EEPROM's
   pins.
4. Bind secrets to a policy a key authorizes, or to PCR 4 and 7 together with
   PCR 11, not to PCR 7 alone; do not rely on a TPM password's secrecy for more
   than the minutes it takes to guess it.
5. Use a boot loader without a prompt on the serial console (a unified kernel
   image under systemd-boot), or one that asks for a password.
6. Build every release with `FIRMWARE_VERSION`, and keep `dbx` fresh with each one.

## Checks

The parts of this that the repository runs:

- the scenarios in `scenarios/` boot the firmware under Raspberry Pi's
  bootloader in pimu: Secure Boot's accepts and refusals, capsules (signed,
  older, changed, by a stranger, relabelled, junk), update bundles (run, and
  refused when no update key signed them), the variable store's
  tampering and compaction, the runtime services' rules, the boot key and the
  device key's locks, the TPM's commands, the watchdog's spans, and Debian's
  kernel under lockdown
- `scripts/test-tpm.sh` runs the TPM's code on the host against reference
  vectors, drives it with `tpm2-tools` and `systemd-cryptenroll`, runs commands
  that would overrun a slot or a buffer, and checks the log writes control
  characters as text
- `scripts/test-acpi.sh` checks the ACPI and SMBIOS tables with the ACPICA tools
  and `dmidecode`
- `scripts/check-key-scrub.py` reads the VPU's memory after the boot key is
  released and looks for the key's pads, states and digest

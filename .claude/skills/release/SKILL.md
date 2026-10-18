---
name: release
description: Cut a nuboot release - work out the version bump from what changed since the last tag, write the release notes, then tag and push so the release workflow builds and publishes start4.elf (no version commit). Use when asked to "make a release", "cut a release", "release the firmware" or "tag a version".
---

# Cutting a release

A release is an `X.Y.Z` tag on main — no `v` prefix. Pushing that tag runs
`.github/workflows/release.yml`: it checks the tag, builds `start4.elf` with
the same toolchain and certificates `build.yml` uses, and publishes it as that
tag's GitHub release. Everything this skill does happens locally until the
final push, so every decision can be changed before anything is public.

There is no bot and no API key in CI: you read the changes and decide the bump
yourself.

The release build refuses to run without the `PI4_PK_CERT`, `PI4_KEK_CERT`,
`PI4_DB_CERT` and `PI4_UPDATE_PUB` repository secrets, where `build.yml` makes
keys of its own: a `start4.elf` with throwaway keys boots nothing signed on a
board and takes no update, so it is not worth publishing. It also signs the
update with the `PI4_UPDATE_KEY` and `PI4_DB_KEY` secrets. The certificates and
`PI4_UPDATE_PUB` (base64 of `keys/update.pub`) are public; the two keys are
private, and only the user sets those. If the repository has none set
(`gh api repos/{owner}/{repo}/actions/secrets --jq .total_count`), say so
before tagging.

## 1. Check the preconditions

Stop and report if either of these fails rather than working around it:

- The working tree is clean and the branch is `main`.
- `git fetch origin` then `git status -sb` shows main level with
  `origin/main`. Release what is pushed, never a local-only commit.

Then look at what CI has already said about the commit being released:

```bash
gh run list --commit "$(git rev-parse HEAD)" \
  --json workflowName,status,conclusion --jq '.[] | "\(.workflowName) \(.status) \(.conclusion // "")"'
```

**Never wait for a run that is still going.** The release job builds the tagged
commit itself, so an in-flight run is not a reason to hold the release.

A run that has already **completed and failed** on that commit is worth
pausing for: name the workflow that failed and ask whether to release anyway.
Release on a yes — a red run is the user's call, not a veto.

The release job checks the same thing for itself: it refuses a commit
`build.yml` has already failed on, and only warns when that workflow has
no finished run for the commit. So a red run you decide to release anyway
needs the failing workflow re-run green on that commit first, or the release
job will stop on it.

## 2. Find what is being released

```bash
last=$(git describe --tags --match '[0-9]*' --abbrev=0 2>/dev/null)
```

With no version tag yet this is the first release: use the whole history, and
see the first-release note in section 4.

Read all three of these before deciding anything:

```bash
git log --format='%h %s%n%b' "$last..HEAD"
git diff --stat "$last..HEAD"
git diff "$last..HEAD" -- src/ uefi/src/ uefi/stub/ scripts/ build.rs Cargo.toml
```

The subjects alone are not enough: nothing in a subject says whether a change
is breaking. Read the diff.

## 3. Decide the bump

What this repository publishes is one file, so its compatibility surface is
what a board that already runs the previous release has stored or trusts, and
what the operating system it starts relies on.

**Breaking** — something that ran the previous release stops working, or needs
changing to keep working:

- a board that booted the previous `start4.elf` no longer boots, or needs its
  EEPROM configuration, boot order or `boot.img` changed to boot
- the UEFI variable store's format changed so that what the previous release
  wrote is ignored or lost
- the Secure Boot keys the firmware trusts changed, or the TPM's seeds and the
  measured boot's PCRs derive differently, so that data sealed to the TPM no
  longer unseals
- a mailbox tag, a device tree node or an ACPI table an operating system
  drives was changed or removed
- the `boot.img`, `boot.sig` or capsule format changed
- the update bundle's format, its key or the update slot's address changed, so
  that the `start4.elf` an owner signed earlier takes no update of this release
  and the owner has to sign this one

**Feature** — something new that an old user does not notice: a device the
firmware now describes or serves to the OS, a boot that reaches further than it
did, a stand-by behaviour, a new published file.

**Fix** — everything else: a corrected register sequence, a timing fix, docs,
scripts, CI, refactors.

The tag is the firmware's version, packed as `X<<24 | Y<<16 | Z` so that
releases order as numbers: a release is at most `255.255.65535`, and the
workflow builds with `FIRMWARE_VERSION` set to the tag.

Then map that to a version. **While the version is `0.x`, the minor field is
the incompatible slot**, so both breaking and feature bump it:

| Verdict  | `0.1.0` becomes |
|----------|-----------------|
| breaking | `0.2.0`         |
| feature  | `0.2.0`         |
| fix      | `0.1.1`         |

Say in the summary which of the two a minor bump came from — the notes carry
the detail that the number cannot. Cutting `1.0.0` is a deliberate decision:
never do it on your own reading, only when the user asks for it by name.

Two things override your reading, in this order:

1. **What the user said.** "make a patch release" settles it; classify only
   when they did not say.
2. **A trailer on any commit in the range.** `Breaking-change: <what>` forces
   breaking, `Feature: <what>` forces at least feature. Normal commits need no
   trailer — the default is a fix.

## 4. Write the notes

Match the repository's voice: plain, direct, no emoji, no praise, no
"🎉 What's New". Present tense, saying what the release does rather than what
was committed.

Structure:

- One or two sentences saying what this release is, when there is a theme.
- Grouped bullets under `### ` headings by area (`Boot`, `UEFI`, `TPM`,
  `Stand-by`, `Build`, ...). Skip an empty group.
- A `### Breaking` section first, whenever there is one, saying what to change.
- Leave out pure-CI, formatting and revert-of-an-unreleased-commit churn.
- Mark register and field names, addresses, mailbox tags, paths and commands as
  inline code.
- Name hardware by board type and revision (`Raspberry Pi 4B d03115`), never by
  hostname, and do not paste OTP dumps or anything secret.

The workflow appends what each published file is (`start4.elf` and the update's cabinet), so leave that out of the
notes. For the first release, describe what the firmware is and how far it
boots today rather than listing the whole history.

## 5. Show the user, then apply

Print the proposed version, one line on why that bump, and the full notes.
Wait for approval before touching anything.

**A release makes no commit.** The version lives in the tag alone —
`Cargo.toml` says `0.0.0` on purpose and nothing reads `CARGO_PKG_VERSION`, so
there is nothing to bump and no `Release X.Y.Z` commit to write. Tag the commit
that is already there:

```bash
version=X.Y.Z
git tag -a --cleanup=verbatim -F notes.md "$version"
```

`--cleanup=verbatim` is not optional: git's default cleanup strips every line
starting with `#` from a tag message, which would silently eat the notes'
Markdown headings.

Leave the build to CI: the release job builds the tagged commit, so there is no
need to run `scripts/build.sh` first.

## 6. Push

Pushing the tag publishes a release — **always ask before pushing, even when the
user has already approved the version and the notes**. Show exactly what will be
pushed:

```bash
git push origin "$version"
```

Only the tag: main is already pushed, which section 1 checked.

If the user declines, leave the tag in place and say how to undo it
(`git tag -d $version`).

## 7. Watch the build

```bash
gh run watch "$(gh run list --workflow=release.yml --limit 1 --json databaseId -q '.[0].databaseId')"
```

It runs as three jobs — `check`, `build`, `publish` — and builds the VC4
toolchain's codegen backend on a cache miss, so a cold run is long. When it
finishes, check the release carries `start4.elf` and report the release URL.

If it fails, the tag stays and the release is absent or incomplete. Fix the
cause on main and cut the next patch version rather than moving the tag — a
moved tag breaks anyone who already fetched it.

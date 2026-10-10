# Agent instructions

- Keep changes focused on the requested firmware or workflow task.
- Read the relevant code and existing documentation before editing; preserve
  repository conventions and avoid unrelated cleanup.
- This is firmware for headless servers on the Raspberry Pi 4 family. Display,
  camera, audio and anything else a headless server does not use is out of
  scope.
- **Zero config.** A behaviour takes its default from the board and the boot
  medium, not from a settings file. Do not add a `config.txt`-style key, or
  any other setting, without asking first.
- **Log through `error!`/`warn!`/`info!`/`debug!`/`trace!`** (`src/log.rs`):
  one record per event, the subsystem as its target, and the values as named
  fields rather than formatted into the message.
- Run the smallest relevant tests or build checks before finishing.
- Do not commit secrets or generated firmware blobs.
- **Name real hardware by board type, never by hostname.** When a doc,
  comment, test, commit or issue cites a measurement or a test run on a real
  board, write the model and revision code — `Raspberry Pi 4B d03115`, not
  `rpi-dev`. A hostname only means something on one person's network; the
  revision code (`Revision` in `/proc/cpuinfo`) says which model, PCB revision
  and RAM size the value came from.
- **Never let CI or anything in `scripts/` depend on real hardware.** The
  reference boards are ad-hoc and only sometimes reachable, and CI runs in the
  cloud. Anything that has to *reach* a board at build or test time is a broken
  build waiting to happen.
- **Never commit an OTP dump.** `vcgencmd otp_dump` on a real board
  includes device-unique and secret material — the board serial, the customer
  key hash, and the device private key. Quoting one or two named rows whose
  value is genuinely needed is fine when they are blank or non-secret; dumping
  the table is not. The same goes for anything else read out of OTP, and for
  the bootcode `HMAC_KEY`.
- Do not add `Co-authored-by:` trailers to commits.
- For boot changes, validate behavior in pimu before anything goes near a
  board, and document any remaining shims or known limitations.

## Writing README.md and docs/

The README and `docs/*.md` are for someone who wants to know what this firmware
does, whether it works on their board, and how to build and run it. They are
not a lab notebook.

- Describe the current state, in the present tense. No history of how it got
  there: no "took four defects to reach", "used to", "now works", "the first
  attempt", "turned out to be".
- No debugging stories. What a bug was, how it was found and why the model hid
  it go in the commit message that fixes it, not in the docs.
- No narration about the maintainer's setup ("the board is headless", "has
  nothing in a USB socket", "boots from its card"). A test status table says
  what was tested; it does not explain why the rest was not.
- Keep test status to the tables and the short list of how a board was run.
  Update a table cell rather than adding a paragraph about the run.
- A rationale belongs in the docs only when a reader needs it to use or build
  the firmware correctly.
- Before finishing a docs edit, reread the changed section as a stranger who
  has never seen this repository. Delete anything that reads like a diary
  entry or a progress report.

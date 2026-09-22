# `wyrd` CLI reference

The `wyrd` process host (`crates/wyrd-cli`): argument parsing,
credential files, mount orchestration, diagnostics, and exit codes
over the daemon's public surface. It never implements drive logic
itself — every subcommand opens the drive through `WyrdNode` and the
behavior lives in `wyrd-core` / `wyrd-daemon`. This document mirrors
`crates/wyrd-cli/src/main.rs`; when they disagree, the code wins and
this document is stale.

## Subcommands

```
wyrd init <drive_dir> --identity-file <path> --passphrase-file <path>
wyrd mount <drive_dir> <mountpoint> [--relay <url>...] [--verbose] \
    --identity-file <path> --passphrase-file <path>
wyrd export <drive_dir> <out_dir> \
    --identity-file <path> --passphrase-file <path>
wyrd member <drive_dir> (list | log | status | remove <device> [--yes] | rotate | set-owner <device> | invite <device> <encryption-key> <out>) \
    --identity-file <path> --passphrase-file <path>
wyrd device <drive_dir> (id | pairing-request <out> | join <invitation>) \
    --identity-file <path> --passphrase-file <path>
```

### `init` — create a drive

Writes the drive's keystore and object store under `<drive_dir>`:
identity, root custody, genesis membership. Idempotent only in the
sense that re-running refuses — init never merges into an existing
drive.

### `mount` — serve a live read-write projection

Serves the drive's live projection at `<mountpoint>` via FUSE until
SIGINT/SIGTERM, which shuts down cleanly (flush, unmount, exit).
Writes through the mount commit as snapshots; the serving endpoint
and bulk source stay up for the life of the mount so peers can fetch
what this drive holds.

- `--relay <url>` (repeatable): control-plane relays. With none
  given, control-plane intake stays idle and the drive is local-only —
  mounts still serve local state.
- `--verbose`: debug-level FUSE request logs (opcode, latency, reply
  errno) on stderr and in `mount.log`. Without it the mount logs at
  info level.

On macOS the mount preflights the macFUSE runtime before binding any
endpoint: a missing kext or mount daemon fails fast with the checklist
next to the raw error (whose errno may be stale — macFUSE's libfuse2
mount can fail without setting errno).

### `export` — materialize a plain copy

Writes the drive's namespace to `<out_dir>` as an ordinary directory
tree: files, directories (empty ones included), symlinks, and the
executable bit (0o755 vs 0o644). The output needs no wyrd software to
read afterward — this is the offline egress path guaranteed before
any format break.

- Offline by construction: no `--relay` flag exists, and export never
  touches relays, the mailbox, the serving endpoint, or FUSE.
  Content the device does not hold fails the export closed, naming
  the missing bytes — a partial tree that silently drops files is
  worse than no tree.
- Multi-head conflicts export as `name@N` siblings, numbered in
  SnapshotId byte order — the same numbering the mounted `foo@N`
  grammar selects by. Export never picks a winner silently.
- Symlinks pass the same confinement policy as the mount: absolute
  and root-escaping targets are refused, so the plain copy stays
  self-contained.
- `<out_dir>` must not exist or must be empty; export never merges
  into a populated tree. The walk lands in a uniquely named staging
  sibling and renames it into place only after the whole tree
  succeeds, so a failed export leaves no partial tree behind. Each
  run heartbeats its staging; a later export sweeps staging that
  proves exporter ownership (exact generated name plus a valid
  heartbeat marker) with a heartbeat older than an hour, and leaves
  everything else — live runs, user directories, marker-less
  leftovers — alone or for manual cleanup. Concurrent exports to
  the same destination race to publish: the first rename wins and
  later ones fail with a populated destination — the destination
  always holds one complete tree, never a mix.

### `member` — administer drive membership

Reads project the membership log offline over the keystore; writes
author one transition plus catch-up obligations through the engine,
which enforces owner-only — the CLI never decides authorization
itself. Catch-up delivery to other devices happens on the next
mounted sync via the mailbox, not here. Devices are 64 hex
characters (x-only pubkeys).

- `list`: members and owners at the canonical tip, one identity per
  line under an `epoch <n> tip <id>` header.
- `log`: every observed transition in epoch order with its
  canonical status (`canonical`, `contested`, `voided`, `orphaned`,
  `pending`, `invalid:<reason>`) and author; frozen conflict epochs
  are marked.
- `status`: known tip epoch and id, member/owner counts, frozen
  state, and held epoch secrets. Knowledge is not possession: a
  known epoch without its secret authorizes nothing until the
  capability arrives.
- `remove <device>`: author a removal transition. The removed device
  receives no new-epoch material; its acquisition ends at the
  removal boundary while its history stays valid. Removing the sole
  owner is valid but terminal — it empties the owner set and no
  future transition can be authorized — so it requires `--yes`.
- `rotate`: force a fresh epoch secret. Membership unchanged; every
  current member is owed the new-epoch wrap.
- `set-owner <device>`: hand ownership to a member (v0 ownership is
  a singleton). Authority comes from the pre-transition owner set,
  so the current owner signs the handover.
- `invite <device> <encryption-key> <out>`: admit a device and write
  its sealed invitation to `<out>` for out-of-band delivery. The
  transition commits with the usual catch-up obligations; the
  newcomer joins from the invitation file. The destination is
  claimed before the commit: an existing file is refused, and an
  uncreatable path fails with no transition authored. A write
  failure past the commit leaves the admission standing (the error
  says so) — retrying the same invite then reports `AlreadyMember`.

Membership state beyond the CLI: device identity is single-use
within a membership chain — a removed device returns only under a
fresh identity (`docs/epochs.md`).

### `device` — pair this device with a drive

The local-device half of multi-device setup. Pairing and join are
offline file exchanges; the drive directory holds the staged secret
and (after join) the member custody record. Catch-up arrives on the
next mounted sync, not here.

- `id`: this device's id plus the encryption key the membership
  state registers for it. `unregistered` is honest, not an error: a
  fresh join holds genesis only, and its own admission arrives with
  the catch-up set. Also the cheapest reopen probe — it opens the
  keystore, which works for owner and member records alike.
- `pairing-request <out>`: stage this device's pairing secret and
  write the public pairing material (device plus encryption key, no
  secrets) to `<out>` for the owner. Re-running returns the same
  key: the owner may already have admitted it.
- `join <invitation>`: join from the owner's sealed invitation.
  Member custody persists before the accept commits, so the device
  reopens afterwards. A pairing for another key, a truncated or
  forged invitation, or a join without pairing all fail closed, and
  a refused join writes nothing. Join never targets an owner's
  drive home or another device's member directory: an owner record
  refuses outright, and a member record for another device refuses
  rather than stranding it.

The pairing flow, end to end:

```
# newcomer, in its own directory
wyrd device <newcomer-dir> pairing-request pairing.txt --identity-file ... --passphrase-file ...
# owner, with the pairing material
wyrd member <owner-dir> invite <device> <encryption-key> invitation --identity-file ... --passphrase-file ...
# newcomer, with the invitation file
wyrd device <newcomer-dir> join invitation --identity-file ... --passphrase-file ...
```

## Credential files

All subcommands take `--identity-file` and `--passphrase-file`.
Both are read and hardened by wyrd code, never by clap:

- The identity file holds exactly 32 raw bytes or 64 hex characters
  (whitespace-trimmed); anything else is rejected.
- The passphrase file holds UTF-8 text with one trailing newline
  stripped; files over 4096 bytes are rejected.
- Files are opened without following symlinks, must be regular files
  owned by the current user, and must grant nothing to group or
  other (Unix). Credential handling is Unix-only.
- Secrets never reach logs, error text, or diagnostics — stages, ids,
  errnos, and latencies only.

## Diagnostics and exit codes

- `mount` initializes structured diagnostics first: events to stderr
  plus `drive_dir/mount.log`, truncated per mount (one mount, one
  log — no rotation code). Init, export, member, and device log nothing to disk.
- `--help` and `--version` print and exit successfully.
- Exit `0` on success; exit `2` on any failure, with the reason on
  stderr (`error: ...`). Usage errors (bad flags, missing options)
  are failures too, not help text.

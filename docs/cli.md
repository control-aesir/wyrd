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
  into a populated tree. The walk lands in `<out_dir>.wyrd-export-staging`,
  claimed atomically and renamed into place only after the whole tree
  succeeds, so a failed export leaves no partial tree behind — and a
  crashed run's staging is cleared by the next export. Concurrent
  exports to the same destination are not supported: at most one
  proceeds, the other fails closed.

## Credential files

All three subcommands take `--identity-file` and `--passphrase-file`.
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
  log — no rotation code). Init and export log nothing to disk.
- `--help` and `--version` print and exit successfully.
- Exit `0` on success; exit `2` on any failure, with the reason on
  stderr (`error: ...`). Usage errors (bad flags, missing options)
  are failures too, not help text.

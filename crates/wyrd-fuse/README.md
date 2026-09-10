# wyrd-fuse

Wyrd's presentation layer: mount a Wyrd drive as a standard filesystem.

## What belongs here

- The **live view**: the drive's current state as an ordinary read/write folder
- **Time travel**: browsing previous snapshot heads and restoring them, using
  ordinary file tools
- **Materialization**: remote-only paths are visible and open on demand
  (block-and-fetch, `EIO` when offline); cached content evicts by policy;
  pinned content stays local
- **Conflict surfacing in the filesystem**: conflicted paths appear as
  directories holding both versions

## What does not belong here

Storage, format, and networking logic. This crate translates filesystem
operations into format-layer calls and renders format-layer state as files.

## Status

Read-only drive view implemented mount-free (`src/view.rs`: lookup,
readdir, open, read, stat over the format layer, remote-only content
mapped through `FetchStatus`, conflicts surfaced per the policy in
`docs/sync-and-peers.md`). Kernel mounting still pending: it requires
macFUSE on macOS and FUSE 3 on Linux, and a daemon composing this view
with `wyrd-sync`.

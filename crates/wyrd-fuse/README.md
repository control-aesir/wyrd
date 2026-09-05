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

Not implemented. Mounting requires macFUSE on macOS and FUSE 3 on Linux; both
constraints shape how much can run in tests, so the crate will lean on the
format layer being pure and mount-free.

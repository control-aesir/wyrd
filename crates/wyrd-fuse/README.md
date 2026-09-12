# wyrd-fuse

Wyrd's presentation layer: the drive as a standard filesystem, mounted by
the daemon over `fuser`.

## What belongs here

- The **live view** (`src/view.rs`): the drive's current state as an
  ordinary read-only folder — lookup, readdir, open, read, stat
- **Time travel**: browsing previous snapshot heads with ordinary file
  tools (restoration workflows live in `wyrd-sync` recovery)
- **Materialization**: remote-only paths are visible and open on demand.
  Absent bytes map to `FetchStatus` at the view boundary; the daemon's
  want registry blocks open/read with a bounded deadline (`EIO` on
  expiry) and fetches
- **Conflict surfacing in the filesystem**: conflicted paths appear as
  conflict nodes with union listings of both versions, read-only

## What does not belong here

Storage, format, and networking logic. This crate translates filesystem
operations into format-layer calls and renders format-layer state as
files. It never mounts (mounting is the daemon's composition) and never
fetches (fetching is the engine's plan).

## Status

The mount-free view and the daemon's read-only FUSE backend (`wyrd mount`)
are in place and under test, including open-fd stability across head
advancement. Write support behind the mount is pending; the write path
exists through the daemon API (`Daemon::put_file`/`Daemon::remove`).
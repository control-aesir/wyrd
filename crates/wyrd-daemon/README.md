# wyrd-daemon

Wyrd's composition crate: it owns a `wyrd-sync` engine, projects the
`wyrd-fuse` view over it, and exposes the presentation backends — a
read-only FUSE mount today, mobile file surfaces later. The `wyrd` binary
(`init`, `mount`) lives here.

## What belongs here

- **Composition** (`core.rs`): `Daemon` wires an `Engine` (durable state,
  fetch planning, authoring, vault) to a `DriveView` with daemon
  materialization policy. Heads reach the view only through the engine's
  classified projection — never derived from announcements here.
- **The write path**: `Daemon::put_file` and `Daemon::remove` publish
  authored snapshots — manifest generation, vault import, and announcement
  ride the engine.
- **Fetch-on-open** (`want.rs`, `LiveDaemon`): a want registry on its own
  lock; `open`/`read` on remote-only content blocks on a bounded deadline
  (`EIO` on expiry) while the fetch plan satisfies registered wants.
- **The FUSE backend** (`fuse.rs`, `fuser`): the read-only kernel surface —
  lookup, readdir, open, read, stat. Open descriptors stay stable across
  head advancement.
- **The live mailbox** (`live_mailbox.rs`): one `LiveMailbox` owns one
  Tokio runtime and one relay client; relay health is polled and readable
  (`MailboxHealth`), so an outage is diagnosable instead of silent.
- **The `wyrd` CLI** (`main.rs`): `wyrd init` creates the drive keystore;
  `wyrd mount --relay …` serves the drive's read-only projection and joins
  the control plane.

## What does not belong here

Format, cryptography, membership, and transport logic. The daemon composes
and never reimplements: new protocol behavior belongs in `wyrd-sync`, new
filesystem semantics belong in `wyrd-fuse`.

## Status

Read-only FUSE mount, fetch-on-open, authored writes through the daemon
API, and the durable serving vault (`Daemon::serve`) are in place and
under test. Pending: the real-iroh serving router loopback (peers dialing
`wyrd mount` over live transport), the multi-relay mailbox, NIP-46 signer
wiring, and write support behind the mount.
//! Wyrd's embeddable local node: the drive's namespace, snapshots,
//! mutations, materialization, and sync control, composed over
//! `wyrd-sync` with no daemon process assumed — mobile hosts, CLIs, and
//! the daemon all build on this crate.
//!
//! The layering contract is machine-enforced (`wyrd-contracts`
//! contract 34): this crate depends on `wyrd-format` and `wyrd-sync`
//! only, never on presentation (fuser), argument parsing (clap), POSIX
//! errno mapping (libc), or process supervision. `nostr` use stays
//! inside the mailbox subsystem. The daemon is one host for the node,
//! never its definition.

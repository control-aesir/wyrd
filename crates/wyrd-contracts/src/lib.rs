//! Wyrd's cross-crate architectural contract suite (principal review,
//! 2026-09-10 §9): one named test per contract, each composed through
//! the public APIs of `wyrd-format → wyrd-sync → wyrd-fuse →
//! wyrd-daemon`, so an invariant regression fails a test instead of a
//! deployment. The suite is a workspace leaf: it depends on every
//! crate and nothing depends on it.
//!
//! The contracts (normative homes in parentheses):
//!
//! 1. `unverified_snapshots_never_become_live_fuse_heads` — the
//!    signature gate and head classification are the only path into
//!    the view; the view never derives heads from announcements
//!    itself (`architecture.md` invariant 3).
//! 2. `content_ids_never_appear_in_vault_transport_records` — vaults
//!    see only `StorageId`-addressed AEAD bytes; ContentIds stay
//!    member-only (`architecture.md` invariant 4).
//! 3. `malformed_manifests_never_become_materialized_content` — a
//!    rejected manifest leaves nothing local and nothing served.
//! 4. `changed_descendants_never_create_directory_path_conflicts` —
//!    DAG conflicts merge structurally; only genuine path divergence
//!    conflicts (`sync-and-peers.md`, Conflicts).
//! 5. `open_fds_remain_stable_across_head_advancement` — a descriptor
//!    serves its open-time capture, never whatever occupies the path
//!    later (daemon FUSE backend).
//! 6. `deferred_messages_survive_queue_pressure` — the pending bound
//!    sheds to the relay without consuming, and held messages commit
//!    once their dependency lands (`sync-and-peers.md`, operational
//!    patterns).
//! 7. `bulk_ceilings_stay_bounded_and_oversize_fails_closed` — the
//!    engine never offers a ceiling above the configured limit, a
//!    source refuses oversized payloads without serving bytes, and
//!    oversize is invalid remote data.
//! 8. `unverified_snapshots_cannot_become_live_fuse_heads` — the view
//!    accepts heads only through the verification capability; a forged
//!    body is refused at the boundary and never mounts.

#[cfg(test)]
mod fuse_contracts;
#[cfg(test)]
mod support;
#[cfg(test)]
mod sync_contracts;
#[cfg(test)]
mod vault_contracts;

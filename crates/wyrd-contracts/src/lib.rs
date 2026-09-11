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
//! 8. `forged_snapshots_are_rejected_before_fuse_head_installation` —
//!    heads cross the view boundary only as verified bodies through
//!    the supported composition path; a forged body is refused before
//!    any head can exist.
//! 9. `only_engine_classification_mounts_the_daemon_view` — the
//!    production head path end to end: control plane and bulk fetch
//!    run through the daemon, and only the engine's classified
//!    projection mounts the drive (`architecture.md` invariant 3).
//! 10. `failed_projection_leaves_installed_heads_untouched` — a
//!     damaged durable store fails the projection closed and the view
//!     keeps serving what it served before; refresh is all-or-nothing.
//! 11. `authored_snapshots_mount_through_the_daemon_view` — the local
//!     write path: a member authors a snapshot and the daemon's
//!     classified projection serves its tree (`docs/epochs.md`).
//! 12. `a_bootstrapped_drive_serves_its_first_authored_snapshot` — a
//!     drive created by the production bootstrap (identity, root,
//!     genesis) serves its first authored snapshot (`docs/epochs.md`).

#[cfg(test)]
mod fuse_contracts;
#[cfg(test)]
mod support;
#[cfg(test)]
mod sync_contracts;
#[cfg(test)]
mod vault_contracts;

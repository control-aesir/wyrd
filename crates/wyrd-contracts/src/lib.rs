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
//!     keeps serving what it served before. Pins the decided v0
//!     policy: failure ⇒ heads unchanged ⇒ error surfaced ⇒ no
//!     automatic repair, resync, or clear (`docs/epochs.md`). The
//!     projection itself is per validity class, not all-or-nothing:
//!     verified heads install, heads still fetching wait (never
//!     blanking a serving view), damaged heads fail — pinned by
//!     `a_pending_only_pass_still_delivers_the_durable_outbox`,
//!     `an_installed_head_survives_a_pending_successor_refresh`,
//!     `a_damaged_head_beside_an_installed_one_fails_the_pass_closed`,
//!     and the two mixed-validity head contracts.
//! 11. `authored_snapshots_mount_through_the_daemon_view` — the local
//!     write path: a member authors a snapshot and the daemon's
//!     classified projection serves its tree (`docs/epochs.md`).
//! 12. `a_bootstrapped_drive_serves_its_first_authored_snapshot` — a
//!     drive created by the production bootstrap (identity, root,
//!     genesis) serves its first authored snapshot (`docs/epochs.md`).
//! 13. `a_serving_daemon_serves_a_peer_over_live_iroh` — the serving
//!     router loopback: a real-iroh endpoint over the durable vault
//!     serves a peer's fetch from announcement routes alone, and a
//!     serving restart's route update rewires subsequent fetches
//!     (`sync-and-peers.md` exchange; tracking issue: real-iroh
//!     serving router loopback).
//! 14. `snapshot_manifest_closure_correspondence` — a snapshot's manifest
//!     hierarchy must correspond exactly to its tree closure; a valid
//!     manifest advertising unreachable objects is rejected
//!     (`object-model.md`, decision 27).
//! 15. `a_mismatched_snapshot_manifest_never_mounts` — tree nodes are
//!     fetchable, and the daemon verifies each head's tree/manifest
//!     closure before installing it: a validly signed body whose manifest
//!     describes different content never becomes a mounted head
//!     (`object-model.md`, decision 27).
//! 16. `daemon_write_publication_and_retry_converges_across_members` —
//!     the local write publication path end to end: one member authors
//!     through `put_file` and announces through the control-plane
//!     mailbox, the other drains, fetches from the author's serving
//!     vault, and serves the file; a failed announcement leaves the
//!     authored snapshot durable and the retry converges without
//!     re-authoring (`docs/epochs.md`, local write).
//! 17. `invited_device_converges_on_ordered_catch_up` — the admission
//!     transition plus its capability wrap drain to acceptance with
//!     nothing held, skipped, or duplicated (P2 fresh-device discovery).
//! 18. `invited_device_converges_on_reversed_catch_up` — the wrap holds
//!     for its unseen transition, then the transition flushes it;
//!     redelivery collapses to duplicates.
//! 19. `invited_device_converges_on_duplicated_catch_up` — redelivery
//!     is dedupe, not state.
//! 20. `invited_device_converges_after_gap_then_redelivery` — a missing
//!     intermediate delivery heals when the transition lands later.
//! 21. `offline_device_catch_up_accumulates_contiguously` — while the
//!     newcomer is away its queue holds every epoch from admission to
//!     tip with nothing skipped or doubled; epochs past its invitation
//!     stall loudly (retained) until rotation delivery lands them a
//!     key — the documented cross-epoch boundary.
//! 22. `forged_transition_from_member_cannot_extend_newcomer_state` —
//!     an owner-signed but invalid sibling is suppressed while the
//!     genuine admission converges around it; the pusher is transport,
//!     never authority.
//!
//! The layering contracts (workspace extraction program):
//!
//! 34. `crate_dependencies_follow_the_layered_dag` — every member's
//!     production dependencies point downward along
//!     `wyrd-format → wyrd-sync → wyrd-core → presentation`, and the
//!     policy fails closed on unknown crates or edges
//!     (`docs/architecture.md`, crate map).
//!
//! The node contracts (provider-neutral boundary):
//!
//! 35. `node_composes_and_serves_without_a_presentation_backend` —
//!     the composed node runs, mutates, and serves with no backend in
//!     the path, asserting through the `NamespaceView` surface
//!     (`docs/architecture.md`, layer target).
//!
//! 36. `node_serves_over_a_view_defined_outside_the_fuse_crate` —
//!     the loop, parts, and projection compose over an out-of-crate
//!     `NamespaceView` implementation, so the node never names one
//!     presentation's view type (`docs/architecture.md`, layer target).
//!
//! 37. `recovery_grafts_content_only_and_voided_transitions_never_authorize` —
//!     recovery is eligible only onto eligible heads, and a voided
//!     membership binding voids every snapshot on it through any
//!     ancestry shape (`docs/epochs.md`, Layer 3).
//!
//! The upgrade contracts (`docs/upgrade-contract.md`), one per invariant:
//!
//! 23. `upgrade_new_encoding_is_new_representation` — re-stored content
//!     is a no-op under the same ContentId; later writes never touch
//!     stored objects (invariant 1).
//! 24. `upgrade_format_versions_are_carried_on_the_wire` — the commit
//!     envelope version rides byte 0 of every commit file (invariant
//!     2, wire half).
//! 25. `upgrade_old_objects_stay_readable` — a reopened object store
//!     serves what it served before, with nothing rewritten
//!     (invariant 3, same-version form).
//! 26. `upgrade_previous_release_store_replays` — genuine
//!     `v0.1.0-alpha.1` bytes open and replay under the current
//!     build, with an oldness gate on the record tags (invariant 3,
//!     cross-release form).
//! 27. `upgrade_derived_state_rebuilds_from_facts` — a fresh engine
//!     recovers committed coverage by replay, stably across restarts
//!     (invariant 4).
//! 28. `upgrade_mixed_versions_fail_named` — a forged envelope version
//!     fails open with `ControlError::UnknownVersion` (invariant 5,
//!     gate half).
//! 29. `upgrade_reads_never_mint_authority` — open, load, and
//!     projection write no history and mint no transitions
//!     (invariant 6).
//! 30. `upgrade_old_epoch_material_stays_decryptable` — the fixture's
//!     epoch-1..2 grant still unwraps under the current build
//!     (invariant 7).
//! 31. `upgrade_appends_never_rewrite` — a new commit appends; existing
//!     files stay byte-identical (invariant 8).
//! 32. `upgrade_orphaned_temps_are_ignored` — stale `*.tmp` siblings
//!     are walked past by open and load; the full crash boundary is
//!     pinned in wyrd-sync's crash-matrix tests (invariant 9,
//!     orphaned-temps form).
//! 33. `upgrade_unknown_refuses_loudly` — unknown envelope and control
//!     versions and a flipped commit version refuse with their names
//!     (invariant 10).
//!
//! Deliberately ignored until their blockers land:
//! `upgrade_replays_previous_fact_payload_versions` (fact-payload
//! versioning, v0.9.0) and `upgrade_full_version_matrix_synchronizes`
//! (capability negotiation).

#[cfg(test)]
mod egress_contracts;
#[cfg(test)]
mod fuse_contracts;
#[cfg(test)]
mod join_contracts;
#[cfg(test)]
mod layer_contracts;
#[cfg(test)]
mod node_contracts;
#[cfg(test)]
mod removal_contracts;
#[cfg(test)]
mod serving_contracts;
#[cfg(test)]
mod support;
#[cfg(test)]
mod sync_contracts;
#[cfg(test)]
mod upgrade_contracts;
#[cfg(test)]
mod vault_contracts;

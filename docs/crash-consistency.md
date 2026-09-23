# Crash-consistency boundaries

The explicit durable-boundary list for the crash-consistency audit:
every subsystem that survives a restart, the order its writes land
in, the crash windows between them, and the invariant plus the test
that pins each window. A crash anywhere must leave before-XOR-full
state per subsystem — torn writes are invisible, never half-applied —
and the subsystems must agree with each other on reopen.

This is an extensible inventory of current boundaries, not an
exhaustive closed set: future durable recovery state (for example a
device-local journal) adds its own write, replay, and
snapshot-commit sections and tests without reworking the model.

Four boundary kinds recur below:

- **durable**: bytes that survive power loss (fsynced files, CURRENT-anchored commits).
- **visible**: durable bytes the post-restart state actually reads (seq ≤ CURRENT, recorded facts, vault files by name).
- **servable**: visible state offered to peers (heads, VaultSource maps, routes).
- **propagated**: servable state a peer has consumed (acked mail, delivered catch-up, fetched bytes).

## Fact log

One batch per intake/plan/author op through `DurableStore::commit_until`
(`durable/store.rs`). Eight crash stages from temp-write to dir-fsync;
visible iff `seq <= CURRENT`; replay verifies the hash chain over
`1..=CURRENT`. A torn commit returns `Ok` with nothing durable.
Pinned by `crash_matrix_never_hybrid` (all eight stages: reopen sees
the before-state XOR the full batch, never a hybrid) and
`orphan_files_are_ignored` (`durable/tests.rs`).

## Membership authoring

Each authoring commits transition + self capability + every catch-up
obligation (queued transitions, wraps, head announcements) in ONE
batch — there is no window where a transition is durable but its
outbox is not. Validation stages against a cloned log, so a failed
op leaves no phantom tip. Pinned by `failed_admit_leaves_no_phantom_tip`
and `admit_queues_and_delivers_newcomer_catch_up` (restart before
first send still delivers; `author/tests_admission.rs`).

## Snapshot authoring and heads

Vault imports land before the facts that name them (body, then each
fresh seal during the manifest walk), and body + manifests + queued
announcements commit in one batch. A torn authoring commit restarts
headless and re-authors cleanly; orphaned vault envelopes stay
unreferenced (append-only, no GC). A published head's objects survive
the author's own restart and serve to peers afterwards. Pinned by
`a_torn_authoring_commit_leaves_no_half_advertised_state`,
`crash_before_announce_resumes_without_reauthoring`,
`authored_snapshot_survives_restart`, and
`announced_head_serves_from_the_author_vault_after_author_restart`
(`engine/tests_serving.rs`, `engine/tests_drain.rs`).

## Send pipeline (outbox)

Queued obligations ride the authoring batch; sealing and delivery
marks (`AnnouncementSealed/Delivered`, transition/capability
sealed+delivered) commit as their own facts. The relay retains every
unacked envelope, so a crash mid-loop resends only the unacked with
identical sealed bytes, and a crash between commit and first send
resumes without re-authoring. Pinned by
`partial_send_then_restart_resends_only_the_unacked` and
`crash_before_announce_resumes_without_reauthoring`
(`engine/tests_drain.rs`).

## Keystore and custody

The owner record (wrapped root + device secret + epoch-1 escrow)
seals before the store opens and writes before the genesis commits;
member custody writes before the accept commits. A crash in either
window resumes on open: the genesis is deterministic and
owner-verified, the member secret is reused idempotently. Pinned by
`an_interrupted_bootstrap_resumes_on_open`, `join_round_trip_reopens_as_member`,
and the lifecycle create/open roundtrips (`runtime/bootstrap.rs`,
`engine/tests_lifecycle.rs`).

## Escrow sidecars

Strictly commit-then-escrow: a crash in the window leaves a committed
epoch with no sidecar (degraded recovery — keyring catch-up still
serves; only root-alone recovery of that epoch waits), never an
orphan a retry could mismatch. Every later authoring backfills
missing sidecars from the keyring; present sidecars are never
rewritten. Reopening installs escrowed keys fill-vacant and fails
closed (`EscrowConflict`) on a sidecar disagreeing with held
material. Pinned by `failed_escrow_persist_heals_on_next_authoring`,
`per_transition_escrow_restores_later_epochs_from_root_alone`, and
`conflicting_escrow_sidecar_fails_owner_open_closed`
(`runtime/bootstrap.rs`).

## Vault

One file per transport root named by the root's hex; temp + fsync +
rename + dir-fsync with the rename as publication. A torn import
leaves a temp file, never a servable root. Fetch imports into the
vault before marking local, so a record never names a missing
representation on either the authoring or the fetch path. Pinned by
the vault rename/dir-sync reconciliation tests (`serving.rs`),
`torn_plan_commit_is_ignored_on_reopen`, and
`fetched_representations_serve_after_restart_and_reauthoring`.

## Mailbox ack and intake

Commit precedes settle per envelope: accepted/duplicates/discards ack,
deferred/held/skipped retry. A commit failure resyncs and never
settles that envelope, so it redelivers. Suppression verdicts and
pending queues are memory-only and revalidate after restart; the
durable seen set survives. Pinned by the intake restart suite
(`intake/tests_pipeline.rs`: crash-before-commit redelivery,
suppression revalidation, redelivery-stays-duplicate) and the
resilience suite (`intake/tests_resilience.rs`).

## Fetch and plan

Plan batches commit per pass with resync-on-error; a torn plan batch
is ignored on reopen and refetch heals exactly-once; restarts between
intake, planning, and partial plans converge without loss or
duplication. Pinned by `torn_plan_commit_is_ignored_on_reopen`,
`plan_fetches_bodies_and_live_heads_survive_a_restart`
(`plan/tests_execution.rs`), and the convergence restart suite
(`engine/tests_convergence.rs`).

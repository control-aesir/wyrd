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
`orphan_files_are_ignored` (`durable/tests.rs`). One tag is not
verbatim: a stated reconciliation view (`0x18`) whose evidence is not
a per-class subset of the tip derivation is dropped at load with a
warning instead of replayed — the claim fails closed while the store
stays open — so the replayed projection can be narrower than the
committed log by exactly the refused statements.

## Membership authoring

Each authoring commits transition + self capability + every catch-up
obligation (queued transitions, wraps, head announcements) in ONE
batch — there is no window where a transition is durable but its
outbox is not. Validation stages against a cloned log, so a failed
op leaves no phantom tip. Pinned by `failed_admit_leaves_no_phantom_tip`
and `admit_queues_and_delivers_newcomer_catch_up` (restart before
first send still delivers; `author/tests_admission.rs`).

## Namespace carry across transitions

A transition supersedes the previous heads without file work, so
the author stages the current eligible-head set as durable carry
obligations (`CarryQueued`) in its own batch BEFORE the transition
commits — the set derives inside the engine, so no caller can stage
a stale branch — then drains the queue (`CarryDone` per head)
afterwards. The crash states, all pinned in
`author/tests_carry.rs`:

- crash between stage and transition: the heads are still
  eligible, so the drain discharges the staged set — benign. The
  discharge still republishes the composed baseline: a stage-only
  crash must serve the valid head, not an empty view. Pinned by
  `stage_only_crash_serves_the_still_eligible_head`
  (`daemon/core/tests_mount.rs`).
- crash between transition commit and drain: the staged set
  survives; the next drain (after a restart, or after the next
  transition) completes it. Pinned by
  `interrupted_carry_resumes_after_restart_without_memory_bases`.
- crash between a carry commit and its Done marker: the retry
  finds the current-epoch child and discharges without
  re-authoring — exactly once. Pinned by
  `torn_carry_commit_discharges_without_duplicates`.
- carry with unheld bytes: the drain fails closed
  (`TreeUnavailable`) with the obligation still pending; restoring
  the bytes and retrying resumes. Pinned by
  `missing_tree_carry_fails_closed_and_retries`.
- departed author (self-removal): the drain authors nothing and
  leaves the set pending on the frozen drive. Pinned by
  `self_removal_leaves_the_queue_pending`.
- mounted write before any drain: `into_live` drains before
  exposing the view or admitting mutations, so the first write
  extends recovered history — and a drain failure fails
  composition closed instead of serving an empty view over pending
  recovery. Pinned by
  `mounted_write_after_interrupted_carry_extends_recovered_history`
  (`daemon/core/tests_mount.rs`).

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
sealed+delivered) commit as their own facts. The relay is expected to
retain every unacked envelope — but retention is bounded and assumed
so (see the forget contract in `sync-and-peers.md`), making this an
expectation, not a guarantee — so a crash mid-loop resends only the
unacked with identical sealed bytes, and a crash between commit and
first send resumes without re-authoring. Pinned by
`partial_send_then_restart_resends_only_the_unacked` and
`crash_before_announce_resumes_without_reauthoring`
(`engine/tests_drain.rs`).

A capability obligation whose sealed bytes went stale adds one more
durable boundary before the mailbox: `CapabilitySealedReplaced`
commits the replacement *before* the send, naming the superseded
fact. Three triggers reach it: a rotation framed under a superseded
version, a current-framing rotation sealed to a superseded
registration, and a pre-framing epoch-sealed capability fact. A crash
after the replacement commit and before the send therefore resumes by
sending the committed bytes, not by re-minting the stale fact into a
different set — the pass-local overlay this replaced died with the
process and appended one fsynced, then-ignored record per obligation
per pass for the whole outage. Minting is gated on the engine holding
mint authority for the transition's pre-state, so a sender without it
appends no replacement and leaves the obligation pending rather than
recording a transmission the recipient would suppress. Pinned by
`stale_capability_obligation_recovers_byte_identically_across_restart`,
`stale_registration_obligation_recovers_byte_identically_across_restart`,
`preframing_obligation_recovers_byte_identically_across_restart`,
`non_owner_stale_obligation_commits_no_replacement`,
`non_owner_stale_registration_commits_no_replacement`,
`non_owner_preframing_commits_no_replacement`,
`stale_obligation_without_secrets_stays_pending`,
`stale_registration_without_secrets_stays_pending`,
`preframing_without_secrets_stays_pending`,
`replacement_commit_is_atomic_at_every_crash_stage`,
`stale_registration_replacement_commit_is_atomic_at_every_crash_stage`,
and `preframing_replacement_commit_is_atomic_at_every_crash_stage`
(`engine/tests_delivery.rs`).

Answering a reconciliation statement adds two more windows, both on
the retire-before-send ordering. A crash between the retire commits
and the scoped sends leaves covered obligations durably retired
(they need no send) and missing ones still pending (the next pass
sends them): every obligation ends up either retired or pending,
never both and never neither. Pinned by
`partial_reconciliation_then_crash_resumes_without_double_sending`
(`engine/tests_response.rs`), which tears the retire batch and
asserts the pending set is whole before the next statement
completes it. A crash inside the chunked retire commit (1024-fact
batches) leaves a partial durable retirement; the remainder stays
pending for the next statement, re-derived from fresh durable
evidence rather than resumed from a cursor. Pinned by
`retire_commits_across_chunks` for the multi-chunk shape and by
the same tear test for the atomicity direction.

### The obligation invariant

> A durable obligation must replay to the same obligation, or to an
> explicitly recorded durable successor. A retry pass must never
> manufacture an ignored durable fact.

This is the rule. `CapabilitySealedReplaced` discharges it for all
three stale shapes above: the `0x01` → `0x02` proof-format transition
(the case the owner proof actually creates), stale registration (a
recipient re-registered under a new encryption key, so the sealed
bytes can never open for them), and pre-framing epoch-sealed
capability facts. The invariant is what mattered in each conversion,
not the fact's origin: a stale-registration replacement names the
exact sealed fact the new registration retires, and replay resolves
the chain to the newest bytes either way.

## Restart equivalence

The predicate over the surfaces above: durable externally
meaningful state before a crash/reopen is equivalent to the state
after the reopen. The per-surface table below IS the relation —
not a claim about every question an operator can ask (timestamps,
diagnostic counters, retry generations, telemetry, and transient
connection state are excluded precisely because several must
differ across a restart). The table is authoritative in exactly
this sense: every row names its observable, its verdict, and the
strongest pin available — a direct test where one can be written,
a named derivation where it cannot. The
whole-state snapshot (`SyncStatus`, observed from committed facts
only) is the aggregate tripwire over the rows it covers — serving
residency, the seen-id log, the route table, and suppression
verdicts have no `SyncStatus` field, and the snapshot says nothing
about them. Nothing here prevents the snapshot from shrinking;
what prevents silent shrinkage is that each row carries its own
pin, and a row whose direct pin stops proving the row fails by
name. Rows with derivation pins say so in their cells instead of
pretending a test exists.

Four verdicts, per surface:

- **survives**: byte- or value-identical after reopen.
- **rebuilt**: reconstructed from durable facts; externally
  equivalent, not necessarily identical bytes.
- **lost, correctly**: memory-only by design; the loss is part of
  the contract, and a test pins the loss so nobody "fixes" it.
- **excluded**: outside the relation by name; tested elsewhere or
  not at all.

| Surface | Verdict | Pinned by |
| --- | --- | --- |
| Heads (live set, per-head classification) | survives | `restart_equivalence_heads_match` |
| Durable facts (`seq <= CURRENT` commits) | survives | `restart_equivalence_durable_facts_match` |
| Membership log and tip | survives | `restart_equivalence_membership_and_control_state_match` |
| Control state (announcement projection, committed capabilities) | rebuilt | same test; replays through `Engine::resync` (`engine/mod.rs`) |
| Materialization state (`Cached` / `Pinned` policies, local objects) | survives | `restart_equivalence_materialization_state_matches` |
| Pending outbox obligations | survives | `restart_equivalence_pending_obligations_match`; replay is the obligation invariant above |
| Serving residency: vault files (hex-named sealed roots) | survives | `restart_equivalence_serving_residency_matches` compares `vault().roots()` |
| Serving residency: `VaultSource` maps (roots, bodies, sealed) | rebuilt | `maps_for_test` compared across the reopen in `restart_equivalence_serving_residency_matches`; reconstructed from `RuntimeState` on every `VaultSource::from_state` (`sync/serving.rs`) |
| Seen-id log (inbox `seen` set, `mailbox.seen` file) | rebuilt | replayed in `resync`; torn tail truncated on open; behaviorally pinned by `redelivery_after_restart_stays_duplicate` (duplicates still recognized after the reopen) |
| Route table | rebuilt | pure derivation of the announcement projection (`publish_recorded_routes` reads `state.announcement(&snapshot)` per recorded snapshot); the projection equality in the control-state row IS the pin — no independent test constructs an iroh bulk source for this |
| Want registry (waiter demand, admission cache) | lost, correctly | `want_registry_loss_is_expected_and_re_demands_from_durable_state` pins the loss half; never persisted (`core/want.rs`). The re-demand half (loop re-registers from surviving `Cached`) follows from the materialization row but has no dedicated pin — follow-up with the materialization work, not claimed here |
| Suppression verdicts | lost, correctly | `suppression_cache_loss_re_derives_the_same_verdict` (warm-cache short-circuit vs post-restart revalidation to the same outcome); also `suppression_revalidates_after_restart`, `redelivery_after_restart_stays_duplicate` |
| Mutation queue and parent tokens | lost, correctly | session-local by design (`core/mutation.rs`); shutdown completes blocked submitters with `Shutdown` (`shutdown_with_registry_releases_held_wants`, `submit_after_shutdown_fails_fast`) |
| **Serving endpoint identity/address** | **excluded** | rebound on restart by design; post-restart announcement is convergence, tested separately — never make it durable to satisfy this table |
| Timestamps, counters, retry generations, telemetry, transient connection state | excluded | must differ; outside the relation |

The restart-loss rule, normative for state that does not exist
yet (peer-repair generations and evidence when they land): a
memory-only loss is equivalent only when restart initializes that
state to its defined fresh-start state AND the resulting
externally meaningful behavior matches a clean restart. The
behavior induced by the reset is what is equivalent, not the
counter value: a fresh generation may permit a new repair
attempt, but it must not alter durable content, durable
obligations, or externally meaningful correctness state. No rows
are written against unlanded implementation; the rows extend when
the code lands.

The invariant as one assertion,
`a_crash_loses_ephemeral_state_but_no_durable_obligation`: a real
reopen across mid-flight state (a pending outbox obligation, pinned
materialization, a served representation) asserts both halves —
every in-scope row matches, and no durable obligation was lost.
The reopen runs through the real protocol at the fact-log crash
stages: `AfterRenameCommit` must show the before-state with the
obligation still pending; `AfterRenameCurrent` must replay the
obligation byte-identically; the temp stages must ignore the
orphan and still match the before-state.

## Keystore and custody

The owner record (wrapped root + device secret + epoch-1 escrow)
seals before the store opens and writes before the genesis commits;
member custody writes before the accept commits. A crash in either
window resumes on open: the genesis is deterministic and
owner-verified, the member secret is reused idempotently. Pinned by
`an_interrupted_bootstrap_resumes_on_open`, `join_round_trip_reopens_as_member`,
and the lifecycle create/open roundtrips (`runtime/bootstrap.rs`,
`engine/tests_lifecycle.rs`). The open itself takes the store lock
before reading the custody record, so the read is serialized against
cooperating writers; a missing record is refused before the store
opens, so a refused open writes nothing (`open_on_a_drive_only_directory_writes_nothing`,
`open_keystore_against_a_held_lock_reports_contention`).

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

The vault-to-mirror write-through after the rename runs over a
bounded queue (64 items / 64 MiB; `MAX_MIRROR_QUEUE_ITEMS` /
`MAX_MIRROR_QUEUE_BYTES` in `serving.rs`). A crash between the
rename and the write-through heals via the held-root path
(`reconcile_held`: re-sync the directory, re-import into the
mirror), and a full queue is backpressure (`VaultError::MirrorFull`,
naming the refused root), never a silent drop: the vault file is
already durable, the readiness barrier stays not-ready so no
announcement discharges over an unserved representation, and a
restart rebuilds the mirror from the vault. Queue depth travels
with the not-ready report in the pass logs, and a queue that is
actually rejecting warns at the default log level. Pinned by
`a_full_mirror_queue_applies_backpressure_without_losing_the_vault`,
`serving_reopen_rebuilds_the_mirror_from_the_vault`, and
`reimport_reconciles_a_vault_file_the_mirror_never_saw`.

A poisoned durability-bookkeeping lock fails the operation, never the
process: no directory is assumed durable or repaired on state a
panicked holder may have left inconsistent, so the instance stays
failed until restart. Pinned by
`poisoned_pending_fails_reconcile_at_the_first_acquire` and
`poisoned_verified_fails_verify_dir_before_any_sync`
(`wyrd-format/src/durable.rs`).

## Mailbox ack and intake

Commit precedes settle per envelope: accepted/duplicates ack,
discards settle Poison, deferred/held/skipped retry. A commit
failure resyncs and never settles that envelope, so it redelivers.
Suppression verdicts and pending queues are memory-only and
revalidate after restart; the announcement and committed-capability
projections are rebuilt from durable facts on every resync, so
post-restart duplicate verdicts re-derive from the store rather than
from memory the crash took; poison settlements are memory-only too,
so redelivery re-poisons; the durable seen set survives for
consumption. Pinned by the intake restart suite
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

## Materialization policy

Each subtree policy operation (pin, unpin, evict) commits its facts
in exactly one batch (`Engine::set_materializations`): a crash
before the commit leaves the previous state, a crash after leaves
the full new state, and a torn commit file is ignored on reopen
like any other torn batch — never a partial pin the census would
report as unpromised files. Pinned by
`batched_materializations_commit_once` (one commit file for N
identities plus duplicates, re-batch commits nothing;
`wyrd-sync/src/runtime/engine/tests_materialization.rs`),
`pin_dedupes_shared_chunks_and_repin_is_a_noop` (re-pin reports
`pinned == 0, already_pinned == 3`),
`evict_refuses_pinned_content_without_committing`
(`wyrd-core/src/policy.rs`), and
`pin_survives_restart_and_evict_keeps_bytes`
(`wyrd-daemon/src/core/tests_policy.rs`).

## Quarantine repair

The drain orders claim-clear before unlink, so a crash lands in
exactly one of two consistent states: claim and bytes both present
(nothing happened — the waiter re-reports and the next pass
repairs), or claim cleared with bytes still on disk (the repair
converges — a read re-observes the rejection and re-submits, and
`insert` heals a present-but-unverifiable name). Bytes gone under a
live claim cannot happen: the unlink never runs before the commit.
Two bounds, both by process lifetime: the in-memory queue loses a
  diagnostic emitted microseconds before the crash (diagnostic
  persistence belongs to `17-observability` — child 14 delivered
  counts-only run diagnostics), and the retained-bytes counter keeps
charging the claimed-cleared-but-still-present bytes until
`FsObjectStore::open` re-seeds from disk. Pinned by `record_objects_removed_batches_many_identities`
(one batch, duplicates collapse) and the drain's phase order
(`wyrd-core/src/quarantine.rs`).

## Scrub repair

The drain orders re-verify before claim-clear before accountant
subtract, so a crash lands in exactly one of three consistent
states: observation lost (memory-only — the next sweep re-stats
the entry and re-reports), claim cleared with the accountant
still charging the lost bytes (the repair converges — the plan
re-drives the fetch, and the reopen walk re-seeds the count from
the store), or all three durable (repaired). Bytes kept under a
cleared claim cannot strand: the re-verify runs before the
commit, so a concurrent heal keeps its claim with no redundant
fetch. One bound, by process lifetime: the in-memory queue and
the walk cursor reset on restart (the sweep restarts
deterministically from the beginning — coverage, never
freshness, is what a restart loses). Pinned by
`missing_chunk_clears_claim_and_subtracts_size` (clear plus
manifest-sized subtract), `healed_bytes_keep_their_claim`
(re-verify before clear), and
`probe_covers_entries_in_bounded_slices` (bounded slices plus
wrap) (`wyrd-core/src/scrub.rs`). The scrub commits through the
same `DurableStore::commit` path and fact kind
(`ObjectRemoved`) the quarantine matrix
(`crash_matrix_never_hybrid`) already covers, so no second crash
matrix is kept: the windows above name the scrub-specific order
(the re-verify), and the shared commit path carries the rest.

## Unmount teardown

Unmount commits still-dirty handles best-effort before dropping the
handle table, and stops the mailbox, bulk source, and serving endpoint
under bounded deadlines with the fallible outcomes folded into the
exit status (bulk is graceful-or-abort and cannot fail). The
commit executes against the still-open queue on every shutdown
path: the loop returns without settling, the session joins
first (destroy submits while the post-return drain executes
concurrently), admission closes only after the join — the session
join is the submission boundary, so no destroy-time submission can
race the drain's end. The commit still refuses fast with `Shutdown` (and the
loss is logged per path) only for submissions that race the admission
close itself; unmount stays a safety net, not a durability boundary.
Pinned by
`signal_path_shutdown_preserves_dirty_handle`,
`terminal_loop_error_preserves_dirty_handle`,
`teardown_preserves_every_dirty_handle_and_drops_clean`,
`release_after_loop_return_commits_dirty_handle`,
`loop_thread_panic_tears_down_bounded`,
`submissions_racing_admission_close_resolve_bounded`
(`wyrd-daemon/src/core/tests_teardown.rs`),
`loop_return_keeps_queue_open_for_teardown_submits`,
`terminal_loop_error_completes_blocked_submitters`,
`clean_stop_completes_blocked_submitters`
(`wyrd-daemon/src/core/tests_run_loop.rs`),
`loop_return_trips_shutdown_without_settling`
(`wyrd-daemon/src/lifecycle.rs`),
`destroy_commits_dirty_write_handles_while_queue_live`,
`destroy_after_queue_shutdown_clears_without_hanging`
(`wyrd-daemon/src/fuse/tests_backend.rs`),
`close_deadline_reports_a_stalled_close`,
`zero_deadline_trips_a_stalled_stop_but_spares_a_ready_one`,
`graceful_close_inside_the_deadline_reports_finished`, and
`stalled_close_reports_unfinished_inside_a_bound`
(`wyrd-sync/src/close.rs`),
`live_close_returns_past_a_zero_deadline` (`wyrd-sync/src/bulk.rs`),
`live_serving_stop_returns_past_a_zero_deadline` and
`poisoned_mirror_lock_reports_but_still_shuts_down`
(`wyrd-sync/src/serving.rs`), and
`combine_status_reports_transport_shutdown_failures`
(`wyrd-cli/src/tests_cli.rs`).

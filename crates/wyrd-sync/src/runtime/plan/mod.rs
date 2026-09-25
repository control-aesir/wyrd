//! Fetch-plan orchestration for the runtime sync engine.
//!
//! The engine owns durable state and intake. This module owns the repeated
//! reconcile/fetch/commit pass that turns that state into local manifests and
//! objects. The individual fetch validators remain on `Engine` for now so the
//! security-sensitive state access stays explicit during the decomposition.

use wyrd_format::{ObjectStore, SnapshotId};

use super::engine::{Engine, EngineError, ExecuteReport, FetchKey};
use super::fetch::FetchOutcome;
use super::{PendingObjectFetch, RuntimeState};
use crate::bulk::BulkSource;
use crate::control::SnapshotAnnouncement;

/// Look up the announcement a planned body derives from. The plan's
/// pending bodies come from the same projection, so a miss is a
/// reconcile/projection disagreement — an internal bug, not sender
/// data — and fails the pass instead of panicking the process.
fn planned_announcement<'a>(
    runtime: &'a RuntimeState,
    snapshot: &SnapshotId,
) -> Result<&'a SnapshotAnnouncement, EngineError> {
    runtime
        .announcement(snapshot)
        .ok_or(EngineError::AnnouncementUnavailable(*snapshot))
}

/// Execute the current fetch plan to convergence.
pub(super) fn execute(
    engine: &mut Engine,
    bulk: &mut impl BulkSource,
    objects: &mut impl ObjectStore,
) -> Result<ExecuteReport, EngineError> {
    execute_inner(engine, bulk, objects, None)
}

/// The same run under a wall-clock budget: the plan stops starting
/// fetch work once `deadline` passes, and every attempt started before
/// it is capped at the remaining time, so a stalled provider cannot
/// push a caller's timeout decision past its bound. Work not started
/// stays pending and the next run picks it up; the attempt cap is
/// cleared on the way out, including on error.
pub(super) fn execute_sliced(
    engine: &mut Engine,
    bulk: &mut impl BulkSource,
    objects: &mut impl ObjectStore,
    deadline: Option<std::time::Instant>,
) -> Result<ExecuteReport, EngineError> {
    bulk.set_attempt_deadline(deadline);
    let result = execute_inner(engine, bulk, objects, deadline);
    bulk.set_attempt_deadline(None);
    result
}

/// Whether a wall-clock budget is spent: every start point checks, so
/// a run owes at most the one in-flight attempt (itself capped) past
/// the deadline.
fn spent(deadline: Option<std::time::Instant>) -> bool {
    deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline)
}

/// Execute the current fetch plan to convergence, optionally under a
/// wall-clock budget.
fn execute_inner(
    engine: &mut Engine,
    bulk: &mut impl BulkSource,
    objects: &mut impl ObjectStore,
    deadline: Option<std::time::Instant>,
) -> Result<ExecuteReport, EngineError> {
    let mut report = ExecuteReport::default();
    engine.fetch_run += 1;
    loop {
        let rebuilt = engine.store.rebuild(engine.device)?;
        let mut runtime = rebuilt.runtime;
        let keyring = rebuilt.keyring;
        let plan = runtime.reconcile();
        // Items this pass has not yet fulfilled, counted down as work
        // lands: the unfulfilled total covers everything planned and
        // not delivered, whether the run exhausted the plan or stopped
        // at the wall-clock budget.
        let mut remaining = plan.pending_snapshot_bodies.len()
            + plan.pending_snapshots.len()
            + plan.pending_manifests.len()
            + plan.pending_objects.len();
        let mut facts = Vec::new();
        for snapshot in &plan.pending_snapshot_bodies {
            if spent(deadline) {
                report.unfulfilled = remaining;
                return Ok(report);
            }
            // Backoff: a repeatedly invalid body stops being attempted
            // while cooled. Bodies strike by snapshot: the announcement
            // carries only the id.
            let body_key = FetchKey::Body(*snapshot);
            if !engine.fetch_eligible(&body_key) {
                continue;
            }
            match super::fetch::snapshot_body(bulk, &runtime, snapshot) {
                FetchOutcome::Fulfilled(body) => {
                    // The cross-record binding: the body must be the one
                    // the accepted announcement describes. The snapshot
                    // id covers the bytes, but a lying announcement can
                    // still name a real body under wrong metadata — and
                    // that metadata drives manifest-key selection while
                    // the body's own binding drives authorization. Only
                    // an agreeing pair commits; a disagreement is the
                    // sender's invalid data, not a transport failure.
                    let announced = planned_announcement(&runtime, snapshot)?;
                    let agrees = announced.author == body.author
                        && announced.epoch == body.epoch
                        && announced.membership == body.membership;
                    if !agrees {
                        report.invalid += 1;
                        engine.note_fetch_invalid(&body_key);
                        continue;
                    }
                    match crate::durable::AuthorizedSnapshot::authorize(body, &engine.drive) {
                        Ok(authorized) => {
                            // Residency precedes the durable record: the
                            // verified body lands in the serving vault
                            // before the fact commits, so the recorded
                            // snapshot never names a missing body.
                            match engine.vault.import(&authorized.snapshot().encode()) {
                                Ok(_) => {
                                    runtime.record_snapshot_body(authorized.snapshot().clone())?;
                                    facts.push(crate::durable::Fact::SnapshotBody(authorized));
                                    report.snapshot_bodies += 1;
                                    remaining -= 1;
                                    engine.note_fetch_fulfilled(&body_key);
                                }
                                Err(error) => {
                                    // A full or unwritable disk aborts the
                                    // pass; anything else is a local I/O
                                    // condition that never strikes.
                                    if let Some(fatal) = super::fetch::fatal_vault(&error) {
                                        return Err(EngineError::Store(fatal));
                                    }
                                    report.local_failures += 1;
                                }
                            }
                        }
                        Err(_) => {
                            report.invalid += 1;
                            engine.note_fetch_invalid(&body_key);
                        }
                    }
                }
                FetchOutcome::Invalid => {
                    report.invalid += 1;
                    engine.note_fetch_invalid(&body_key);
                }
                FetchOutcome::Missing => report.missing += 1,
                FetchOutcome::UnavailableKey => report.unavailable_keys += 1,
                FetchOutcome::Transport => {
                    report.transport_errors += 1;
                    engine.note_fetch_transport_failure(&body_key);
                }
                FetchOutcome::Local => report.local_failures += 1,
                FetchOutcome::Store(fatal) => return Err(EngineError::Store(fatal)),
            }
        }
        for snapshot in &plan.pending_snapshots {
            if spent(deadline) {
                report.unfulfilled = remaining;
                return Ok(report);
            }
            // Backoff: a repeatedly invalid root stops being attempted
            // while cooled (the snapshot stays pending). Roots strike by
            // snapshot: no storage address exists before the fetch.
            let root_key = FetchKey::Root(*snapshot);
            if !engine.fetch_eligible(&root_key) {
                continue;
            }
            match super::fetch::root(
                &engine.drive,
                bulk,
                &keyring,
                &runtime,
                &engine.vault,
                snapshot,
            ) {
                FetchOutcome::Fulfilled(record) => {
                    runtime.record_manifest(record.clone())?;
                    facts.push(crate::durable::Fact::Manifest(record));
                    report.manifests += 1;
                    remaining -= 1;
                    engine.note_fetch_fulfilled(&root_key);
                }
                FetchOutcome::Invalid => {
                    report.invalid += 1;
                    engine.note_fetch_invalid(&root_key);
                }
                FetchOutcome::Missing => report.missing += 1,
                FetchOutcome::UnavailableKey => report.unavailable_keys += 1,
                FetchOutcome::Transport => {
                    report.transport_errors += 1;
                    engine.note_fetch_transport_failure(&root_key);
                }
                FetchOutcome::Local => report.local_failures += 1,
                FetchOutcome::Store(fatal) => return Err(EngineError::Store(fatal)),
            }
        }
        for (id, link) in &plan.pending_manifests {
            if spent(deadline) {
                report.unfulfilled = remaining;
                return Ok(report);
            }
            // Backoff: a repeatedly invalid child representation is
            // skipped while cooled — no attempt, item stays pending.
            let child_key = FetchKey::Storage(link.storage);
            if !engine.fetch_eligible(&child_key) {
                continue;
            }
            match super::fetch::child(
                &engine.drive,
                bulk,
                &keyring,
                &runtime,
                &engine.vault,
                id,
                link,
            ) {
                FetchOutcome::Fulfilled(record) => {
                    runtime.record_manifest(record.clone())?;
                    facts.push(crate::durable::Fact::Manifest(record));
                    report.manifests += 1;
                    remaining -= 1;
                    engine.note_fetch_fulfilled(&child_key);
                }
                FetchOutcome::Invalid => {
                    report.invalid += 1;
                    engine.note_fetch_invalid(&child_key);
                }
                FetchOutcome::Missing => report.missing += 1,
                FetchOutcome::UnavailableKey => report.unavailable_keys += 1,
                FetchOutcome::Transport => {
                    report.transport_errors += 1;
                    engine.note_fetch_transport_failure(&child_key);
                }
                FetchOutcome::Local => report.local_failures += 1,
                FetchOutcome::Store(fatal) => return Err(EngineError::Store(fatal)),
            }
        }
        for (content, candidates) in &plan.pending_objects {
            if spent(deadline) {
                report.unfulfilled = remaining;
                return Ok(report);
            }
            // Backoff: cooled representations are not attempted. A
            // content with every representation cooled makes no attempt
            // at all — the item just stays pending.
            let eligible: Vec<PendingObjectFetch> = candidates
                .iter()
                .filter(|candidate| engine.fetch_eligible(&FetchKey::Storage(candidate.storage_id)))
                .cloned()
                .collect();
            if eligible.is_empty() {
                continue;
            }
            let attempt = super::fetch::object(
                &engine.drive,
                bulk,
                &keyring,
                objects,
                &engine.vault,
                content,
                &eligible,
            );
            // Strike representations whose bytes arrived and failed
            // validation regardless of the aggregate verdict: a corrupt
            // candidate keeps earning strikes even when a later
            // candidate fulfilled. Transport failures strike on the
            // same ledger (an unreachable route backs off instead of
            // retrying every pass and starving the items behind it).
            // Absent, key-less, and locally-refused candidates never
            // strike: they are not evidence against the representation.
            for storage in &attempt.invalid {
                engine.note_fetch_invalid(&FetchKey::Storage(*storage));
            }
            for storage in &attempt.transport_failed {
                engine.note_fetch_transport_failure(&FetchKey::Storage(*storage));
            }
            match attempt.aggregate {
                FetchOutcome::Fulfilled(()) => {
                    runtime.mark_local_object(*content);
                    facts.push(crate::durable::Fact::LocalObject(*content));
                    report.objects += 1;
                    remaining -= 1;
                    // Only the representation that served valid bytes
                    // clears its backoff state; other candidates keep
                    // their accumulated strikes.
                    if let Some(storage) = attempt.fulfilled {
                        engine.note_fetch_fulfilled(&FetchKey::Storage(storage));
                    }
                }
                FetchOutcome::Invalid => {
                    report.invalid += 1;
                }
                FetchOutcome::Missing => report.missing += 1,
                FetchOutcome::UnavailableKey => report.unavailable_keys += 1,
                FetchOutcome::Transport => report.transport_errors += 1,
                FetchOutcome::Local => report.local_failures += 1,
                FetchOutcome::Store(fatal) => return Err(EngineError::Store(fatal)),
            }
        }

        if facts.is_empty() {
            report.unfulfilled = remaining;
            return Ok(report);
        }
        if let Err(error) = engine.commit_facts(&facts) {
            let _ = engine.resync();
            return Err(error.into());
        }
        // The convergence pass the commits unlocked starts only if the
        // budget allows: stopping here leaves the rest planned and
        // pending for the next run.
        if spent(deadline) {
            report.unfulfilled = remaining;
            return Ok(report);
        }
    }
}

// Plan behavior tests live beside the executor, one file per theme:
// plan execution and convergence, and rejection/byte accounting.
#[cfg(test)]
mod tests_accounting;
#[cfg(test)]
mod tests_execution;

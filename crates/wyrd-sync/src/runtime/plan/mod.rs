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
    let mut report = ExecuteReport::default();
    engine.fetch_run += 1;
    loop {
        let rebuilt = engine.store.rebuild(engine.device)?;
        let mut runtime = rebuilt.runtime;
        let keyring = rebuilt.keyring;
        let plan = runtime.reconcile();
        let mut facts = Vec::new();
        for snapshot in &plan.pending_snapshot_bodies {
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
                FetchOutcome::Transport => report.transport_errors += 1,
                FetchOutcome::Local => report.local_failures += 1,
                FetchOutcome::Store(fatal) => return Err(EngineError::Store(fatal)),
            }
        }
        for snapshot in &plan.pending_snapshots {
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
                    engine.note_fetch_fulfilled(&root_key);
                }
                FetchOutcome::Invalid => {
                    report.invalid += 1;
                    engine.note_fetch_invalid(&root_key);
                }
                FetchOutcome::Missing => report.missing += 1,
                FetchOutcome::UnavailableKey => report.unavailable_keys += 1,
                FetchOutcome::Transport => report.transport_errors += 1,
                FetchOutcome::Local => report.local_failures += 1,
                FetchOutcome::Store(fatal) => return Err(EngineError::Store(fatal)),
            }
        }
        for (id, link) in &plan.pending_manifests {
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
                    engine.note_fetch_fulfilled(&child_key);
                }
                FetchOutcome::Invalid => {
                    report.invalid += 1;
                    engine.note_fetch_invalid(&child_key);
                }
                FetchOutcome::Missing => report.missing += 1,
                FetchOutcome::UnavailableKey => report.unavailable_keys += 1,
                FetchOutcome::Transport => report.transport_errors += 1,
                FetchOutcome::Local => report.local_failures += 1,
                FetchOutcome::Store(fatal) => return Err(EngineError::Store(fatal)),
            }
        }
        for (content, candidates) in &plan.pending_objects {
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
            // candidate fulfilled. Absent, key-less, transport-failed,
            // and locally-refused candidates never strike.
            for storage in &attempt.invalid {
                engine.note_fetch_invalid(&FetchKey::Storage(*storage));
            }
            match attempt.aggregate {
                FetchOutcome::Fulfilled(()) => {
                    runtime.mark_local_object(*content);
                    facts.push(crate::durable::Fact::LocalObject(*content));
                    report.objects += 1;
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
            report.unfulfilled = plan.pending_snapshot_bodies.len()
                + plan.pending_snapshots.len()
                + plan.pending_manifests.len()
                + plan.pending_objects.len();
            return Ok(report);
        }
        if let Err(error) = engine.commit_facts(&facts) {
            let _ = engine.resync();
            return Err(error.into());
        }
    }
}

// Plan behavior tests live beside the executor, one file per theme:
// plan execution and convergence, and rejection/byte accounting.
#[cfg(test)]
mod tests_accounting;
#[cfg(test)]
mod tests_execution;

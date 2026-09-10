//! Fetch-plan orchestration for the runtime sync engine.
//!
//! The engine owns durable state and intake. This module owns the repeated
//! reconcile/fetch/commit pass that turns that state into local manifests and
//! objects. The individual fetch validators remain on `Engine` for now so the
//! security-sensitive state access stays explicit during the decomposition.

use wyrd_format::ObjectStore;

use super::engine::{Engine, EngineError, ExecuteReport};
use super::fetch::FetchOutcome;
use super::PendingObjectFetch;
use crate::bulk::BulkSource;

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

        for snapshot in &plan.pending_snapshots {
            match super::fetch::root(&engine.drive, bulk, &keyring, &runtime, snapshot) {
                FetchOutcome::Fulfilled(record) => {
                    runtime.record_manifest(record.clone())?;
                    facts.push(crate::durable::Fact::Manifest(record));
                    report.manifests += 1;
                }
                FetchOutcome::Missing => report.missing += 1,
                FetchOutcome::Invalid => report.invalid += 1,
                FetchOutcome::UnavailableKey => report.unavailable_keys += 1,
                FetchOutcome::Transport => report.transport_errors += 1,
                FetchOutcome::Local => report.local_failures += 1,
            }
        }
        for (id, link) in &plan.pending_manifests {
            // Backoff: a repeatedly invalid child representation is
            // skipped while cooled — no attempt, item stays pending.
            if !engine.fetch_eligible(&link.storage) {
                continue;
            }
            match super::fetch::child(&engine.drive, bulk, &keyring, &runtime, id, link) {
                FetchOutcome::Fulfilled(record) => {
                    runtime.record_manifest(record.clone())?;
                    facts.push(crate::durable::Fact::Manifest(record));
                    report.manifests += 1;
                    engine.note_fetch_fulfilled(&link.storage);
                }
                FetchOutcome::Invalid => {
                    report.invalid += 1;
                    engine.note_fetch_invalid(&link.storage);
                }
                FetchOutcome::Missing => report.missing += 1,
                FetchOutcome::UnavailableKey => report.unavailable_keys += 1,
                FetchOutcome::Transport => report.transport_errors += 1,
                FetchOutcome::Local => report.local_failures += 1,
            }
        }
        for (content, candidates) in &plan.pending_objects {
            // Backoff: cooled representations are not attempted. A
            // content with every representation cooled makes no attempt
            // at all — the item just stays pending.
            let eligible: Vec<PendingObjectFetch> = candidates
                .iter()
                .filter(|candidate| engine.fetch_eligible(&candidate.storage_id))
                .cloned()
                .collect();
            if eligible.is_empty() {
                continue;
            }
            match super::fetch::object(&engine.drive, bulk, &keyring, objects, content, &eligible) {
                FetchOutcome::Fulfilled(()) => {
                    runtime.mark_local_object(*content);
                    facts.push(crate::durable::Fact::LocalObject(*content));
                    report.objects += 1;
                    for candidate in &eligible {
                        engine.note_fetch_fulfilled(&candidate.storage_id);
                    }
                }
                FetchOutcome::Invalid => {
                    report.invalid += 1;
                    // Every eligible candidate was tried and the worst
                    // outcome was invalid; strike each representation
                    // that participated in the failure.
                    for candidate in &eligible {
                        engine.note_fetch_invalid(&candidate.storage_id);
                    }
                }
                FetchOutcome::Missing => report.missing += 1,
                FetchOutcome::UnavailableKey => report.unavailable_keys += 1,
                FetchOutcome::Transport => report.transport_errors += 1,
                FetchOutcome::Local => report.local_failures += 1,
            }
        }

        if facts.is_empty() {
            report.unfulfilled = plan.pending_snapshots.len()
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

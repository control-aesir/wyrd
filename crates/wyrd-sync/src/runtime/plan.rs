//! Fetch-plan orchestration for the runtime sync engine.
//!
//! The engine owns durable state and intake. This module owns the repeated
//! reconcile/fetch/commit pass that turns that state into local manifests and
//! objects. The individual fetch validators remain on `Engine` for now so the
//! security-sensitive state access stays explicit during the decomposition.

use wyrd_format::ObjectStore;

use super::engine::{Engine, EngineError, ExecuteReport};
use crate::bulk::BulkSource;

/// Execute the current fetch plan to convergence.
pub(super) fn execute(
    engine: &mut Engine,
    bulk: &mut impl BulkSource,
    objects: &mut impl ObjectStore,
) -> Result<ExecuteReport, EngineError> {
    let mut report = ExecuteReport::default();
    loop {
        let rebuilt = engine.store.rebuild(engine.device)?;
        let mut runtime = rebuilt.runtime;
        let keyring = rebuilt.keyring;
        let plan = runtime.reconcile();
        let mut facts = Vec::new();

        for snapshot in &plan.pending_snapshots {
            if let Some(record) = Engine::fetch_root(
                &engine.drive,
                bulk,
                &keyring,
                &runtime,
                snapshot,
                &mut report.transport_errors,
            ) {
                runtime.record_manifest(record.clone())?;
                facts.push(crate::durable::Fact::Manifest(record));
                report.manifests += 1;
            }
        }
        for (id, link) in &plan.pending_manifests {
            if let Some(record) = Engine::fetch_child(
                &engine.drive,
                bulk,
                &keyring,
                &runtime,
                id,
                link,
                &mut report.transport_errors,
            ) {
                runtime.record_manifest(record.clone())?;
                facts.push(crate::durable::Fact::Manifest(record));
                report.manifests += 1;
            }
        }
        for (content, candidates) in &plan.pending_objects {
            if Engine::fetch_object(
                &engine.drive,
                bulk,
                &keyring,
                objects,
                content,
                candidates,
                &mut report.transport_errors,
            ) {
                runtime.mark_local_object(*content);
                facts.push(crate::durable::Fact::LocalObject(*content));
                report.objects += 1;
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

//! Snapshot authoring: merges, recovery, the live-head projection, and the single-rebuild write session.

use std::collections::HashSet;

use wyrd_format::{ContentId, ObjectStore, SnapshotId};

use crate::durable::AuthorizeSnapshot;
use crate::durable::{AuthorizedSnapshot, Rebuilt};

use super::super::author;
use super::{Engine, EngineError, PendingWrite, SnapshotHead};

impl Engine {
    /// Merge explicit snapshot heads into one snapshot: the
    /// deterministic merged tree over the selected heads plus the
    /// merge spec (`Take` one head's version per conflicted root
    /// path, or drop it), parented onto exactly the selected heads.
    /// Heads must be current eligible heads (at least two); paths
    /// the heads agree on are taken automatically and conflicted
    /// paths need a spec line or the default. Ordinary member
    /// authority, current epoch, existing announcement outbox — no
    /// membership change. See [`author::merge`].
    pub fn merge_heads<S: ObjectStore>(
        &mut self,
        objects: &mut S,
        heads: Vec<SnapshotId>,
        default: Option<SnapshotId>,
        spec: std::collections::BTreeMap<String, author::MergeSelection>,
    ) -> Result<AuthorizedSnapshot, EngineError>
    where
        S::Error: std::fmt::Debug,
    {
        author::merge(self, objects, heads, default, spec)
    }

    /// Plan a merge over explicit snapshot heads without authoring
    /// anything: the per-path classification a resolver shows the
    /// user before they select. Read-only; shares the
    /// classification [`merge_heads`] validates against, so a
    /// future graphical resolver consumes this instead of
    /// reimplementing it. See [`author::merge`].
    ///
    /// [`merge_heads`]: Engine::merge_heads
    pub fn merge_plan<S: ObjectStore>(
        &self,
        objects: &S,
        heads: Vec<SnapshotId>,
    ) -> Result<author::MergePlan, EngineError>
    where
        S::Error: std::fmt::Debug,
    {
        author::plan_merge(self, objects, heads)
    }

    /// Preview a merge over explicit source heads with a full spec:
    /// every check [`merge_heads`] applies before authoring, minus
    /// the authoring. Read-only; the `--dry-run` front end shows
    /// the returned plan instead of committing. A preview that
    /// passes predicts the commit's pre-authoring verdict on stable
    /// state — the commit still re-runs every gate itself, so bytes
    /// that leave between preview and commit fail the commit, never
    /// slip through.
    ///
    /// [`merge_heads`]: Engine::merge_heads
    pub fn merge_preview<S: ObjectStore>(
        &self,
        objects: &S,
        heads: Vec<SnapshotId>,
        default: Option<SnapshotId>,
        spec: &std::collections::BTreeMap<String, author::MergeSelection>,
    ) -> Result<author::MergePlan, EngineError>
    where
        S::Error: std::fmt::Debug,
    {
        author::preview_merge(self, objects, heads, default, spec).map(|(plan, _)| plan)
    }

    /// Plan a recovery over one source snapshot without authoring
    /// anything: the per-path status a dry run shows before the
    /// operator selects. Read-only; shares the classification
    /// [`recover`] validates against. See
    /// [`author::recover`].
    ///
    /// [`recover`]: Engine::recover
    pub fn recovery_plan<S: ObjectStore>(
        &self,
        objects: &S,
        from: SnapshotId,
    ) -> Result<author::RecoveryPlan, EngineError>
    where
        S::Error: std::fmt::Debug,
    {
        author::plan_recovery(self, objects, from)
    }

    /// Preview a recovery over one source snapshot with a full
    /// selection: every check [`recover`] applies before
    /// authoring, minus the authoring and minus the owner gate
    /// (previewing reads history any keystore holder can read;
    /// only authoring needs the owner). Read-only; the `--dry-run`
    /// front end shows the plan plus the graft names instead of
    /// committing. Same staleness note as [`merge_preview`]: the
    /// commit re-runs every gate itself.
    ///
    /// [`recover`]: Engine::recover
    /// [`merge_preview`]: Engine::merge_preview
    pub fn recovery_preview<S: ObjectStore>(
        &self,
        objects: &S,
        from: SnapshotId,
        takes: &[String],
        all: bool,
        contents: &[ContentId],
    ) -> Result<author::RecoveryPreview, EngineError>
    where
        S::Error: std::fmt::Debug,
    {
        author::preview_recovery(self, objects, from, takes, all, contents)
            .map(|(preview, _)| preview)
    }

    /// Recover selected source rows into a recovery-flagged
    /// snapshot: the deterministic graft tree over the selection,
    /// parented onto the current eligible heads by the current
    /// canonical owner. Takes name source root paths (root-entry
    /// granularity, like the merge spec), `all` takes the whole
    /// source tree, and `contents` grafts explicitly named content
    /// ids the operator no longer knows a path for. See
    /// [`author::recover`].
    pub fn recover<S: ObjectStore>(
        &mut self,
        objects: &mut S,
        from: SnapshotId,
        takes: &[String],
        all: bool,
        contents: &[ContentId],
    ) -> Result<AuthorizedSnapshot, EngineError>
    where
        S::Error: std::fmt::Debug,
    {
        author::recover(self, objects, from, takes, all, contents)
    }

    /// The classified live-head projection: the verified snapshot bodies
    /// the authorization engine currently marks `Eligible` — live-lineage
    /// DAG heads at the current epoch (`docs/epochs.md`). Built from
    /// durable snapshot-body facts and the membership log, so it survives
    /// restarts; backends install exactly this set as the view's heads.
    /// Everything else in the DAG is retained history and never advances
    /// the live view. Each head is re-verified on the way out, so the
    /// projection is typed as `AuthorizedSnapshot`: durable bytes that
    /// no longer verify fail the projection instead of reaching a view.
    ///
    /// `EngineError::InvalidHead` is a defense-in-depth invariant
    /// failure, not the primary durable-corruption path: classification
    /// verifies every observed body before it can become eligible, so
    /// this re-authorization repeats the same check over the same bytes
    /// while constructing the typed value. A failure here means an
    /// internal invariant broke, not that a new corruption flavor was
    /// detected.
    ///
    /// Calls at an unchanged durable tip re-serve the memoized
    /// projection instead of replaying history (see the
    /// `live_heads_cache` field).
    pub fn live_heads(&self) -> Result<Vec<AuthorizedSnapshot>, EngineError> {
        let tip = self.store.current();
        if let Ok(guard) = self.live_heads_cache.lock() {
            if let Some((cached_tip, heads)) = guard.as_ref() {
                if *cached_tip == tip {
                    return Ok(heads.clone());
                }
            }
        }
        let (_, heads) = self.rebuild_eligible_heads()?;
        if let Ok(mut guard) = self.live_heads_cache.lock() {
            *guard = Some((tip, heads.clone()));
        }
        Ok(heads)
    }

    /// One durable rebuild plus DAG classification, shared by every
    /// reader that names the eligible heads: the rebuild replays the
    /// same facts each projection replays, so sharing the helper keeps
    /// the classification identical everywhere without duplicating the
    /// observe loop.
    fn rebuild_eligible_heads(&self) -> Result<(Rebuilt, Vec<AuthorizedSnapshot>), EngineError> {
        let rebuilt = self.store.rebuild(self.device)?;
        let mut dag = crate::authorization::SnapshotDag::new(self.drive);
        for body in rebuilt.runtime.snapshot_bodies.values() {
            dag.observe(body.clone());
        }
        let heads = dag
            .eligible_head_bodies(&rebuilt.log)
            .into_iter()
            .map(|snapshot| {
                AuthorizedSnapshot::authorize(snapshot, &self.drive)
                    .map_err(EngineError::InvalidHead)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok((rebuilt, heads))
    }

    /// Capture a write session: one rebuild, one classification. The
    /// write path calls this once, mutates the object store over
    /// [`PendingWrite::base_tree`], then authors with
    /// [`Engine::author_pending_write`] — no second rebuild between.
    pub fn begin_write(&self) -> Result<PendingWrite, EngineError> {
        let (rebuilt, heads) = self.rebuild_eligible_heads()?;
        Ok(PendingWrite { rebuilt, heads })
    }

    /// Author a new snapshot over `tree` inside `pending`, reusing its
    /// rebuild instead of replaying durable state again. Parents are
    /// the session's eligible heads — selected by the engine, never
    /// by the caller — and every check [`author_snapshot`] applies
    /// still applies, over the same rebuilt state. A session naming
    /// several heads fails closed: use the merge API to resolve first.
    ///
    /// [`author_snapshot`]: Engine::author_snapshot
    pub fn author_pending_write<S: ObjectStore>(
        &mut self,
        objects: &S,
        tree: ContentId,
        pending: PendingWrite,
    ) -> Result<AuthorizedSnapshot, EngineError>
    where
        S::Error: std::fmt::Debug,
    {
        if pending.heads.len() > 1 {
            return Err(EngineError::WriteConflicted {
                heads: pending.heads.len(),
            });
        }
        let parents = pending
            .heads
            .iter()
            .map(|head| head.snapshot().snapshot_id())
            .collect();
        author::author_over(self, objects, tree, parents, pending.rebuilt, 0)
    }

    /// The live heads as of a past epoch, over the currently
    /// recorded bodies. The one caller is admission resume: after
    /// the admission commit advances the tip, the current projection
    /// no longer sees the pre-admission closure, so resume pins the
    /// horizon to the pre-admission tip's epoch (see
    /// `authorization::classify_at_epoch`). Same verification gate
    /// as [`Engine::live_heads`]: durable facts carry verified
    /// bodies only.
    pub fn live_heads_at_epoch(&self, epoch: u64) -> Result<Vec<AuthorizedSnapshot>, EngineError> {
        let rebuilt = self.store.rebuild(self.device)?;
        let mut dag = crate::authorization::SnapshotDag::new(self.drive);
        for body in rebuilt.runtime.snapshot_bodies.values() {
            dag.observe(body.clone());
        }
        dag.eligible_heads_at_epoch(&rebuilt.log, epoch)
            .into_iter()
            .filter_map(|id| dag.snapshot(&id).cloned())
            .map(|snapshot| {
                AuthorizedSnapshot::authorize(snapshot, &self.drive)
                    .map_err(EngineError::InvalidHead)
            })
            .collect()
    }

    /// One DAG head with its authorization classification: the
    /// inspection basis for merges. Only [`Eligible`] heads may
    /// advance the live view or serve as merge sources; every other
    /// class is retained history with its reason attached. Sorted
    /// ascending by id, like every other head listing.
    ///
    /// [`Eligible`]: crate::authorization::Classification::Eligible
    pub fn snapshot_heads(&self) -> Result<Vec<SnapshotHead>, EngineError> {
        // One rebuild for the listing and the live projection alike:
        // the eligible set below is byte-for-byte what `live_heads`
        // would compute at this tip, so warming its memo here lets a
        // following `live_heads` serve from memory instead of
        // replaying history again. Non-eligible rows still carry
        // their reason with no author/tree detail — verified heads
        // only, as before.
        let (rebuilt, eligible) = self.rebuild_eligible_heads()?;
        let tip = self.store.current();
        if let Ok(mut guard) = self.live_heads_cache.lock() {
            *guard = Some((tip, eligible));
        }
        let mut dag = crate::authorization::SnapshotDag::new(self.drive);
        for body in rebuilt.runtime.snapshot_bodies.values() {
            dag.observe(body.clone());
        }
        let live: HashSet<SnapshotId> = dag.heads().into_iter().collect();
        // Heads join their bodies for the epoch: a head without its
        // body is dropped, never listed with a guessed epoch — the
        // safe direction, matching the eligible-head projection.
        let mut heads: Vec<SnapshotHead> = dag
            .classify(&rebuilt.log)
            .into_iter()
            .filter(|(id, _)| live.contains(id))
            .filter_map(|(id, classification)| {
                let body = rebuilt.runtime.snapshot_bodies.get(&id)?;
                Some(SnapshotHead {
                    id,
                    classification,
                    epoch: body.epoch,
                    flags: body.flags(),
                })
            })
            .collect();
        heads.sort_by_key(|head| head.id);
        Ok(heads)
    }

    /// Author a new snapshot over `tree`, signed by this device and bound
    /// to the canonical membership state. `objects` is the plaintext
    /// object store the drive materializes from; the root must be a
    /// canonical tree object present there whose bytes hash back to
    /// `tree`, so a snapshot whose root is absent or misaddressed is
    /// refused before it is bound. Descendant trees and chunks are not
    /// required to be local: materialization is local policy, and a
    /// member may author a snapshot reusing content it does not hold.
    /// Parents are the current eligible heads: a single-head drive
    /// extends its live state, and a conflicted drive resolves onto every
    /// head (`docs/epochs.md`, local write; `docs/object-model.md`,
    /// resolution). The body is verified once and committed durably; the
    /// live-head projection picks it up on the next rebuild. Fails closed
    /// when the root is unavailable or misaddressed, the log has no
    /// canonical tip, or this device is not a member of it.
    pub fn author_snapshot<S: ObjectStore>(
        &mut self,
        objects: &S,
        tree: ContentId,
    ) -> Result<AuthorizedSnapshot, EngineError>
    where
        S::Error: std::fmt::Debug,
    {
        author::author(self, objects, tree)
    }

    /// Author a recovery snapshot over `tree`, signed by this device
    /// and bound to the canonical membership state. `tree` is
    /// explicitly selected historical content — a recorded ContentId
    /// the owner chose to republish, never live-derived lineage —
    /// while the parents are always the current eligible heads, so a
    /// recovery grafts bytes without adopting a dead fork. The body
    /// carries the recovery flag under the signature
    /// (`docs/epochs.md`, recovery snapshots). Only the current
    /// canonical owner may recover; anyone else fails closed with
    /// [`EngineError::RecoveryNotOwner`]. Fails closed like
    /// [`Engine::author_snapshot`] otherwise.
    ///
    /// Milestone note: the content-recovery creation workflow is
    /// deferred to v0.3 (see `ROADMAP.md`), so v0.2 ships no operator
    /// surface for this method — no CLI command or daemon entry point
    /// calls it. It stays public because `wyrd-contracts` pins the
    /// normative grafting rule end to end from outside this crate.
    pub fn author_recovery_snapshot<S: ObjectStore>(
        &mut self,
        objects: &S,
        tree: ContentId,
    ) -> Result<AuthorizedSnapshot, EngineError>
    where
        S::Error: std::fmt::Debug,
    {
        author::author_recovery(self, objects, tree)
    }
}

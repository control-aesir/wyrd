//! Fold and force, with the taken-handle bookkeeping types.

use std::sync::{Arc, Mutex};

use fuser::FileHandle;

use wyrd_core::mutation::{
    FileIdentity, FoldDisposition, FoldForcerOutcome, FoldMember, MutationError, MutationKind,
    MutationOutcome, MutationQueue,
};

use wyrd_core::session::FoldLease;

use wyrd_format::ObjectStore;
use wyrd_fuse::{Materialization, ViewError};

use super::super::inode::{Handle, WriteHandle};
use super::{log_budget_refusal, log_refused, mutation_errno, FuseBackend};

/// One taken dirty buffer: the fold detached the image under the
/// handle's lock and parked writers on `fold_wake` until it settles
/// the handle, so no concurrent write is lost between the take and
/// the re-pin.
pub(super) struct TakenMember {
    pub(super) handle: Arc<Mutex<WriteHandle>>,
    /// First-in-first-buffered order: members apply by this stamp.
    pub(super) seq: u64,
    pub(super) path: String,
    pub(super) base: FileIdentity,
    pub(super) executable: bool,
    pub(super) append: bool,
    pub(super) content: Vec<u8>,
}

/// What owns a fold's forcing privilege: a dirty handle's own commit
/// (its taken buffer carries the privilege), a namespace operation's
/// own syscall, or nothing (shutdown: no privilege, per-member
/// best-effort, no abort).
enum FoldSubmitForcer {
    Handle(Arc<Mutex<WriteHandle>>),
    Op(MutationKind),
    None,
}

/// One submitted fold run: one queue member settling one or more
/// taken handles. Same-path append sequences merge into their
/// earliest run, so sequential appends concatenate instead of
/// contending. The queue kind lives only in the submitted `members`
/// (built once, inline); the run keeps the taken positions and the
/// forcing flag the settle needs.
struct SubmitMember {
    /// Taken handles behind this run, in buffering order.
    taken: Vec<usize>,
    forcer: bool,
}

/// Which dirty handles one gather leaves pending: namespace
/// operations rebind the paths they touch, so content buffered for
/// those paths stays for its own later boundary (resolving stale
/// like today) instead of entangling its base with the rebinding —
/// while every other dirty handle folds. A handle whose path no
/// longer resolves is likewise left alone: it is already stale, and
/// folding it now would only fail it early. The forcing handle
/// itself is never filtered: its syscall reports its own outcome.
pub(super) struct GatherFilter<'a> {
    /// Paths the operation rebinds or destroys; writers there stay.
    pub(super) skip_paths: &'a [String],
    /// Leave already-stale (unresolvable) writers pending.
    pub(super) exclude_absent: bool,
    /// The forcing handle: always taken when dirty.
    pub(super) own: Option<&'a Arc<Mutex<WriteHandle>>>,
}

/// The queue kind for one taken buffer: an append sequence commits
/// onto the current end with no base comparison, anything else
/// commits its full image against its base.
fn taken_kind(taken: &TakenMember) -> MutationKind {
    if taken.append {
        MutationKind::AppendFile {
            path: taken.path.clone(),
            content: taken.content.clone(),
        }
    } else {
        MutationKind::CommitFile {
            path: taken.path.clone(),
            base: taken.base.clone(),
            executable: taken.executable,
            content: taken.content.clone(),
        }
    }
}

/// The applied outcome behind a winning disposition, for settling a
/// taken handle onto its committed state. Called only for applied
/// dispositions — the caller discriminates first — so a failed or
/// restored disposition here is a contract break and fails closed as
/// `None` instead of inventing a success to settle onto.
fn disposition_outcome(disposition: &FoldDisposition) -> Option<MutationOutcome> {
    match disposition {
        FoldDisposition::Committed(identity) => Some(MutationOutcome::Committed(identity.clone())),
        FoldDisposition::Created(identity) => Some(MutationOutcome::Created(identity.clone())),
        FoldDisposition::Done => Some(MutationOutcome::Done),
        FoldDisposition::Failed(_) | FoldDisposition::Restored => None,
    }
}

/// Settle one taken handle onto its applied outcome: advance the base
/// to the committed identity, refresh the capture, drop the dirty
/// mark, and release the budget. A missed capture re-pin is terminal,
/// like the single-handle commit before it: a clean handle with a
/// pre-commit capture next to a post-commit base would serve stale
/// bytes on reads and materialize them into the next write, so the
/// handle is failed closed instead.
fn settle_applied<S: ObjectStore, M: Materialization>(
    backend: &FuseBackend<S, M>,
    taken: &TakenMember,
    outcome: &MutationOutcome,
) -> Result<(), fuser::Errno>
where
    S::Error: std::fmt::Debug,
{
    // Resolve the capture before taking the handle lock: the
    // projection is an immutable snapshot, so this nests no locks.
    let capture = backend.capture_for(&taken.path);
    let mut write = taken.handle.lock().map_err(|_| fuser::Errno::EIO)?;
    match outcome {
        MutationOutcome::Committed(identity) | MutationOutcome::Created(identity) => {
            write.executable = identity.executable();
            write.base = identity.clone();
        }
        MutationOutcome::Done => {}
        MutationOutcome::Fold { .. } => {
            // Applied outcomes are never folds; fail closed and loud.
            tracing::error!("settle got a fold outcome for an applied member");
            write.failed = true;
            write.dirty = false;
            write.inflight = None;
            backend.budget.release(write.id);
            backend.fold_wake.notify_all();
            return Err(fuser::Errno::EIO);
        }
    }
    match capture {
        Ok(capture) => {
            write.capture = capture;
            write.dirty = false;
            write.inflight = None;
            backend.budget.release(write.id);
            backend.fold_wake.notify_all();
            Ok(())
        }
        Err(error) => {
            tracing::debug!(
                path = taken.path.as_str(),
                ?error,
                "settle could not re-pin the committed handle; failing it closed"
            );
            write.failed = true;
            write.dirty = false;
            write.inflight = None;
            backend.budget.release(write.id);
            backend.fold_wake.notify_all();
            Err(error)
        }
    }
}

/// Settle one taken handle as failed: terminal, overlay discarded,
/// budget released — like any refused single commit.
fn settle_failed<S: ObjectStore, M: Materialization>(
    backend: &FuseBackend<S, M>,
    taken: &TakenMember,
) where
    S::Error: std::fmt::Debug,
{
    if let Ok(mut write) = taken.handle.lock() {
        write.failed = true;
        write.dirty = false;
        write.inflight = None;
        backend.budget.release(write.id);
    }
    backend.fold_wake.notify_all();
}

/// Settle one taken handle as restored: its image goes back and it
/// stays dirty and retryable for its own forcing event. The budget
/// was never released, so the reservation still covers the image.
fn settle_restored<S: ObjectStore, M: Materialization>(
    backend: &FuseBackend<S, M>,
    taken: &TakenMember,
) where
    S::Error: std::fmt::Debug,
{
    if let Ok(mut write) = taken.handle.lock() {
        write.image = Some(taken.content.clone());
        write.dirty = true;
        write.inflight = None;
    }
    backend.fold_wake.notify_all();
}

impl<S: ObjectStore, M: Materialization> FuseBackend<S, M>
where
    S::Error: std::fmt::Debug,
{
    /// Whether `path` resolves in the served view: a writer whose
    /// path is gone is already stale, whatever its base says. Lookup
    /// failures other than absence (and a broken projection) include
    /// rather than exclude — the loop decides those closed.
    pub(super) fn path_resolves(&self, path: &str) -> bool {
        let Ok(projection) = self.projection() else {
            return true;
        };
        !matches!(projection.view().lookup(path), Err(ViewError::NotFound))
    }

    /// The paths one operation rebinds or destroys: writers buffered
    /// for these stay pending for their own boundary instead of
    /// folding into the rebinding. Only exact paths are excluded — a
    /// writer under a renamed source still folds pre-rename and rides
    /// the subtree to the new path (its handle goes terminal at
    /// settle), per the rename contract in `docs/write-path.md`. A
    /// truncating `setattr` rebinds nothing — its same-path writers
    /// fold and lose the tie, per the write-path contract — so it
    /// filters no path.
    fn forcer_skip_paths(kind: &MutationKind) -> Vec<String> {
        match kind {
            MutationKind::Mkdir { path }
            | MutationKind::Unlink { path }
            | MutationKind::Rmdir { path }
            | MutationKind::CreateFile { path, .. } => vec![path.clone()],
            MutationKind::Rename { from, to, .. } => vec![from.clone(), to.clone()],
            _ => Vec::new(),
        }
    }

    /// Account a fold's transient submission memory before it is
    /// submitted: the queue kinds clone the taken images, so the
    /// fold's footprint is ~2× the taken bytes while in flight. On
    /// refusal every taken image is restored and the fold reports
    /// `ENOSPC` — memory pressure, retryable, with all handles
    /// unchanged — instead of submitting unaccounted. The lease lives
    /// until the settle completes.
    fn lease_fold(&self, taken: &[TakenMember]) -> Result<FoldLease<'_>, fuser::Errno> {
        let bytes = taken.iter().map(|taken| taken.content.len()).sum();
        self.budget.reserve_fold(bytes).map_err(|error| {
            log_budget_refusal("fold-lease", error);
            for taken in taken {
                settle_restored(self, taken);
            }
            fuser::Errno::ENOSPC
        })
    }

    /// Submit one fold over taken members: the non-forcing members in
    /// buffering order, then the operation forcer last (it buffered at
    /// submit time), or the handle forcer inline at its own buffering
    /// position. Same-path append sequences merge into their earliest
    /// run in FIFO order — sequential appends concatenate, so one
    /// member carries their concatenation and every merged handle
    /// settles from its disposition. Returns the loop's raw outcome
    /// plus the submitted runs; settling happens in
    /// [`settle_fold`](Self::settle_fold).
    fn run_fold(
        &self,
        queue: &Arc<MutationQueue>,
        taken: &[TakenMember],
        forcer: &FoldSubmitForcer,
    ) -> (Result<MutationOutcome, MutationError>, Vec<SubmitMember>) {
        let forcer_taken = match forcer {
            FoldSubmitForcer::Handle(handle) => taken
                .iter()
                .position(|taken| Arc::ptr_eq(&taken.handle, handle)),
            _ => None,
        };
        let mut submitted: Vec<SubmitMember> = Vec::with_capacity(taken.len() + 1);
        let mut members: Vec<FoldMember> = Vec::with_capacity(taken.len() + 1);
        // Open append run per path, by submitted position.
        let mut runs: Vec<(String, usize)> = Vec::new();
        for (index, taken) in taken.iter().enumerate() {
            let is_forcer = Some(index) == forcer_taken;
            if taken.append {
                if let Some((_, pos)) = runs.iter().find(|(path, _)| *path == taken.path) {
                    let pos = *pos;
                    if let FoldMember {
                        kind: MutationKind::AppendFile { content, .. },
                        ..
                    } = &mut members[pos]
                    {
                        content.extend_from_slice(&taken.content);
                    }
                    submitted[pos].taken.push(index);
                    submitted[pos].forcer |= is_forcer;
                    members[pos].forcer |= is_forcer;
                    continue;
                }
            }
            let pos = submitted.len();
            if taken.append {
                runs.push((taken.path.clone(), pos));
            }
            submitted.push(SubmitMember {
                taken: vec![index],
                forcer: is_forcer,
            });
            members.push(FoldMember {
                kind: taken_kind(taken),
                forcer: is_forcer,
            });
        }
        if let FoldSubmitForcer::Op(kind) = forcer {
            submitted.push(SubmitMember {
                taken: Vec::new(),
                forcer: true,
            });
            members.push(FoldMember {
                kind: kind.clone(),
                forcer: true,
            });
        }
        // The engine settles by position and reads privilege off the
        // queue member, while the daemon reads it off the run: the two
        // bits must agree, and the merge arm above is the only place
        // that writes both.
        debug_assert_eq!(
            submitted.iter().map(|run| run.forcer).collect::<Vec<_>>(),
            members
                .iter()
                .map(|member| member.forcer)
                .collect::<Vec<_>>(),
            "submitter and queue views of fold privilege agree"
        );
        (queue.submit(MutationKind::Fold { members }), submitted)
    }

    /// Settle taken handles from the loop's fold outcome: winners
    /// re-pin onto the committed identity, losers go terminal, and
    /// restored members get their image back and stay dirty. Merged
    /// append runs settle every merged handle from the run's
    /// disposition. A channel failure (the fold never ran) fails every
    /// taken handle closed like a refused single commit. Returns the
    /// forcer's outcome for the forcing syscall plus one committed
    /// flag per taken path, in take order, for best-effort logging.
    fn settle_fold(
        &self,
        taken: &[TakenMember],
        submitted: &[SubmitMember],
        forcer: &FoldSubmitForcer,
        result: Result<MutationOutcome, MutationError>,
    ) -> (Result<MutationOutcome, fuser::Errno>, Vec<(String, bool)>) {
        let fail_all = |taken: &[TakenMember]| {
            for taken in taken {
                settle_failed(self, taken);
            }
            taken
                .iter()
                .map(|taken| (taken.path.clone(), false))
                .collect::<Vec<_>>()
        };
        // Settle every taken handle behind one submitted run from the
        // run's disposition. Every handle settles — no short-circuit —
        // and the run counts as committed only when all of them do.
        let settle_run =
            |taken: &[TakenMember], run: &SubmitMember, disposition: &FoldDisposition| {
                let mut committed = true;
                for index in &run.taken {
                    let taken = &taken[*index];
                    let settled = match disposition {
                        FoldDisposition::Committed(_)
                        | FoldDisposition::Created(_)
                        | FoldDisposition::Done => {
                            match disposition_outcome(disposition) {
                                Some(outcome) => settle_applied(self, taken, &outcome).is_ok(),
                                // Unreachable: discriminated above, but
                                // a contract break must fail the handle
                                // rather than settle it onto nothing.
                                None => {
                                    tracing::error!(
                                        "settle got a non-applied disposition on the applied path"
                                    );
                                    settle_failed(self, taken);
                                    false
                                }
                            }
                        }
                        FoldDisposition::Failed(_) => {
                            settle_failed(self, taken);
                            false
                        }
                        FoldDisposition::Restored => {
                            settle_restored(self, taken);
                            false
                        }
                    };
                    committed &= settled;
                }
                committed
            };
        match result {
            Err(error) => {
                log_refused(&error);
                let errno = mutation_errno(&error);
                let summary = fail_all(taken);
                (Err(errno), summary)
            }
            Ok(MutationOutcome::Fold {
                forcer: forcer_outcome,
                members,
            }) => {
                let expect = submitted.iter().filter(|run| !run.forcer).count();
                if members.len() != expect {
                    tracing::error!(
                        expected = expect,
                        got = members.len(),
                        "fold disposition count mismatch; failing every taken handle closed"
                    );
                    let summary = fail_all(taken);
                    return (Err(fuser::Errno::EIO), summary);
                }
                let mut member_iter = members.into_iter();
                let mut summary = Vec::with_capacity(taken.len());
                for run in submitted {
                    if run.forcer {
                        continue;
                    }
                    let Some(disposition) = member_iter.next() else {
                        for index in &run.taken {
                            settle_failed(self, &taken[*index]);
                            summary.push((taken[*index].path.clone(), false));
                        }
                        continue;
                    };
                    let committed = settle_run(taken, run, &disposition);
                    for index in &run.taken {
                        summary.push((taken[*index].path.clone(), committed));
                    }
                }
                match (forcer, forcer_outcome) {
                    (FoldSubmitForcer::Handle(_), FoldForcerOutcome::Applied(outcome)) => {
                        if let Some(run) = submitted.iter().find(|run| run.forcer) {
                            // A settle failure already failed the handle
                            // closed; report its errno instead of a
                            // success the handle cannot honor.
                            let mut settled = true;
                            let mut settle_error = fuser::Errno::EIO;
                            for index in &run.taken {
                                if let Err(error) = settle_applied(self, &taken[*index], &outcome) {
                                    settled = false;
                                    settle_error = error;
                                }
                            }
                            if !settled {
                                return (Err(settle_error), summary);
                            }
                        }
                        (Ok(*outcome), summary)
                    }
                    (FoldSubmitForcer::Handle(_), FoldForcerOutcome::Failed(error)) => {
                        log_refused(&error);
                        let errno = mutation_errno(&error);
                        if let Some(run) = submitted.iter().find(|run| run.forcer) {
                            for index in &run.taken {
                                settle_failed(self, &taken[*index]);
                            }
                        }
                        (Err(errno), summary)
                    }
                    (_, FoldForcerOutcome::Applied(outcome)) => (Ok(*outcome), summary),
                    (_, FoldForcerOutcome::Failed(error)) => {
                        log_refused(&error);
                        (Err(mutation_errno(&error)), summary)
                    }
                }
            }
            Ok(other) => {
                // The loop answered a fold with a non-fold outcome:
                // contract break, fail everything closed and loud.
                tracing::error!(outcome = ?other, "fold answered with a non-fold outcome");
                let summary = fail_all(taken);
                (Err(fuser::Errno::EIO), summary)
            }
        }
    }

    /// The earliest-buffered dirty handle on `path`, if any: the
    /// delegate a clean `fsync` forces through. Clones arcs under the
    /// table lock, then inspects handles one at a time — never nested,
    /// never with the table held. Handles taken by a concurrent fold
    /// stay eligible: delegating to one parks on its settle inside
    /// [`force_handle`](Self::force_handle) instead of returning
    /// before the path is durable.
    ///
    /// Idle `fsync` stays O(1): a zero dirty-handle count means no
    /// handle holds a budget reservation, and a reservation is held
    /// exactly while its handle is dirty, so there is nothing on any
    /// path to delegate to.
    fn earliest_dirty_on(&self, path: &str) -> Option<Arc<Mutex<WriteHandle>>> {
        if self.budget.dirty_handles() == 0 {
            return None;
        }
        let arcs: Vec<Arc<Mutex<WriteHandle>>> = {
            let Ok(files) = self.files.lock() else {
                return None;
            };
            files
                .by_handle
                .values()
                .filter_map(|handle| match handle {
                    Handle::Write(write) => Some(Arc::clone(write)),
                    Handle::Read(_) => None,
                })
                .collect()
        };
        let mut best: Option<(u64, Arc<Mutex<WriteHandle>>)> = None;
        for arc in &arcs {
            let Ok(write) = arc.lock() else {
                continue;
            };
            if !write.dirty || write.failed || write.path != path {
                continue;
            }
            let replace = best.as_ref().is_none_or(|(seq, _)| write.dirty_seq < *seq);
            if replace {
                best = Some((write.dirty_seq, Arc::clone(arc)));
            }
        }
        best.map(|(_, arc)| arc)
    }

    /// Path-scoped durability boundary: `fsync`/`fdatasync` on any
    /// descriptor of a path with pending data makes that path's data
    /// durable (DG-1 rule 3), unlike `flush`, which only ever commits
    /// the calling handle's own bytes. A dirty caller folds like
    /// [`force_handle`](Self::force_handle); a clean caller delegates
    /// to the earliest dirty handle on its path, so the fold still
    /// carries a genuine forcer — real bytes, real privilege, genuine
    /// abort semantics. A path with no pending data anywhere commits
    /// nothing.
    fn force_path(&self, handle: &Arc<Mutex<WriteHandle>>) -> Result<(), fuser::Errno> {
        if self.mutations.is_none() {
            return Err(fuser::Errno::EROFS);
        }
        loop {
            let path = {
                let write = handle.lock().map_err(|_| fuser::Errno::EIO)?;
                let write = self.wait_inflight(write)?;
                if write.failed {
                    return Err(fuser::Errno::EIO);
                }
                if write.dirty {
                    drop(write);
                    return self.force_handle(handle);
                }
                write.path.clone()
            };
            match self.earliest_dirty_on(&path) {
                // Nothing pending on this path: a committing boundary
                // with no pending data commits nothing.
                None => return Ok(()),
                Some(other) => {
                    // The delegate's error is this path's error too:
                    // its fold is what would have made the path
                    // durable, and it did not happen.
                    self.force_handle(&other)?;
                }
            }
        }
    }

    /// Path-scoped commit for `fsync`/`fdatasync`: folds the calling
    /// path's pending data durable even when the calling handle itself
    /// is clean. Read descriptors have no path to scope to and commit
    /// nothing, as before.
    pub fn fsync_handle(&self, fh: FileHandle) -> Result<(), fuser::Errno> {
        match self.handle_of(fh)? {
            Handle::Read(_) => Ok(()),
            Handle::Write(handle) => self.force_path(&handle),
        }
    }

    /// Fold a writable handle's own bytes durable: gather its image
    /// plus every other dirty image, submit one fold, and settle. A
    /// concurrent fold that takes our image first is awaited, then
    /// the state is re-read: clean means durable, dirty means ours to
    /// fold. Mirrors the old single-handle commit's reporting: only a
    /// committed content outcome succeeds, anything else is terminal.
    pub(super) fn force_handle(
        &self,
        handle: &Arc<Mutex<WriteHandle>>,
    ) -> Result<(), fuser::Errno> {
        let queue = Arc::clone(self.mutations.as_ref().ok_or(fuser::Errno::EROFS)?);
        loop {
            {
                let write = handle.lock().map_err(|_| fuser::Errno::EIO)?;
                let write = self.wait_inflight(write)?;
                if write.failed {
                    return Err(fuser::Errno::EIO);
                }
                if !write.dirty {
                    return Ok(());
                }
            }
            let taken = self.gather_taken(
                std::slice::from_ref(handle),
                &GatherFilter {
                    skip_paths: &[],
                    exclude_absent: true,
                    own: Some(handle),
                },
            )?;
            if !taken.iter().any(|taken| Arc::ptr_eq(&taken.handle, handle)) {
                // A concurrent fold took our image between the check
                // and the gather; loop back to await it.
                continue;
            }
            let forcer = FoldSubmitForcer::Handle(Arc::clone(handle));
            let _fold_lease = self.lease_fold(&taken)?;
            let (result, submitted) = self.run_fold(&queue, &taken, &forcer);
            let (mapped, _) = self.settle_fold(&taken, &submitted, &forcer, result);
            return match mapped {
                Ok(MutationOutcome::Committed(_)) => Ok(()),
                Ok(_) => {
                    // A content commit that reports anything else
                    // failed: terminal like any refused commit.
                    if let Ok(mut write) = handle.lock() {
                        write.failed = true;
                        write.dirty = false;
                        write.inflight = None;
                        self.budget.release(write.id);
                    }
                    self.fold_wake.notify_all();
                    tracing::debug!("fold got non-committed outcome for a handle commit");
                    Err(fuser::Errno::EIO)
                }
                Err(error) => Err(error),
            };
        }
    }

    /// Fold one operation plus every dirty image into one snapshot:
    /// the forcing syscall for namespace operations, creates, and
    /// truncating opens. Returns the forcer's own outcome, exactly as
    /// if it had submitted alone.
    pub(super) fn force_op(&self, kind: MutationKind) -> Result<MutationOutcome, fuser::Errno> {
        let queue = Arc::clone(self.mutations.as_ref().ok_or(fuser::Errno::EROFS)?);
        let skip_paths = Self::forcer_skip_paths(&kind);
        let taken = self.gather_taken(
            &[],
            &GatherFilter {
                skip_paths: &skip_paths,
                exclude_absent: true,
                own: None,
            },
        )?;
        let forcer = FoldSubmitForcer::Op(kind);
        let _fold_lease = self.lease_fold(&taken)?;
        let (result, submitted) = self.run_fold(&queue, &taken, &forcer);
        let (mapped, _) = self.settle_fold(&taken, &submitted, &forcer, result);
        mapped
    }

    /// Fold an explicit handle set with no privilege and no abort:
    /// the destroy path, best-effort per path. Returns one committed
    /// flag per taken path, in take order.
    pub(super) fn force_explicit(
        &self,
        candidates: &[Arc<Mutex<WriteHandle>>],
    ) -> Vec<(String, bool)> {
        let Some(queue) = self.mutations.as_ref().map(Arc::clone) else {
            return Vec::new();
        };
        let taken = match self.gather_taken(
            candidates,
            &GatherFilter {
                skip_paths: &[],
                exclude_absent: false,
                own: None,
            },
        ) {
            Ok(taken) => taken,
            Err(_) => return Vec::new(),
        };
        if taken.is_empty() {
            return Vec::new();
        }
        // Memory pressure restores the taken images inside
        // `lease_fold`; the per-path loss log below reports them.
        let _fold_lease = match self.lease_fold(&taken) {
            Ok(lease) => lease,
            Err(_) => {
                return taken
                    .iter()
                    .map(|taken| (taken.path.clone(), false))
                    .collect();
            }
        };
        let forcer = FoldSubmitForcer::None;
        let (result, submitted) = self.run_fold(&queue, &taken, &forcer);
        let (_, summary) = self.settle_fold(&taken, &submitted, &forcer, result);
        summary
    }
}

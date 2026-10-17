use std::sync::Arc;
use std::time::Instant;

use wyrd_format::{ContentId, StoreFailure};

use super::parents::{FileIdentity, ParentToken};
use super::queue::Reply;

/// What an applied mutation produced. Namespace mutations report `Done`;
/// file mutations return the new identity so the caller can advance its
/// handle's base without a second resolution pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MutationOutcome {
    /// A namespace change with no content to hand back (e.g. `mkdir`).
    Done,
    /// A newly created empty file, with its durable identity.
    Created(FileIdentity),
    /// A committed file image, with its durable identity.
    Committed(FileIdentity),
    /// A folded commit: the forcing member's own outcome plus one
    /// disposition per non-forcing member, positional over the
    /// submitted member order. The daemon settles each taken handle
    /// from its disposition and reports the forcer's outcome to the
    /// forcing syscall exactly as if it had submitted alone.
    Fold {
        forcer: FoldForcerOutcome,
        members: Vec<FoldDisposition>,
    },
}

/// What the fold's forcing member came to: its applied outcome, or
/// its own failure — which aborts the fold with nothing committed
/// and restores every other member to pending.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FoldForcerOutcome {
    /// The forcer applied: its outcome, as if submitted alone.
    Applied(Box<MutationOutcome>),
    /// The forcer failed on its own cause: nothing committed.
    Failed(MutationError),
}

/// What a folded non-forcing member came to. Winners carry the same
/// outcome their mutation would have reported alone; losers carry
/// their own errno cause; restored members were untouched by an
/// aborted fold and stay pending for their own forcing event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FoldDisposition {
    /// The member applied and committed: new identity, as `Committed`.
    Committed(FileIdentity),
    /// The member applied with no content to hand back, as `Done`.
    Done,
    /// The member created its file, as `Created`.
    Created(FileIdentity),
    /// The member failed on its own cause: its handle goes terminal.
    Failed(MutationError),
    /// An aborted fold left the member untouched: the daemon puts its
    /// image back and it stays dirty and retryable.
    Restored,
}

/// The attributable source class of one authored snapshot: the
/// mutation variant that produced it. A [`MutationKind::Fold`] counts
/// once as `Fold` — the fold is the commit, and its members never
/// author alone. Path-free by construction: variant classes, never
/// paths, so the operator surface can render them without inheriting
/// the `Debug` impls' path rendering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitSource {
    Mkdir,
    CreateFile,
    CommitFile,
    AppendFile,
    Unlink,
    Rmdir,
    Rename,
    SetAttrs,
    Fold,
}

impl From<&MutationKind> for CommitSource {
    fn from(kind: &MutationKind) -> Self {
        match kind {
            MutationKind::Mkdir { .. } => CommitSource::Mkdir,
            MutationKind::CreateFile { .. } => CommitSource::CreateFile,
            MutationKind::CommitFile { .. } => CommitSource::CommitFile,
            MutationKind::AppendFile { .. } => CommitSource::AppendFile,
            MutationKind::Unlink { .. } => CommitSource::Unlink,
            MutationKind::Rmdir { .. } => CommitSource::Rmdir,
            MutationKind::Rename { .. } => CommitSource::Rename,
            MutationKind::SetAttrs { .. } => CommitSource::SetAttrs,
            MutationKind::Fold { .. } => CommitSource::Fold,
        }
    }
}

/// Lifetime write-path totals for the operator surface: snapshot
/// rate and source breakdown, admission-to-commit latency. Plain
/// data under the queue lock — the loop updates it on completion
/// and authoring, supervisors and `sync now` read a copy. Counters
/// only, never paths or content: nothing rendered from here can
/// leak what a snapshot carries.
#[derive(Debug, Clone)]
pub struct WriteStats {
    /// Snapshots authored through the traced seam, all sources.
    pub snapshots: u64,
    /// Submissions completed successfully. Not all author: a no-op
    /// setattr or an empty append completes without a snapshot, so
    /// this and `snapshots` are separate counters by design.
    pub commits: u64,
    /// Submissions completed as failures, all causes.
    pub failures: u64,
    /// Admission-to-completion latency over committed submissions,
    /// in microseconds: the caller was blocked for this long.
    pub commit_latency_us_sum: u64,
    /// Slowest committed submission, in microseconds.
    pub commit_latency_us_max: u64,
    /// Per-source snapshot counts, in [`CommitSource`] order below.
    pub mkdir: u64,
    pub create_file: u64,
    pub commit_file: u64,
    pub append_file: u64,
    pub unlink: u64,
    pub rmdir: u64,
    pub rename: u64,
    pub set_attrs: u64,
    pub fold: u64,
    /// Queue creation: the rate denominator.
    pub started: Instant,
}

impl WriteStats {
    /// Snapshots per minute over the queue's lifetime. Zero until the
    /// first snapshot — a rate over no time is not a number.
    pub fn snapshots_per_minute(&self) -> f64 {
        let minutes = self.started.elapsed().as_secs_f64() / 60.0;
        if self.snapshots == 0 || minutes <= 0.0 {
            return 0.0;
        }
        self.snapshots as f64 / minutes
    }

    /// Mean admission-to-commit latency over committed submissions,
    /// in microseconds. Zero when nothing committed.
    pub fn commit_latency_us_mean(&self) -> u64 {
        if self.commits == 0 {
            return 0;
        }
        self.commit_latency_us_sum / self.commits
    }
}

impl Default for WriteStats {
    fn default() -> Self {
        WriteStats {
            snapshots: 0,
            commits: 0,
            failures: 0,
            commit_latency_us_sum: 0,
            commit_latency_us_max: 0,
            mkdir: 0,
            create_file: 0,
            commit_file: 0,
            append_file: 0,
            unlink: 0,
            rmdir: 0,
            rename: 0,
            set_attrs: 0,
            fold: 0,
            started: Instant::now(),
        }
    }
}

/// Why a submitted mutation did not commit. The POSIX boundary maps
/// these; the variants are the contract's error table, not the format's
/// generic error type (the channel stays non-generic over the store's
/// error). `Store` and `Engine` are opaque: any durability, authoring,
/// or validation failure collapses to `EIO` at the boundary.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MutationError {
    /// The queue is at its admission bound; the request never executed
    /// and never will. POSIX `EAGAIN`.
    #[error("mutation queue saturated")]
    Saturated,
    /// A lock on the channel is poisoned: fail closed.
    #[error("mutation channel lock poisoned")]
    Lock,
    /// More than one eligible live head: a path mutation has no single
    /// tree to read-modify-write. POSIX `EIO`.
    #[error("cannot mutate while the drive has {heads} live heads")]
    Conflicted { heads: usize },
    /// An invalid path or entry name. POSIX `EINVAL`.
    #[error("invalid path or name: {0}")]
    Invalid(String),
    /// A missing path. POSIX `ENOENT`.
    #[error("{0:?} does not exist")]
    NotFound(String),
    /// A path component resolves through a non-directory. POSIX
    /// `ENOTDIR`.
    #[error("{0:?} is not a directory")]
    NotADirectory(String),
    /// A directory operation on a file. POSIX `EISDIR`.
    #[error("{0:?} is a directory")]
    IsDirectory(String),
    /// The target name already exists. POSIX `EEXIST`.
    #[error("{0:?} already exists")]
    AlreadyExists(String),
    /// A non-empty directory would be removed or replaced. POSIX
    /// `ENOTEMPTY`.
    #[error("{0:?} is not empty")]
    DirectoryNotEmpty(String),
    /// An illegal rename (into a descendant, trailing-slash mismatch).
    /// POSIX `EINVAL`.
    #[error("invalid rename: {0}")]
    InvalidRename(String),
    /// A writable handle's base identity no longer matches the path's
    /// current identity (content change, kind change, or removal). The
    /// commit performs no merge and authors no snapshot. POSIX `EIO`.
    #[error("stale handle for {0:?}: the path changed since it opened")]
    Stale(String),
    /// A queued create observed a parent directory incarnation that is no
    /// longer current. POSIX `ESTALE`.
    #[error("stale parent for {0:?}: the directory changed before create")]
    StaleParent(String),
    /// The operation exceeds a representable or budgeted size. POSIX
    /// `EFBIG`.
    #[error("resulting size {0} exceeds the supported bound")]
    TooLarge(u64),
    /// The operation exceeds a protocol structural ceiling (tree,
    /// manifest, or membership counts). POSIX `EFBIG`, like the byte
    /// ceiling: a count, not a size, so it names both instead of
    /// overloading [`MutationError::TooLarge`]. Integers only — no
    /// foreign error text crosses the channel.
    #[error("count {count} exceeds the limit of {max}")]
    TooMany { count: usize, max: usize },
    /// Object-store or tree access failed. A classified resource
    /// condition keeps its errno (`ENOSPC` for a full disk, `EACCES`
    /// for an unwritable store); everything else is POSIX `EIO`.
    #[error("object store failed")]
    Store(StoreFailure),
    /// Authoring, durability, or validation failed. POSIX `EIO`.
    #[error("engine failed")]
    Engine,
    /// Authoring needs content that is not locally available: the base
    /// closure references chunks with no sealed representation and no
    /// plaintext here. Never reaches the POSIX boundary — the loop
    /// registers a want for every named chunk and holds the mutation
    /// pending. One evaluation names the whole set it discovered (the
    /// authoring walk collects every miss, single-miss sites name one),
    /// so a cold device demands everything together instead of one
    /// chunk per pass. Carries the single head the mutation was
    /// evaluated against so the retry can pin it without re-reading
    /// the head set.
    #[error("authoring needs remote content {chunks:?}")]
    NeedContent {
        chunks: Vec<ContentId>,
        base: Option<wyrd_format::SnapshotId>,
    },
    /// A deferred mutation waited past `max_mutation_wait` for its
    /// authoring prerequisites. POSIX `ETIMEDOUT`: the operation was
    /// valid but its prerequisite never became available in time.
    #[error("mutation prerequisite wait expired")]
    TimedOut,
    /// The live loop stopped before completing the request — terminal
    /// error or shutdown — so it may never have executed. POSIX `EIO`:
    /// a distinct variant (not a bare `Engine`) so supervisors and
    /// tests can tell "never serviced" from "serviced but failed".
    #[error("live loop stopped before completing the mutation")]
    Shutdown,
}

impl MutationError {
    /// Classify a format mutation failure. The structured variants map
    /// straight through; a store failure keeps its resource
    /// classification (full and unwritable stay distinguishable at
    /// the POSIX boundary); everything else (missing tree,
    /// tree failure, name/path mismatch, component errors) is an
    /// `EIO` or an `EINVAL` at the boundary, never a silently
    /// different errno.
    pub fn from_format<E: std::fmt::Debug + wyrd_format::StoreError>(
        error: wyrd_format::MutationError<E>,
    ) -> Self {
        use wyrd_format::MutationError as F;
        match error {
            F::NotADirectory(path) => MutationError::NotADirectory(path),
            F::IsDirectory(path) => MutationError::IsDirectory(path),
            F::NotFound(path) => MutationError::NotFound(path),
            F::AlreadyExists(path) => MutationError::AlreadyExists(path),
            F::DirectoryNotEmpty(path) => MutationError::DirectoryNotEmpty(path),
            F::InvalidRename(reason) => MutationError::InvalidRename(reason),
            F::Path(_) | F::NameMismatch { .. } => MutationError::Invalid(error.to_string()),
            F::Store(error) => MutationError::Store(error.failure()),
            F::MissingTree(_) | F::Tree(_) => MutationError::Store(StoreFailure::Transient),
        }
    }
}

/// One queued operation. Slice 2 carries `Mkdir`; this slice adds
/// `CreateFile` and `CommitFile`. Later slices add unlink, rmdir,
/// rename, and setattr. Paths are canonical components (the format
/// layer re-validates them).
#[derive(Clone, PartialEq, Eq)]
pub enum MutationKind {
    /// Create an empty directory; no intermediates (`insert_into` is the
    /// format layer's strict-parents rule).
    Mkdir { path: String },
    /// Create an empty regular file as its own snapshot (the `create`
    /// op's namespace half). The parent token is the directory incarnation
    /// observed by the presentation caller; it is checked again by the
    /// live loop. `EEXIST` when the name is taken.
    CreateFile { path: String, parent: ParentToken },
    /// Commit a writable handle's full logical image onto the current
    /// head, accepted only if the path still carries `base`. `executable`
    /// is the handle's buffered exec bit for the committed entry.
    CommitFile {
        path: String,
        base: FileIdentity,
        executable: bool,
        content: Vec<u8>,
    },
    /// Append `content` to the current head's file at `path`. Unlike
    /// [`CommitFile`](MutationKind::CommitFile) there is no content
    /// comparison: append is position-independent and observes an
    /// intervening commit, but still requires the path to exist as a
    /// regular file (never creates, never resurrects).
    AppendFile { path: String, content: Vec<u8> },
    /// Remove the file or symlink at `path`; a directory is `EISDIR`.
    Unlink { path: String },
    /// Remove the empty directory at `path`.
    Rmdir { path: String },
    /// Move `from` to `to`. `no_replace` is `RENAME_NOREPLACE`.
    Rename {
        from: String,
        to: String,
        no_replace: bool,
    },
    /// One `setattr`: apply the requested size and/or exec change as a
    /// single namespace mutation, publishing exactly one root or none.
    /// `size` on a non-file is `EISDIR`; an exec change on a non-file is
    /// a no-op. At least one field is set.
    ///
    /// `base` is an optional precondition, never a merge: when it is
    /// set the path must still carry exactly that file identity or the
    /// mutation is [`MutationError::Stale`]. A `setattr` addressed by
    /// path alone stays path-addressed (`None`) — POSIX `truncate` and
    /// `chmod` act on whatever the path names now — while the `O_TRUNC`
    /// half of an open is bound to the identity that open observed, so
    /// a same-path replacement can never have the truncation applied to
    /// it.
    SetAttrs {
        path: String,
        size: Option<u64>,
        executable: Option<bool>,
        base: Option<FileIdentity>,
    },
    /// One commit-forcing event's whole pending set plus itself,
    /// applied as a single snapshot (`docs/write-path.md`, DG-1
    /// table). Members are ordered first-in-first-buffered; exactly
    /// one member carries `forcer: true` and lends the fold its
    /// privilege (a same-path tie) and its abort rule (a failed
    /// forcer commits nothing) — except the shutdown fold, whose
    /// members are all non-forcing and fail per member, best-effort.
    /// A `Fold` never nests: a member whose kind is itself a `Fold`
    /// fails the whole submission closed.
    Fold { members: Vec<FoldMember> },
}

/// One folded member: a non-`Fold` operation plus whether it is the
/// commit-forcing event that owns the fold.
#[derive(Clone, PartialEq, Eq)]
pub struct FoldMember {
    /// The operation to apply. Never [`MutationKind::Fold`].
    pub kind: MutationKind,
    /// The forcing member: wins same-path ties it survives, and its
    /// failure aborts the fold with nothing committed.
    pub forcer: bool,
}

/// Diagnostic rendering for [`MutationKind`] redacts file content:
/// `CommitFile` and `AppendFile` own the full plaintext image, and any
/// `{:?}` of the queue (logs, error paths, panic captures) must never
/// carry user bytes. Variant names, paths, identities, and content
/// *lengths* still render — enough to diagnose a stuck or misrouted
/// mutation without exposing what it carries.
impl std::fmt::Debug for MutationKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MutationKind::Mkdir { path } => f.debug_struct("Mkdir").field("path", path).finish(),
            MutationKind::CreateFile { path, parent } => f
                .debug_struct("CreateFile")
                .field("path", path)
                .field("parent", parent)
                .finish(),
            MutationKind::CommitFile {
                path,
                base,
                executable,
                content,
            } => f
                .debug_struct("CommitFile")
                .field("path", path)
                .field("base", base)
                .field("executable", executable)
                .field("content_len", &content.len())
                .finish(),
            MutationKind::AppendFile { path, content } => f
                .debug_struct("AppendFile")
                .field("path", path)
                .field("content_len", &content.len())
                .finish(),
            MutationKind::Unlink { path } => f.debug_struct("Unlink").field("path", path).finish(),
            MutationKind::Rmdir { path } => f.debug_struct("Rmdir").field("path", path).finish(),
            MutationKind::Rename {
                from,
                to,
                no_replace,
            } => f
                .debug_struct("Rename")
                .field("from", from)
                .field("to", to)
                .field("no_replace", no_replace)
                .finish(),
            MutationKind::SetAttrs {
                path,
                size,
                executable,
                base,
            } => f
                .debug_struct("SetAttrs")
                .field("path", path)
                .field("size", size)
                .field("executable", executable)
                .field("base", base)
                .finish(),
            MutationKind::Fold { members } => {
                f.debug_struct("Fold").field("members", members).finish()
            }
        }
    }
}

/// Diagnostic rendering for [`FoldMember`] redacts like its kind:
/// the forcing flag renders, member content never does.
impl std::fmt::Debug for FoldMember {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FoldMember")
            .field("kind", &self.kind)
            .field("forcer", &self.forcer)
            .finish()
    }
}

/// A submitted operation, opaque to callers: the id is diagnostic, the
/// kind is the loop's instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutationRequest {
    pub(super) id: MutationId,
    pub(super) kind: MutationKind,
}

impl MutationRequest {
    /// The request's diagnostic identity.
    pub fn id(&self) -> MutationId {
        self.id
    }

    /// The operation to apply.
    pub fn kind(&self) -> &MutationKind {
        &self.kind
    }
}

/// A monotonic submission id: diagnostics and tests, never semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MutationId(pub(super) u64);

impl std::fmt::Display for MutationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "mutation-{}", self.0)
    }
}

/// One admitted request plus its reply slot: the loop executes it and
/// completes the slot, waking the blocked submitter.
pub struct QueuedMutation {
    pub(super) request: MutationRequest,
    pub(super) reply: Arc<Reply>,
    /// The single head this mutation was first evaluated against, set
    /// by [`MutationBatch::defer`]. A retried mutation must observe
    /// exactly this head: anything else is `Stale`, never a silent
    /// rebase onto newer state.
    pub(super) base: Option<wyrd_format::SnapshotId>,
    /// When the entry was first held for authoring prerequisites.
    /// `None` until the first defer; later defers must not reset it.
    pub(super) first_deferred: Option<Instant>,
    /// When the request was admitted. The prerequisite clock runs
    /// from admission — the caller has been blocked since — so the
    /// pass that first evaluates the request is inside the budget
    /// too; a first evaluation that arrives after the budget expires
    /// fails terminal `TimedOut` instead of starting a new wait.
    pub(super) submitted: Instant,
    /// Fetch wants this entry registered while held, in registration
    /// order. Released when the entry completes on any path — commit,
    /// failure, timeout, drop, or shutdown — so deferred retries never
    /// accumulate waiter counts against the registry bound.
    pub(super) wanted: Vec<ContentId>,
}

impl QueuedMutation {
    /// The request to apply (id and kind).
    pub fn request(&self) -> &MutationRequest {
        &self.request
    }
}

impl std::fmt::Debug for QueuedMutation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueuedMutation")
            .field("request", &self.request)
            .finish_non_exhaustive()
    }
}

//! Shared drive-path semantics (contracts 42-49): the embedded
//! consumer (core mutation channel plus [`LiveReader`]) and the FUSE
//! adapter ([`FuseBackend`]) observe identical outcomes for identical
//! scenarios. Both drivers compose from the same live parts over
//! identically seeded scratch drives; each scenario collects a trace
//! of normalized [`Outcome`]s per path and asserts the traces match.
//! A deliberately diverged trace must fail the comparator (pinned by
//! the harness self-test), so the suite cannot pass vacuously.
//!
//! Error normalization is the load-bearing claim: each side's typed
//! errors map to a canonical tag, and the tag tables live next to the
//! scenarios so review can audit them. Where the two paths are
//! *documentedly* different (descriptors pin their open-time capture
//! while handle-less reads re-resolve; a bounded remote-only wait
//! versus an immediate errno), the test asserts each side's own
//! documented tag instead of cross-equality.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use wyrd_core::live::{LiveConfig, LiveParts};
use wyrd_core::mutation::{
    FileIdentity, FoldForcerOutcome, FoldMember, MutationError, MutationKind, MutationOutcome,
    MutationQueue,
};
use wyrd_core::projection::SharedProjection;
use wyrd_core::read::{LiveReader, ReadError};
use wyrd_core::view::RuntimeMaterialization;
use wyrd_core::want::WantRegistry;
use wyrd_daemon::core::WyrdNode;
use wyrd_daemon::fuse::FuseBackend;
use wyrd_format::{
    ContentId, Entry, FetchStatus, MemoryObjectStore, ObjectKind, ObjectStore, Tree,
};
use wyrd_fuse::{DriveView, Materialization, ViewError};
use wyrd_sync::bulk::MemoryBulkSource;
use wyrd_sync::keys::DeviceIdentitySecret;
use wyrd_sync::runtime::Engine;
use wyrd_sync::transport::mailbox::{
    Delivery, DeliveryId, Disposition, Mailbox, MailboxEnvelope, MailboxError, SendReport,
};

use crate::support::{fixture_heads, scratch_dir, signed_head};

type LiveView = DriveView<MemoryObjectStore, RuntimeMaterialization>;

/// A control plane that never speaks: every observed change is local.
struct SilentMailbox;

impl Mailbox for SilentMailbox {
    fn send(&mut self, _envelope: MailboxEnvelope) -> Result<SendReport, MailboxError> {
        Ok(SendReport { accepted: 1 })
    }

    fn recv(&mut self) -> Result<Option<Delivery>, MailboxError> {
        Ok(None)
    }

    fn settle(&mut self, _id: DeliveryId, _disposition: Disposition) -> Result<(), MailboxError> {
        Ok(())
    }
}

/// One normalized scenario observation: bytes read, clean success, a
/// canonical error tag, a publication generation, or an idle verdict.
/// Both drivers produce these; the suite compares them.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Outcome {
    Bytes(Vec<u8>),
    Ok,
    Err(&'static str),
    Gen(u64),
    Quiet(bool),
}

impl Outcome {
    /// Scripted steps are known-good at their point in the script: a
    /// non-`Ok` is a scenario bug, fail with context, never coerce.
    fn into_ok(self, context: &str) {
        assert_eq!(self, Outcome::Ok, "scripted setup step failed: {context}");
    }
}

/// The core channel's typed failures in POSIX-equivalence tags. The
/// mapping mirrors the `POSIX ...` notes on [`MutationError`]; a miss
/// here is a conformance claim, fail it loudly, never silently.
fn mutation_tag(error: &MutationError) -> &'static str {
    match error {
        MutationError::NotFound(_) => "not-found",
        MutationError::NotADirectory(_) => "not-a-directory",
        MutationError::IsDirectory(_) => "is-a-directory",
        MutationError::AlreadyExists(_) => "already-exists",
        MutationError::DirectoryNotEmpty(_) => "directory-not-empty",
        MutationError::Invalid(_) | MutationError::InvalidRename(_) => "invalid",
        MutationError::Stale(_) | MutationError::StaleParent(_) => "stale",
        MutationError::TooLarge(_) | MutationError::TooMany { .. } => "too-large",
        MutationError::TimedOut => "timed-out",
        MutationError::Saturated => "saturated",
        MutationError::Shutdown => "shutdown",
        MutationError::Conflicted { .. }
        | MutationError::Lock
        | MutationError::Store(_)
        | MutationError::Engine
        | MutationError::NeedContent { .. } => "io-error",
    }
}

/// The adapter's errnos in the same tags. `ESTALE` covers retired
/// inodes and stale parents alike; resource failures stay `EIO` at
/// this boundary (the store keeps its own classification).
fn errno_tag(error: fuser::Errno) -> &'static str {
    match error {
        fuser::Errno::ENOENT => "not-found",
        fuser::Errno::ENOTDIR => "not-a-directory",
        fuser::Errno::EISDIR => "is-a-directory",
        fuser::Errno::EEXIST => "already-exists",
        fuser::Errno::ENOTEMPTY => "directory-not-empty",
        fuser::Errno::EINVAL => "invalid",
        fuser::Errno::ESTALE => "stale",
        fuser::Errno::EFBIG => "too-large",
        fuser::Errno::ETIMEDOUT => "timed-out",
        fuser::Errno::EAGAIN => "saturated",
        fuser::Errno::EROFS => "read-only",
        fuser::Errno::EIO => "io-error",
        _ => "unmapped-errno",
    }
}

fn view_tag(error: &ViewError) -> &'static str {
    match error {
        ViewError::NotFound => "not-found",
        ViewError::NotMaterialized { .. } => "not-materialized",
        ViewError::Unavailable { .. } => "terminal-unavailable",
        ViewError::Conflict => "conflict",
        ViewError::NotAFile => "not-a-file",
        _ => "unmapped-view-error",
    }
}

/// Read failures in trace tags: the lookup/open/read surface reports
/// view errors directly, while demand failures surface as bounded
/// timeouts and settled rejections as terminals.
fn read_tag(error: &ReadError) -> &'static str {
    match error {
        ReadError::View(inner) => view_tag(inner),
        ReadError::Timeout { .. } => "timed-out",
        ReadError::Terminal(inner) => match inner {
            ViewError::Unavailable { .. } => "terminal-unavailable",
            _ => "terminal-other",
        },
        _ => "unmapped-read-error",
    }
}

/// The trace comparator: every step must match exactly. The harness
/// self-test feeds it a synthetic divergence, so a comparator that
/// always passes fails the suite instead of the scenarios.
fn assert_same_traces(embedded: &[Outcome], adapter: &[Outcome]) {
    assert_eq!(
        embedded.len(),
        adapter.len(),
        "both paths run the same script"
    );
    for (step, (left, right)) in embedded.iter().zip(adapter.iter()).enumerate() {
        assert_eq!(
            left, right,
            "step {step} diverges between the embedded path and the FUSE adapter"
        );
    }
}

#[test]
fn conformance_comparator_rejects_a_synthetic_divergence() {
    let trace = vec![Outcome::Ok, Outcome::Bytes(b"same".to_vec())];
    assert_same_traces(&trace, &trace);
    let diverged = vec![Outcome::Ok, Outcome::Bytes(b"other".to_vec())];
    let caught = std::panic::catch_unwind(|| assert_same_traces(&trace, &diverged));
    assert!(
        caught.is_err(),
        "a diverged trace must fail the comparator, or the suite passes vacuously"
    );
}

/// One live drive: a scratch engine, the into_live split, and the
/// loop on its own thread. Both drivers build from these parts; drop
/// stops the loop and removes the scratch dir.
struct LiveSession {
    stop: Arc<AtomicBool>,
    loop_handle: Option<
        std::thread::JoinHandle<
            Result<wyrd_daemon::core::LiveSummary, wyrd_daemon::core::LiveError>,
        >,
    >,
    parts: LiveParts<LiveView>,
    dir: std::path::PathBuf,
}

impl LiveSession {
    /// A scratch drive with the loop running: the loop thread owns
    /// the node, the test thread keeps the parts both drivers build
    /// from.
    fn fresh(name: &str) -> Self {
        let dir = scratch_dir(&format!("shared-semantics-{name}"));
        let engine = Engine::create(
            dir.clone(),
            "shared-semantics-pass",
            DeviceIdentitySecret::generate().unwrap(),
        )
        .unwrap();
        let node: WyrdNode<LiveView> = WyrdNode::new(engine, MemoryObjectStore::default()).unwrap();
        let (mut live, parts) = node
            .into_live(Duration::from_secs(30), &LiveConfig::default())
            .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let loop_stop = Arc::clone(&stop);
        let config = LiveConfig {
            interval: Duration::from_millis(10),
            ..LiveConfig::default()
        };
        let handle = std::thread::spawn(move || {
            let mut mailbox = SilentMailbox;
            live.run_loop(
                &mut mailbox,
                None::<&mut MemoryBulkSource>,
                &loop_stop,
                &config,
                &mut |_, _| {},
            )
        });
        LiveSession {
            stop,
            loop_handle: Some(handle),
            parts,
            dir,
        }
    }

    fn shutdown(&mut self) {
        self.parts.mutations.shutdown();
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.loop_handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for LiveSession {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.loop_handle.take() {
            let _ = handle.join();
        }
        std::fs::remove_dir_all(&self.dir).ok();
    }
}

/// The embedded consumer: submits [`MutationKind`]s straight to the
/// channel and reads through [`LiveReader`] over the publication
/// slot. No backend exists on this path.
struct Embedded {
    queue: Arc<MutationQueue>,
    slot: SharedProjection<LiveView>,
    reader: LiveReader,
}

impl Embedded {
    fn new(session: &LiveSession) -> Self {
        Embedded {
            queue: Arc::clone(&session.parts.mutations),
            slot: Arc::clone(&session.parts.projection),
            reader: LiveReader::new(Duration::from_secs(5)),
        }
    }

    fn submit(&self, kind: MutationKind) -> Outcome {
        match self.queue.submit(kind) {
            Ok(_) => Outcome::Ok,
            Err(error) => Outcome::Err(mutation_tag(&error)),
        }
    }

    fn mkdir(&self, path: &str) -> Outcome {
        self.submit(MutationKind::Mkdir {
            path: path.to_string(),
        })
    }

    /// Create `name` under `parent` (empty for the root) with `bytes`:
    /// the namespace half plus the content append, mirroring what a
    /// create-then-commit does through the adapter.
    fn create(&self, parent: &str, name: &str, bytes: &[u8]) -> Outcome {
        let path = if parent.is_empty() {
            name.to_string()
        } else {
            format!("{parent}/{name}")
        };
        let Some(token) = self.queue.capture_parent(parent) else {
            return Outcome::Err("stale");
        };
        if let Err(error) = self.queue.submit(MutationKind::CreateFile {
            path: path.clone(),
            parent: token,
        }) {
            return Outcome::Err(mutation_tag(&error));
        }
        self.submit(MutationKind::AppendFile {
            path,
            content: bytes.to_vec(),
        })
    }

    fn read(&self, path: &str) -> Outcome {
        let projection = self.slot.read().expect("projection lock").clone();
        match self.reader.read_file(projection.view(), path) {
            Ok(bytes) => Outcome::Bytes(bytes),
            Err(error) => Outcome::Err(read_tag(&error)),
        }
    }

    fn rename(&self, from: &str, to: &str) -> Outcome {
        self.submit(MutationKind::Rename {
            from: from.to_string(),
            to: to.to_string(),
            no_replace: false,
        })
    }

    fn unlink(&self, path: &str) -> Outcome {
        self.submit(MutationKind::Unlink {
            path: path.to_string(),
        })
    }

    fn rmdir(&self, path: &str) -> Outcome {
        self.submit(MutationKind::Rmdir {
            path: path.to_string(),
        })
    }

    fn set_size(&self, path: &str, size: u64) -> Outcome {
        self.submit(MutationKind::SetAttrs {
            path: path.to_string(),
            size: Some(size),
            executable: None,
            base: None,
        })
    }

    /// Commit `content` as one fold carrying a single `CommitFile`:
    /// the channel-side shape of the adapter's merged commit run. The
    /// adapter opens `O_RDWR` (append false), so at commit it submits
    /// a `CommitFile` for the whole buffered image — not an append
    /// run — and the mirror does the same, with the same base.
    /// Returns the committed identity for chained commits.
    fn fold_commit(
        &self,
        path: &str,
        base: FileIdentity,
        content: &[u8],
    ) -> Result<FileIdentity, Outcome> {
        match self.queue.submit(MutationKind::Fold {
            members: vec![FoldMember {
                kind: MutationKind::CommitFile {
                    path: path.to_string(),
                    base,
                    executable: false,
                    content: content.to_vec(),
                },
                forcer: true,
            }],
        }) {
            Ok(MutationOutcome::Fold {
                forcer: FoldForcerOutcome::Applied(boxed),
                ..
            }) => match *boxed {
                MutationOutcome::Committed(identity) => Ok(identity),
                _ => Err(Outcome::Err("unexpected-outcome")),
            },
            Ok(_) => Err(Outcome::Err("unexpected-outcome")),
            Err(error) => Err(Outcome::Err(mutation_tag(&error))),
        }
    }

    /// A create on a parent token captured before the directory was
    /// reincarnated: tokens survive descendant changes but rotate when
    /// the directory itself is replaced, so moving the directory away
    /// and recreating it strands the old token as `StaleParent`. The
    /// channel-side companion to the adapter's retired-inode path.
    fn stale_parent_create(&self, parent: &str, name: &str, bytes: &[u8]) -> Outcome {
        let path = format!("{parent}/{name}");
        let moved = format!("{parent}-gone");
        if self.mkdir(parent) != Outcome::Ok {
            return Outcome::Err("setup-failed");
        }
        let Some(token) = self.queue.capture_parent(parent) else {
            return Outcome::Err("stale");
        };
        // Reincarnate the directory out from under the token: the move
        // retires the observed incarnation, the fresh mkdir mints a
        // new one, and the path exists again — so only the token is
        // wrong when the create evaluates.
        if self.rename(parent, &moved) != Outcome::Ok {
            return Outcome::Err("setup-failed");
        }
        if self.mkdir(parent) != Outcome::Ok {
            return Outcome::Err("setup-failed");
        }
        if let Err(error) = self.queue.submit(MutationKind::CreateFile {
            path: path.clone(),
            parent: token,
        }) {
            return Outcome::Err(mutation_tag(&error));
        }
        self.submit(MutationKind::AppendFile {
            path,
            content: bytes.to_vec(),
        })
    }

    fn generation(&self) -> Outcome {
        Outcome::Gen(self.slot.read().expect("projection lock").generation())
    }

    /// An idle verdict: the generation must not move while nothing is
    /// submitted. Both paths run the same check, so a chatty loop
    /// fails the traces on both sides equally.
    fn idle(&self) -> Outcome {
        let before = self.slot.read().expect("projection lock").generation();
        std::thread::sleep(Duration::from_millis(250));
        let after = self.slot.read().expect("projection lock").generation();
        Outcome::Quiet(before == after)
    }
}

/// The FUSE adapter path: the same scenario steps through
/// [`FuseBackend`] entry points, the calls the mounted filesystem
/// would make. Inode 1 is the root; deeper parents resolve through
/// `attr_at`, exactly as the adapter's own callers do.
struct Adapter {
    backend: FuseBackend<MemoryObjectStore, RuntimeMaterialization>,
}

impl Adapter {
    fn new(session: &LiveSession) -> Self {
        Adapter {
            backend: FuseBackend::shared_with_wants(
                Arc::clone(&session.parts.projection),
                Arc::clone(&session.parts.wants),
                Arc::clone(&session.parts.mutations),
                session.parts.open_timeout,
                &session.parts.budgets,
            ),
        }
    }

    fn ino_of(&self, path: &str) -> Result<u64, Outcome> {
        match self.backend.attr_at(path) {
            Ok(attr) => Ok(attr.ino.0),
            Err(error) => Err(Outcome::Err(errno_tag(error))),
        }
    }

    fn mkdir(&self, parent: u64, name: &str) -> Outcome {
        match self.backend.mkdir_at(parent, name) {
            Ok(_) => Outcome::Ok,
            Err(error) => Outcome::Err(errno_tag(error)),
        }
    }

    /// Create `name` under `parent` with `bytes`: the adapter's own
    /// create, buffered write, and commit — one namespace mutation
    /// plus one content commit, like the embedded create.
    fn create(&self, parent: u64, name: &str, bytes: &[u8]) -> Outcome {
        let handle = match self.backend.create_at(parent, name, libc::O_RDWR) {
            Ok((handle, _, _)) => handle,
            Err(error) => return Outcome::Err(errno_tag(error)),
        };
        let wrote = self.backend.write_handle(handle, 0, bytes);
        let committed = wrote
            .map_err(errno_tag)
            .map(|_| ())
            .and_then(|()| self.backend.commit_handle(handle).map_err(errno_tag));
        let _ = self.backend.release_handle(handle);
        match committed {
            Ok(()) => Outcome::Ok,
            Err(tag) => Outcome::Err(tag),
        }
    }

    fn read(&self, path: &str) -> Outcome {
        let handle = match self.backend.open_at(path) {
            Ok(handle) => handle,
            Err(error) => return Outcome::Err(errno_tag(error)),
        };
        let bytes = self.backend.read_handle(handle, 0, u32::MAX);
        let _ = self.backend.release_handle(handle);
        match bytes {
            Ok(bytes) => Outcome::Bytes(bytes),
            Err(error) => Outcome::Err(errno_tag(error)),
        }
    }

    fn rename(&self, parent: u64, name: &str, new_parent: u64, new_name: &str) -> Outcome {
        match self
            .backend
            .rename_at(parent, name, new_parent, new_name, false)
        {
            Ok(()) => Outcome::Ok,
            Err(error) => Outcome::Err(errno_tag(error)),
        }
    }

    fn unlink(&self, parent: u64, name: &str) -> Outcome {
        match self.backend.unlink_at(parent, name) {
            Ok(()) => Outcome::Ok,
            Err(error) => Outcome::Err(errno_tag(error)),
        }
    }

    fn rmdir(&self, parent: u64, name: &str) -> Outcome {
        match self.backend.rmdir_at(parent, name) {
            Ok(()) => Outcome::Ok,
            Err(error) => Outcome::Err(errno_tag(error)),
        }
    }

    fn set_size(&self, path: &str, size: u64) -> Outcome {
        let ino = match self.ino_of(path) {
            Ok(ino) => ino,
            Err(outcome) => return outcome,
        };
        match self.backend.set_size_at(ino, size) {
            Ok(()) => Outcome::Ok,
            Err(error) => Outcome::Err(errno_tag(error)),
        }
    }

    fn generation(&self) -> Outcome {
        match self.backend.generation() {
            Ok(gen) => Outcome::Gen(gen),
            Err(error) => Outcome::Err(errno_tag(error)),
        }
    }

    /// Rewrite `path` at `offset` with `data` through a fresh write
    /// handle: open, buffer, commit, release. The second-commit shape
    /// for chained base comparisons.
    fn rewrite(&self, path: &str, offset: u64, data: &[u8]) -> Outcome {
        let handle = match self.backend.open_write(path, libc::O_RDWR) {
            Ok(handle) => handle,
            Err(error) => return Outcome::Err(errno_tag(error)),
        };
        let wrote = match self.backend.write_handle(handle, offset, data) {
            Ok(_) => Outcome::Ok,
            Err(error) => Outcome::Err(errno_tag(error)),
        };
        if wrote != Outcome::Ok {
            let _ = self.backend.release_handle(handle);
            return wrote;
        }
        let committed = match self.backend.commit_handle(handle) {
            Ok(()) => Outcome::Ok,
            Err(error) => Outcome::Err(errno_tag(error)),
        };
        let _ = self.backend.release_handle(handle);
        committed
    }

    /// Open `name` under `parent` for buffered writes: the namespace
    /// half only, no commit yet.
    fn begin_create(&self, parent: u64, name: &str) -> Result<fuser::FileHandle, Outcome> {
        match self.backend.create_at(parent, name, libc::O_RDWR) {
            Ok((handle, _, _)) => Ok(handle),
            Err(error) => Err(Outcome::Err(errno_tag(error))),
        }
    }

    /// Buffer `chunks` onto an open write handle and commit once: the
    /// adapter's fold path — several writes, one snapshot. Writes land
    /// at successive offsets, so the image concatenates like separate
    /// buffered appends. First error wins; the handle releases either
    /// way.
    ///
    /// Healthy-path only: on a failed write the commit is skipped but
    /// the handle still releases, and release folds best-effort — so a
    /// refused commit could still publish partial bytes. Do not reuse
    /// this helper for a negative case without draining or dropping
    /// the dirty handle first.
    fn commit_writes(&self, handle: fuser::FileHandle, chunks: &[&[u8]]) -> Outcome {
        let mut result = Outcome::Ok;
        let mut offset = 0u64;
        for chunk in chunks {
            match self.backend.write_handle(handle, offset, chunk) {
                Ok(_) => offset += chunk.len() as u64,
                Err(error) => {
                    result = Outcome::Err(errno_tag(error));
                    break;
                }
            }
        }
        if result == Outcome::Ok {
            result = match self.backend.commit_handle(handle) {
                Ok(()) => Outcome::Ok,
                Err(error) => Outcome::Err(errno_tag(error)),
            };
        }
        let _ = self.backend.release_handle(handle);
        result
    }

    fn idle(&self) -> Outcome {
        let before = self.generation();
        std::thread::sleep(Duration::from_millis(250));
        let after = self.generation();
        match (before, after) {
            (Outcome::Gen(a), Outcome::Gen(b)) => Outcome::Quiet(a == b),
            (first, _) => first,
        }
    }
}

/// Contract 42: create/write/read round-trips identically — a
/// multi-window file (past one read window, so the window loop is in
/// the trace), its generations, and an idle loop that publishes
/// nothing on either path.
#[test]
fn embedded_and_adapter_paths_agree_on_create_write_read() {
    let big: Vec<u8> = (0..300 * 1024 + 13).map(|i| (i % 251) as u8).collect();
    let run = |session: &LiveSession| {
        let emb = Embedded::new(session);
        vec![
            emb.mkdir("docs"),
            emb.create("docs", "big.bin", &big),
            emb.read("docs/big.bin"),
            emb.generation(),
            emb.set_size("docs/big.bin", 7),
            emb.read("docs/big.bin"),
            emb.idle(),
        ]
    };
    let run_adapter = |session: &LiveSession| {
        let be = Adapter::new(session);
        // The adapter resolves deeper parents through attr, like its
        // own callers: find docs and create inside it.
        let created = be.mkdir(1, "docs");
        let docs = be.ino_of("docs").expect("docs resolves");
        let mut trace = vec![created];
        trace.extend([
            be.create(docs, "big.bin", &big),
            be.read("docs/big.bin"),
            be.generation(),
            be.set_size("docs/big.bin", 7),
            be.read("docs/big.bin"),
            be.idle(),
        ]);
        trace
    };

    let embedded_session = LiveSession::fresh("cwr-embedded");
    let embedded_trace = run(&embedded_session);
    let adapter_session = LiveSession::fresh("cwr-adapter");
    let adapter_trace = run_adapter(&adapter_session);

    assert_same_traces(&embedded_trace, &adapter_trace);
    assert!(
        matches!(&embedded_trace[2], Outcome::Bytes(b) if *b == big),
        "the round-trip serves the authored bytes, not a placeholder"
    );
    assert!(
        matches!(&embedded_trace[5], Outcome::Bytes(b) if *b == big[..7]),
        "truncate keeps the prefix on both paths"
    );
    assert_eq!(embedded_trace[6], Outcome::Quiet(true));
}

/// Contract 43: rename and delete move and remove the same bytes, and
/// the old path fails identically afterwards.
#[test]
fn embedded_and_adapter_paths_agree_on_rename_and_delete() {
    let run = |session: &LiveSession| {
        let emb = Embedded::new(session);
        vec![
            emb.mkdir("mv"),
            emb.create("mv", "a.txt", b"moved bytes"),
            emb.rename("mv/a.txt", "mv/b.txt"),
            emb.read("mv/a.txt"),
            emb.read("mv/b.txt"),
            emb.unlink("mv/b.txt"),
            emb.read("mv/b.txt"),
            emb.rmdir("mv"),
        ]
    };
    let run_adapter = |session: &LiveSession| {
        let be = Adapter::new(session);
        let created = be.mkdir(1, "mv");
        let mv = be.ino_of("mv").expect("mv resolves");
        let mut trace = vec![created];
        trace.extend([
            be.create(mv, "a.txt", b"moved bytes"),
            be.rename(mv, "a.txt", mv, "b.txt"),
            be.read("mv/a.txt"),
            be.read("mv/b.txt"),
            be.unlink(mv, "b.txt"),
            be.read("mv/b.txt"),
            be.rmdir(1, "mv"),
        ]);
        trace
    };

    let embedded_session = LiveSession::fresh("rnd-embedded");
    let embedded_trace = run(&embedded_session);
    let adapter_session = LiveSession::fresh("rnd-adapter");
    let adapter_trace = run_adapter(&adapter_session);

    assert_same_traces(&embedded_trace, &adapter_trace);
    assert_eq!(embedded_trace[3], Outcome::Err("not-found"));
    assert_eq!(embedded_trace[4], Outcome::Bytes(b"moved bytes".to_vec()));
    assert_eq!(embedded_trace[6], Outcome::Err("not-found"));
}

/// Contract 44: the error classes match — duplicates, wrong kinds,
/// non-empty directories, and missing paths fail with the same tags
/// on both paths.
#[test]
fn embedded_and_adapter_paths_agree_on_error_classes() {
    let run = |session: &LiveSession| {
        let emb = Embedded::new(session);
        vec![
            emb.mkdir("err"),
            emb.create("err", "f.txt", b"x"),
            emb.create("err", "f.txt", b"y"),
            emb.mkdir("err/f.txt/sub"),
            emb.unlink("err"),
            emb.rmdir("err"),
            emb.read("err/nope.txt"),
        ]
    };
    let run_adapter = |session: &LiveSession| {
        let be = Adapter::new(session);
        let created = be.mkdir(1, "err");
        let err = be.ino_of("err").expect("err resolves");
        let first = be.create(err, "f.txt", b"x");
        let file = be.ino_of("err/f.txt").expect("f.txt resolves");
        vec![
            created,
            first,
            be.create(err, "f.txt", b"y"),
            be.mkdir(file, "sub"),
            be.unlink(1, "err"),
            be.rmdir(1, "err"),
            be.read("err/nope.txt"),
        ]
    };

    let embedded_session = LiveSession::fresh("err-embedded");
    let embedded_trace = run(&embedded_session);
    let adapter_session = LiveSession::fresh("err-adapter");
    let adapter_trace = run_adapter(&adapter_session);

    assert_same_traces(&embedded_trace, &adapter_trace);
    assert_eq!(embedded_trace[2], Outcome::Err("already-exists"));
    assert_eq!(embedded_trace[3], Outcome::Err("not-a-directory"));
    assert_eq!(embedded_trace[4], Outcome::Err("is-a-directory"));
    assert_eq!(embedded_trace[5], Outcome::Err("directory-not-empty"));
    assert_eq!(embedded_trace[6], Outcome::Err("not-found"));
}

/// Contract 45: publication accounting matches — every committing
/// step advances the generation on both paths in lockstep.
#[test]
fn embedded_and_adapter_paths_agree_on_publication() {
    let run = |session: &LiveSession| {
        let emb = Embedded::new(session);
        vec![
            emb.generation(),
            emb.mkdir("pub"),
            emb.generation(),
            emb.create("pub", "one.txt", b"1"),
            emb.generation(),
            emb.create("pub", "two.txt", b"2"),
            emb.generation(),
            emb.unlink("pub/one.txt"),
            emb.generation(),
        ]
    };
    let run_adapter = |session: &LiveSession| {
        let be = Adapter::new(session);
        let baseline = be.generation();
        let created = be.mkdir(1, "pub");
        let after_mkdir = be.generation();
        let publ = be.ino_of("pub").expect("pub resolves");
        let one = be.create(publ, "one.txt", b"1");
        let after_one = be.generation();
        let two = be.create(publ, "two.txt", b"2");
        let after_two = be.generation();
        let unlinked = be.unlink(publ, "one.txt");
        vec![
            baseline,
            created,
            after_mkdir,
            one,
            after_one,
            two,
            after_two,
            unlinked,
            be.generation(),
        ]
    };

    let embedded_session = LiveSession::fresh("pub-embedded");
    let embedded_trace = run(&embedded_session);
    let adapter_session = LiveSession::fresh("pub-adapter");
    let adapter_trace = run_adapter(&adapter_session);

    assert_same_traces(&embedded_trace, &adapter_trace);
    assert_eq!(embedded_trace[0], Outcome::Gen(0), "baseline is zero");
    let gens: Vec<u64> = embedded_trace
        .iter()
        .filter_map(|o| match o {
            Outcome::Gen(g) => Some(*g),
            _ => None,
        })
        .collect();
    assert!(
        gens.windows(2).all(|w| w[1] > w[0]),
        "every committing step advances the generation: {gens:?}"
    );

    // Stale aftermath, per-path documented tags (same theme as 43,
    // asserted individually): descriptors pin their open-time capture
    // (contract 5), so a pre-move handle keeps serving after the path
    // is gone; operating by the retired inode instead is `ESTALE`;
    // the handle-less embedded reader re-resolves to `not-found`, and
    // a create on a pre-bump parent token is `stale` through the
    // channel too.
    let stale_session = LiveSession::fresh("stale");
    let be = Adapter::new(&stale_session);
    be.create(1, "victim.txt", b"doomed")
        .into_ok("create serves");
    let victim_ino = be.ino_of("victim.txt").expect("victim resolves");
    let handle = be
        .backend
        .open_at("victim.txt")
        .expect("victim opens before the move");
    be.rename(1, "victim.txt", 1, "moved.txt")
        .into_ok("rename serves");
    be.unlink(1, "moved.txt").into_ok("unlink serves");
    let pinned = be.backend.read_handle(handle, 0, 64);
    assert_eq!(
        pinned.map_err(errno_tag),
        Ok(b"doomed".to_vec()),
        "a pre-move descriptor serves its capture past the delete"
    );
    assert_eq!(
        be.backend.set_size_at(victim_ino, 1).map_err(errno_tag),
        Err("not-found"),
        "a fully retired inode resolves nowhere, not even stale"
    );
    // A fully retired parent is gone, not stale: with blocking
    // submits there is no removal-race window (the `ESTALE` the
    // channel reports for a queued-but-unpublished removal needs two
    // racing threads), so removal-then-create resolves nowhere.
    be.mkdir(1, "p").into_ok("parent serves");
    let parent_ino = be.ino_of("p").expect("parent resolves");
    be.rmdir(1, "p").into_ok("parent removed");
    assert_eq!(
        be.create(parent_ino, "orphan.txt", b"x"),
        Outcome::Err("not-found"),
        "creating under a removed parent resolves nowhere"
    );
    let emb = Embedded::new(&stale_session);
    assert_eq!(
        emb.read("victim.txt"),
        Outcome::Err("not-found"),
        "the handle-less path re-resolves the vanished path"
    );
    assert_eq!(
        emb.stale_parent_create("stale-dir", "late.txt", b"x"),
        Outcome::Err("stale"),
        "a create on a pre-reincarnation parent token is stale through the channel too"
    );
}

/// Residency for the read-level conformance drive: store presence
/// serves, absent identities are remote-only unless listed terminal.
/// Mirrors what `RuntimeMaterialization` reports off engine state,
/// without an engine.
struct TriMaterialization {
    served: Vec<ContentId>,
    terminal: Vec<ContentId>,
}

impl Materialization for TriMaterialization {
    fn status(&self, id: &ContentId) -> FetchStatus {
        if self.terminal.contains(id) {
            FetchStatus::Unavailable(1)
        } else if self.served.contains(id) {
            FetchStatus::Available
        } else {
            FetchStatus::RemoteOnly
        }
    }
}

/// Contract 46: conflict and materialization reads agree — versioned
/// conflict reads serve the same bytes on both paths, served bytes
/// match, and each failure class surfaces its documented tag per
/// path (bounded wait versus immediate errno are structurally
/// different surfaces over the same verdict).
#[test]
fn embedded_and_adapter_readers_agree_on_conflicts_and_materialization() {
    let mut store = MemoryObjectStore::default();
    let served_id = store.insert(ObjectKind::Chunk, b"served bytes").unwrap();
    let v1 = store.insert(ObjectKind::Chunk, b"version one").unwrap();
    let v2 = store.insert(ObjectKind::Chunk, b"version two").unwrap();
    let remote_id = ContentId::from_bytes([0xE1; 32]);
    let gone_id = ContentId::from_bytes([0xE2; 32]);
    let root_a = Tree::from_entries(vec![
        Entry::file("served.txt", 12, false, vec![served_id]).unwrap(),
        Entry::file("remote.txt", 7, false, vec![remote_id]).unwrap(),
        Entry::file("gone.txt", 4, false, vec![gone_id]).unwrap(),
        Entry::file("f.txt", 11, false, vec![v1]).unwrap(),
    ])
    .unwrap()
    .insert_into(&mut store)
    .unwrap();
    // `served/remote/gone` agree across both heads, so only `f.txt`
    // diverges into a conflict: single-head presence would itself
    // conflict (creation versus deletion is undecidable in the merge).
    let root_b = Tree::from_entries(vec![
        Entry::file("served.txt", 12, false, vec![served_id]).unwrap(),
        Entry::file("remote.txt", 7, false, vec![remote_id]).unwrap(),
        Entry::file("gone.txt", 4, false, vec![gone_id]).unwrap(),
        Entry::file("f.txt", 11, false, vec![v2]).unwrap(),
    ])
    .unwrap()
    .insert_into(&mut store)
    .unwrap();
    let view = DriveView::new(
        store,
        TriMaterialization {
            served: vec![served_id],
            terminal: vec![gone_id],
        },
        fixture_heads(vec![signed_head(root_a), signed_head(root_b)]),
    );
    let projection = Arc::new(std::sync::RwLock::new(Arc::new(
        wyrd_core::projection::Projection::initial(view, 0),
    )));
    let backend = FuseBackend::shared(Arc::clone(&projection));
    let wants = Arc::new(WantRegistry::default());
    let reader = LiveReader::new(Duration::from_millis(150)).with_wants(Arc::clone(&wants));
    let view_projection = projection.read().expect("projection lock").clone();

    let read_embedded = |path: &str| match reader.read_file(view_projection.view(), path) {
        Ok(bytes) => Outcome::Bytes(bytes),
        Err(error) => Outcome::Err(read_tag(&error)),
    };
    let read_adapter = |path: &str| {
        let handle = match backend.open_at(path) {
            Ok(handle) => handle,
            Err(error) => return Outcome::Err(errno_tag(error)),
        };
        let bytes = backend.read_handle(handle, 0, u32::MAX);
        let _ = backend.release_handle(handle);
        match bytes {
            Ok(bytes) => Outcome::Bytes(bytes),
            Err(error) => Outcome::Err(errno_tag(error)),
        }
    };

    // Served bytes are identical through both readers.
    assert_eq!(
        read_embedded("served.txt"),
        Outcome::Bytes(b"served bytes".to_vec())
    );
    assert_eq!(read_embedded("served.txt"), read_adapter("served.txt"));

    // The conflicted path fails the plain name on both readers, and
    // the versioned names serve the same bytes in the same slots. The
    // plain-name tags differ by surface (the reader names the
    // conflict, the adapter reports the open refusal as `EIO`), so
    // they assert individually; the versioned reads compare across.
    assert_eq!(read_embedded("f.txt"), Outcome::Err("conflict"));
    assert_eq!(read_adapter("f.txt"), Outcome::Err("io-error"));
    let emb_versions = [read_embedded("f.txt@1"), read_embedded("f.txt@2")];
    let be_versions = [read_adapter("f.txt@1"), read_adapter("f.txt@2")];
    assert_eq!(emb_versions, be_versions);
    let mut union: Vec<Outcome> = emb_versions.into_iter().collect();
    union.sort_by_key(|o| format!("{o:?}"));
    assert_eq!(
        union,
        vec![
            Outcome::Bytes(b"version one".to_vec()),
            Outcome::Bytes(b"version two".to_vec()),
        ]
    );

    // Remote-only: the embedded read waits bounded and times out; the
    // adapter fails the demand-wait fast as `EIO` (documented on
    // `open_at`: a deadline expiry is never a partial file). Same
    // verdict, documented per-path tags.
    assert_eq!(read_embedded("remote.txt"), Outcome::Err("timed-out"));
    assert_eq!(read_adapter("remote.txt"), Outcome::Err("io-error"));

    // Terminally unavailable: fast failure on both. The reader names
    // the settled verdict; the adapter reports `EIO` like every other
    // demand failure — so the reader distinguishes remote-only from
    // terminal while the adapter collapses both, pinned here.
    assert_eq!(
        read_embedded("gone.txt"),
        Outcome::Err("terminal-unavailable")
    );
    assert_eq!(read_adapter("gone.txt"), Outcome::Err("io-error"));
}

/// Contract 47: committed bytes survive a restart with no running
/// daemon — reopen from custody, refresh heads, and both readers
/// serve the authored bytes.
#[test]
fn committed_bytes_survive_restart_without_a_running_daemon() {
    let dir = scratch_dir("shared-semantics-restart");
    let identity = DeviceIdentitySecret::generate().unwrap();
    let engine = Engine::create(dir.clone(), "restart-pass", identity.clone()).unwrap();
    let mut node: WyrdNode<DriveView<wyrd_format::FsObjectStore, RuntimeMaterialization>> =
        WyrdNode::new(
            engine,
            wyrd_format::FsObjectStore::open(dir.clone()).unwrap(),
        )
        .unwrap();
    node.put_file("keep.txt", b"persist me").unwrap();
    drop(node);

    let reopened = Engine::open_keystore(dir.clone(), "restart-pass", identity.clone()).unwrap();
    let mut reopened_node: WyrdNode<DriveView<wyrd_format::FsObjectStore, RuntimeMaterialization>> =
        WyrdNode::new(
            reopened,
            wyrd_format::FsObjectStore::open(dir.clone()).unwrap(),
        )
        .unwrap();
    reopened_node.refresh_live_heads().unwrap();
    // No loop is ever started: the bytes serve from custody alone.
    let (_, parts) = reopened_node
        .into_live(Duration::from_secs(30), &LiveConfig::default())
        .unwrap();
    let reader = LiveReader::new(Duration::from_secs(5));
    let projection = parts.projection.read().expect("projection lock").clone();
    let via_reader = match reader.read_file(projection.view(), "keep.txt") {
        Ok(bytes) => Outcome::Bytes(bytes),
        Err(error) => Outcome::Err(read_tag(&error)),
    };
    let backend = FuseBackend::shared_with_wants(
        Arc::clone(&parts.projection),
        Arc::clone(&parts.wants),
        Arc::clone(&parts.mutations),
        parts.open_timeout,
        &parts.budgets,
    );
    let handle = backend.open_at("keep.txt").expect("reopened drive serves");
    let via_adapter = backend.read_handle(handle, 0, 64).unwrap();
    let _ = backend.release_handle(handle);

    assert_eq!(via_reader, Outcome::Bytes(b"persist me".to_vec()));
    assert_eq!(via_adapter, b"persist me");
    std::fs::remove_dir_all(dir).unwrap();
}

/// Contract 48: shutdown closes the mutation channel for both paths —
/// new submissions fail closed on each side while already-published
/// bytes keep serving.
#[test]
fn shutdown_closes_the_mutation_channel_for_both_paths() {
    let mut session = LiveSession::fresh("shutdown");
    let emb = Embedded::new(&session);
    let be = Adapter::new(&session);
    emb.create("", "before.txt", b"pre-shutdown")
        .into_ok("pre-shutdown create serves");
    session.shutdown();

    assert_eq!(
        emb.submit(MutationKind::Mkdir {
            path: "after".to_string(),
        }),
        Outcome::Err("shutdown"),
        "the channel refuses admission after shutdown"
    );
    assert_eq!(
        be.create(1, "after.txt", b"x"),
        Outcome::Err("io-error"),
        "the adapter surfaces the closed channel as EIO instead of hanging"
    );
    // The published generation is undisturbed, and its bytes keep
    // serving on both readers: serving never needed the loop.
    assert_eq!(emb.generation(), be.generation());
    assert_eq!(
        emb.read("before.txt"),
        Outcome::Bytes(b"pre-shutdown".to_vec())
    );
    assert_eq!(be.read("before.txt"), emb.read("before.txt"));
}

/// Contract 49 (review F-1): fold coalescing agrees — several
/// buffered writes collapse into one snapshot at commit on the
/// adapter, matching one fold submit on the channel. Both sides
/// submit the same shape (create, then one fold carrying one
/// `CommitFile`), advance the generation in lockstep over two
/// chained commits, and serve the coalesced bytes.
#[test]
fn adapter_write_folding_matches_embedded_fold_script() {
    let chunks: &[&[u8]] = &[b"aa", b"bb", b"cc"];
    let merged: Vec<u8> = chunks.concat();
    let run = |session: &LiveSession| {
        let emb = Embedded::new(session);
        let baseline = emb.generation();
        // Create the empty file and take its minted identity: the
        // base the commit below must carry, exactly like the
        // adapter's handle-captured base.
        let (created, empty_base) = match emb.queue.submit(MutationKind::CreateFile {
            path: "fold.txt".to_string(),
            parent: emb.queue.capture_parent("").expect("root token"),
        }) {
            Ok(MutationOutcome::Created(identity)) => (Outcome::Ok, Some(identity)),
            Ok(_) => (Outcome::Err("unexpected-outcome"), None),
            Err(error) => (Outcome::Err(mutation_tag(&error)), None),
        };
        let after_create = emb.generation();
        let base = empty_base.expect("create mints an identity");
        let first_id = emb
            .fold_commit("fold.txt", base, &merged)
            .expect("first fold commits");
        let after_fold = emb.generation();
        let first_read = emb.read("fold.txt");
        // Second commit chains on the committed identity: the base
        // comparison is pinned past empty, not just at bootstrap.
        emb.fold_commit("fold.txt", first_id, b"aabbccdd")
            .expect("second fold commits");
        vec![
            baseline,
            created,
            after_create,
            Outcome::Ok,
            after_fold,
            first_read,
            Outcome::Ok,
            emb.generation(),
            emb.read("fold.txt"),
        ]
    };
    let run_adapter = |session: &LiveSession| {
        let be = Adapter::new(session);
        let baseline = be.generation();
        let handle = be.begin_create(1, "fold.txt").expect("create opens");
        let after_create = be.generation();
        let committed = be.commit_writes(handle, chunks);
        let after_fold = be.generation();
        let first_read = be.read("fold.txt");
        let rewritten = be.rewrite("fold.txt", 6, b"dd");
        vec![
            baseline,
            Outcome::Ok,
            after_create,
            committed,
            after_fold,
            first_read,
            rewritten,
            be.generation(),
            be.read("fold.txt"),
        ]
    };

    let embedded_session = LiveSession::fresh("fold-embedded");
    let embedded_trace = run(&embedded_session);
    let adapter_session = LiveSession::fresh("fold-adapter");
    let adapter_trace = run_adapter(&adapter_session);

    assert_same_traces(&embedded_trace, &adapter_trace);
    assert_eq!(
        embedded_trace[5],
        Outcome::Bytes(b"aabbcc".to_vec()),
        "the fold serves the coalesced bytes"
    );
    assert_eq!(
        embedded_trace[8],
        Outcome::Bytes(b"aabbccdd".to_vec()),
        "the chained commit extends the image"
    );
    let gens: Vec<u64> = embedded_trace
        .iter()
        .filter_map(|o| match o {
            Outcome::Gen(g) => Some(*g),
            _ => None,
        })
        .collect();
    assert_eq!(
        gens,
        vec![gens[0], gens[0] + 1, gens[0] + 2, gens[0] + 3],
        "create plus two folds is three snapshots in lockstep: {gens:?}"
    );
}

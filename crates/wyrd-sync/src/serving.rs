//! The durable serving surface: sealed envelopes the device authored or
//! fetched, keyed by the transport root the mappings and announcements
//! name (object-model.md decision 26). Append-only like the object
//! store; importing a root that is already held is a no-op, and a
//! restart loses nothing — the bytes are the drive's own ciphertext on
//! disk.
//!
//! [`Vault`] stores raw representation bytes and answers by the address
//! the bytes themselves hash to: the transport root, the same value the
//! verified transfer checks. [`VaultSource`] layers the composer's
//! durable runtime state over the vault so the eager snapshot/root
//! addresses (`sync-and-peers.md` exchange) also serve: the maps are
//! rebuilt from records and bodies on every pass, so restart
//! rehydration is "rebuild from durable state", never "rehydrate bytes".

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh::{endpoint::presets, protocol::Router, Endpoint, EndpointAddr};
use iroh_blobs::{store::fs::FsStore, BlobsProtocol};
use thiserror::Error;
use wyrd_format::durable;
use wyrd_format::{BaoRoot, ContentId, SnapshotId, StorageId};

use crate::bulk::{AttemptBudget, BulkError, BulkSource, SealedManifest};
use crate::runtime::RuntimeState;
use crate::seal::blob_root;
use crate::transport::encode_node_addr;

/// The vault directory inside a drive directory.
const VAULT_DIR: &str = "vault";

/// A raw byte CAS with no authorization semantics: it stores and serves
/// bytes under their own hash, for whoever is allowed to reach the
/// drive's ciphertext at all. Authorization lives one layer up —
/// [`VaultSource`] offers only representations durably recorded by the
/// runtime machines, and every fetch still passes the AEAD/identity
/// admission checks before plaintext is trusted.
/// Bound for the serving mirror write-through queue: at most this many
/// representations wait for the drain task, and at most this many bytes
/// across them. A single representation can reach `Limits::V0`
/// `max_object_bytes` (64 MiB), so the byte bound admits one max-size
/// item while the item bound absorbs bursts of small manifests. The
/// reservation is released when the drain worker receives an item (not
/// when the import lands), so peak memory for one max-size object is
/// roughly three times the bound: the queued reservation, the in-flight
/// import the worker holds, and the caller's own buffer plus its
/// write-through copy. Bounded at a known multiple, as the issue
/// requires — never proportional to authoring speed.
/// Overflow applies backpressure at [`Vault::import`] (a typed
/// [`VaultError::MirrorFull`], retried on a later pass) instead of
/// growing without bound, and [`ServingHandle::flush_bounded`] reports
/// a full queue as not-ready so announcements never discharge over
/// representations the mirror has not served.
pub const MAX_MIRROR_QUEUE_ITEMS: usize = 64;
pub const MAX_MIRROR_QUEUE_BYTES: usize = 64 << 20;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("vault I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// The serving mirror queue is full: the vault file is durable
    /// (the rename happened before write-through), but the mirror has
    /// not accepted these bytes. Retry the import on a later pass;
    /// the readiness barrier reports not-ready until the drain
    /// catches up, and a restart rebuilds the mirror from the vault.
    /// Per-item backpressure, never a batch wedge (see
    /// `docs/error-conventions.md`). Carries the refused transport
    /// root so a rejection traces to its publication.
    #[error("serving mirror queue full for {root}: {queued_bytes}/{max_bytes} bytes in {queued_items} items, rejected {rejected}")]
    MirrorFull {
        root: BaoRoot,
        queued_items: usize,
        queued_bytes: usize,
        max_bytes: usize,
        rejected: u64,
    },
}

/// Shared accounting for one serving mirror queue: queued depth in
/// items and bytes plus rejection/failure counters. One `Arc` is held
/// by the write-through sender, the drain worker, and every readiness
/// handle, so [`MirrorStats`] reads the live queue without locking.
#[derive(Debug, Default)]
struct MirrorAccounting {
    queued_items: std::sync::atomic::AtomicUsize,
    queued_bytes: std::sync::atomic::AtomicUsize,
    rejected_full: std::sync::atomic::AtomicU64,
    failed_imports: std::sync::atomic::AtomicU64,
}

impl MirrorAccounting {
    /// Release one item permit as its item is handled. Saturating:
    /// the drain owns the release half, and a miscount must decay
    /// the counters, never underflow them into nonsense the
    /// observability surface then reports.
    fn release_item(&self) {
        let _ = self
            .queued_items
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |items| {
                Some(items.saturating_sub(1))
            });
    }

    /// Release a byte reservation as its item is handled. Saturating,
    /// for the same reason as [`release_item`](Self::release_item).
    fn release_bytes(&self, len: usize) {
        let _ = self
            .queued_bytes
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |bytes| {
                Some(bytes.saturating_sub(len))
            });
    }
}

/// Point-in-time serving mirror queue observability: depth against the
/// [`MAX_MIRROR_QUEUE_ITEMS`] / [`MAX_MIRROR_QUEUE_BYTES`] bounds plus
/// the rejection and failure counters. A rising `rejected_full` names
/// a mirror slower than authoring; a nonzero `failed_imports` names a
/// mirror store that cannot land what the vault holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MirrorStats {
    pub queued_items: usize,
    pub queued_bytes: usize,
    pub capacity_items: usize,
    pub capacity_bytes: usize,
    pub rejected_full: u64,
    pub failed_imports: u64,
}

/// The bounded write-through sender for one serving mirror: a
/// [`tokio::sync::mpsc::Sender`] plus the shared [`MirrorAccounting`].
/// Cloned into the vault slot, the endpoint, and every readiness
/// handle; the drain worker holds the accounting half.
#[derive(Debug, Clone)]
pub(crate) struct MirrorSender {
    inner: tokio::sync::mpsc::Sender<MirrorItem>,
    accounting: std::sync::Arc<MirrorAccounting>,
}

pub(crate) fn mirror_channel() -> (MirrorSender, tokio::sync::mpsc::Receiver<MirrorItem>) {
    let (inner, receiver) = tokio::sync::mpsc::channel::<MirrorItem>(MAX_MIRROR_QUEUE_ITEMS);
    (
        MirrorSender {
            inner,
            accounting: std::sync::Arc::new(MirrorAccounting::default()),
        },
        receiver,
    )
}

impl MirrorSender {
    /// The single backpressure constructor: counts one rejection and
    /// snapshots the live depth, so every `MirrorFull` reports
    /// consistent counters.
    fn mirror_full(&self, root: BaoRoot) -> VaultError {
        VaultError::MirrorFull {
            root,
            queued_items: self.accounting.queued_items.load(Ordering::SeqCst),
            queued_bytes: self.accounting.queued_bytes.load(Ordering::SeqCst),
            max_bytes: MAX_MIRROR_QUEUE_BYTES,
            rejected: self.accounting.rejected_full.fetch_add(1, Ordering::SeqCst) + 1,
        }
    }

    /// Enqueue one sealed representation, reserving its bytes first so
    /// the aggregate stays under [`MAX_MIRROR_QUEUE_BYTES`] even when
    /// many small senders race. A closed channel (mirror detached)
    /// releases the reservation and reports `Ok`: serving heals on the
    /// next boot rebuild, never by failing the publication.
    fn send_import(&self, root: BaoRoot, bytes: Vec<u8>) -> Result<(), VaultError> {
        let len = bytes.len();
        loop {
            let queued = self.accounting.queued_bytes.load(Ordering::SeqCst);
            let over = match queued.checked_add(len) {
                Some(total) => total > MAX_MIRROR_QUEUE_BYTES,
                None => true,
            };
            if over {
                return Err(self.mirror_full(root));
            }
            if self
                .accounting
                .queued_bytes
                .compare_exchange(queued, queued + len, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                break;
            }
        }
        self.accounting.queued_items.fetch_add(1, Ordering::SeqCst);
        match self.inner.try_send(MirrorItem::Import(bytes)) {
            Ok(()) => Ok(()),
            Err(tokio::sync::mpsc::error::TrySendError::Full(MirrorItem::Import(returned))) => {
                self.accounting.release_item();
                self.accounting.release_bytes(returned.len());
                Err(self.mirror_full(root))
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                // A non-import item shares the item bound but holds no
                // byte reservation of its own: release what this call
                // reserved and report backpressure. Unreachable through
                // this path today (imports are the only callers), but
                // the accounting must stay exact if that changes.
                self.accounting.release_item();
                self.accounting.release_bytes(len);
                Err(self.mirror_full(root))
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                self.accounting.release_item();
                self.accounting.release_bytes(len);
                Ok(())
            }
        }
    }

    /// Enqueue a barrier item, which carries no import bytes and so
    /// contends only for the item bound. The single send path that
    /// maintains the item pairing: every barrier `try_send` goes
    /// through this helper, so `stats` tracks waiting work, not
    /// history. Returns the channel error with the item permit
    /// already released.
    fn send_barrier(
        &self,
        item: MirrorItem,
    ) -> Result<(), tokio::sync::mpsc::error::TrySendError<MirrorItem>> {
        self.accounting.queued_items.fetch_add(1, Ordering::SeqCst);
        match self.inner.try_send(item) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.accounting.release_item();
                Err(error)
            }
        }
    }

    fn stats(&self) -> MirrorStats {
        MirrorStats {
            queued_items: self.accounting.queued_items.load(Ordering::SeqCst),
            queued_bytes: self.accounting.queued_bytes.load(Ordering::SeqCst),
            capacity_items: MAX_MIRROR_QUEUE_ITEMS,
            capacity_bytes: MAX_MIRROR_QUEUE_BYTES,
            rejected_full: self.accounting.rejected_full.load(Ordering::SeqCst),
            failed_imports: self.accounting.failed_imports.load(Ordering::SeqCst),
        }
    }
}

/// The drive's sealed representation store: one file per transport root,
/// named by the root's hex, written atomically and never rewritten.
pub struct Vault {
    dir: PathBuf,
    /// The live serving mirror's bounded write-through sender, attached
    /// by [`ServingEndpoint::open`] and replaced (never co-held) on
    /// reopen. Imports enqueue after the durable rename, so the vault
    /// stays the source of truth and the mirror is a derived,
    /// self-healing cache: a detached channel or a failed mirror import
    /// only delays serving until the next boot rebuild, while a full
    /// queue applies backpressure at import time (never a silent drop).
    /// The slot is shared (`Arc`) so the endpoint can detach it on
    /// shutdown: an import after shutdown must not enqueue into a
    /// channel nobody will drain.
    mirror: std::sync::Arc<Mutex<Option<MirrorSender>>>,
    /// Publication durability and its pending-directory recovery state.
    /// Production uses [`durable::fsync_dir`]; tests replace it to inject
    /// a post-rename durability failure and exercise the recovery path.
    durability: durable::Durability,
}

/// One write-through item for the serving mirror.
pub(crate) enum MirrorItem {
    /// Newly durable sealed bytes to import into the serving store.
    Import(Vec<u8>),
    /// A drain barrier: the sender receives readiness once every earlier
    /// import has been handled — `Ok` when all landed, `Err` naming the
    /// first import failure (sticky until restart, see [`drain_mirror`]).
    Flush(
        tokio::sync::oneshot::Sender<Result<(), String>>,
        /// The caller's in-flight permit: cleared by the worker when
        /// the barrier is actually handled, never by the caller's
        /// timeout — a timed-out barrier still sits in the queue, and
        /// a permit released early would let the next pass queue
        /// another one behind it.
        Option<Arc<std::sync::atomic::AtomicBool>>,
    ),
}

/// A cloneable readiness handle for a serving endpoint: the channel
/// and runtime the [`flush`](ServingEndpoint::flush) barrier needs,
/// without the owned router and runtime the endpoint's shutdown
/// consumes. The composer hands one to the live loop's serving
/// barrier, so every publish pass gates announcement discharge on
/// mirror readiness while endpoint ownership (and shutdown) stays
/// with the composer.
#[derive(Debug, Clone)]
pub struct ServingHandle {
    runtime: tokio::runtime::Handle,
    sender: MirrorSender,
    /// At most one barrier is in flight: a caller whose timed-out
    /// barrier is still queued behind a slow import must not pile
    /// more barriers onto the bounded channel (they would only
    /// queue more stale acks). While set, a second caller reports
    /// "not ready" instead of enqueueing its own.
    barrier_in_flight: Arc<std::sync::atomic::AtomicBool>,
}

impl ServingHandle {
    /// Wait until every import enqueued so far has landed in the
    /// serving mirror. A mirror import that failed makes the barrier
    /// fail — announcing over a representation the mirror cannot
    /// serve would strand the peer until a restart.
    pub fn flush(&self) -> std::io::Result<()> {
        match self.flush_bounded(std::time::Duration::MAX) {
            Ok(true) => Ok(()),
            Ok(false) => Err(std::io::Error::other("serving mirror drain stopped")),
            Err(error) => Err(error),
        }
    }

    /// The barrier under a time budget: `Ok(true)` once every earlier
    /// import landed, `Ok(false)` when the budget ran out first (the
    /// drain continues in the background and the next barrier sees
    /// it) or the bounded queue is full behind a slow mirror, `Err`
    /// when the mirror failed or is gone. A caller gating
    /// discharge treats "not ready" exactly like failure: skip the
    /// send, retry next pass — the readiness ordering never weakens,
    /// and a slow mirror can no longer stretch the caller's pass.
    pub fn flush_bounded(&self, budget: std::time::Duration) -> Result<bool, std::io::Error> {
        // One outstanding barrier: a caller that finds one in flight
        // (the previous pass timed out but its item is still queued
        // behind a slow import) reports "not ready" instead of
        // queueing another onto the bounded channel.
        if self
            .barrier_in_flight
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Ok(false);
        }
        let release = Arc::clone(&self.barrier_in_flight);
        let (ack, wait) = tokio::sync::oneshot::channel();
        match self.try_send_flush(MirrorItem::Flush(ack, Some(Arc::clone(&release)))) {
            Ok(()) => {}
            Err(FlushSend::Full) => {
                // The queue is full of imports behind a slow drain:
                // no room for the barrier either. Release the permit
                // (nothing was enqueued, so no worker will clear it)
                // and report not-ready; the next pass retries.
                release.store(false, Ordering::SeqCst);
                return Ok(false);
            }
            Err(FlushSend::Closed(error)) => {
                release.store(false, Ordering::SeqCst);
                return Err(error);
            }
        }
        // The timeout runs as a task on the runtime: a bare
        // `Handle::block_on` drives no timer, so the deadline would
        // panic instead of firing.
        let waiter = self.runtime.spawn(async move {
            // On timeout the barrier is still queued: the permit stays
            // held until the worker handles it (the drain clears it),
            // so coalescing reflects actual queue consumption.
            match tokio::time::timeout(budget, wait).await {
                Ok(Ok(Ok(()))) => Ok(true),
                Ok(Ok(Err(message))) => Err(std::io::Error::other(format!(
                    "serving mirror import failed: {message}"
                ))),
                Ok(Err(_)) => Err(std::io::Error::other("serving mirror drain stopped")),
                Err(_) => Ok(false),
            }
        });
        self.runtime.block_on(waiter).map_err(|_| {
            // The task itself was lost (runtime gone): nothing will
            // clear the permit, so release it here.
            release.store(false, Ordering::SeqCst);
            std::io::Error::other("serving barrier task lost")
        })?
    }

    /// Live queue observability: depth against the item/byte bounds
    /// plus rejection and failure counters.
    pub fn stats(&self) -> MirrorStats {
        self.sender.stats()
    }

    /// Enqueue a drain barrier without blocking: `Full` (no room
    /// behind a slow drain) is a distinct, non-error outcome the
    /// caller maps to not-ready; `Closed` (mirror detached) is an
    /// I/O error like before.
    fn try_send_flush(&self, item: MirrorItem) -> Result<(), FlushSend> {
        // Barriers carry no import bytes, so they bypass the byte
        // reservation and only contend for the item bound. The item
        // pairing lives in `MirrorSender::send_barrier`, the single
        // barrier send path.
        match self.sender.send_barrier(item) {
            Ok(()) => Ok(()),
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => Err(FlushSend::Full),
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Err(FlushSend::Closed(
                std::io::Error::other("serving mirror closed"),
            )),
        }
    }
}

/// The non-blocking barrier-send outcome: a full queue is backpressure
/// (report not-ready), a closed channel is a gone mirror (error).
enum FlushSend {
    Full,
    Closed(std::io::Error),
}

/// Unique temp-file suffix so concurrent imports of the same root never
/// share a scratch path (same-root importers race only at the atomic
/// rename, where the bytes are identical by construction).
static NEXT_TMP: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

impl Vault {
    /// Open (or create) the vault directory under a drive directory.
    pub fn open(drive_dir: &Path) -> Result<Self, VaultError> {
        let dir = drive_dir.join(VAULT_DIR);
        std::fs::create_dir_all(&dir)?;
        Ok(Vault {
            dir,
            mirror: std::sync::Arc::new(Mutex::new(None)),
            durability: durable::Durability::new(),
        })
    }

    /// The mirror slot, shared with the serving endpoint that owns the
    /// drain task. The endpoint clears it on shutdown.
    pub(crate) fn mirror_slot(&self) -> std::sync::Arc<Mutex<Option<MirrorSender>>> {
        std::sync::Arc::clone(&self.mirror)
    }

    /// Bytes of sealed representations on disk, counted without
    /// touching anything. The observational half of retention
    /// reporting alongside the fact log: the vault is resident but
    /// unenforced, so `cache policy` shows this next to the
    /// quota-enforced object-store count rather than folding it in.
    /// Import scratch files (`.tmp-*`, a crashed import's debris) are
    /// excluded — they are not servable representations — and a missing
    /// vault directory counts as zero.
    pub fn resident_bytes(&self) -> Result<u64, VaultError> {
        let mut total = 0u64;
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(VaultError::Io(error)),
        };
        for entry in entries {
            let entry = entry.map_err(VaultError::Io)?;
            // One stat per entry: `metadata` answers both questions —
            // kind and length. `DirEntry::metadata` does not traverse
            // symlinks, so a symlink inside the vault directory is
            // excluded from the observational count rather than
            // followed out of the measured tree. A file that vanishes
            // first was never ours to count; any other listing failure
            // is operational.
            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(VaultError::Io(error)),
            };
            if !metadata.is_file() {
                continue;
            }
            let path = entry.path();
            if path
                .file_name()
                .is_some_and(|name| name.as_encoded_bytes().starts_with(b".tmp-"))
            {
                continue;
            }
            total += metadata.len();
        }
        Ok(total)
    }

    /// Import sealed bytes: the file name is the bytes' own transport
    /// root, so the address handed out is exactly what the transfer
    /// verifies against. Importing an already-held root is a no-op —
    /// objects are immutable and the store is append-only. The temp file
    /// is scoped to the root (distinct roots never collide on the temp
    /// path), and the rename is the publication point: a torn write
    /// leaves a temp file, never a servable root. Publication uses the
    /// same crash protocol as the object store (temp + `fsync` + rename +
    /// directory `fsync`, `wyrd_format::durable`), so the new directory
    /// entry, not just the ciphertext, survives a power failure.
    ///
    /// The rename and the directory `fsync` are distinct stages. A rename
    /// failure leaves nothing published, but a directory-`fsync` failure
    /// leaves the file installed and not known durable; that error is
    /// surfaced, and a retry takes the held-root path, which re-syncs the
    /// directory and re-imports into the mirror. Both are idempotent, so a
    /// crash between the rename and the mirror write-through heals too.
    pub fn import(&self, sealed: &[u8]) -> Result<BaoRoot, VaultError> {
        let root = blob_root(sealed);
        let path = self.path(&root);
        // Repair any directory whose earlier publication failed its
        // fsync before deciding the import is a no-op.
        self.durability.reconcile()?;
        if path.is_file() {
            self.reconcile_held(root, sealed)?;
            return Ok(root);
        }
        let tmp = self.dir.join(format!(
            ".tmp-{}-{}-{}",
            root,
            std::process::id(),
            NEXT_TMP.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        self.durability.write_temp(&tmp, sealed)?;
        match self.durability.publish_temp(&tmp, &path) {
            Ok(()) => {}
            Err(durable::PublishError::Rename(error)) => {
                let _ = std::fs::remove_file(&tmp);
                // A concurrent import of the same root may have published
                // first; identical bytes hash to the same root, so the
                // existing file is the winner and this call reconciles
                // instead of failing.
                if path.is_file() {
                    self.reconcile_held(root, sealed)?;
                    return Ok(root);
                }
                return Err(error.into());
            }
            Err(durable::PublishError::DirectorySync(error)) => {
                // The rename installed the file but its directory entry is
                // not known durable. Notify the mirror best-effort so the
                // failure does not also strand serving readiness, then
                // surface the durability error; a retry re-syncs the
                // directory. Best-effort is literal here: even a full
                // queue — and even a poisoned slot — must not outrank
                // the error the caller was promised. The retry's
                // held-root path re-imports into the mirror once the
                // drain has room, and still surfaces a poisoned slot
                // through that path.
                let _ = self.notify_mirror(root, sealed);
                return Err(error.into());
            }
        }
        self.notify_mirror(root, sealed)?;
        Ok(root)
    }

    /// Make an already-held root durable and served: confirm the vault
    /// directory's durability and re-import into the mirror. Both steps
    /// are idempotent, so this heals a prior post-rename `fsync` failure
    /// (including across a restart), a crash before the mirror
    /// write-through, or a concurrent winner this process never observed.
    /// Takes the already-computed root: rehashing here would pay a full
    /// pass over the representation on exactly the degraded path this
    /// queue exists to keep cheap.
    fn reconcile_held(&self, root: BaoRoot, sealed: &[u8]) -> Result<(), VaultError> {
        self.durability.verify_dir(&self.dir)?;
        self.notify_mirror(root, sealed)?;
        Ok(())
    }

    /// Write-through to the serving mirror. A detached channel only
    /// delays serving until the next boot rebuild, never the
    /// publication — but a poisoned slot lock fails the import, and a
    /// full bounded queue applies backpressure (`VaultError::MirrorFull`,
    /// naming the refused root): the vault file is already durable, so
    /// the caller retries the import on a later pass and the readiness
    /// barrier stays not-ready until the drain catches up. Poison means
    /// a thread panicked mid-critical-section, so the operation fails
    /// instead of the process.
    fn notify_mirror(&self, root: BaoRoot, sealed: &[u8]) -> Result<(), VaultError> {
        let sender = self
            .mirror
            .lock()
            .map_err(|_| std::io::Error::other("vault mirror lock poisoned"))?
            .clone();
        if let Some(sender) = sender {
            sender.send_import(root, sealed.to_vec())?;
        }
        Ok(())
    }

    /// Live queue observability, if a mirror is attached: `None` when
    /// serving is detached (shutdown or never opened).
    pub fn mirror_stats(&self) -> Option<MirrorStats> {
        self.mirror
            .lock()
            .ok()?
            .as_ref()
            .map(|sender| sender.stats())
    }

    /// Attach the write-through channel of a serving mirror. Replacing
    /// an already-attached channel strands the old one (its sends fail
    /// and are ignored); a serving restart is the normal replacement.
    pub(crate) fn attach_mirror(&self, sender: MirrorSender) -> Result<(), VaultError> {
        *self
            .mirror
            .lock()
            .map_err(|_| std::io::Error::other("vault mirror lock poisoned"))? = Some(sender);
        Ok(())
    }

    /// The sealed bytes at a transport root, if held — and the read is
    /// verified: filenames are mutable filesystem state, so a file whose
    /// contents no longer hash to its name is not the requested
    /// representation. A mismatch is absence (`None`), never bytes under
    /// the wrong root; the corrupt file is left in place for an explicit
    /// scrub path (reads never mutate append-only state).
    pub fn sealed(&self, root: &BaoRoot) -> Result<Option<Vec<u8>>, VaultError> {
        match std::fs::read(self.path(root)) {
            Ok(bytes) => {
                if blob_root(&bytes) == *root {
                    Ok(Some(bytes))
                } else {
                    Ok(None)
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// Every transport root held. Unreferenced bytes are harmless
    /// (append-only CAS; GC does not exist in v0), and this iterator is
    /// how the composer reconciles vault residency against the records.
    pub fn roots(&self) -> Result<Vec<BaoRoot>, VaultError> {
        let mut roots = Vec::new();
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Ok(bytes) = hex_to_32(&name) {
                if entry.metadata()?.is_file() {
                    roots.push(BaoRoot::from_bytes(bytes));
                }
            }
        }
        roots.sort();
        Ok(roots)
    }

    fn path(&self, root: &BaoRoot) -> PathBuf {
        self.dir.join(root.to_string())
    }
}

/// The vault directory inside a drive directory holding the serving
/// mirror's own bao-encoded copy of held representations. The vault is
/// the durable source of truth; this directory is derived state,
/// rebuilt from it on every [`ServingEndpoint::open`]. The copy is the
/// cost of riding iroh-blobs' supported serving path instead of a
/// version-coupled custom store backend; unifying the two stores is a
/// post-v1 storage question (GC does not exist in v0).
const SERVE_DIR: &str = "serve";

/// Bound for the blocking runtime shutdown in [`ServingEndpoint::shutdown`]:
/// worker threads normally exit in milliseconds once the endpoint, router,
/// and mirror drain are done; the bound only bites when teardown itself is
/// wedged, and a wedged shutdown must surface as a slow close rather than
/// a silently lingering thread pool.
const RUNTIME_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

/// A real-iroh serving surface over the durable vault.
///
/// One iroh endpoint accepting iroh-blobs fetches from an [`FsStore`]
/// mirror beside the vault: every sealed representation the vault holds
/// is servable by its transport root, which is exactly the address the
/// verified transfer checks. The mirror is derived state — rebuilt from
/// the vault at [`open`](Self::open), fed write-through through the
/// vault's attached channel, and healed by the next restart when either
/// side drifts.
///
/// The endpoint owns its own multi-thread runtime (the router and the
/// write-through drain are spawned tasks on it), so composition stays
/// sync: [`open`](Self::open) returns with serving fully live, and
/// [`flush`](Self::flush) orders serving readiness against announcement
/// (flush before announcing the address, so a peer that acts on the
/// announcement finds every byte importable).
pub struct ServingEndpoint {
    runtime: tokio::runtime::Runtime,
    router: Router,
    endpoint: Endpoint,
    /// Clone of the bounded write-through sender, for [`flush`](Self::flush).
    sender: MirrorSender,
    /// The vault's mirror slot, cleared on shutdown so imports stop.
    mirror: std::sync::Arc<Mutex<Option<MirrorSender>>>,
}

/// The serving mirror's write-through worker: import each queued
/// representation, remember the first failure, and answer each barrier
/// with the accumulated readiness. A failed import is sticky until a
/// restart: the vault treats an already-held root as a no-op, so the
/// representation is never re-queued, and the boot rebuild is the healing
/// path. Extracted so tests can inject an import that fails and prove
/// `flush` reports it instead of claiming readiness.
///
/// The worker owns the accounting half: it releases the byte/item
/// reservation on receipt (the bound covers waiting bytes, not the one
/// in-flight import) and counts landed failures for [`MirrorStats`].
async fn drain_mirror<F, Fut>(
    mut receiver: tokio::sync::mpsc::Receiver<MirrorItem>,
    accounting: std::sync::Arc<MirrorAccounting>,
    mut import: F,
) where
    F: FnMut(Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    let mut failure: Option<String> = None;
    while let Some(item) = receiver.recv().await {
        // Every queued item held one item permit, released as it is
        // handled so `stats` tracks waiting work, not history. A
        // barrier that timed out still sits in the queue and still
        // holds its permit until handled here. Releases saturate
        // instead of underflowing: a miscount decays the counters,
        // never wraps them.
        accounting.release_item();
        match item {
            MirrorItem::Import(bytes) => {
                accounting.release_bytes(bytes.len());
                if let Err(error) = import(bytes).await {
                    accounting.failed_imports.fetch_add(1, Ordering::SeqCst);
                    failure.get_or_insert(error);
                }
            }
            MirrorItem::Flush(ack, permit) => {
                let _ = ack.send(match &failure {
                    Some(error) => Err(error.clone()),
                    None => Ok(()),
                });
                if let Some(permit) = permit {
                    permit.store(false, std::sync::atomic::Ordering::SeqCst);
                }
            }
        }
    }
}

impl ServingEndpoint {
    /// Serve the vault over a default iroh endpoint: N0 relays for
    /// reachability, standard address discovery.
    pub fn open(vault: &Vault, drive_dir: &Path) -> std::io::Result<Self> {
        Self::open_with(vault, drive_dir, Endpoint::builder(presets::N0))
    }

    /// Serve the vault over a relay-disabled loopback endpoint with
    /// address discovery cleared: hermetic serving for two daemons on
    /// one host, the shape the contract suite composes.
    pub fn open_loopback(vault: &Vault, drive_dir: &Path) -> std::io::Result<Self> {
        Self::open_with(
            vault,
            drive_dir,
            Endpoint::builder(presets::N0DisableRelay).clear_address_lookup(),
        )
    }

    fn open_with(
        vault: &Vault,
        drive_dir: &Path,
        builder: iroh::endpoint::Builder,
    ) -> std::io::Result<Self> {
        let serve_dir = drive_dir.join(SERVE_DIR);
        std::fs::create_dir_all(&serve_dir)?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        let endpoint = runtime
            .block_on(builder.bind())
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let store = runtime
            .block_on(FsStore::load(&serve_dir))
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        // Boot rebuild: every root the vault holds becomes servable.
        // A sealed() read that fails verification names a corrupt
        // vault file and is skipped (absence, not bytes under the
        // wrong root). The vault is the truth for serving, and it
        // repairs on its own plane: client-plane quarantine (`12`)
        // discards rejected representations without touching vault
        // bytes, and vault-byte repair belongs to scrub (`13`) —
        // never to a client read's side effects.
        for root in vault.roots().map_err(std::io::Error::other)? {
            let Some(sealed) = vault.sealed(&root).map_err(std::io::Error::other)? else {
                continue;
            };
            runtime
                .block_on(async { store.blobs().add_bytes(sealed).await })
                .map_err(|error| std::io::Error::other(error.to_string()))?;
        }
        let (sender, receiver) = mirror_channel();
        let blobs = store.blobs().clone();
        let accounting = std::sync::Arc::clone(&sender.accounting);
        let router = runtime.block_on(async {
            tokio::spawn(drain_mirror(receiver, accounting, move |bytes| {
                let blobs = blobs.clone();
                async move {
                    blobs
                        .add_bytes(bytes::Bytes::from(bytes))
                        .await
                        .map(|_| ())
                        .map_err(|error| error.to_string())
                }
            }));
            Router::builder(endpoint.clone())
                // No per-requester check here, by design (trust.md
                // T17): the second argument is a telemetry sink, not
                // an admission hook — the protocol has no
                // per-requester admission point. The (address, hash)
                // pairs that make a lookup possible travel inside
                // sealed announcements to members and readers alone;
                // admission is content verification on the fetch side.
                // A root with no published route is absence at the
                // fetch plane (the endpoint itself answers an unheld
                // root with a protocol error, and answers no listing).
                // The push half lands nothing: pushes issued through
                // the public client never register in the mirror, so
                // the serve-only role needs no admission hook and no
                // protocol wrapper (a wrapper would fork the crate's
                // dispatch for zero behavior change). Upstream does
                // declare `push: Disabled` in `EventMask::DEFAULT`,
                // but that field is not consulted on the request path
                // in iroh-blobs 0.103.0 — the pin is behavioral, not a
                // mask reading. `serving_mount_refuses_push_and_leaves_the_mirror_unchanged`
                // re-verifies it end to end; if a dependency bump ever
                // makes a push land, that test is where it shows.
                .accept(iroh_blobs::ALPN, BlobsProtocol::new(&store, None))
                .spawn()
        });
        let mirror = vault.mirror_slot();
        vault
            .attach_mirror(sender.clone())
            .map_err(std::io::Error::other)?;
        Ok(ServingEndpoint {
            runtime,
            router,
            endpoint,
            sender,
            mirror,
        })
    }

    /// The endpoint's current connectable address: node id, direct ip
    /// addresses, and relay url. This is what an announcement's
    /// `node_addr` encodes; call [`flush`](Self::flush) first.
    pub fn addr(&self) -> EndpointAddr {
        self.endpoint.addr()
    }

    /// The endpoint's route as canonical announcement bytes.
    pub fn node_addr_bytes(&self) -> Vec<u8> {
        encode_node_addr(&self.addr())
    }

    /// A cloneable readiness handle for the live loop's serving
    /// barrier: shares this endpoint's mirror channel and runtime, so
    /// per-pass announcement gating does not move the endpoint.
    pub fn handle(&self) -> ServingHandle {
        ServingHandle {
            runtime: self.runtime.handle().clone(),
            sender: self.sender.clone(),
            barrier_in_flight: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Wait until every import enqueued so far has landed in the serving
    /// mirror. Publication paths flush before announcing, so a peer acting
    /// on the announcement never races the write-through. A mirror import
    /// that failed makes the barrier fail — announcing over a representation
    /// the mirror cannot serve would strand the peer until a restart.
    pub fn flush(&self) -> std::io::Result<()> {
        self.handle().flush()
    }

    /// The endpoint's barrier under a time budget: see
    /// [`ServingHandle::flush_bounded`].
    pub fn flush_bounded(&self, budget: std::time::Duration) -> Result<bool, std::io::Error> {
        self.handle().flush_bounded(budget)
    }

    /// Live queue observability for this endpoint's mirror.
    pub fn stats(&self) -> MirrorStats {
        self.sender.stats()
    }

    /// Stop serving and join the runtime. The vault's write-through slot
    /// is cleared first: imports made after shutdown must not enqueue
    /// into a channel whose drain task is about to die with no readiness
    /// signal. Reopening attaches a fresh channel.
    ///
    /// The shutdown blocks until the worker threads exit (bounded by
    /// [`RUNTIME_SHUTDOWN_TIMEOUT`]) instead of dropping the runtime:
    /// a dropped multi-thread runtime shuts its workers down in the
    /// background, and under load those lingering threads outlive the
    /// caller — nextest attributes them to whatever test runs next.
    /// The mirror sender is dropped before the blocking shutdown: the
    /// drain task ends when its last sender goes away, and holding one
    /// would stall the join for the full timeout on every call.
    ///
    /// The transport stop (router shutdown plus endpoint close) waits
    /// at most `deadline`: the router's own shutdown awaits a graceful
    /// endpoint close internally, so bounding only the trailing close
    /// would leave the wait unbounded behind a stage that pre-closes.
    /// A timeout abandons the graceful stop and reports it — the
    /// endpoint is then aborted (iroh logs it), so peers see a hard
    /// connection failure rather than a clean close. The sender drop
    /// and runtime join below still run, so no worker outlives the
    /// shutdown either way.
    ///
    /// Every stage is captured, not returned early: the endpoint close
    /// runs even when the router shutdown reports an error, and the
    /// sender drop and runtime join run regardless, or a panicked
    /// handler task reintroduces exactly the lingering threads this
    /// shutdown exists to join. The first error is still reported.
    pub fn shutdown(self, deadline: std::time::Duration) -> std::io::Result<()> {
        let mirror_result = self
            .mirror
            .lock()
            .map(|mut slot| *slot = None)
            .map_err(|_| std::io::Error::other("vault mirror lock poisoned"));
        let transport_result = self
            .runtime
            .block_on(super::close::with_deadline(
                super::close::stop_with_close(
                    async {
                        self.router
                            .shutdown()
                            .await
                            .map_err(|error| std::io::Error::other(error.to_string()))
                    },
                    // Unconditional: a router failure (panicked accept
                    // task) must not skip the graceful close. Usually
                    // a no-op, since a clean router shutdown already
                    // closed the endpoint — kept so the close never
                    // depends on router internals.
                    self.endpoint.close(),
                ),
                deadline,
                "serving transport stop timed out",
            ))
            .and_then(|inner| inner);
        drop(self.sender);
        self.runtime.shutdown_timeout(RUNTIME_SHUTDOWN_TIMEOUT);
        mirror_result.and(transport_result)
    }
}

fn hex_to_32(name: &str) -> Result<[u8; 32], ()> {
    if name.len() != 64 {
        return Err(());
    }
    let mut out = [0u8; 32];
    for (i, chunk) in name.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16).ok_or(())?;
        let lo = (chunk[1] as char).to_digit(16).ok_or(())?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Ok(out)
}

/// The serving view of one drive: the vault's sealed bytes plus the
/// composer's durable runtime state, so every address the fetch plane
/// knows how to name is servable. The maps are derived — never stored —
/// so a restart rebuilds them by replaying durable state, and vault
/// bytes outlive every process.
///
/// The verification chain stays three-staged (trust.md): the author's
/// signature proves the author named `R` as the route for identity `X`;
/// the transport (Bao/vault) proves received bytes hash to `R`; the
/// AEAD/content admission proves the received representation decrypts to
/// the claimed plaintext. This view participates in the first two — it
/// never substitutes for the third.
pub struct VaultSource {
    vault: Vault,
    /// Root manifests by snapshot: the eager exchange address.
    roots: BTreeMap<SnapshotId, (ContentId, BaoRoot)>,
    /// Snapshot bodies: the plaintext CAS objects whose content id is
    /// the snapshot id.
    bodies: BTreeMap<SnapshotId, Vec<u8>>,
    /// Sealed representation addresses: storage id to transport root.
    sealed: BTreeMap<StorageId, BaoRoot>,
}

impl VaultSource {
    /// Rebuild the serving maps from durable state: root manifests from
    /// the recorded records, storage addresses from every recorded
    /// mapping and child link, bodies from the recorded snapshot
    /// bodies. Only recorded state serves — an announcement or mapping
    /// the device has not durably accepted is not offered to peers.
    pub fn from_state(state: &RuntimeState, vault: &Vault) -> Result<Self, VaultError> {
        let mut roots = BTreeMap::new();
        let mut bodies = BTreeMap::new();
        let mut sealed = BTreeMap::new();
        for snapshot in state.recorded_snapshots() {
            // The root manifest serves by snapshot id and by the transport
            // root the record carries; a record with no sealed envelope
            // (recordable via the durable codec) still serves those two
            // routes, and contributes nothing to the storage map.
            if let Some(record) = state.root_manifest_record(&snapshot) {
                roots.insert(snapshot, (record.manifest_id, record.transport));
            }
            if let Some(body) = state.snapshot_body(&snapshot) {
                bodies.insert(snapshot, body.encode());
            }
        }
        for record in state.manifest_records() {
            for entry in record.manifest.entries() {
                sealed.insert(entry.storage_id, entry.transport);
            }
            for link in record.manifest.children() {
                sealed.insert(link.storage, link.transport);
            }
        }
        Ok(VaultSource {
            vault: Vault {
                dir: vault.dir.clone(),
                mirror: std::sync::Arc::new(Mutex::new(None)),
                durability: durable::Durability::new(),
            },
            roots,
            bodies,
            sealed,
        })
    }

    /// Test-only: the rebuilt serving maps, for the
    /// restart-equivalence residency row. Compared across a reopen
    /// to prove `from_state` reconstructs them from durable state
    /// rather than carrying memory.
    #[cfg(test)]
    pub(crate) fn maps_for_test(&self) -> ServingMaps {
        (self.roots.clone(), self.bodies.clone(), self.sealed.clone())
    }
}

/// The rebuilt serving maps as one comparable value: root
/// manifests by snapshot, snapshot bodies, and sealed addresses.
/// Named so the test-only accessor below stays under
/// `clippy::type_complexity`.
#[cfg(test)]
pub(crate) type ServingMaps = (
    BTreeMap<SnapshotId, (ContentId, BaoRoot)>,
    BTreeMap<SnapshotId, Vec<u8>>,
    BTreeMap<StorageId, BaoRoot>,
);

/// Local vault reads: instantaneous, so the plan's per-attempt cap
/// has nothing to bound.
impl AttemptBudget for VaultSource {}

impl BulkSource for VaultSource {
    fn fetch_root_manifest(
        &mut self,
        snapshot: &SnapshotId,
        max: usize,
    ) -> Result<Option<SealedManifest>, BulkError> {
        let Some((content_id, transport)) = self.roots.get(snapshot) else {
            return Ok(None);
        };
        let sealed = self
            .vault
            .sealed(transport)
            .map_err(|error| BulkError::Transport(error.to_string()))?;
        let Some(sealed) = sealed else {
            return Ok(None);
        };
        if sealed.len() > max {
            return Err(BulkError::Oversize {
                bytes: sealed.len(),
                max,
            });
        }
        Ok(Some(SealedManifest {
            content_id: *content_id,
            sealed,
        }))
    }

    fn fetch_snapshot(
        &mut self,
        snapshot: &SnapshotId,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        let Some(body) = self.bodies.get(snapshot).cloned() else {
            return Ok(None);
        };
        if body.len() > max {
            return Err(BulkError::Oversize {
                bytes: body.len(),
                max,
            });
        }
        Ok(Some(body))
    }

    fn fetch_sealed(
        &mut self,
        storage: &StorageId,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        let Some(transport) = self.sealed.get(storage).copied() else {
            return Ok(None);
        };
        self.fetch_transport(&transport, max)
    }

    fn fetch_transport(
        &mut self,
        root: &BaoRoot,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        let sealed = self
            .vault
            .sealed(root)
            .map_err(|error| BulkError::Transport(error.to_string()))?;
        let Some(sealed) = sealed else {
            return Ok(None);
        };
        if sealed.len() > max {
            return Err(BulkError::Oversize {
                bytes: sealed.len(),
                max,
            });
        }
        Ok(Some(sealed))
    }
}

impl crate::runtime::RoutePublishing for VaultSource {
    /// The serving view holds bytes, not peer addresses: its tests and
    /// callers populate routes directly when it doubles as a bulk peer.
    fn publish_routes(
        &mut self,
        _state: &crate::runtime::RuntimeState,
    ) -> Result<crate::runtime::RouteReport, crate::runtime::EngineError> {
        Ok(crate::runtime::RouteReport::default())
    }
}

// Sibling test file under the workspace tests_* naming: #[path] is required
// because default resolution from this parent would look for tests.rs, not this name.
#[cfg(test)]
#[path = "serving/tests_serving.rs"]
mod tests;

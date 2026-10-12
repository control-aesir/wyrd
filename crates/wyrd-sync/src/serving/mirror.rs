use std::sync::atomic::Ordering;
use std::sync::Arc;

use wyrd_format::BaoRoot;

use super::vault::VaultError;

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
/// Overflow applies backpressure at [`Vault::import`](super::vault::Vault::import) (a typed
/// [`VaultError::MirrorFull`], retried on a later pass) instead of
/// growing without bound, and [`ServingHandle::flush_bounded`] reports
/// a full queue as not-ready so announcements never discharge over
/// representations the mirror has not served.
pub const MAX_MIRROR_QUEUE_ITEMS: usize = 64;
pub const MAX_MIRROR_QUEUE_BYTES: usize = 64 << 20;

/// Shared accounting for one serving mirror queue: queued depth in
/// items and bytes plus rejection/failure counters. One `Arc` is held
/// by the write-through sender, the drain worker, and every readiness
/// handle, so [`MirrorStats`] reads the live queue without locking.
#[derive(Debug, Default)]
pub(crate) struct MirrorAccounting {
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
    pub(crate) fn release_item(&self) {
        let _ = self
            .queued_items
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |items| {
                Some(items.saturating_sub(1))
            });
    }

    /// Release a byte reservation as its item is handled. Saturating,
    /// for the same reason as [`release_item`](Self::release_item).
    pub(crate) fn release_bytes(&self, len: usize) {
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
    pub(crate) accounting: std::sync::Arc<MirrorAccounting>,
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
    pub(crate) fn send_import(&self, root: BaoRoot, bytes: Vec<u8>) -> Result<(), VaultError> {
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
    pub(crate) fn send_barrier(
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

    pub(crate) fn stats(&self) -> MirrorStats {
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
/// and runtime the [`flush`](super::endpoint::ServingEndpoint::flush) barrier needs,
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
    /// A handle over an explicit runtime and sender, with a fresh
    /// in-flight permit. Production handles come from the endpoint;
    /// tests build their own over a scratch runtime and channel.
    pub(crate) fn new(runtime: tokio::runtime::Handle, sender: MirrorSender) -> Self {
        ServingHandle {
            runtime,
            sender,
            barrier_in_flight: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

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
pub(crate) async fn drain_mirror<F, Fut>(
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

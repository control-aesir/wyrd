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
use std::sync::Mutex;
use std::time::Duration;

use iroh::{endpoint::presets, protocol::Router, Endpoint, EndpointAddr};
use iroh_blobs::{store::fs::FsStore, BlobsProtocol};
use thiserror::Error;
use wyrd_format::durable;
use wyrd_format::{BaoRoot, ContentId, SnapshotId, StorageId};

use crate::bulk::{BulkError, BulkSource, SealedManifest};
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
#[derive(Debug, Error)]
pub enum VaultError {
    #[error("vault I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

/// The drive's sealed representation store: one file per transport root,
/// named by the root's hex, written atomically and never rewritten.
pub struct Vault {
    dir: PathBuf,
    /// The live serving mirror's write-through channel, attached by
    /// [`ServingEndpoint::open`] and replaced (never co-held) on reopen.
    /// Imports enqueue after the durable rename, so the vault stays the
    /// source of truth and the mirror is a derived, self-healing cache:
    /// a dropped channel or a failed mirror import only delays serving
    /// until the next boot rebuild. The slot is shared (`Arc`) so the
    /// endpoint can detach it on shutdown: an import after shutdown must
    /// not silently enqueue into a channel nobody will drain.
    mirror: std::sync::Arc<Mutex<Option<tokio::sync::mpsc::UnboundedSender<MirrorItem>>>>,
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
    Flush(tokio::sync::oneshot::Sender<Result<(), String>>),
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
    sender: tokio::sync::mpsc::UnboundedSender<MirrorItem>,
}

impl ServingHandle {
    /// Wait until every import enqueued so far has landed in the
    /// serving mirror. A mirror import that failed makes the barrier
    /// fail — announcing over a representation the mirror cannot
    /// serve would strand the peer until a restart.
    pub fn flush(&self) -> std::io::Result<()> {
        let (ack, wait) = tokio::sync::oneshot::channel();
        self.send(MirrorItem::Flush(ack))?;
        match self.runtime.block_on(wait) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(message)) => Err(std::io::Error::other(format!(
                "serving mirror import failed: {message}"
            ))),
            Err(_) => Err(std::io::Error::other("serving mirror drain stopped")),
        }
    }

    fn send(&self, item: MirrorItem) -> std::io::Result<()> {
        self.sender
            .send(item)
            .map_err(|_| std::io::Error::other("serving mirror closed"))
    }
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
    pub(crate) fn mirror_slot(
        &self,
    ) -> std::sync::Arc<Mutex<Option<tokio::sync::mpsc::UnboundedSender<MirrorItem>>>> {
        std::sync::Arc::clone(&self.mirror)
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
            self.reconcile_held(sealed)?;
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
                    self.reconcile_held(sealed)?;
                    return Ok(root);
                }
                return Err(error.into());
            }
            Err(durable::PublishError::DirectorySync(error)) => {
                // The rename installed the file but its directory entry is
                // not known durable. Notify the mirror best-effort so the
                // failure does not also strand serving readiness, then
                // surface the error; a retry re-syncs the directory.
                // A poisoned mirror slot fails too — the op fails either
                // way, and poison outranks the durability error.
                self.notify_mirror(sealed)?;
                return Err(error.into());
            }
        }
        self.notify_mirror(sealed)?;
        Ok(root)
    }

    /// Make an already-held root durable and served: confirm the vault
    /// directory's durability and re-import into the mirror. Both steps
    /// are idempotent, so this heals a prior post-rename `fsync` failure
    /// (including across a restart), a crash before the mirror
    /// write-through, or a concurrent winner this process never observed.
    fn reconcile_held(&self, sealed: &[u8]) -> Result<(), VaultError> {
        self.durability.verify_dir(&self.dir)?;
        self.notify_mirror(sealed)?;
        Ok(())
    }

    /// Write-through to the serving mirror. A dead channel only delays
    /// serving until the next boot rebuild, never the publication — but a
    /// poisoned slot lock fails the import: poison means a thread
    /// panicked mid-critical-section, so the operation fails instead of
    /// the process.
    fn notify_mirror(&self, sealed: &[u8]) -> Result<(), VaultError> {
        if let Some(sender) = self
            .mirror
            .lock()
            .map_err(|_| std::io::Error::other("vault mirror lock poisoned"))?
            .as_ref()
        {
            let _ = sender.send(MirrorItem::Import(sealed.to_vec()));
        }
        Ok(())
    }

    /// Attach the write-through channel of a serving mirror. Replacing
    /// an already-attached channel strands the old one (its sends fail
    /// and are ignored); a serving restart is the normal replacement.
    pub(crate) fn attach_mirror(
        &self,
        sender: tokio::sync::mpsc::UnboundedSender<MirrorItem>,
    ) -> Result<(), VaultError> {
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
    /// Clone of the write-through channel, for [`flush`](Self::flush).
    sender: tokio::sync::mpsc::UnboundedSender<MirrorItem>,
    /// The vault's mirror slot, cleared on shutdown so imports stop.
    mirror: std::sync::Arc<Mutex<Option<tokio::sync::mpsc::UnboundedSender<MirrorItem>>>>,
}

/// The serving mirror's write-through worker: import each queued
/// representation, remember the first failure, and answer each barrier
/// with the accumulated readiness. A failed import is sticky until a
/// restart: the vault treats an already-held root as a no-op, so the
/// representation is never re-queued, and the boot rebuild is the healing
/// path. Extracted so tests can inject an import that fails and prove
/// `flush` reports it instead of claiming readiness.
async fn drain_mirror<F, Fut>(
    mut receiver: tokio::sync::mpsc::UnboundedReceiver<MirrorItem>,
    mut import: F,
) where
    F: FnMut(Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    let mut failure: Option<String> = None;
    while let Some(item) = receiver.recv().await {
        match item {
            MirrorItem::Import(bytes) => {
                if let Err(error) = import(bytes).await {
                    failure.get_or_insert(error);
                }
            }
            MirrorItem::Flush(ack) => {
                let _ = ack.send(match &failure {
                    Some(error) => Err(error.clone()),
                    None => Ok(()),
                });
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
        // wrong root); the vault is the truth and the next scrub or
        // refetch repairs serving.
        for root in vault.roots().map_err(std::io::Error::other)? {
            let Some(sealed) = vault.sealed(&root).map_err(std::io::Error::other)? else {
                continue;
            };
            runtime
                .block_on(async { store.blobs().add_bytes(sealed).await })
                .map_err(|error| std::io::Error::other(error.to_string()))?;
        }
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel::<MirrorItem>();
        let blobs = store.blobs().clone();
        let router = runtime.block_on(async {
            tokio::spawn(drain_mirror(receiver, move |bytes| {
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
    /// A failing router shutdown is captured, not returned early: the
    /// sender drop and the runtime join below must run regardless, or a
    /// panicked handler task reintroduces exactly the lingering threads
    /// this shutdown exists to join. The first error is still reported.
    pub fn shutdown(self) -> std::io::Result<()> {
        *self
            .mirror
            .lock()
            .map_err(|_| std::io::Error::other("vault mirror lock poisoned"))? = None;
        let router_result = self
            .runtime
            .block_on(async { self.router.shutdown().await });
        self.runtime.block_on(self.endpoint.close());
        drop(self.sender);
        self.runtime.shutdown_timeout(RUNTIME_SHUTDOWN_TIMEOUT);
        router_result.map_err(|error| std::io::Error::other(error.to_string()))?;
        Ok(())
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
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::EpochSecret;
    use crate::seal::seal_manifest;
    use wyrd_format::{DriveId, Manifest, SnapshotId};

    fn drive() -> DriveId {
        DriveId::from_bytes([0xEE; 32])
    }

    fn vault() -> Vault {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("wyrd-vault-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Vault::open(&dir).unwrap()
    }

    /// Poison the mirror slot: a thread panics while holding the lock.
    fn poisoned_vault() -> Vault {
        let vault = vault();
        let mirror = std::sync::Arc::clone(&vault.mirror);
        let poisoner = std::thread::spawn(move || {
            let _guard = mirror.lock().unwrap();
            panic!("poison the mirror slot");
        });
        let _ = poisoner.join();
        vault
    }

    /// A poisoned mirror slot fails the import instead of panicking the
    /// process: poison means a thread panicked mid-critical-section.
    #[test]
    fn poisoned_mirror_lock_fails_import() {
        let vault = poisoned_vault();
        assert!(
            matches!(vault.import(b"poisoned mirror"), Err(VaultError::Io(_))),
            "a poisoned mirror slot must fail the import, not panic"
        );
    }

    /// Attaching to a poisoned mirror slot fails instead of panicking.
    #[test]
    fn poisoned_mirror_lock_fails_attach() {
        let vault = poisoned_vault();
        let (sender, _receiver) = tokio::sync::mpsc::unbounded_channel();
        assert!(
            matches!(vault.attach_mirror(sender), Err(VaultError::Io(_))),
            "a poisoned mirror slot must fail the attach, not panic"
        );
    }

    #[test]
    fn serving_endpoint_serves_vault_roots_over_iroh() {
        let dir = serve_dir();
        let vault = Vault::open(&dir).unwrap();
        let serving = ServingEndpoint::open_loopback(&vault, &dir).unwrap();
        let sealed = b"verified through the serving endpoint".to_vec();
        let root = vault.import(&sealed).unwrap();
        // The write-through is async; flush orders serving readiness
        // against the announcement a peer would act on.
        serving.flush().unwrap();

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let client = runtime.block_on(async {
            Endpoint::builder(presets::N0DisableRelay)
                .clear_address_lookup()
                .bind()
                .await
                .unwrap()
        });
        let mut source =
            crate::bulk::IrohBulkSource::with_runtime(client, std::sync::Arc::new(runtime));
        source.publish_transport(crate::bulk::IrohBlobRef {
            provider: serving.addr(),
            hash: *root.as_bytes(),
        });
        assert_eq!(
            source.fetch_transport(&root, usize::MAX).unwrap(),
            Some(sealed)
        );
        // A root the vault never held is absence, not error.
        assert_eq!(
            source
                .fetch_transport(&BaoRoot::from_bytes([0x33; 32]), usize::MAX)
                .unwrap(),
            None
        );
        source.shutdown();
        serving.shutdown().unwrap();
    }

    #[test]
    fn serving_reopen_rebuilds_the_mirror_from_the_vault() {
        let dir = serve_dir();
        let vault = Vault::open(&dir).unwrap();
        let sealed = b"the mirror is derived state".to_vec();
        let root = vault.import(&sealed).unwrap();
        let first = ServingEndpoint::open_loopback(&vault, &dir).unwrap();
        first.flush().unwrap();
        first.shutdown().unwrap();

        // Reopen: the boot rebuild re-imports the vault's roots, so the
        // representation serves again under its transport root.
        let reopened = ServingEndpoint::open_loopback(&vault, &dir).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let client = runtime.block_on(async {
            Endpoint::builder(presets::N0DisableRelay)
                .clear_address_lookup()
                .bind()
                .await
                .unwrap()
        });
        let mut source =
            crate::bulk::IrohBulkSource::with_runtime(client, std::sync::Arc::new(runtime));
        source.publish_transport(crate::bulk::IrohBlobRef {
            provider: reopened.addr(),
            hash: *root.as_bytes(),
        });
        assert_eq!(
            source.fetch_transport(&root, usize::MAX).unwrap(),
            Some(sealed)
        );
        source.shutdown();
        reopened.shutdown().unwrap();
    }

    #[test]
    fn node_addr_bytes_round_trip_through_the_route_codec() {
        let dir = serve_dir();
        let vault = Vault::open(&dir).unwrap();
        let serving = ServingEndpoint::open_loopback(&vault, &dir).unwrap();
        let decoded = crate::transport::decode_node_addr(&serving.node_addr_bytes()).unwrap();
        assert_eq!(decoded.id, serving.addr().id);
        serving.shutdown().unwrap();
    }

    /// Shutdown runs the full cleanup sequence instead of returning
    /// early: the endpoint reads closed and the write-through mirror is
    /// detached, so a skipped close would fail here rather than leaving
    /// a connectable address behind. Router-shutdown failure itself is
    /// not simulated — iroh reports it only for a panicked handler
    /// task, which no public trigger produces — so the error path is
    /// enforced by construction (the result is captured before the
    /// sender drop and the runtime join, and returned after).
    #[test]
    fn shutdown_closes_the_endpoint_and_clears_the_mirror() {
        let dir = serve_dir();
        let vault = Vault::open(&dir).unwrap();
        let serving = ServingEndpoint::open_loopback(&vault, &dir).unwrap();
        let endpoint = serving.endpoint.clone();
        assert!(!endpoint.is_closed(), "a live endpoint reads open");
        serving.shutdown().unwrap();
        assert!(endpoint.is_closed(), "shutdown closes the endpoint");
        assert!(
            vault.mirror_slot().lock().expect("mirror lock").is_none(),
            "shutdown detaches the write-through mirror"
        );
    }

    fn serve_dir() -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("wyrd-serving-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Fetch a representation from a loopback serving endpoint by
    /// transport root over a real iroh client: `None` when the mirror
    /// does not serve it.
    fn fetch_from(serving: &ServingEndpoint, root: &BaoRoot) -> Option<Vec<u8>> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let client = runtime.block_on(async {
            Endpoint::builder(presets::N0DisableRelay)
                .clear_address_lookup()
                .bind()
                .await
                .unwrap()
        });
        let mut source =
            crate::bulk::IrohBulkSource::with_runtime(client, std::sync::Arc::new(runtime));
        source.publish_transport(crate::bulk::IrohBlobRef {
            provider: serving.addr(),
            hash: *root.as_bytes(),
        });
        let fetched = source.fetch_transport(root, usize::MAX).ok().flatten();
        source.shutdown();
        fetched
    }

    #[test]
    fn concurrent_same_root_imports_publish_once() {
        let vault = vault();
        let sealed = vec![0x5Au8; 96];
        let root = blob_root(&sealed);
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| scope.spawn(|| vault.import(&sealed).unwrap()))
                .collect();
            for handle in handles {
                assert_eq!(handle.join().unwrap(), root);
            }
        });
        assert_eq!(vault.sealed(&root).unwrap(), Some(sealed));
        // Every importer either published or found the winner; no
        // scratch file survives.
        for entry in std::fs::read_dir(&vault.dir).unwrap() {
            let name = entry.unwrap().file_name();
            assert!(
                !name.to_string_lossy().starts_with(".tmp-"),
                "stale import scratch file"
            );
        }
    }

    #[tokio::test]
    async fn mirror_flush_reports_the_first_import_failure() {
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
        let worker = tokio::spawn(drain_mirror(receiver, |_bytes| async {
            Err::<(), String>("disk full".to_string())
        }));
        sender.send(MirrorItem::Import(vec![1, 2, 3])).unwrap();
        let (ack, wait) = tokio::sync::oneshot::channel();
        sender.send(MirrorItem::Flush(ack)).unwrap();
        assert!(
            wait.await.unwrap().is_err(),
            "flush must not claim readiness"
        );
        // The failure is sticky: the vault no-ops an already-held root,
        // so the representation is never re-queued until a restart
        // rebuilds the mirror.
        let (ack, wait) = tokio::sync::oneshot::channel();
        sender.send(MirrorItem::Flush(ack)).unwrap();
        assert!(wait.await.unwrap().is_err());
        drop(sender);
        worker.await.unwrap();
    }

    #[test]
    fn imports_are_noop_for_held_roots_and_serve_by_root() {
        let vault = vault();
        let sealed = vec![0x42u8; 40];
        let root = vault.import(&sealed).unwrap();
        assert_eq!(root, blob_root(&sealed));
        assert_eq!(vault.sealed(&root).unwrap(), Some(sealed.clone()));
        // Re-import is a no-op (append-only; put of existing content).
        assert_eq!(vault.import(&sealed).unwrap(), root);
        // An unknown root is absence, not error.
        assert_eq!(
            vault.sealed(&BaoRoot::from_bytes([0x11; 32])).unwrap(),
            None
        );
        // The temp-file pattern must not leak into the root listing.
        assert_eq!(vault.roots().unwrap(), vec![root]);
    }

    #[test]
    fn partial_imports_never_serve() {
        // A torn write leaves a temp file, not a servable root: the
        // rename is the publication point.
        let vault = vault();
        let dir = &vault.dir;
        let torn = dir.join(".tmp-orphan");
        std::fs::write(&torn, b"half written").unwrap();
        assert_eq!(
            vault.sealed(&BaoRoot::from_bytes([0x33; 32])).unwrap(),
            None
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn failed_publication_surfaces_an_error_and_leaves_no_temp() {
        // A directory squatting on the root name blocks the rename: the
        // failure must surface (never a phantom success), and the
        // scratch file must be cleaned up.
        let vault = vault();
        let sealed = b"blocked representation".to_vec();
        let root = blob_root(&sealed);
        std::fs::create_dir_all(vault.dir.join(root.to_string()).join("child")).unwrap();
        assert!(vault.import(&sealed).is_err());
        for entry in std::fs::read_dir(&vault.dir).unwrap() {
            let name = entry.unwrap().file_name();
            assert!(
                !name.to_string_lossy().starts_with(".tmp-"),
                "stale import scratch file"
            );
        }
    }

    /// Directory-sync calls made by the injection test below; the first
    /// fails, the rest use the real implementation.
    static DIR_SYNC_CALLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    fn fail_first_dir_sync(dir: &Path) -> std::io::Result<()> {
        if DIR_SYNC_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
            return Err(std::io::Error::other("injected directory fsync failure"));
        }
        durable::fsync_dir(dir)
    }

    #[test]
    fn reimport_reconciles_a_vault_file_the_mirror_never_saw() {
        // Boot the endpoint against an empty vault so its boot rebuild
        // cannot import the representation. Then place the file directly,
        // as a publication that installed ciphertext but never reached
        // the mirror (a crash before write-through, or a concurrent
        // winner this process did not observe).
        let dir = serve_dir();
        let vault = Vault::open(&dir).unwrap();
        let serving = ServingEndpoint::open_loopback(&vault, &dir).unwrap();
        let sealed = b"stranded representation".to_vec();
        let root = blob_root(&sealed);
        std::fs::write(vault.dir.join(root.to_string()), &sealed).unwrap();
        assert!(
            fetch_from(&serving, &root).is_none(),
            "the mirror must not serve it before reconciliation"
        );

        // Re-importing a held root reconciles instead of no-oping: the
        // directory is re-synced and the mirror receives the bytes.
        assert_eq!(vault.import(&sealed).unwrap(), root);
        serving.flush().unwrap();
        assert_eq!(fetch_from(&serving, &root), Some(sealed));
        serving.shutdown().unwrap();
    }

    #[test]
    fn post_rename_directory_sync_failure_is_reconciled_on_retry() {
        let dir = serve_dir();
        let mut vault = Vault::open(&dir).unwrap();
        let serving = ServingEndpoint::open_loopback(&vault, &dir).unwrap();
        DIR_SYNC_CALLS.store(0, std::sync::atomic::Ordering::SeqCst);
        vault.durability = durable::Durability::with_sync(fail_first_dir_sync);

        let sealed = b"durability failure reconciled".to_vec();
        let root = blob_root(&sealed);
        // The rename publishes the file, then the injected directory
        // fsync fails: the durability error must surface.
        let error = vault.import(&sealed).unwrap_err();
        assert!(
            error.to_string().contains("injected"),
            "unexpected error: {error}"
        );
        assert!(
            vault.dir.join(root.to_string()).is_file(),
            "the rename installed the live file"
        );

        // A retry takes the held-root path, re-syncs the directory
        // (second call succeeds), and reconciles the mirror.
        assert_eq!(vault.import(&sealed).unwrap(), root);
        serving.flush().unwrap();
        assert_eq!(fetch_from(&serving, &root), Some(sealed));
        serving.shutdown().unwrap();
    }

    /// Directory-sync calls seen by the restart-recovery test.
    static REOPEN_SYNC_CALLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    fn count_dir_sync(dir: &Path) -> std::io::Result<()> {
        REOPEN_SYNC_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        durable::fsync_dir(dir)
    }

    #[test]
    fn reopening_reconciles_a_held_vault_directory() {
        let dir = serve_dir();
        let sealed = b"restart reconciliation".to_vec();
        let root = blob_root(&sealed);
        {
            let vault = Vault::open(&dir).unwrap();
            vault.import(&sealed).unwrap();
        }
        // Reopen: the fresh durability layer has verified nothing, so
        // the first import of the held root must fsync the vault
        // directory before reporting success.
        let mut vault = Vault::open(&dir).unwrap();
        REOPEN_SYNC_CALLS.store(0, std::sync::atomic::Ordering::SeqCst);
        vault.durability = durable::Durability::with_sync(count_dir_sync);
        assert_eq!(vault.import(&sealed).unwrap(), root);
        assert_eq!(
            REOPEN_SYNC_CALLS.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        // Verified now: a second import is a cheap no-op.
        assert_eq!(vault.import(&sealed).unwrap(), root);
        assert_eq!(
            REOPEN_SYNC_CALLS.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }

    #[test]
    fn corrupt_file_contents_serve_nothing_under_their_name() {
        // Filenames are mutable filesystem state: a file whose contents
        // no longer hash to its name is not the requested representation.
        // The read refuses (absence) and never mutates the append-only
        // store.
        let vault = vault();
        let sealed = vec![0x42u8; 40];
        let root = vault.import(&sealed).unwrap();
        std::fs::write(vault.dir.join(root.to_string()), b"tampered bytes").unwrap();
        assert_eq!(
            vault.sealed(&root).unwrap(),
            None,
            "bytes that do not hash to the requested root are absence"
        );
        assert_eq!(
            vault.roots().unwrap(),
            vec![root],
            "reads never mutate vault state; scrub is explicit"
        );
    }

    #[test]
    fn distinct_roots_never_collide_on_the_temp_path() {
        // The temp file is scoped to the root, so concurrent imports of
        // different roots through one vault cannot overwrite each other.
        let vault = vault();
        let a = vault.import(b"first representation").unwrap();
        let b = vault.import(b"second representation").unwrap();
        assert_ne!(a, b);
        assert_eq!(
            vault.sealed(&a).unwrap(),
            Some(b"first representation".to_vec())
        );
        assert_eq!(
            vault.sealed(&b).unwrap(),
            Some(b"second representation".to_vec())
        );
    }

    #[test]
    fn a_representationless_root_record_is_not_a_panic() {
        // Durable state can carry a root manifest with no sealed
        // representation at all (the codec accepts a zero storage count):
        // the serving view fails closed to "nothing to serve", never
        // panics at reconstruction.
        let vault = vault();
        let snapshot = SnapshotId::from_bytes([0x01; 32]);
        let secret = EpochSecret::from_bytes([0x07; 32]);
        let manifest = Manifest::new(snapshot, Vec::new(), Vec::new()).unwrap();
        let key = secret.manifest_key(&drive(), 1, &snapshot);
        let (manifest_id, obj) = seal_manifest(&key, &manifest).unwrap();
        vault.import(&obj.encode()).unwrap();
        let mut runtime = RuntimeState::new(drive());
        runtime
            .record_manifest(crate::runtime::ManifestRecord {
                is_root: true,
                manifest_id,
                representations: std::collections::BTreeMap::new(),
                transport: crate::seal::transport_root(&obj),
                manifest,
            })
            .unwrap();
        let mut source = VaultSource::from_state(&runtime, &vault).unwrap();
        let served = source
            .fetch_root_manifest(&snapshot, usize::MAX)
            .unwrap()
            .expect("the root manifest still serves by id and root");
        assert_eq!(served.content_id, manifest_id);
        assert_eq!(
            source
                .fetch_sealed(&StorageId::from_bytes([0x02; 32]), usize::MAX)
                .unwrap(),
            None,
            "no storage representations were recorded, so none serve"
        );
    }
    #[test]
    fn the_source_serves_recorded_state_only() {
        // from_state layers the durable records over the vault: a
        // snapshot with neither a recorded root manifest nor a recorded
        // body serves nothing, and every recorded address serves.
        let vault = vault();
        let state = RuntimeState::new(drive());
        let mut source = VaultSource::from_state(&state, &vault).unwrap();
        let snapshot = SnapshotId::from_bytes([0x01; 32]);
        assert_eq!(
            source.fetch_root_manifest(&snapshot, usize::MAX).unwrap(),
            None
        );
        assert_eq!(source.fetch_snapshot(&snapshot, usize::MAX).unwrap(), None);
        assert_eq!(
            source
                .fetch_sealed(&StorageId::from_bytes([0x02; 32]), usize::MAX)
                .unwrap(),
            None
        );
        assert_eq!(
            source
                .fetch_transport(&BaoRoot::from_bytes([0x03; 32]), usize::MAX)
                .unwrap(),
            None
        );

        // Record a root manifest whose mapping names a sealed chunk, import
        // both envelopes, and the source serves the root-manifest routes
        // (by snapshot id and transport root) plus the mapped chunk by
        // its storage address.
        let secret = EpochSecret::from_bytes([0x07; 32]);
        let plaintext = b"vault served chunk".to_vec();
        let content = wyrd_format::ContentId::derive(wyrd_format::ObjectKind::Chunk, &plaintext);
        let chunk_key = secret.object_key(
            &drive(),
            1,
            &content,
            wyrd_format::ObjectKind::Chunk,
            crate::seal::SEAL_VERSION,
        );
        let sealed_chunk = crate::seal::seal(
            &chunk_key,
            wyrd_format::ObjectKind::Chunk,
            &content,
            &plaintext,
        )
        .unwrap();
        let entry = crate::seal::entry_for(
            wyrd_format::ObjectKind::Chunk,
            1,
            &sealed_chunk,
            &content,
            &plaintext,
        )
        .unwrap();
        vault.import(&sealed_chunk.encode()).unwrap();
        let manifest = Manifest::new(snapshot, vec![entry], Vec::new()).unwrap();
        let secret = EpochSecret::from_bytes([0x07; 32]);
        let key = secret.manifest_key(&drive(), 1, &snapshot);
        let (manifest_id, obj) = seal_manifest(&key, &manifest).unwrap();
        vault.import(&obj.encode()).unwrap();
        let mut runtime = RuntimeState::new(drive());
        runtime
            .record_manifest(crate::runtime::ManifestRecord {
                is_root: true,
                manifest_id,
                representations: std::collections::BTreeMap::from([(
                    obj.storage_id(),
                    crate::seal::transport_root(&obj),
                )]),
                transport: crate::seal::transport_root(&obj),
                manifest,
            })
            .unwrap();
        let mut source = VaultSource::from_state(&runtime, &vault).unwrap();
        let served = source
            .fetch_root_manifest(&snapshot, usize::MAX)
            .unwrap()
            .expect("the recorded root manifest serves");
        assert_eq!(served.content_id, manifest_id);
        assert_eq!(served.sealed, obj.encode());
        assert_eq!(
            source
                .fetch_transport(&crate::seal::transport_root(&obj), usize::MAX)
                .unwrap(),
            Some(obj.encode())
        );
        assert_eq!(
            source
                .fetch_sealed(&sealed_chunk.storage_id(), usize::MAX)
                .unwrap(),
            Some(sealed_chunk.encode())
        );
    }
}

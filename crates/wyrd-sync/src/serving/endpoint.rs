use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use iroh::{endpoint::presets, protocol::Router, Endpoint, EndpointAddr};
use iroh_blobs::{store::fs::FsStore, BlobsProtocol};

use super::mirror::{drain_mirror, mirror_channel, MirrorSender, MirrorStats, ServingHandle};
use super::vault::Vault;
use crate::transport::encode_node_addr;

/// The vault directory inside a drive directory holding the serving
/// mirror's own bao-encoded copy of held representations. The vault is
/// the durable source of truth; this directory is derived state,
/// rebuilt from it on every [`ServingEndpoint::open`]. The copy is the
/// cost of riding iroh-blobs' supported serving path instead of a
/// version-coupled custom store backend; unifying the two stores is a
/// post-v1 storage question (GC does not exist in v0).
pub(crate) const SERVE_DIR: &str = "serve";

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
    pub(crate) endpoint: Endpoint,
    /// Clone of the bounded write-through sender, for [`flush`](Self::flush).
    sender: MirrorSender,
    /// The vault's mirror slot, cleared on shutdown so imports stop.
    pub(crate) mirror: std::sync::Arc<Mutex<Option<MirrorSender>>>,
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
        // Owner-only from creation when this call establishes the leaf;
        // a pre-existing directory keeps its mode. The vault holds the
        // ciphertext, this directory holds its serving mirror.
        crate::durable::ensure_owner_only_dir(&serve_dir)?;
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
        ServingHandle::new(self.runtime.handle().clone(), self.sender.clone())
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
            .block_on(crate::close::with_deadline(
                crate::close::stop_with_close(
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

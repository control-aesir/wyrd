//! Bulk object transport: the sync fetch boundary for sealed bytes.
//!
//! The control plane (mailbox) carries small gossip; everything bulky —
//! sealed manifests and sealed objects — moves through [`BulkSource`],
//! synchronously by design like the rest of `wyrd-sync`: the in-memory
//! fake serves tests, and [`IrohBulkSource`] provides the network backend.
//!
//! Fetches are size-aware: the caller passes the pre-decode byte ceiling
//! with every request, and the source classifies an oversize
//! representation as [`BulkError::Oversize`] instead of handing over
//! undecodable bytes. Both sources enforce the ceiling before buffering
//! the representation: the memory source checks its stored bytes, and
//! the iroh source checks the cryptographically verified blob size
//! first, then streams the body into a bounded buffer that aborts past
//! the ceiling — a hostile peer cannot force more than `max` plus one
//! chunk of allocation no matter what it claims or streams.
//!
//! Addressing mirrors what each party may know. Sealed objects are
//! vault-visible, so they fetch by [`StorageId`]. The root manifest of
//! a snapshot has no vault-visible pointer (the announcement carries
//! only the snapshot id), so roots fetch by [`SnapshotId`] from a member
//! peer holding that snapshot's metadata — this is the eager manifest
//! exchange of sync-and-peers.md, not a vault read. Snapshot bodies
//! fetch the same way: they are plaintext CAS objects whose content id
//! equals the snapshot id (`ObjectKind::Snapshot`). The returned
//! [`ContentId`] of a root fetch is an untrusted hint:
//! `seal::open_manifest` still enforces it as AAD before the record is
//! trusted.

use std::collections::BTreeMap;
use std::sync::Arc;

use bao_tree::io::BaoContentItem;
use iroh::{Endpoint, EndpointAddr};
use iroh_blobs::{
    get::request::{get_blob, get_verified_size, GetBlobItem},
    Hash,
};
use n0_future::{Stream, StreamExt};
use thiserror::Error;
use tokio::runtime::Runtime;
use wyrd_format::{ContentId, SnapshotId, StorageId};

/// A sealed root manifest as a member peer serves it: the claimed
/// logical identity alongside the sealed bytes. The claim verifies as
/// the AAD of the seal on open; a lying peer fails the tag, never the
/// record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedManifest {
    pub content_id: ContentId,
    pub sealed: Vec<u8>,
}

/// Bulk fetch failures. Absence is `Ok(None)` — the peer simply does
/// not hold the bytes — while transport trouble and oversize
/// representations surface here. The engine treats absence and
/// transport trouble as "try again later": nothing commits, nothing
/// is lost. Oversize is classified at this boundary so the plan layer
/// counts it as invalid remote data, not transport trouble.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BulkError {
    #[error("bulk transport failed: {0}")]
    Transport(String),
    #[error("sealed representation of {bytes} bytes exceeds the {max}-byte fetch ceiling")]
    Oversize { bytes: usize, max: usize },
}

/// The synchronous bulk boundary: sealed manifests and sealed objects
/// by their fetch addresses. Every fetch is size-aware: `max` is the
/// caller's pre-decode byte ceiling, and a representation over it must
/// fail with [`BulkError::Oversize`] rather than return bytes.
pub trait BulkSource {
    /// The sealed root manifest a member peer holds for a snapshot, if any.
    fn fetch_root_manifest(
        &mut self,
        snapshot: &SnapshotId,
        max: usize,
    ) -> Result<Option<SealedManifest>, BulkError>;

    /// The snapshot body a member peer holds: the plaintext CAS object
    /// whose content id equals the snapshot id, if any.
    fn fetch_snapshot(
        &mut self,
        snapshot: &SnapshotId,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError>;

    /// Sealed bytes (manifest or object) at a vault-visible address, if held.
    fn fetch_sealed(
        &mut self,
        storage: &StorageId,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError>;
}

/// A remotely addressable iroh blob.
///
/// Iroh's BLAKE3 hash is deliberately kept separate from Wyrd's
/// [`StorageId`]. The latter is the protocol identity and the former is the
/// transport verification root; an explicit mapping is required between them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrohBlobRef {
    pub provider: EndpointAddr,
    pub hash: [u8; 32],
}

impl IrohBlobRef {
    fn hash(&self) -> Hash {
        Hash::from_bytes(self.hash)
    }
}

/// A synchronous [`BulkSource`] backed by iroh-blobs' verified streaming API.
///
/// The address maps are populated by the control/runtime layer. Root manifests
/// use a snapshot address because their vault-visible StorageId is not known
/// from a snapshot announcement; ordinary manifests and objects use StorageId.
/// A successful transfer is returned only after iroh-blobs has verified the Bao
/// stream. Wyrd's AEAD and identity checks still happen in the sync engine.
pub struct IrohBulkSource {
    endpoint: Endpoint,
    runtime: Arc<Runtime>,
    roots: BTreeMap<SnapshotId, (ContentId, IrohBlobRef)>,
    snapshots: BTreeMap<SnapshotId, IrohBlobRef>,
    sealed: BTreeMap<StorageId, IrohBlobRef>,
}

impl std::fmt::Debug for IrohBulkSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IrohBulkSource")
            .field("endpoint", &self.endpoint.id())
            .field("roots", &self.roots.len())
            .field("snapshots", &self.snapshots.len())
            .field("sealed", &self.sealed.len())
            .finish()
    }
}

impl IrohBulkSource {
    /// Create a source using a runtime owned by the caller.
    ///
    /// The runtime must outlive all calls to this source. Calls are blocking at
    /// the [`BulkSource`] boundary, matching the existing engine API.
    pub fn with_runtime(endpoint: Endpoint, runtime: Arc<Runtime>) -> Self {
        Self {
            endpoint,
            runtime,
            roots: BTreeMap::new(),
            snapshots: BTreeMap::new(),
            sealed: BTreeMap::new(),
        }
    }

    /// Create a source with a dedicated current-thread runtime.
    pub fn new(endpoint: Endpoint) -> std::io::Result<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        Ok(Self::with_runtime(endpoint, Arc::new(runtime)))
    }

    /// Publish the transport address for a snapshot's root manifest.
    pub fn publish_root(&mut self, snapshot: SnapshotId, content_id: ContentId, blob: IrohBlobRef) {
        self.roots.insert(snapshot, (content_id, blob));
    }

    /// Publish the transport address for a snapshot body.
    pub fn publish_snapshot(&mut self, snapshot: SnapshotId, blob: IrohBlobRef) {
        self.snapshots.insert(snapshot, blob);
    }

    /// Publish the transport address for a sealed manifest or object.
    pub fn publish_sealed(&mut self, storage: StorageId, blob: IrohBlobRef) {
        self.sealed.insert(storage, blob);
    }

    /// Close the owned endpoint after all in-flight transfers have finished.
    pub fn shutdown(&self) {
        self.runtime.block_on(self.endpoint.close());
    }

    fn fetch(&self, blob: &IrohBlobRef, max: usize) -> Result<Vec<u8>, BulkError> {
        // The ceiling is enforced twice: the verified size rejects an
        // oversize blob before anything transfers or allocates, and the
        // bounded accumulator below caps allocation while streaming, so
        // a peer that streams past its announced size still cannot force
        // more than `max` plus one leaf of buffering.
        let endpoint = self.endpoint.clone();
        let provider = blob.provider.clone();
        let hash = blob.hash();
        self.runtime.block_on(async move {
            let connection = endpoint
                .connect(provider, iroh_blobs::ALPN)
                .await
                .map_err(|error| BulkError::Transport(error.to_string()))?;
            let (size, _) = get_verified_size(&connection, &hash)
                .await
                .map_err(|error| BulkError::Transport(error.to_string()))?;
            if size > max as u64 {
                return Err(BulkError::Oversize {
                    bytes: usize::try_from(size).unwrap_or(usize::MAX),
                    max,
                });
            }
            bounded_blob_bytes(get_blob(connection, hash), max).await
        })
    }
}

/// Concatenate one blob stream into a buffer capped at `max` content
/// bytes: leaf data accumulates until the ceiling is crossed, parents
/// are protocol overhead (tree hashes, never content) and skip the
/// count, and the bytes return only after `Done` — transport
/// verification completes before the engine sees anything. Generic
/// over the item stream so tests can prove the bound without a
/// network; the live path passes the real `GetBlobResult`.
async fn bounded_blob_bytes<S>(stream: S, max: usize) -> Result<Vec<u8>, BulkError>
where
    S: Stream<Item = GetBlobItem>,
{
    let mut stream = Box::pin(stream);
    let mut out = Vec::new();
    while let Some(item) = stream.next().await {
        match item {
            GetBlobItem::Item(BaoContentItem::Leaf(leaf)) => {
                out.extend_from_slice(&leaf.data);
                if out.len() > max {
                    return Err(BulkError::Oversize {
                        bytes: out.len(),
                        max,
                    });
                }
            }
            GetBlobItem::Item(BaoContentItem::Parent(_)) => {}
            GetBlobItem::Done(_) => return Ok(out),
            GetBlobItem::Error(cause) => {
                return Err(BulkError::Transport(cause.to_string()));
            }
        }
    }
    Err(BulkError::Transport(
        "blob stream ended without completion".to_string(),
    ))
}

impl BulkSource for IrohBulkSource {
    fn fetch_root_manifest(
        &mut self,
        snapshot: &SnapshotId,
        max: usize,
    ) -> Result<Option<SealedManifest>, BulkError> {
        let Some((content_id, blob)) = self.roots.get(snapshot) else {
            return Ok(None);
        };
        self.fetch(blob, max).map(|sealed| {
            Some(SealedManifest {
                content_id: *content_id,
                sealed,
            })
        })
    }

    fn fetch_snapshot(
        &mut self,
        snapshot: &SnapshotId,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        let Some(blob) = self.snapshots.get(snapshot) else {
            return Ok(None);
        };
        self.fetch(blob, max).map(Some)
    }

    fn fetch_sealed(
        &mut self,
        storage: &StorageId,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        let Some(blob) = self.sealed.get(storage) else {
            return Ok(None);
        };
        self.fetch(blob, max).map(Some)
    }
}

/// An in-memory bulk peer for tests: preloaded sealed bytes keyed by
/// their fetch addresses. No network, no async.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MemoryBulkSource {
    roots: BTreeMap<SnapshotId, SealedManifest>,
    snapshots: BTreeMap<SnapshotId, Vec<u8>>,
    sealed: BTreeMap<StorageId, Vec<u8>>,
}

impl MemoryBulkSource {
    /// Serve a sealed root manifest for a snapshot.
    pub fn publish_root(&mut self, snapshot: SnapshotId, manifest: SealedManifest) {
        self.roots.insert(snapshot, manifest);
    }

    /// Serve a snapshot body at its snapshot address.
    pub fn publish_snapshot(&mut self, snapshot: SnapshotId, body: Vec<u8>) {
        self.snapshots.insert(snapshot, body);
    }

    /// Serve sealed bytes at a storage address.
    pub fn publish_sealed(&mut self, storage: StorageId, sealed: Vec<u8>) {
        self.sealed.insert(storage, sealed);
    }
}

impl BulkSource for MemoryBulkSource {
    fn fetch_root_manifest(
        &mut self,
        snapshot: &SnapshotId,
        max: usize,
    ) -> Result<Option<SealedManifest>, BulkError> {
        let Some(manifest) = self.roots.get(snapshot).cloned() else {
            return Ok(None);
        };
        if manifest.sealed.len() > max {
            return Err(BulkError::Oversize {
                bytes: manifest.sealed.len(),
                max,
            });
        }
        Ok(Some(manifest))
    }

    fn fetch_snapshot(
        &mut self,
        snapshot: &SnapshotId,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        let Some(body) = self.snapshots.get(snapshot).cloned() else {
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
        let Some(sealed) = self.sealed.get(storage).cloned() else {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> SnapshotId {
        SnapshotId::from_bytes([0x11; 32])
    }

    #[test]
    fn oversize_sealed_bytes_classify_structured() {
        let mut bulk = MemoryBulkSource::default();
        let storage = StorageId::from_bytes([0x44; 32]);
        bulk.publish_sealed(storage, vec![0xBB; 65]);
        // Size-aware fetch: the ceiling rides the request, and an
        // oversize representation is classified at the boundary instead
        // of surfacing later as undecodable bytes.
        assert_eq!(
            bulk.fetch_sealed(&storage, 64),
            Err(BulkError::Oversize { bytes: 65, max: 64 })
        );
        assert_eq!(
            bulk.fetch_sealed(&storage, 65).unwrap(),
            Some(vec![0xBB; 65])
        );
    }

    #[test]
    fn missing_bytes_are_absence_not_error() {
        let mut bulk = MemoryBulkSource::default();
        assert_eq!(
            bulk.fetch_root_manifest(&snapshot(), usize::MAX).unwrap(),
            None
        );
        assert_eq!(
            bulk.fetch_sealed(&StorageId::from_bytes([0x22; 32]), usize::MAX)
                .unwrap(),
            None
        );
    }

    #[test]
    fn bounded_accumulator_aborts_past_ceiling_without_consuming_tail() {
        use bao_tree::io::{BaoContentItem, Leaf};
        use bytes::Bytes;
        use n0_future::stream;

        // A lying or broken peer streams past its announced size: the
        // accumulator must abort at the ceiling plus one leaf, never
        // buffering the tail.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut items = stream::iter(vec![
            GetBlobItem::Item(BaoContentItem::Leaf(Leaf {
                offset: 0,
                data: Bytes::from_static(b"0123456789"),
            })),
            GetBlobItem::Item(BaoContentItem::Leaf(Leaf {
                offset: 10,
                data: Bytes::from_static(b"0123456789"),
            })),
            GetBlobItem::Item(BaoContentItem::Leaf(Leaf {
                offset: 20,
                data: Bytes::from_static(b"0123456789"),
            })),
        ]);
        let result = runtime.block_on(bounded_blob_bytes(&mut items, 15));
        assert_eq!(result, Err(BulkError::Oversize { bytes: 20, max: 15 }));
        // The third leaf was never pulled: allocation stopped at the
        // ceiling instead of draining the stream.
        assert!(
            runtime.block_on(items.next()).is_some(),
            "abort must leave the tail unconsumed"
        );
    }

    #[test]
    fn bounded_accumulator_rejects_stream_without_completion() {
        use n0_future::stream;

        // Bytes that arrive without the transport's completion signal
        // are unverified by definition: they must fail, never return.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = runtime.block_on(bounded_blob_bytes(stream::iter(vec![]), usize::MAX));
        assert!(matches!(result, Err(BulkError::Transport(_))));
    }

    #[test]
    fn published_bytes_serve_by_address() {
        let mut bulk = MemoryBulkSource::default();
        let manifest = SealedManifest {
            content_id: ContentId::from_bytes([0x33; 32]),
            sealed: vec![0xAA; 40],
        };
        let storage = StorageId::from_bytes([0x44; 32]);
        bulk.publish_root(snapshot(), manifest.clone());
        bulk.publish_sealed(storage, vec![0xBB; 40]);
        assert_eq!(
            bulk.fetch_root_manifest(&snapshot(), usize::MAX).unwrap(),
            Some(manifest)
        );
        assert_eq!(
            bulk.fetch_sealed(&storage, usize::MAX).unwrap(),
            Some(vec![0xBB; 40])
        );
    }

    #[test]
    fn iroh_source_fetches_bao_verified_bytes() {
        use iroh::{endpoint::presets, protocol::Router, Endpoint};
        use iroh_blobs::{store::mem::MemStore, BlobsProtocol};

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (server, client, router, hash) = runtime.block_on(async {
            let server = Endpoint::builder(presets::N0DisableRelay)
                .clear_address_lookup()
                .bind()
                .await
                .unwrap();
            let store = MemStore::new();
            let blobs = BlobsProtocol::new(&store, None);
            let router = Router::builder(server.clone())
                .accept(iroh_blobs::ALPN, blobs)
                .spawn();
            let tag = store.add_slice(b"verified over iroh").await.unwrap();
            let client = Endpoint::builder(presets::N0DisableRelay)
                .clear_address_lookup()
                .bind()
                .await
                .unwrap();
            (server, client, router, tag.hash)
        });

        let provider = direct_addr(&server);
        let runtime = Arc::new(runtime);
        let mut source = IrohBulkSource::with_runtime(client, runtime.clone());
        let storage = StorageId::from_bytes([0x55; 32]);
        source.publish_sealed(
            storage,
            IrohBlobRef {
                provider,
                hash: *hash.as_bytes(),
            },
        );

        assert_eq!(
            source.fetch_sealed(&storage, usize::MAX).unwrap(),
            Some(b"verified over iroh".to_vec())
        );

        runtime.block_on(async {
            router.shutdown().await.unwrap();
            server.close().await;
        });
        source.shutdown();
    }

    #[test]
    fn iroh_source_rejects_oversize_blob_before_buffering() {
        use iroh::{endpoint::presets, protocol::Router, Endpoint};
        use iroh_blobs::{store::mem::MemStore, BlobsProtocol};

        // Multi-chunk blob (bao leaves are 1 KiB) over the ceiling: the
        // verified size rejects it before anything transfers, so this
        // returns fast without ever buffering the 8 KiB.
        let oversize = vec![0xCC; 8192];
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (server, client, router, hash) = runtime.block_on(async {
            let server = Endpoint::builder(presets::N0DisableRelay)
                .clear_address_lookup()
                .bind()
                .await
                .unwrap();
            let store = MemStore::new();
            let blobs = BlobsProtocol::new(&store, None);
            let router = Router::builder(server.clone())
                .accept(iroh_blobs::ALPN, blobs)
                .spawn();
            let tag = store.add_slice(oversize.clone()).await.unwrap();
            let client = Endpoint::builder(presets::N0DisableRelay)
                .clear_address_lookup()
                .bind()
                .await
                .unwrap();
            (server, client, router, tag.hash)
        });

        let provider = direct_addr(&server);
        let runtime = Arc::new(runtime);
        let mut source = IrohBulkSource::with_runtime(client, runtime.clone());
        let storage = StorageId::from_bytes([0x88; 32]);
        source.publish_sealed(
            storage,
            IrohBlobRef {
                provider,
                hash: *hash.as_bytes(),
            },
        );

        assert_eq!(
            source.fetch_sealed(&storage, 4096),
            Err(BulkError::Oversize {
                bytes: 8192,
                max: 4096
            })
        );

        runtime.block_on(async {
            router.shutdown().await.unwrap();
            server.close().await;
        });
        source.shutdown();
    }

    #[test]
    fn iroh_source_fetches_root_manifest_by_snapshot() {
        use iroh::{endpoint::presets, protocol::Router, Endpoint};
        use iroh_blobs::{store::mem::MemStore, BlobsProtocol};

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (server, client, router, hash) = runtime.block_on(async {
            let server = Endpoint::builder(presets::N0DisableRelay)
                .clear_address_lookup()
                .bind()
                .await
                .unwrap();
            let store = MemStore::new();
            let blobs = BlobsProtocol::new(&store, None);
            let router = Router::builder(server.clone())
                .accept(iroh_blobs::ALPN, blobs)
                .spawn();
            let tag = store.add_slice(b"root manifest bytes").await.unwrap();
            let client = Endpoint::builder(presets::N0DisableRelay)
                .clear_address_lookup()
                .bind()
                .await
                .unwrap();
            (server, client, router, tag.hash)
        });

        let snapshot = SnapshotId::from_bytes([0x66; 32]);
        let content_id = ContentId::from_bytes([0x77; 32]);
        let runtime = Arc::new(runtime);
        let mut source = IrohBulkSource::with_runtime(client, runtime.clone());
        source.publish_root(
            snapshot,
            content_id,
            IrohBlobRef {
                provider: direct_addr(&server),
                hash: *hash.as_bytes(),
            },
        );

        assert_eq!(
            source.fetch_root_manifest(&snapshot, usize::MAX).unwrap(),
            Some(SealedManifest {
                content_id,
                sealed: b"root manifest bytes".to_vec(),
            })
        );
        assert_eq!(
            source
                .fetch_root_manifest(&SnapshotId::from_bytes([0x88; 32]), usize::MAX)
                .unwrap(),
            None
        );

        runtime.block_on(async {
            router.shutdown().await.unwrap();
            server.close().await;
        });
        source.shutdown();
    }

    fn direct_addr(endpoint: &iroh::Endpoint) -> EndpointAddr {
        let mut address = EndpointAddr::new(endpoint.id());
        for ip in endpoint.addr().ip_addrs() {
            address = address.with_ip_addr(*ip);
        }
        address
    }
}

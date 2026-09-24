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
//! first, then streams the body into a buffer pre-sized from that
//! size which checks each leaf against the remaining budget before
//! copying — a hostile peer cannot force more than `max` bytes of
//! content, and accepted fetches allocate exactly what was verified.
//!
//! Addressing mirrors what each party may know. Sealed objects are
//! vault-visible, so they fetch by [`StorageId`]; representations also
//! carry their transport root (object-model.md decision 26), and
//! [`BulkSource::fetch_transport`] serves a representation whose raw
//! BLAKE3 (Bao root) is the requested address — the author-attested
//! routing column, verified by the transfer itself. The root manifest of
//! a snapshot is additionally fetchable by [`SnapshotId`] from a member
//! peer holding that snapshot's metadata (the eager manifest exchange of
//! sync-and-peers.md, not a vault read); fetch::root prefers the
//! announcement's transport root and falls back to the exchange. Snapshot
//! bodies are plaintext CAS objects whose content id equals the snapshot
//! id (`ObjectKind::Snapshot`), fetchable the same way; the transport
//! path prefers the announcement's body root. The returned
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
use wyrd_format::{BaoRoot, ContentId, SnapshotId, StorageId};

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

    /// Sealed (or plaintext, for bodies) bytes at a transport-root
    /// address: the representation whose raw BLAKE3 over its bytes is
    /// `root` (object-model.md decision 26). The address is the
    /// author-attested routing column carried by announcements and
    /// manifest mappings; the transfer itself verifies against it on the
    /// live path. Absence is `Ok(None)`.
    fn fetch_transport(&mut self, root: &BaoRoot, max: usize)
        -> Result<Option<Vec<u8>>, BulkError>;
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

/// Append a provider unless the exact ref is already held, preserving
/// publication order and keeping periodic route passes idempotent.
fn push_unique(candidates: &mut Vec<IrohBlobRef>, blob: IrohBlobRef) {
    if !candidates.contains(&blob) {
        candidates.push(blob);
    }
}

/// Upper bound for one provider dial: iroh discovery can stall behind
/// relay propagation, and an unbounded dial wedges the supervised loop
/// inside a pass (no error, no idle line, FUSE still serving — a peer
/// that looks alive but never converges). A timeout reports as
/// transport failure, so the plan retries it on the next pass.
const FETCH_DIAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Upper bound for one whole blob fetch (dial plus verified transfer):
/// the dial bound alone still leaves the size discovery and the Bao
/// stream unbounded, and a peer that connects but never streams wedges
/// the pass exactly the same way. Must exceed the dial bound with room
/// for a slow-but-moving transfer; oversize and verified-invalid still
/// short-circuit before any bytes buffer.
const FETCH_BLOB_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(90);

/// Dial one provider with a deadline: the timeout above is the live
/// value; the parameter exists so tests can prove boundedness fast
/// against an unroutable provider.
async fn dial(
    endpoint: &Endpoint,
    provider: EndpointAddr,
    timeout: std::time::Duration,
) -> Result<iroh::endpoint::Connection, BulkError> {
    tokio::time::timeout(timeout, endpoint.connect(provider, iroh_blobs::ALPN))
        .await
        .map_err(|_| BulkError::Transport("provider dial timed out".to_string()))?
        .map_err(|error| BulkError::Transport(error.to_string()))
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
    /// Sealed representations by storage address. A representation is
    /// immutable and may be advertised by several members, so each
    /// address keeps every provider in publication order rather than a
    /// single overwritten one: a dead route must not displace a live
    /// alternate.
    sealed: BTreeMap<StorageId, Vec<IrohBlobRef>>,
    /// Representations by Bao root, same multi-provider rule. Snapshot
    /// and root-manifest addresses are different: the author-signed
    /// announcement names exactly one route per snapshot, and a route
    /// update replaces it (last accepted wins), so those maps stay
    /// single-valued by policy.
    transport: BTreeMap<BaoRoot, Vec<IrohBlobRef>>,
}

impl std::fmt::Debug for IrohBulkSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IrohBulkSource")
            .field("endpoint", &self.endpoint.id())
            .field("roots", &self.roots.len())
            .field("snapshots", &self.snapshots.len())
            .field("sealed", &self.sealed.len())
            .field("transport", &self.transport.len())
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
            transport: BTreeMap::new(),
        }
    }

    /// Create a source with a dedicated current-thread runtime.
    pub fn new(endpoint: Endpoint) -> std::io::Result<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        Ok(Self::with_runtime(endpoint, Arc::new(runtime)))
    }

    /// Create a source bound to a default iroh endpoint (N0 relays for
    /// peer reachability) on a dedicated runtime: the binary's fetch
    /// side, with no endpoint plumbing in the composer.
    pub fn connect_default() -> std::io::Result<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let endpoint = runtime
            .block_on(async {
                iroh::Endpoint::builder(iroh::endpoint::presets::N0)
                    .bind()
                    .await
            })
            .map_err(|error| std::io::Error::other(error.to_string()))?;
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
    /// Repeated publication of the same provider is a no-op, so a
    /// periodic route pass neither reorders nor grows the candidate
    /// list.
    pub fn publish_sealed(&mut self, storage: StorageId, blob: IrohBlobRef) {
        push_unique(self.sealed.entry(storage).or_default(), blob);
    }

    /// Publish the transport address for a representation by its Bao
    /// root (object-model.md decision 26): the root is derived from the
    /// blob's own hash — the verified-transfer identity and the fetch
    /// address are the same value by construction, so a mapping cannot
    /// name unrelated bytes.
    pub fn publish_transport(&mut self, blob: IrohBlobRef) {
        push_unique(
            self.transport
                .entry(BaoRoot::from_bytes(blob.hash))
                .or_default(),
            blob,
        );
    }

    /// Drop every route this source holds. Route maps are derived from
    /// durable state, so a publication pass clears before republishing:
    /// without it, providers for superseded routes accumulate across
    /// passes and a stale provider could outlive its announcement.
    pub(crate) fn clear_routes(&mut self) {
        self.roots.clear();
        self.snapshots.clear();
        self.sealed.clear();
        self.transport.clear();
    }

    /// The recorded provider candidates for a sealed representation, in
    /// publication order: diagnostics and tests.
    #[cfg(test)]
    pub(crate) fn sealed_route(&self, storage: &StorageId) -> Option<&[IrohBlobRef]> {
        self.sealed.get(storage).map(Vec::as_slice)
    }

    /// Close the owned endpoint after all in-flight transfers have finished.
    pub fn shutdown(&self) {
        self.runtime.block_on(self.endpoint.close());
    }

    /// Fetch a representation by trying each recorded provider in
    /// publication order. Absence and transport failure fall through to
    /// the next candidate; oversize is terminal because every provider
    /// serves the same immutable bytes, so the size is a property of the
    /// representation, not of the route. With no provider serving it,
    /// the last transport error is returned (or absence when there were
    /// no candidates).
    fn fetch_candidates(
        &self,
        candidates: &[IrohBlobRef],
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        Self::fetch_candidates_with(candidates, max, |blob, max| self.fetch(blob, max))
    }

    /// The provider-fallthrough loop, extracted so tests can drive it
    /// without a network. Candidates are tried in publication order;
    /// absence and transport failure fall through to the next; oversize
    /// is terminal because every provider serves the same immutable
    /// bytes. With none serving, the last transport error returns (or
    /// absence when there were no candidates).
    fn fetch_candidates_with<F>(
        candidates: &[IrohBlobRef],
        max: usize,
        mut fetch: F,
    ) -> Result<Option<Vec<u8>>, BulkError>
    where
        F: FnMut(&IrohBlobRef, usize) -> Result<Vec<u8>, BulkError>,
    {
        let mut last_error = None;
        for blob in candidates {
            match fetch(blob, max) {
                Ok(bytes) => return Ok(Some(bytes)),
                Err(oversize @ BulkError::Oversize { .. }) => return Err(oversize),
                Err(error) => last_error = Some(error),
            }
        }
        match last_error {
            Some(error) => Err(error),
            None => Ok(None),
        }
    }

    fn fetch(&self, blob: &IrohBlobRef, max: usize) -> Result<Vec<u8>, BulkError> {
        // The ceiling is enforced twice: the verified size rejects an
        // oversize blob before anything transfers, and the bounded
        // accumulator below pre-sizes from that verified size and
        // checks each leaf before copying — a peer that streams past
        // its announced size is refused, and accepted fetches return
        // at most `max` bytes without geometric over-reservation.
        let endpoint = self.endpoint.clone();
        let provider = blob.provider.clone();
        let hash = blob.hash();
        self.runtime.block_on(async move {
            // One deadline for the whole attempt: dial, size discovery,
            // and streaming share it, so a peer that connects but never
            // streams cannot outlast a peer that never answers. Slow
            // passes still complete; the plan retries what they miss.
            tokio::time::timeout(FETCH_BLOB_TIMEOUT, async move {
                let connection = dial(&endpoint, provider, FETCH_DIAL_TIMEOUT).await?;
                let (size, _) = get_verified_size(&connection, &hash)
                    .await
                    .map_err(|error| BulkError::Transport(error.to_string()))?;
                if size > max as u64 {
                    return Err(BulkError::Oversize {
                        bytes: usize::try_from(size).unwrap_or(usize::MAX),
                        max,
                    });
                }
                bounded_blob_bytes(get_blob(connection, hash), max, size as usize).await
            })
            .await
            .map_err(|_| BulkError::Transport("blob fetch timed out".to_string()))?
        })
    }
}

impl crate::runtime::RoutePublishing for MemoryBulkSource {
    /// The in-memory fake never carries live routes: its tests publish
    /// addresses by hand.
    fn publish_routes(
        &mut self,
        _state: &crate::runtime::RuntimeState,
    ) -> Result<crate::runtime::RouteReport, crate::runtime::EngineError> {
        Ok(crate::runtime::RouteReport::default())
    }
}

/// Concatenate one blob stream into a buffer capped at `max` content
/// bytes: the buffer is pre-sized from `reserve` — the verified blob
/// size on the live path, so accepted fetches never reallocate — and
/// each leaf is checked against the remaining budget before it is
/// copied, so the returned content never exceeds `max`. Parents are
/// protocol overhead (tree hashes, never content) and skip the count,
/// and the bytes return only after `Done` — transport verification
/// completes before the engine sees anything. Generic over the item
/// stream so tests can prove the bound without a network; the live
/// path passes the real `GetBlobResult`.
async fn bounded_blob_bytes<S>(stream: S, max: usize, reserve: usize) -> Result<Vec<u8>, BulkError>
where
    S: Stream<Item = GetBlobItem>,
{
    let mut stream = Box::pin(stream);
    let mut out = Vec::with_capacity(reserve.min(max));
    while let Some(item) = stream.next().await {
        match item {
            GetBlobItem::Item(BaoContentItem::Leaf(leaf)) => {
                // Budget before copy: a single hostile leaf must not
                // force more than the remaining ceiling of allocation.
                if leaf.data.len() > max.saturating_sub(out.len()) {
                    return Err(BulkError::Oversize {
                        bytes: out.len().saturating_add(leaf.data.len()),
                        max,
                    });
                }
                out.extend_from_slice(&leaf.data);
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
        let Some(candidates) = self.sealed.get(storage) else {
            return Ok(None);
        };
        self.fetch_candidates(candidates, max)
    }

    fn fetch_transport(
        &mut self,
        root: &BaoRoot,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        let Some(candidates) = self.transport.get(root) else {
            return Ok(None);
        };
        self.fetch_candidates(candidates, max)
    }
}

/// An in-memory bulk peer for tests: preloaded sealed bytes keyed by
/// their fetch addresses. No network, no async.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MemoryBulkSource {
    roots: BTreeMap<SnapshotId, SealedManifest>,
    snapshots: BTreeMap<SnapshotId, Vec<u8>>,
    sealed: BTreeMap<StorageId, Vec<u8>>,
    transport: BTreeMap<BaoRoot, Vec<u8>>,
}

impl MemoryBulkSource {
    /// Serve a sealed root manifest for a snapshot.
    pub fn publish_root(&mut self, snapshot: SnapshotId, manifest: SealedManifest) {
        self.roots.insert(snapshot, manifest);
    }

    /// Publish sealed (or plaintext) bytes under the transport root the
    /// bytes themselves carry: the map key is derived from the content,
    /// so the address the publisher hands out is exactly what the
    /// transfer verifies against. A publisher cannot place bytes under a
    /// root they do not hash to.
    pub fn publish_transport(&mut self, bytes: Vec<u8>) {
        self.transport.insert(crate::seal::blob_root(&bytes), bytes);
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

    fn fetch_transport(
        &mut self,
        root: &BaoRoot,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        let Some(bytes) = self.transport.get(root).cloned() else {
            return Ok(None);
        };
        if bytes.len() > max {
            return Err(BulkError::Oversize {
                bytes: bytes.len(),
                max,
            });
        }
        Ok(Some(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bao_tree::io::{BaoContentItem, Leaf};
    use bytes::Bytes;

    fn snapshot() -> SnapshotId {
        SnapshotId::from_bytes([0x11; 32])
    }

    fn leaf(offset: u64, data: Bytes) -> GetBlobItem {
        GetBlobItem::Item(BaoContentItem::Leaf(Leaf { offset, data }))
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
        assert_eq!(
            bulk.fetch_transport(&BaoRoot::from_bytes([0x33; 32]), usize::MAX)
                .unwrap(),
            None
        );
    }

    #[test]
    fn transport_addresses_name_only_their_own_bytes() {
        // Publishing derives the map key from the content itself: the
        // bytes are reachable exactly under the root they hash to, so a
        // wrong root is absence before any transfer, never unverified
        // bytes (decision 26: the transfer is the verification).
        let bytes = b"sealed representation bytes".to_vec();
        let root = crate::seal::blob_root(&bytes);
        let mut bulk = MemoryBulkSource::default();
        bulk.publish_transport(bytes.clone());
        assert_eq!(
            bulk.fetch_transport(&root, usize::MAX).unwrap(),
            Some(bytes)
        );
        assert_eq!(
            bulk.fetch_transport(&BaoRoot::from_bytes([0x77; 32]), usize::MAX)
                .unwrap(),
            None,
            "a root the bytes do not hash to names nothing"
        );
        assert_eq!(
            bulk.fetch_transport(&root, 4),
            Err(BulkError::Oversize { bytes: 27, max: 4 })
        );
    }

    #[test]
    fn bounded_accumulator_aborts_past_ceiling_without_consuming_tail() {
        use n0_future::stream;

        // A lying or broken peer streams past its announced size: the
        // accumulator must refuse the leaf that crosses the ceiling,
        // never buffering the tail.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut items = stream::iter(vec![
            leaf(0, Bytes::from_static(b"0123456789")),
            leaf(10, Bytes::from_static(b"0123456789")),
            leaf(20, Bytes::from_static(b"0123456789")),
        ]);
        let result = runtime.block_on(bounded_blob_bytes(&mut items, 15, 15));
        assert_eq!(result, Err(BulkError::Oversize { bytes: 20, max: 15 }));
        // The third leaf was never pulled: allocation stopped at the
        // ceiling instead of draining the stream.
        assert!(
            runtime.block_on(items.next()).is_some(),
            "abort must leave the tail unconsumed"
        );
    }

    #[test]
    fn bounded_accumulator_rejects_single_leaf_over_remaining_budget() {
        use n0_future::stream;

        // One leaf larger than the whole ceiling: it must be refused
        // before copying, not buffered and then rejected — otherwise a
        // hostile leaf of arbitrary size blows the allocation bound.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut items = stream::iter(vec![
            leaf(0, Bytes::from(vec![0xAA; 1024])),
            leaf(1024, Bytes::from_static(b"tail")),
        ]);
        let result = runtime.block_on(bounded_blob_bytes(&mut items, 16, 16));
        assert_eq!(
            result,
            Err(BulkError::Oversize {
                bytes: 1024,
                max: 16
            })
        );
        assert!(
            runtime.block_on(items.next()).is_some(),
            "refusal must happen before the leaf is consumed"
        );
    }

    #[test]
    fn bounded_accumulator_holds_exact_boundary_and_zero_max() {
        use n0_future::stream;

        // Exactly `max` bytes fit; the next byte does not — and with a
        // zero ceiling even the first byte is refused uncopied.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let items = stream::iter(vec![
            leaf(0, Bytes::from_static(b"0123456789")),
            leaf(10, Bytes::from_static(b"0123456789")),
            leaf(20, Bytes::from_static(b"x")),
        ]);
        assert_eq!(
            runtime.block_on(bounded_blob_bytes(items, 20, 20)),
            Err(BulkError::Oversize { bytes: 21, max: 20 })
        );
        let items = stream::iter(vec![leaf(0, Bytes::from_static(b"x"))]);
        assert_eq!(
            runtime.block_on(bounded_blob_bytes(items, 0, 0)),
            Err(BulkError::Oversize { bytes: 1, max: 0 })
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
        let result = runtime.block_on(bounded_blob_bytes(stream::iter(vec![]), usize::MAX, 0));
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
    fn fetch_candidates_tries_providers_in_order_and_falls_through() {
        let key = |seed: u8| iroh::SecretKey::from_bytes(&[seed; 32]).public();
        let a = IrohBlobRef {
            provider: EndpointAddr::new(key(0x11)),
            hash: [0xAA; 32],
        };
        let b = IrohBlobRef {
            provider: EndpointAddr::new(key(0x22)),
            hash: [0xAA; 32],
        };
        let mut tried = Vec::new();
        let served =
            IrohBulkSource::fetch_candidates_with(&[a.clone(), b.clone()], 64, |blob, _max| {
                tried.push(blob.provider.id);
                if blob == &a {
                    Err(BulkError::Transport("down".into()))
                } else {
                    Ok(vec![1, 2, 3])
                }
            })
            .unwrap();
        assert_eq!(served, Some(vec![1, 2, 3]));
        assert_eq!(
            tried,
            vec![a.provider.id, b.provider.id],
            "publication order, then fallthrough"
        );

        // Oversize is terminal: the representation's size does not
        // depend on which provider serves it.
        let oversize =
            IrohBulkSource::fetch_candidates_with(&[a.clone(), b.clone()], 1, |blob, _| {
                if blob == &a {
                    Err(BulkError::Oversize { bytes: 5, max: 1 })
                } else {
                    Ok(Vec::new())
                }
            });
        assert!(matches!(oversize, Err(BulkError::Oversize { .. })));

        // No candidates is absence, not an error.
        assert_eq!(
            IrohBulkSource::fetch_candidates_with(&[], 1, |_, _| unreachable!()).unwrap(),
            None
        );
    }

    #[test]
    fn iroh_source_falls_back_across_providers_for_one_root() {
        use iroh::{endpoint::presets, protocol::Router, Endpoint};
        use iroh_blobs::{store::mem::MemStore, BlobsProtocol};

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let content = b"shared immutable representation";
        let (server_a, server_b, client, router_a, router_b, hash) = runtime.block_on(async {
            let bind = || async {
                Endpoint::builder(presets::N0DisableRelay)
                    .clear_address_lookup()
                    .bind()
                    .await
                    .unwrap()
            };
            let server_a = bind().await;
            let server_b = bind().await;
            let store_a = MemStore::new();
            let store_b = MemStore::new();
            let router_a = Router::builder(server_a.clone())
                .accept(iroh_blobs::ALPN, BlobsProtocol::new(&store_a, None))
                .spawn();
            let router_b = Router::builder(server_b.clone())
                .accept(iroh_blobs::ALPN, BlobsProtocol::new(&store_b, None))
                .spawn();
            let tag = store_a.add_slice(content).await.unwrap();
            store_b.add_slice(content).await.unwrap();
            let client = bind().await;
            (server_a, server_b, client, router_a, router_b, tag.hash)
        });

        let runtime = Arc::new(runtime);
        let mut source = IrohBulkSource::with_runtime(client, runtime.clone());
        let root = BaoRoot::from_bytes(*hash.as_bytes());
        // Two members advertise the same representation; the dead
        // provider is published LAST, the order that used to win.
        for server in [&server_a, &server_b] {
            source.publish_transport(IrohBlobRef {
                provider: direct_addr(server),
                hash: *hash.as_bytes(),
            });
        }
        assert_eq!(
            source.transport.get(&root).map(Vec::len),
            Some(2),
            "alternate providers are retained, not overwritten"
        );
        source.publish_transport(IrohBlobRef {
            provider: direct_addr(&server_a),
            hash: *hash.as_bytes(),
        });
        assert_eq!(
            source.transport.get(&root).map(Vec::len),
            Some(2),
            "republication is idempotent"
        );
        // The storage-addressed fallback path keeps alternates too.
        let storage = StorageId::from_bytes([0x66; 32]);
        for server in [&server_a, &server_b] {
            source.publish_sealed(
                storage,
                IrohBlobRef {
                    provider: direct_addr(server),
                    hash: *hash.as_bytes(),
                },
            );
        }
        assert_eq!(source.sealed.get(&storage).map(Vec::len), Some(2));

        // The later-published endpoint dies; the fetch still succeeds
        // through the earlier alternate.
        runtime.block_on(async {
            router_b.shutdown().await.unwrap();
            server_b.close().await;
        });
        assert_eq!(
            source.fetch_transport(&root, usize::MAX).unwrap(),
            Some(content.to_vec())
        );

        runtime.block_on(async {
            router_a.shutdown().await.unwrap();
            server_a.close().await;
        });
        source.shutdown();
    }

    #[test]
    fn dial_against_a_silent_relay_times_out_instead_of_hanging() {
        use iroh::{endpoint::presets, Endpoint, RelayUrl};
        use std::time::{Duration, Instant};

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        // A relay that accepts TCP and never speaks: the handshake
        // stalls exactly like the guest failure (relay-coordinated
        // discovery with no bound). The listener is leaked so the port
        // stays open for the test's duration.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::mem::forget(listener);
        let client = runtime.block_on(async {
            Endpoint::builder(presets::N0)
                .clear_address_lookup()
                .bind()
                .await
                .unwrap()
        });
        let relay: RelayUrl = format!("https://127.0.0.1:{port}").parse().unwrap();
        let provider = EndpointAddr::new(iroh::SecretKey::from_bytes(&[0x77; 32]).public())
            .with_relay_url(relay);
        let start = Instant::now();
        let result = runtime.block_on(dial(&client, provider, Duration::from_millis(500)));
        let elapsed = start.elapsed();
        assert!(
            matches!(result, Err(BulkError::Transport(ref message)) if message == "provider dial timed out"),
            "silent relay must trip the dial timeout, got {result:?}"
        );
        assert!(
            elapsed < Duration::from_secs(30),
            "dial must stay bounded, took {elapsed:?}"
        );
        runtime.block_on(client.close());
    }

    #[test]
    fn iroh_source_serves_transport_roots() {
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
            let tag = store.add_slice(b"verified over transport").await.unwrap();
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
        // The map key derives from the blob's own hash: the address the
        // publisher hands out is exactly what the transfer verifies
        // against, so a root/blob mismatch cannot be registered.
        source.publish_transport(IrohBlobRef {
            provider,
            hash: *hash.as_bytes(),
        });
        let root = BaoRoot::from_bytes(*hash.as_bytes());
        assert_eq!(
            source.fetch_transport(&root, usize::MAX).unwrap(),
            Some(b"verified over transport".to_vec())
        );
        assert_eq!(
            source
                .fetch_transport(&BaoRoot::from_bytes([0x99; 32]), usize::MAX)
                .unwrap(),
            None,
            "a root no blob was published under names nothing"
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

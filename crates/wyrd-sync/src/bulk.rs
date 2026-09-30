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
    /// The attempt ran out of its pass-budget slice before completing:
    /// evidence about the budget, never about the provider. The plan
    /// counts it but does not strike on it (a sliced timeout carries
    /// no fault information — with a bigger share the attempt might
    /// have succeeded). Only attempts the candidate walk subdivided
    /// report it: a full-share attempt (the only or last candidate,
    /// or any single-route fetch) reports [`BulkError::Transport`] on
    /// expiry exactly as before, so a hanging route with no one
    /// behind it still backs off. `slice` is the budget that actually
    /// expired at the reporting site: the attempt's slice at the
    /// outer timeout, the dial's slice (`FETCH_DIAL_TIMEOUT` capped)
    /// at the dial timeout — the two coincide at default budgets and
    /// diverge only when a pass budget exceeds the dial bound.
    /// Zero when the walk stopped before granting any. Instant
    /// failures under a slice — refused dials, protocol errors,
    /// oversize — stay [`BulkError::Transport`]: those completed
    /// observations are fault information even when the budget is
    /// tight.
    #[error("bulk attempt ran out of its {slice:?} pass-budget slice")]
    Deadline { slice: std::time::Duration },
    #[error("sealed representation of {bytes} bytes exceeds the {max}-byte fetch ceiling")]
    Oversize { bytes: usize, max: usize },
}

/// Per-attempt fetch deadline knob: the plan hands the source the
/// absolute instant its budget runs out (the nearest held-mutation
/// deadline), and the source clamps **every** attempt to the time
/// remaining at that attempt — a deadline, not a duration, so a later
/// attempt in the same pass cannot re-arm with a stale budget after an
/// earlier attempt burned its share. One stalled provider can no
/// longer push a timeout decision past its wall-clock bound. The
/// default is a no-op (attempts run under the source's own built-in
/// timeouts); sources with real per-attempt deadlines override it.
/// `IrohBulkSource` goes further and divides the remaining time
/// across the candidates that are still unattempted, so each attempt
/// re-arms to a *smaller* share, not the live remaining. The knob is
/// plan-run state: the plan sets it at entry and clears
/// it on the way out.
pub trait AttemptBudget {
    fn set_attempt_deadline(&mut self, _deadline: Option<std::time::Instant>) {}
}

/// The synchronous bulk boundary: sealed manifests and sealed objects
/// by their fetch addresses. Every fetch is size-aware: `max` is the
/// caller's pre-decode byte ceiling, and a representation over it must
/// fail with [`BulkError::Oversize`] rather than return bytes.
pub trait BulkSource: AttemptBudget {
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
/// Order is publication order, and pairs persist within a pass:
/// `publish_recorded_routes` (`transport/routes.rs`) clears between
/// passes, so a dead-first list within one pass comes from that
/// pass's recorded state — the walk tests below build theirs by hand
/// for the same reason, and stay valid only while publication keeps
/// this append-without-prepend shape.
fn push_unique(candidates: &mut Vec<IrohBlobRef>, blob: IrohBlobRef) {
    if !candidates.contains(&blob) {
        candidates.push(blob);
    }
}

/// One candidate's share of the pass budget: the fair division of the
/// time left across the candidates still unattempted, floored so an
/// early-listed slow-but-live provider gets a usable attempt instead
/// of a guaranteed expiry. The floor never exceeds half the remaining
/// budget (and never the dial bound): no candidate takes more than
/// half of what's left, so a dead-first provider cannot spend the
/// whole slice. What it does not promise is a usable share for every
/// candidate: tails shrink geometrically, so with several hanging
/// candidates ahead a late live route can get an unusably small
/// slice. Candidate lists are short in practice — bounded by the
/// distinct recorded providers for one address — so the walk reaches
/// the live route; a deep hanging tail would starve, and fixing that
/// needs route ordering, which belongs to retry-policy work, not to
/// this division. The floor draws from the shared phase budget: at
/// N>=3 the first provider can take up to half the phase's remaining
/// budget where the bare division gave it remaining/N, so intra-item
/// fairness trades against inter-item fairness in the same change.
/// The last candidate always gets everything left; a spent budget
/// shares nothing (the caller stops the walk on a zero share rather
/// than attempting).
fn candidate_share(
    remaining: std::time::Duration,
    index: usize,
    total: usize,
) -> std::time::Duration {
    let fair = remaining / (total - index) as u32;
    fair.max(FETCH_DIAL_TIMEOUT.min(remaining / 2))
}

/// Whether the candidate walk subdivided this attempt below what an
/// unshared attempt would have received. `Shared` attempts that
/// expire report [`BulkError::Deadline`]: the walk took budget from
/// them, so the expiry is budget evidence. `Full` attempts — the only
/// or last candidate, or any single-route fetch outside a walk —
/// report [`BulkError::Transport`] on expiry exactly as before: with
/// no one behind them a hanging route must still back off.
///
/// The walk computes this with [`attempt_bound`] from the granted
/// share and the live remaining, and sets it alongside the re-armed
/// deadline as a pair — `fetch` cannot derive it, because the re-arm
/// makes the remaining it re-reads approximately equal the share by
/// construction. One helper, one call site per attempt, so the
/// timeout that fires and the class it maps to agree structurally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttemptBound {
    Full,
    Shared,
}

/// Whether subdividing to `share` out of `remaining` shortens the
/// attempt below its unshared bound (`remaining` clamped to the
/// built-in blob timeout): a share roomier than the built-ins leaves
/// a `Full` attempt whose expiry is fault evidence, not budget
/// evidence. Pure so tests pin the boundary without a network.
fn attempt_bound(
    share: Option<std::time::Duration>,
    remaining: std::time::Duration,
) -> AttemptBound {
    let unshared = remaining.min(FETCH_BLOB_TIMEOUT);
    match share {
        Some(share) if share.min(FETCH_BLOB_TIMEOUT) < unshared => AttemptBound::Shared,
        _ => AttemptBound::Full,
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
/// against an unroutable provider. A dial cut short by subdivision
/// reports [`BulkError::Deadline`] instead of transport failure: a
/// timeout under an artificially shortened deadline carries no fault
/// information. The class follows the walk's subdivision grant
/// (`bound`), not the dial's own expiry — under a shared slice even
/// a faultily slow provider reads as budget pressure.
/// Instant dial failures (refused, unreachable) stay
/// transport errors — those completed even under the slice.
async fn dial(
    endpoint: &Endpoint,
    provider: EndpointAddr,
    timeout: std::time::Duration,
    bound: AttemptBound,
) -> Result<iroh::endpoint::Connection, BulkError> {
    tokio::time::timeout(timeout, endpoint.connect(provider, iroh_blobs::ALPN))
        .await
        .map_err(|_| {
            if bound == AttemptBound::Shared {
                BulkError::Deadline { slice: timeout }
            } else {
                BulkError::Transport("provider dial timed out".to_string())
            }
        })?
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
    /// Plan-run deadline from [`AttemptBudget`]: the instant the pass's
    /// budget runs out, re-clamped to the remaining time on every
    /// attempt. `None` runs under the built-in timeouts. Plan-run
    /// state, reset by the plan — never source configuration.
    attempt_deadline: Option<std::time::Instant>,
    /// The candidate walk's bound for the in-flight attempt, set
    /// alongside the re-armed [`IrohBulkSource::attempt_deadline`] and
    /// read by `fetch` to classify a timeout as budget evidence
    /// (`Shared`) or fault evidence (`Full`). `None` outside a walk:
    /// single-route fetches are never subdivided. Plan-run state like
    /// the deadline, restored on the same exits.
    attempt_bound: Option<AttemptBound>,
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
            attempt_deadline: None,
            attempt_bound: None,
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

    /// Close the owned endpoint, waiting at most `deadline` for
    /// in-flight transfers to finish: teardown joins must stay bounded
    /// even when a peer stalls mid-transfer. A timeout abandons the
    /// graceful close and reports it — the endpoint is then aborted
    /// (iroh logs it), so the peer sees a hard connection failure
    /// rather than a clean close. The caller still drops the source,
    /// so no transfer outlives the shutdown either way.
    pub fn shutdown(&self, deadline: std::time::Duration) -> std::io::Result<()> {
        self.runtime.block_on(super::close::with_deadline(
            self.endpoint.close(),
            deadline,
            "endpoint close timed out with transfers in flight",
        ))
    }

    /// Fetch a representation by trying each recorded provider in
    /// publication order. Absence and transport failure fall through to
    /// the next candidate; oversize is terminal because every provider
    /// serves the same immutable bytes, so the size is a property of the
    /// representation, not of the route. With no provider serving it,
    /// the last transport error is returned; no candidates at all is
    /// absence; candidates with no completed attempt (a budget spent
    /// before anything could be asked) is a deadline, never a
    /// fabricated absence.
    ///
    /// Under a pass budget each remaining candidate gets a fair share
    /// of the time left, floored so an early slow-but-live provider
    /// gets a usable attempt, recomputed as time burns: without it a
    /// dead-first provider spends the whole remaining slice on its
    /// dial and the live candidates behind it are never attempted —
    /// every pass repeats the same burned dial and the item never
    /// recovers. An attempt the walk subdivided expires as a deadline
    /// the plan counts but does not strike; a full-share attempt (the
    /// only or last candidate) expires as a transport failure exactly
    /// as before, so a hanging route with no one behind it still
    /// backs off. Unbudgeted runs keep the full timeouts per candidate.
    fn fetch_candidates(
        &mut self,
        candidates: &[IrohBlobRef],
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        let budget = self.attempt_deadline;
        let mut last_error = None;
        let total = candidates.len();
        for (index, blob) in candidates.iter().enumerate() {
            if let Some(deadline) = budget {
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                let share = candidate_share(remaining, index, total);
                if share.is_zero() {
                    // The budget is spent to ~1ns: stop the walk with no
                    // attempt and no strike. Attempting on a zero share
                    // could only expire and strike a provider for the
                    // pass running out, never for anything it did.
                    break;
                }
                self.attempt_deadline = Some(std::time::Instant::now() + share);
                self.attempt_bound = Some(attempt_bound(Some(share), remaining));
            }
            match self.fetch(blob, max) {
                Ok(bytes) => {
                    self.attempt_deadline = budget;
                    self.attempt_bound = None;
                    return Ok(Some(bytes));
                }
                Err(oversize @ BulkError::Oversize { .. }) => {
                    self.attempt_deadline = budget;
                    self.attempt_bound = None;
                    return Err(oversize);
                }
                Err(error) => last_error = Some(error),
            }
        }
        self.attempt_deadline = budget;
        self.attempt_bound = None;
        match last_error {
            Some(error) => Err(error),
            // No candidates is genuine absence: nothing to ask. But
            // candidates with no completed attempt means the budget ran
            // out before anything could be asked — a deadline, never a
            // fabricated absence claim about what the peers hold.
            None if total == 0 => Ok(None),
            None => Err(BulkError::Deadline {
                slice: std::time::Duration::ZERO,
            }),
        }
    }

    /// The provider-fallthrough loop, extracted so tests can drive it
    /// without a network. Candidates are tried in publication order;
    /// absence and transport failure fall through to the next; oversize
    /// is terminal because every provider serves the same immutable
    /// bytes. With none serving, the last transport error returns (or
    /// absence when there were no candidates). Test-only: production
    /// goes through [`IrohBulkSource::fetch_candidates`], which
    /// fair-shares the pass budget across the same loop.
    #[cfg(test)]
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
        // The plan may cap this attempt at the time remaining to its
        // deadline, re-read here so every attempt in the pass clamps
        // to the live remaining. How an expiry classifies comes from
        // the walk's bound, set alongside the re-armed deadline: a
        // subdivided (`Shared`) attempt that expires reports
        // [`BulkError::Deadline`], which the plan counts but does not
        // strike — the walk took budget from it, so the expiry is
        // budget evidence. A full-share attempt (the only or last
        // candidate, or any single-route fetch) reports a transport
        // timeout exactly as before: with no one behind it a hanging
        // route must still back off. Only timeouts map this way — an
        // instant failure under a slice (refused dial, protocol error)
        // completed its observation and stays a transport error.
        // Unbudgeted runs use the built-in timeouts.
        let bound = self.attempt_bound.unwrap_or(AttemptBound::Full);
        let blob_timeout = self
            .attempt_deadline
            .map(|deadline| {
                deadline
                    .saturating_duration_since(std::time::Instant::now())
                    .min(FETCH_BLOB_TIMEOUT)
            })
            .unwrap_or(FETCH_BLOB_TIMEOUT);
        let dial_timeout = FETCH_DIAL_TIMEOUT.min(blob_timeout);
        self.runtime.block_on(async move {
            // One deadline for the whole attempt: dial, size discovery,
            // and streaming share it, so a peer that connects but never
            // streams cannot outlast a peer that never answers. Slow
            // passes still complete; the plan retries what they miss.
            tokio::time::timeout(blob_timeout, async move {
                let connection = dial(&endpoint, provider, dial_timeout, bound).await?;
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
            .map_err(|_| {
                if bound == AttemptBound::Shared {
                    BulkError::Deadline {
                        slice: blob_timeout,
                    }
                } else {
                    BulkError::Transport("blob fetch timed out".to_string())
                }
            })?
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

impl AttemptBudget for IrohBulkSource {
    fn set_attempt_deadline(&mut self, deadline: Option<std::time::Instant>) {
        self.attempt_deadline = deadline;
        // The walk re-arms its bound per attempt; a fresh deadline
        // from the plan carries none until the walk grants one.
        self.attempt_bound = None;
    }
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
        // Cloned: the candidate walk below re-arms the per-attempt
        // budget through `&mut self`, which the map borrow would not
        // survive. Candidate lists are short (providers per address),
        // so the copy is cheaper than restructuring the maps.
        let Some(candidates) = self.sealed.get(storage).cloned() else {
            return Ok(None);
        };
        self.fetch_candidates(&candidates, max)
    }

    fn fetch_transport(
        &mut self,
        root: &BaoRoot,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        let Some(candidates) = self.transport.get(root).cloned() else {
            return Ok(None);
        };
        self.fetch_candidates(&candidates, max)
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

/// In-memory: attempts are instant, so the plan's per-attempt cap
/// has nothing to bound.
impl AttemptBudget for MemoryBulkSource {}

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
#[path = "bulk/tests_bulk.rs"]
mod tests;

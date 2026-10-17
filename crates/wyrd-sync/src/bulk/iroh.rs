//! Network bulk backend: `IrohBulkSource` and the walk/timeout machinery.
//!
//! The candidate walk, provider memory, dial/transfer allowances, and the
//! bounded blob accumulator live here with the source that runs them.
//! The fetch contract they implement is `super::BulkSource`.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use ::iroh::{Endpoint, EndpointAddr};
use bao_tree::io::BaoContentItem;
use iroh_blobs::{
    get::request::{get_blob, get_verified_size, GetBlobItem},
    Hash,
};
use n0_future::{Stream, StreamExt};
use tokio::runtime::Runtime;
use wyrd_format::{BaoRoot, ContentId, SnapshotId, StorageId};

use super::{AttemptBudget, BulkError, BulkSource, SealedManifest};

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

/// How long a provider's failure mark sinks it to the walk's tail:
/// judgment, not measurement. Long enough to span consecutive passes
/// (a dead route stays sunk while the pass that observed it is still
/// recent), short enough that a restarted peer recovers without
/// operator action. Revisit when the attempt forensics show flapping
/// (marks re-laid every pass) or sticking (live routes sunk for the
/// whole TTL).
pub(crate) const PROVIDER_BAD_MARK_TTL: std::time::Duration = std::time::Duration::from_secs(300);

/// One provider's last completed failure observation: when it
/// happened. Only failures live here — a fulfilled attempt removes
/// the provider's mark, and a provider with no mark (never tried, or
/// last tried successfully) orders ahead of marked ones. Wall-clock,
/// not pass-counted: the memory belongs to the source and spans
/// passes, while pass numbering belongs to the plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProviderMark {
    pub(crate) failed_at: std::time::Instant,
}

/// Order one walk's candidates from the provider memory: marked
/// providers sink behind unmarked ones, publication order stable
/// within each tier, nobody dropped. The walk attempts the first
/// [`FETCH_WALK_CAP`] of this order per pass — sinking spends a
/// dead route's dial from the tail's attempts instead of the head's,
/// so a live alternate is reached before the cap closes. Expired
/// marks prune here, so the map holds only live evidence. Pure over
/// the map so tests pin the tiers without a network; the live walk
/// passes its own memory with the current instant.
pub(crate) fn order_candidates(
    candidates: &[IrohBlobRef],
    memory: &mut HashMap<[u8; 32], ProviderMark>,
    now: std::time::Instant,
) -> Vec<IrohBlobRef> {
    memory.retain(|_, mark| now.duration_since(mark.failed_at) < PROVIDER_BAD_MARK_TTL);
    let mut live = Vec::with_capacity(candidates.len());
    let mut sunk = Vec::new();
    for blob in candidates {
        if memory.contains_key(blob.provider.id.as_bytes()) {
            sunk.push(blob.clone());
        } else {
            live.push(blob.clone());
        }
    }
    live.extend(sunk);
    live
}

/// One attempt's lesson for the provider memory: fulfillment
/// clears whatever came before (liveness observed beats failure
/// remembered); a dial-phase transport failure lays (or refreshes)
/// the mark — route evidence, independent of which representation
/// was asked for, since the dial never reached the provider;
/// everything else teaches nothing. In particular transfer-phase
/// failures never mark: a live member's legitimate "not found" for
/// one representation must not sink it for others it does serve.
/// Sliced-deadline expiries (budget evidence) and oversize (a
/// representation property) never mark either. Pure so tests pin
/// the rule without a network; `fetch` applies it where phase and
/// error class meet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProviderLesson {
    Clear,
    Mark,
    Ignore,
}

pub(crate) fn provider_lesson(
    result: &Result<Vec<u8>, BulkError>,
    outcome: &AttemptOutcome,
) -> ProviderLesson {
    match result {
        Ok(_) => ProviderLesson::Clear,
        Err(error) => match outcome.phase() {
            AttemptPhase::Dial if matches!(error, BulkError::Transport(_)) => ProviderLesson::Mark,
            _ => ProviderLesson::Ignore,
        },
    }
}

/// Lay (or refresh) one provider's failure mark. Only `fetch` calls
/// this, only for the lesson above — never directly for an error.
pub(crate) fn mark_provider_failed(
    memory: &mut HashMap<[u8; 32], ProviderMark>,
    provider: &[u8; 32],
) {
    memory.insert(
        *provider,
        ProviderMark {
            failed_at: std::time::Instant::now(),
        },
    );
}

/// A fulfilled attempt clears whatever the walk learned about this
/// provider before: liveness observed beats failure remembered.
fn clear_provider_mark(memory: &mut HashMap<[u8; 32], ProviderMark>, provider: &[u8; 32]) {
    memory.remove(provider);
}

/// One candidate's share of the pass budget: the fair division of the
/// time left across the candidates the walk will still attempt,
/// floored so an early-listed slow-but-live provider gets a usable
/// attempt instead of a guaranteed expiry. The floor never exceeds half the remaining
/// budget (and never the dial bound): no candidate takes more than
/// half of what's left, so a dead-first provider cannot spend the
/// whole slice. The division counts only candidates inside the
/// walk bound ([`FETCH_WALK_CAP`]): shares are never reserved for
/// candidates this pass will not attempt. What it does not promise
/// is a usable share for every listed candidate: only the first K
/// are attempted per pass, so a tail past the cap rolls to the next
/// pass — fault-failing heads mark and sink, so the walk pages
/// through failing and dial-hung tails across passes, while
/// persistently stalled transfer-phase heads never mark and pin
/// the tail until they fault, clear, or the representation's
/// strike/burn cooldowns trip (see [`FETCH_WALK_CAP`]).
/// Candidate lists are short in practice — bounded by the
/// distinct recorded providers for one address — so the walk reaches
/// the live route; the floor draws from the shared phase budget: at
/// N>=3 the first provider can take up to half the phase's remaining
/// budget where the bare division gave it remaining/N, so intra-item
/// fairness trades against inter-item fairness in the same change.
/// The last attempted candidate always gets everything left; a spent budget
/// shares nothing (the caller stops the walk on a zero share rather
/// than attempting).
pub(crate) fn candidate_share(
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
pub(crate) enum AttemptBound {
    Full,
    Shared,
}

/// Whether subdividing to `share` out of `remaining` shortens the
/// attempt below its unshared bound (`remaining` clamped to the
/// built-in blob timeout): a share roomier than the built-ins leaves
/// a `Full` attempt whose expiry is fault evidence, not budget
/// evidence. Pure so tests pin the boundary without a network.
pub(crate) fn attempt_bound(
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

/// How many ordered candidates one pass attempts at most: the head
/// plus two fallbacks (retry policy: the walk bound). Judgment, not
/// measurement: three bounds the per-representation per-pass dial
/// cost while today's short lists still fit inside the cap, so
/// behavior changes only when lists grow past it. Fault-failing
/// heads mark and sink, so across passes the walk pages through a
/// failing tail — capped candidates are deferred, never dropped —
/// and un-attempted candidates record nothing (no strike, no burn),
/// retrying next pass by republication. Paging covers dial-phase
/// hangs too: the K-th attempted head always holds the full
/// remaining share, so its dial expiry classifies as fault evidence
/// (like an uncapped walk's last candidate) and marks, sinking one
/// hung head per pass. Transfer-phase hangs never mark — only dial
/// evidence trains the memory — so K or more persistently stalled
/// transfers pin a live tail behind them until they fault, clear,
/// or the representation's strike/burn cooldowns trip (the pinned
/// passes still strike-cool: the last attempted expiry reads as
/// fault). Revisit when lists grow past three live routes or the
/// forensics show pinned tails.
const FETCH_WALK_CAP: usize = 3;

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
pub(crate) async fn dial(
    endpoint: &Endpoint,
    provider: EndpointAddr,
    timeout: std::time::Duration,
    bound: AttemptBound,
) -> Result<::iroh::endpoint::Connection, BulkError> {
    tokio::time::timeout(timeout, endpoint.connect(provider, iroh_blobs::ALPN))
        .await
        .map_err(|_| {
            if bound == AttemptBound::Shared {
                BulkError::Deadline { slice: timeout }
            } else {
                BulkError::Transport(DIAL_TIMED_OUT.to_string())
            }
        })?
        .map_err(|error| BulkError::Transport(error.to_string()))
}

/// The dial deadline firing, as an error message: [`dial`] reports a
/// cut-short dial as [`BulkError::Deadline`] under a subdivided share
/// and as this transport error on a full share. Shared here so the
/// split's phase attribution (`dial_timed_out`) matches on exactly
/// the shapes `dial` promises, never on re-derived strings.
pub(crate) const DIAL_TIMED_OUT: &str = "provider dial timed out";

/// Upper bound for the dial phase of one attempt: the dial runs under
/// its own allowance — the dial bound capped to the attempt budget —
/// never borrowing from the transfer's share of the same budget. A
/// dead candidate's dial costs at most this constant: on a
/// subdivided share the allowance shrinks with the share, on a full
/// share it holds at the dial bound. Pure so tests pin the boundary
/// without a network.
pub(crate) fn dial_allowance(blob_timeout: std::time::Duration) -> std::time::Duration {
    FETCH_DIAL_TIMEOUT.min(blob_timeout)
}

/// Upper bound for the transfer phase (size discovery plus
/// streaming): whatever the dial left of the attempt budget. The two
/// phases tile the attempt exactly — dial elapsed plus transfer
/// allowance equals the attempt budget — so the split fires its
/// timeouts at the same instants the old shared deadline did, and
/// every classification in `fetch` is unchanged. Saturating: a dial
/// that consumed the whole budget leaves the transfer nothing to
/// spend. Pure so tests pin the boundary without a network.
pub(crate) fn transfer_allowance(
    blob_timeout: std::time::Duration,
    dial_elapsed: std::time::Duration,
) -> std::time::Duration {
    blob_timeout.saturating_sub(dial_elapsed)
}

/// Whether a dial error is the dial deadline firing rather than an
/// instant failure (refused, unreachable): only the firing deadline
/// is timeout evidence by phase; instant failures completed their
/// observation. Structural companion to [`dial`]'s contract —
/// timeouts report exactly these two shapes.
pub(crate) fn dial_timed_out(error: &BulkError) -> bool {
    matches!(error, BulkError::Deadline { .. })
        || matches!(error, BulkError::Transport(message) if message == DIAL_TIMED_OUT)
}

/// Which phase of a split attempt produced an outcome: connection
/// establishment, or size discovery plus streaming. Forensics and
/// stats attribute every attempt outcome to its phase, so a budget
/// eaten by dialing reads as dial cost, never as transfer trouble.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AttemptPhase {
    Dial,
    Transfer,
}

/// One attempt's report for the telemetry below: timeouts carry
/// their phase, failures carry the phase plus the content bytes that
/// flowed before the failure (partial progress — the resume
/// decision's numerator), fulfillment carries its bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AttemptOutcome {
    Fulfilled {
        bytes: usize,
    },
    DialTimeout,
    TransferTimeout {
        streamed_bytes: usize,
    },
    Failed {
        phase: AttemptPhase,
        streamed_bytes: usize,
    },
}

impl AttemptOutcome {
    /// The phase that produced this outcome: fulfillment means the
    /// dial succeeded and the transfer completed.
    fn phase(&self) -> AttemptPhase {
        match self {
            AttemptOutcome::Fulfilled { .. } => AttemptPhase::Transfer,
            AttemptOutcome::DialTimeout => AttemptPhase::Dial,
            AttemptOutcome::TransferTimeout { .. } => AttemptPhase::Transfer,
            AttemptOutcome::Failed { phase, .. } => *phase,
        }
    }

    /// Content bytes that flowed in this attempt: the fulfilled
    /// total on success, the partial progress on failure, zero when
    /// the dial never connected.
    fn streamed_bytes(&self) -> usize {
        match *self {
            AttemptOutcome::Fulfilled { bytes } => bytes,
            AttemptOutcome::DialTimeout => 0,
            AttemptOutcome::TransferTimeout { streamed_bytes } => streamed_bytes,
            AttemptOutcome::Failed { streamed_bytes, .. } => streamed_bytes,
        }
    }

    /// The outcome name for the per-attempt forensics line.
    fn outcome_str(&self) -> &'static str {
        match self {
            AttemptOutcome::Fulfilled { .. } => "fulfilled",
            AttemptOutcome::DialTimeout => "dial-timeout",
            AttemptOutcome::TransferTimeout { .. } => "transfer-timeout",
            AttemptOutcome::Failed { .. } => "failed",
        }
    }
}

/// Cumulative fetch telemetry for one network source, exposed so the
/// resume pressure is measurable instead of anecdotal: attempts and
/// their phase outcomes, fulfilled bytes, and wasted bytes — content
/// bytes that flowed in attempts which then failed, the direct cost
/// of restarting from byte zero. Fixed-size counters (no per-hash
/// retention): per-representation repeats stay computable from the
/// per-attempt forensics lines, which carry provider and hash.
/// Atomics so `fetch` (which runs on `&self`) records without a
/// lock; [`IrohBulkSource::fetch_stats`] snapshots them for
/// diagnostics and tests.
#[derive(Debug, Default)]
pub struct BulkFetchStats {
    attempts: AtomicU64,
    dial_timeouts: AtomicU64,
    transfer_timeouts: AtomicU64,
    fulfilled: AtomicU64,
    fulfilled_bytes: AtomicU64,
    wasted_bytes: AtomicU64,
}

/// A point-in-time copy of [`BulkFetchStats`]: plain counters for
/// diagnostics, tests, and the resume threshold.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BulkFetchStatsSnapshot {
    pub attempts: u64,
    pub dial_timeouts: u64,
    pub transfer_timeouts: u64,
    pub fulfilled: u64,
    pub fulfilled_bytes: u64,
    pub wasted_bytes: u64,
}

impl BulkFetchStats {
    /// Fold one attempt's outcome into the counters: every attempt
    /// counts; timeouts count by phase; fulfillment banks its bytes;
    /// every failed attempt banks its streamed bytes as waste —
    /// including instant failures, whose partial progress is just as
    /// lost to a restart as a timeout's.
    pub(crate) fn record(&self, outcome: &AttemptOutcome) {
        self.attempts.fetch_add(1, Ordering::Relaxed);
        match *outcome {
            AttemptOutcome::Fulfilled { bytes } => {
                self.fulfilled.fetch_add(1, Ordering::Relaxed);
                self.fulfilled_bytes
                    .fetch_add(bytes as u64, Ordering::Relaxed);
            }
            AttemptOutcome::DialTimeout => {
                self.dial_timeouts.fetch_add(1, Ordering::Relaxed);
            }
            AttemptOutcome::TransferTimeout { streamed_bytes } => {
                self.transfer_timeouts.fetch_add(1, Ordering::Relaxed);
                self.wasted_bytes
                    .fetch_add(streamed_bytes as u64, Ordering::Relaxed);
            }
            AttemptOutcome::Failed { streamed_bytes, .. } => {
                self.wasted_bytes
                    .fetch_add(streamed_bytes as u64, Ordering::Relaxed);
            }
        }
    }

    pub(crate) fn snapshot(&self) -> BulkFetchStatsSnapshot {
        BulkFetchStatsSnapshot {
            attempts: self.attempts.load(Ordering::Relaxed),
            dial_timeouts: self.dial_timeouts.load(Ordering::Relaxed),
            transfer_timeouts: self.transfer_timeouts.load(Ordering::Relaxed),
            fulfilled: self.fulfilled.load(Ordering::Relaxed),
            fulfilled_bytes: self.fulfilled_bytes.load(Ordering::Relaxed),
            wasted_bytes: self.wasted_bytes.load(Ordering::Relaxed),
        }
    }
}

/// One forensics line per attempt, joining the candidate lines in
/// `fetch_candidates`: which provider served or failed, in which
/// phase, after how much dial latency, with how many content bytes
/// streamed. Debug-level like the rest of the fetch forensics;
/// per-representation repeats across attempts are computable from
/// these lines (provider plus hash) without retaining per-hash
/// state in the source.
fn trace_attempt(
    provider_hex: &str,
    hash_hex: &str,
    outcome: &AttemptOutcome,
    dial_latency: std::time::Duration,
) {
    tracing::debug!(
        provider = provider_hex,
        hash = hash_hex,
        phase = match outcome.phase() {
            AttemptPhase::Dial => "dial",
            AttemptPhase::Transfer => "transfer",
        },
        dial_latency_ms = dial_latency.as_millis(),
        streamed_bytes = outcome.streamed_bytes(),
        outcome = outcome.outcome_str(),
        "bulk attempt finished"
    );
}

/// Render 32 bytes as lowercase hex: the fetch forensics lines need
/// provider and hash ids, and `hex` stays inside `wyrd-format` by the
/// crate rules, so this preallocated manual form is the cheapest
/// available. One allocation per id, never one per byte. Crate-visible
/// so the route-publication line (`transport::routes`) renders the
/// same join key the same way.
pub(crate) fn hex32(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(64);
    for byte in bytes {
        write!(out, "{byte:02x}").expect("writing to a String cannot fail");
    }
    out
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
    pub(crate) snapshots: BTreeMap<SnapshotId, IrohBlobRef>,
    /// Sealed representations by storage address. A representation is
    /// immutable and may be advertised by several members, so each
    /// address keeps every provider in publication order rather than a
    /// single overwritten one: a dead route must not displace a live
    /// alternate.
    pub(crate) sealed: BTreeMap<StorageId, Vec<IrohBlobRef>>,
    /// Representations by Bao root, same multi-provider rule. Snapshot
    /// and root-manifest addresses are different: the author-signed
    /// announcement names exactly one route per snapshot, and a route
    /// update replaces it (last accepted wins), so those maps stay
    /// single-valued by policy.
    pub(crate) transport: BTreeMap<BaoRoot, Vec<IrohBlobRef>>,
    /// Plan-run deadline from [`AttemptBudget`]: the instant the pass's
    /// budget runs out, re-clamped to the remaining time on every
    /// attempt. `None` runs under the built-in timeouts. Plan-run
    /// state, reset by the plan — never source configuration.
    pub(crate) attempt_deadline: Option<std::time::Instant>,
    /// The candidate walk's bound for the in-flight attempt, set
    /// alongside the re-armed [`IrohBulkSource::attempt_deadline`] and
    /// read by `fetch` to classify a timeout as budget evidence
    /// (`Shared`) or fault evidence (`Full`). `None` outside a walk:
    /// single-route fetches are never subdivided. Plan-run state like
    /// the deadline, restored on the same exits.
    pub(crate) attempt_bound: Option<AttemptBound>,
    /// Cumulative fetch telemetry for the split's failure modes (see
    /// [`BulkFetchStats`]): recorded by every attempt, read through
    /// [`IrohBulkSource::fetch_stats`]. Source configuration, never
    /// plan-run state — the counters span passes.
    stats: BulkFetchStats,
    /// Per-provider failure memory for the candidate walk: the last
    /// dial-phase failure observation per provider id, laid by
    /// [`IrohBulkSource::fetch`] and read back as walk order on
    /// later attempts. Transient like the plan's strike ledgers; a
    /// fulfilled attempt clears the provider's mark, and marks
    /// expire after [`PROVIDER_BAD_MARK_TTL`]. Spans passes and
    /// addresses — plan-run state never resets it.
    pub(crate) provider_memory: HashMap<[u8; 32], ProviderMark>,
}

impl std::fmt::Debug for IrohBulkSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IrohBulkSource")
            .field("endpoint", &self.endpoint.id())
            .field("roots", &self.roots.len())
            .field("snapshots", &self.snapshots.len())
            .field("sealed", &self.sealed.len())
            .field("transport", &self.transport.len())
            .field("stats", &self.stats.snapshot())
            .field("provider_memory", &self.provider_memory.len())
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
            stats: BulkFetchStats::default(),
            provider_memory: HashMap::new(),
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
                ::iroh::Endpoint::builder(::iroh::endpoint::presets::N0)
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

    /// Cumulative fetch telemetry for the split's failure modes (see
    /// [`BulkFetchStats`]): attempts, phase outcomes, fulfilled bytes,
    /// and wasted bytes — the resume pressure, measured. A snapshot:
    /// later attempts keep accumulating underneath it. No production
    /// consumer yet: test and diagnostics surface only — the resume
    /// threshold reads the per-attempt debug forensics until a
    /// diagnostics surface adopts the snapshot.
    pub fn fetch_stats(&self) -> BulkFetchStatsSnapshot {
        self.stats.snapshot()
    }

    /// This provider's failure mark, if any: tests pin the record
    /// rules through it.
    #[cfg(test)]
    pub(crate) fn provider_mark(&self, provider: &[u8; 32]) -> Option<ProviderMark> {
        self.provider_memory.get(provider).copied()
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

    /// Close the owned endpoint under the graceful-close policy
    /// ([`crate::GRACEFUL_CLOSE_DEADLINE`]): a clean drain reports
    /// success; an expiry warns and the endpoint (with its runtime)
    /// is dropped by the caller — the abort. Draining waits on
    /// acknowledgements from relay infrastructure that is not part
    /// of daemon shutdown correctness, so a wedged drain must not
    /// fail a shutdown whose application work already stopped. The
    /// only observable difference between the paths is the warning.
    pub fn shutdown(&self, deadline: std::time::Duration) {
        let finished = self.runtime.block_on(crate::close::graceful_or_abort(
            self.endpoint.close(),
            deadline,
        ));
        if !finished {
            tracing::warn!(
                stage = "bulk",
                graceful_deadline_ms = deadline.as_millis(),
                "bulk endpoint close exceeded the graceful deadline; aborting the endpoint"
            );
        }
    }

    /// Fetch a representation by trying at most the first
    /// [`FETCH_WALK_CAP`] freshness-ordered recorded providers:
    /// providers with a live failure mark sink behind unmarked ones
    /// ([`order_candidates`]), publication order stable within each
    /// tier. Absence and transport failure fall through to the next
    /// candidate; oversize is terminal because every provider serves
    /// the same immutable bytes, so the size is a property of the
    /// representation, not of the route. With no provider serving it,
    /// the last transport error is returned; no candidates at all is
    /// absence; candidates with no completed attempt (a budget spent
    /// before anything could be asked) is a deadline, never a
    /// fabricated absence. Candidates past the cap are not attempted
    /// this pass: they record nothing — no strike, no burn — and
    /// retry next pass by republication, paged forward by the marks
    /// the attempted heads lay.
    ///
    /// Ordering moves which candidate holds the last (usually
    /// full-share) slot, so on total failure the surfaced error may
    /// differ from publication order's — in the direction of the
    /// evidence: a sunk dead tail's expiry reads as fault evidence
    /// (struck), a live head's sliced expiry as budget evidence
    /// (counted, not struck). Publication order had it backwards: the
    /// dead-first expiry escaped as a deadline while the live last
    /// candidate's expiry struck for being last. Strike counting
    /// itself is untouched — per run, per representation, above this
    /// walk — and no candidate is ever skipped, so a dead route still
    /// cannot displace a live alternate.
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
        // Freshness first: the memory orders this pass from what the
        // earlier ones learned, so a known-dead route's dial burns
        // tail budget instead of head budget. The maps keep
        // publication order — the walk re-derives the order per walk
        // instead, so intake (publication replaces per pass) is
        // untouched and republication stays a dedup no-op that clears
        // nothing: an announcement attests addressing, never liveness,
        // so only a completed attempt lays or clears a mark.
        let ordered = order_candidates(
            candidates,
            &mut self.provider_memory,
            std::time::Instant::now(),
        );
        let total = ordered.len();
        // The walk bound: at most the first K ordered candidates
        // per pass. The fair division counts only this reach, so no
        // share is reserved for candidates the pass will not ask.
        let reach = total.min(FETCH_WALK_CAP);
        for (index, blob) in ordered.iter().take(reach).enumerate() {
            if let Some(deadline) = budget {
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                let share = candidate_share(remaining, index, reach);
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
                    // Forensics for headless stalls: which provider
                    // served, joining the route-publication line
                    // above on the hex endpoint id. The hash names
                    // the representation (body root vs manifest
                    // transport), so a served-but-uncounted blob can
                    // be traced to its fetch kind.
                    tracing::debug!(
                        provider = %hex32(blob.provider.id.as_bytes()),
                        hash = %hex32(&blob.hash),
                        "bulk candidate served"
                    );
                    return Ok(Some(bytes));
                }
                Err(oversize @ BulkError::Oversize { .. }) => {
                    self.attempt_deadline = budget;
                    self.attempt_bound = None;
                    return Err(oversize);
                }
                Err(error) => {
                    // Forensics for headless stalls: which provider
                    // failed and how — the dial outcome the fetch
                    // counts collapse into transport errors. The
                    // message carries the failure class; the provider
                    // joins the route-publication line.
                    tracing::debug!(
                        provider = %hex32(blob.provider.id.as_bytes()),
                        hash = %hex32(&blob.hash),
                        error = %error,
                        "bulk candidate failed"
                    );
                    // Learning lives in `fetch` (dial-phase route
                    // evidence only): the walk orders from the memory
                    // but never writes it.
                    last_error = Some(error)
                }
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
    /// freshness-orders the same loop, fair-shares the pass budget
    /// across it, and attempts at most [`FETCH_WALK_CAP`].
    #[cfg(test)]
    pub(crate) fn fetch_candidates_with<F>(
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

    pub(crate) fn fetch(&mut self, blob: &IrohBlobRef, max: usize) -> Result<Vec<u8>, BulkError> {
        // The ceiling is enforced twice: the verified size rejects an
        // oversize blob before anything transfers, and the bounded
        // accumulator below pre-sizes from that verified size and
        // checks each leaf before copying — a peer that streams past
        // its announced size is refused, and accepted fetches return
        // at most `max` bytes without geometric over-reservation.
        let endpoint = self.endpoint.clone();
        let provider = blob.provider.clone();
        let hash = blob.hash();
        // Forensics for headless stalls: the per-attempt line below
        // joins the route-publication and candidate lines on these
        // hex ids, so a served-but-uncounted blob and a repeatedly
        // restarted one both trace to provider and representation.
        let provider_hex = hex32(provider.id.as_bytes());
        let provider_id = *provider.id.as_bytes();
        let hash_hex = hex32(hash.as_bytes());
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
        // The split: the dial runs first under its own allowance,
        // then size discovery and streaming run under whatever the
        // dial left of the attempt budget. The allowances tile the
        // budget exactly, so both phases fire at the same instants
        // the old shared deadline did and every error below
        // classifies exactly as before — the split adds measurement
        // (phase, dial latency, bytes streamed), never new timeout
        // behavior.
        let dial_allowance = dial_allowance(blob_timeout);
        let stats = &self.stats;
        // One observe site for every exit: the block reports its
        // result alongside the outcome (and the dial latency the
        // trace needs), so a future exit cannot forget to count —
        // there is nowhere else to return from.
        let (result, outcome, dial_latency) = self.runtime.block_on(async move {
            // Phase 1: dial. A firing dial deadline reports exactly
            // as a dial timeout always has; an instant failure stays
            // a transport error with zero bytes streamed.
            let dial_start = std::time::Instant::now();
            let connection = dial(&endpoint, provider, dial_allowance, bound).await;
            let dial_latency = dial_start.elapsed();
            let connection = match connection {
                Ok(connection) => connection,
                Err(error) => {
                    let outcome = if dial_timed_out(&error) {
                        AttemptOutcome::DialTimeout
                    } else {
                        AttemptOutcome::Failed {
                            phase: AttemptPhase::Dial,
                            streamed_bytes: 0,
                        }
                    };
                    return (Err(error), outcome, dial_latency);
                }
            };
            // Phase 2: size discovery plus streaming under the
            // leftover. The byte probe survives the timeout below:
            // on expiry the partial progress reads off it instead of
            // dying with the cancelled stream.
            let transfer_allowance = transfer_allowance(blob_timeout, dial_latency);
            let progress = AtomicUsize::new(0);
            let transfer = tokio::time::timeout(transfer_allowance, async {
                let (size, _) = get_verified_size(&connection, &hash)
                    .await
                    .map_err(|error| BulkError::Transport(error.to_string()))?;
                if size > max as u64 {
                    return Err(BulkError::Oversize {
                        bytes: usize::try_from(size).unwrap_or(usize::MAX),
                        max,
                    });
                }
                bounded_blob_bytes(
                    get_blob(connection, hash),
                    max,
                    size as usize,
                    Some(&progress),
                )
                .await
            })
            .await;
            let streamed_bytes = progress.load(Ordering::Relaxed);
            match transfer {
                Ok(Ok(bytes)) => {
                    let outcome = AttemptOutcome::Fulfilled { bytes: bytes.len() };
                    (Ok(bytes), outcome, dial_latency)
                }
                Ok(Err(error)) => {
                    // An instant transfer failure (size error,
                    // oversize, protocol error) completed its
                    // observation: fault evidence, with whatever
                    // partial progress banked as waste.
                    (
                        Err(error),
                        AttemptOutcome::Failed {
                            phase: AttemptPhase::Transfer,
                            streamed_bytes,
                        },
                        dial_latency,
                    )
                }
                Err(_) => {
                    // The transfer deadline fired: same instants and
                    // same classes as the old shared deadline — the
                    // reported slice stays the attempt's whole share,
                    // never the leftover, so a starved transfer still
                    // reads as budget pressure on a real attempt, not
                    // as a walk that never granted anything.
                    let error = if bound == AttemptBound::Shared {
                        BulkError::Deadline {
                            slice: blob_timeout,
                        }
                    } else {
                        BulkError::Transport("blob fetch timed out".to_string())
                    };
                    (
                        Err(error),
                        AttemptOutcome::TransferTimeout { streamed_bytes },
                        dial_latency,
                    )
                }
            }
        });
        stats.record(&outcome);
        trace_attempt(&provider_hex, &hash_hex, &outcome, dial_latency);
        // The memory learns here, where phase and error class meet:
        // dial-phase route evidence only (see provider_lesson). The
        // walk orders from it but never writes it — single-route
        // fetches train the same memory, since dial reachability is
        // provider-level, independent of the representation asked for.
        match provider_lesson(&result, &outcome) {
            ProviderLesson::Clear => clear_provider_mark(&mut self.provider_memory, &provider_id),
            ProviderLesson::Mark => mark_provider_failed(&mut self.provider_memory, &provider_id),
            ProviderLesson::Ignore => {}
        }
        result
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
/// path passes the real `GetBlobResult`. The optional progress probe
/// counts accepted leaf bytes as they land, so a caller whose timeout
/// cancels this future still learns the partial progress — the resume
/// decision's numerator. `None` skips the counting.
pub(crate) async fn bounded_blob_bytes<S>(
    stream: S,
    max: usize,
    reserve: usize,
    progress: Option<&AtomicUsize>,
) -> Result<Vec<u8>, BulkError>
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
                if let Some(progress) = progress {
                    progress.fetch_add(leaf.data.len(), Ordering::Relaxed);
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
        let Some((content_id, blob)) = self.roots.get(snapshot).cloned() else {
            return Ok(None);
        };
        self.fetch(&blob, max)
            .map(|sealed| Some(SealedManifest { content_id, sealed }))
    }

    fn fetch_snapshot(
        &mut self,
        snapshot: &SnapshotId,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        let Some(blob) = self.snapshots.get(snapshot).cloned() else {
            return Ok(None);
        };
        self.fetch(&blob, max).map(Some)
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

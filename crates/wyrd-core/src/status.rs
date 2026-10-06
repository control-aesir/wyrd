//! Headless sync observations: structured sync status built from
//! durable state only. No mailbox, no bulk, no network — the read
//! half of the headless consumer contract (`sync status` today, GUI
//! or API surfaces later). Renderers consume these structs; they
//! never parse rendered output.
//!
//! The observation is side-effect free by construction: every source
//! (`runtime_state`, the membership log, head classification) reads
//! committed facts. Status never connects a mailbox, never drains,
//! never sends, and never touches the seen log.

use std::collections::BTreeSet;

use wyrd_format::{DeviceId, SnapshotId};
use wyrd_sync::{
    authorization::Classification,
    membership::KnownState,
    runtime::{Engine, EngineError, MaterializationSummary, OutboxTotals, ReconciliationCounters},
};

use crate::live::PendingObligations;

/// One live head: the merge identity, its epoch, and its author.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadSummary {
    pub id: SnapshotId,
    pub epoch: u64,
    pub author: DeviceId,
}

/// Authorization classification counts over every DAG head (not just
/// the live ones): eligible heads advance the view, every other
/// class is retained history with its reason attached. Named
/// counters rather than a map so a new classification variant fails
/// compilation here instead of silently disappearing from status.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HeadClasses {
    pub eligible: usize,
    pub canonical_history: usize,
    pub superseded: usize,
    pub stranded: usize,
    pub voided: usize,
    pub pending: usize,
    pub rejected: usize,
}

/// Mailbox posture as observed without connecting: configured relay
/// count only. Liveness (connected relays, stream state) requires a
/// live mailbox, which status deliberately never constructs — the
/// seen store opens read-write on connect, so even a health probe
/// would be a durable side effect. Liveness belongs to run reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailboxView {
    /// Relays configured on the command line. Zero means fully
    /// offline: intake stays idle by construction.
    pub configured_relays: usize,
}

/// One peer as the durable surface sees it (OD-17-4 option A): an
/// opaque handle over a peer identity the status legitimately knows
/// — an obligation recipient or a live-head author from committed
/// facts. Handles are assigned in deterministic (byte) order at
/// observation, stable for the rendering and identical across
/// restarts over the same state. A handle is not a peer identity
/// namespace: nothing persists the numbering, and the same peer may
/// hold a different handle after the state changes. The run surface
/// names senders by `DeviceId` — a different set answering a
/// different question (who mailed us); this surface never prints
/// identities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerHandle {
    /// 1-based position in the observation's deterministic peer
    /// order: the rendered `peer-N`. Assigned once in [`observe`],
    /// so the struct and every renderer agree by construction.
    pub handle: usize,
    /// The peer this handle stands for. In-process only: renderers
    /// map it to `peer-N` and never print it.
    pub peer: DeviceId,
    /// Still-undischarged outbox pairs naming this peer. Zero for a
    /// head author nobody owes anything to. Covers the three
    /// itemized obligation classes only — staged carries are local
    /// re-authoring work owed to nobody, so they count in
    /// [`QueueDepth::outbox`] but on no peer line.
    pub pending: usize,
}

/// Backlog as a durable projection (OD-17-3 option C): the number of
/// currently outstanding durable work items, not the number of
/// entries resident in the process's mutation or want queue. Both
/// inputs are committed facts, so the projection is identical before
/// and after a restart over the same state — exactly what the
/// restart-equivalence predicate requires. A live gauge would answer
/// a different question ("what is queued in memory right now") and
/// cannot serve here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QueueDepth {
    /// Still-undischarged outbox pairs: announcements, transitions,
    /// capabilities, and carries. Who we owe, counted. Always the
    /// sum of the itemized obligations and `carries` below, so the
    /// renderer projects rather than infers.
    pub outbox: usize,
    /// Staged namespace carries inside the outbox total: local
    /// re-authoring work owed to nobody, hence on no peer line.
    pub carries: usize,
    /// Reconciliation gaps: announced snapshots without a root
    /// manifest, bodies, or child manifests, plus distinct wanted-
    /// but-not-local contents. What we still need, counted per
    /// missing artifact (a snapshot missing both its body and its
    /// root manifest needs two fetches, so it counts twice).
    pub fetch: usize,
}

impl QueueDepth {
    /// Total outstanding durable work items across both halves.
    pub fn total(&self) -> usize {
        self.outbox + self.fetch
    }

    /// True when nothing is owed and nothing is missing: the
    /// backlog half of convergence.
    pub fn is_empty(&self) -> bool {
        self.total() == 0
    }
}

/// Convergence from durable facts: whether the node has anything
/// left it could do, plus the heads that keep it from saying so.
/// Pending heads may still resolve (bytes, routes, or capabilities
/// outstanding); unfetchable heads are authorization-rejected —
/// terminal damage, not pending work — and are reported, never spun
/// on. Distinct from terminal fetch state (a separate issue's
/// state): rejection here is an authorization verdict, not a fetch
/// outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConvergenceState {
    /// True when the outbox is empty, the fetch projection is empty,
    /// no head awaits closure, and none is rejected. A node with
    /// rejected heads is diverged: something is wrong, even though
    /// no local action remains.
    pub converged: bool,
    /// Heads classified pending: closure outstanding.
    pub pending_heads: usize,
    /// Heads classified rejected: terminally unauthorizable.
    pub unfetchable_heads: usize,
}

/// Structured sync status: outbox obligations with their
/// queued/delivered/pending split, the membership tip against held
/// secrets, live heads with classification, and mailbox posture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncStatus {
    /// Known canonical tip, if the log has one. `None` only on a
    /// drive with no observed membership at all.
    pub tip: Option<KnownState>,
    /// Epochs this device holds secrets for. Knowledge is not
    /// possession: a known epoch without its secret authorizes
    /// nothing until the capability arrives.
    pub held_epochs: Vec<u64>,
    /// Still-undischarged obligations, itemized per class.
    pub obligations: PendingObligations,
    /// Queued vs delivered counts the pending lists subtract.
    pub totals: OutboxTotals,
    /// Currently live heads.
    pub live_heads: Vec<HeadSummary>,
    /// Classification counts over every DAG head.
    pub head_classes: HeadClasses,
    /// Mailbox posture (configuration only, never liveness).
    pub mailbox: MailboxView,
    /// Known members at the tip, by count only: the denominator the
    /// peer handles divide. Zero when there is no tip.
    pub known_members: usize,
    /// Opaque per-peer handles over obligation recipients and head
    /// authors, in deterministic order. Each entry's stored `handle`
    /// is the rendered `peer-N`.
    pub peers: Vec<PeerHandle>,
    /// Outstanding durable work: owed obligations plus missing
    /// fetches, from committed facts only.
    pub queue: QueueDepth,
    /// Reconciliation progress, from committed facts only: received
    /// peer statements plus obligations retired through
    /// reconciliation rather than relay acceptance. Counts only —
    /// classes, never identities — so the renderer cannot leak a
    /// TransitionId or DeviceId through this row. The outstanding
    /// gap is deliberately absent: answering is a live, volatile
    /// evaluation, so unanswered and stalled statements are a run
    /// observation (`sync now`), not a status input.
    pub reconciliation: ReconciliationCounters,
    /// Whether the node has converged, from durable facts.
    pub convergence: ConvergenceState,
    /// Materialization as counts: explicit residency policies plus
    /// locally held objects.
    pub materialization: MaterializationSummary,
}

impl SyncStatus {
    /// Opaque handle for a peer identity, or 0 when the identity is
    /// absent. Zero is unreachable by construction — [`observe`]
    /// derives peers from every identity the status carries — so it
    /// stays opaque rather than leaking the id it failed to map.
    pub fn peer_handle(&self, peer: &DeviceId) -> usize {
        self.peers
            .iter()
            .find(|entry| entry.peer == *peer)
            .map(|entry| entry.handle)
            .unwrap_or(0)
    }
}

/// Observe sync status from durable state. Reads committed facts
/// only; commits nothing, connects to nothing.
pub fn observe(engine: &Engine, configured_relays: usize) -> Result<SyncStatus, EngineError> {
    let tip = engine.membership_log().known_state();
    let held_epochs = match &tip {
        Some(_) => engine.held_epochs()?,
        None => Vec::new(),
    };
    let state = engine.runtime_state()?;
    let obligations = PendingObligations {
        announcements: state.pending_announcements(),
        transitions: state.pending_transitions(),
        capabilities: state.pending_capabilities(),
    };
    let totals = state.outbox_totals();
    let live_heads = engine
        .live_heads()?
        .iter()
        .map(|head| {
            let snapshot = head.snapshot();
            HeadSummary {
                id: snapshot.snapshot_id(),
                epoch: snapshot.epoch,
                author: snapshot.author,
            }
        })
        .collect::<Vec<_>>();
    let mut head_classes = HeadClasses::default();
    for head in engine.snapshot_heads()? {
        match head.classification {
            Classification::Eligible => head_classes.eligible += 1,
            Classification::CanonicalHistory => head_classes.canonical_history += 1,
            Classification::Superseded => head_classes.superseded += 1,
            Classification::Stranded => head_classes.stranded += 1,
            Classification::Voided => head_classes.voided += 1,
            Classification::Pending(_) => head_classes.pending += 1,
            Classification::Rejected(_) => head_classes.rejected += 1,
        }
    }
    // Opaque handles over every identity the status carries:
    // obligation recipients plus head authors, deduplicated and
    // ordered by bytes so the numbering is deterministic — the same
    // state always renders the same handles, across restarts too.
    let mut peer_set = BTreeSet::new();
    let recipients = obligations
        .announcements
        .iter()
        .map(|(_, recipient)| recipient)
        .chain(
            obligations
                .transitions
                .iter()
                .map(|(_, recipient)| recipient),
        )
        .chain(
            obligations
                .capabilities
                .iter()
                .map(|(_, recipient)| recipient),
        );
    for recipient in recipients {
        peer_set.insert(*recipient);
    }
    for head in &live_heads {
        peer_set.insert(head.author);
    }
    let peers = peer_set
        .into_iter()
        .enumerate()
        .map(|(index, peer)| {
            let pending = obligations
                .announcements
                .iter()
                .map(|(_, recipient)| recipient)
                .chain(
                    obligations
                        .transitions
                        .iter()
                        .map(|(_, recipient)| recipient),
                )
                .chain(
                    obligations
                        .capabilities
                        .iter()
                        .map(|(_, recipient)| recipient),
                )
                .filter(|recipient| **recipient == peer)
                .count();
            PeerHandle {
                handle: index + 1,
                peer,
                pending,
            }
        })
        .collect::<Vec<_>>();
    let known_members = match &tip {
        Some(known) => engine
            .membership_log()
            .members_of(&known.transition_id)
            .map(|members| members.len())
            .unwrap_or(0),
        None => 0,
    };
    // The durable backlog (OD-17-3 option C): owed obligations
    // including the carry queue the itemized lists do not cover,
    // plus the reconciliation gaps. Committed facts on both sides.
    let reconcile = state.reconcile();
    let carries = state.pending_carries().len();
    let queue = QueueDepth {
        outbox: obligations.len() + carries,
        carries,
        fetch: reconcile.pending_snapshots.len()
            + reconcile.pending_snapshot_bodies.len()
            + reconcile.pending_manifests.len()
            + reconcile.pending_objects.len(),
    };
    let convergence = ConvergenceState {
        converged: queue.is_empty() && head_classes.pending == 0 && head_classes.rejected == 0,
        pending_heads: head_classes.pending,
        unfetchable_heads: head_classes.rejected,
    };
    let materialization = state.materialization_summary();
    let reconciliation = engine.reconciliation_counters()?;
    Ok(SyncStatus {
        tip,
        held_epochs,
        obligations,
        totals,
        live_heads,
        head_classes,
        mailbox: MailboxView { configured_relays },
        known_members,
        peers,
        queue,
        reconciliation,
        convergence,
        materialization,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use wyrd_format::{Entry, ObjectKind, ObjectStore, Tree};
    use wyrd_sync::keys::DeviceIdentitySecret;

    /// Scratch-drive uniquifier: wall-clock nanos collide across
    /// parallel tests on coarse clocks, so every scratch dir takes
    /// the next sequence number instead.
    static SCRATCH_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    fn scratch_dir(prefix: &str) -> std::path::PathBuf {
        let seq = SCRATCH_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        std::env::temp_dir().join(format!(
            "wyrd-core-status-{prefix}-{}-{}",
            std::process::id(),
            seq
        ))
    }

    /// A scratch two-member engine with one file authored: admitting
    /// the second device queues transition, capability, and
    /// announcement obligations to it.
    fn scratch_authored() -> (Engine, std::path::PathBuf) {
        let identity = DeviceIdentitySecret::generate().unwrap();
        scratch_authored_with(identity)
    }

    /// The same scratch state under a caller-chosen identity, so a
    /// test can reopen the drive with the identical secret.
    fn scratch_authored_with(identity: DeviceIdentitySecret) -> (Engine, std::path::PathBuf) {
        let dir = scratch_dir("authored");
        std::fs::create_dir_all(&dir).unwrap();
        let mut engine = Engine::create(dir.clone(), "core-test-pass", identity).unwrap();
        // Bytes live in the drive's own store: the admission carry
        // re-authors the head at the new epoch from these objects, so
        // a memory-only store would leave the carried epoch headless.
        let mut store = wyrd_format::FsObjectStore::open(dir.clone()).unwrap();
        let chunk = store.insert(ObjectKind::Chunk, b"status-bytes").unwrap();
        let root = Tree::from_entries(vec![Entry::file("f", 12, false, vec![chunk]).unwrap()])
            .unwrap()
            .insert_into(&mut store)
            .unwrap();
        engine.author_snapshot(&store, root).unwrap();
        let peer = DeviceIdentitySecret::generate().unwrap();
        let encryption = wyrd_sync::keys::DeviceEncryptionSecret::generate().unwrap();
        // The product path carries live heads across the transition
        // (see `transition_with_carry` in the CLI): stage before the
        // admission, then author the carried snapshots at the new
        // epoch so the drive keeps serving its files.
        engine.stage_carry_heads().unwrap();
        engine
            .admit_device(peer.device_id(), encryption.encryption_key())
            .unwrap();
        let store = wyrd_format::FsObjectStore::open(dir.clone()).unwrap();
        engine.carry_pending(&store).unwrap();
        (engine, dir)
    }

    /// A fresh drive observes genesis: tip at epoch one, its secret
    /// held, nothing owed, no heads until the first snapshot.
    #[test]
    fn fresh_drive_status_is_genesis_with_empty_outbox() {
        let dir = scratch_dir("fresh");
        std::fs::create_dir_all(&dir).unwrap();
        let identity = DeviceIdentitySecret::generate().unwrap();
        let engine = Engine::create(dir.clone(), "core-test-pass", identity).unwrap();
        let status = observe(&engine, 0).unwrap();
        let tip = status.tip.expect("genesis tip");
        assert_eq!(tip.epoch, 1);
        assert_eq!(status.held_epochs, vec![1]);
        assert!(status.obligations.is_empty());
        assert_eq!(status.totals, OutboxTotals::default());
        assert!(status.live_heads.is_empty());
        assert_eq!(status.mailbox.configured_relays, 0);
        // No obligations and no heads, so no handles — while the
        // genesis tip still names its sole member. Handles and
        // members are different denominators by design.
        assert!(status.peers.is_empty());
        assert_eq!(status.known_members, 1);
        assert!(status.queue.is_empty());
        assert!(status.convergence.converged);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Admitting a peer queues the catch-up chain: one transition
    /// and one capability to it, plus one announcement per lineage
    /// member (the carried head plus its ancestry, each exactly
    /// once). Queued is four, delivered is zero, and the carried
    /// head stays live and eligible.
    #[test]
    fn admission_queues_all_three_obligation_classes() {
        let (engine, dir) = scratch_authored();
        let status = observe(&engine, 2).unwrap();
        assert_eq!(status.obligations.announcements.len(), 2);
        assert_eq!(status.obligations.transitions.len(), 1);
        assert_eq!(status.obligations.capabilities.len(), 1);
        assert_eq!(status.obligations.len(), 4);
        assert_eq!(status.totals.announcements_queued, 2);
        assert_eq!(status.totals.transitions_queued, 1);
        assert_eq!(status.totals.capabilities_queued, 1);
        assert_eq!(status.totals.announcements_delivered, 0);
        assert_eq!(status.totals.transitions_delivered, 0);
        assert_eq!(status.totals.capabilities_delivered, 0);
        assert_eq!(status.live_heads.len(), 1);
        assert_eq!(status.head_classes.eligible, 1);
        assert_eq!(status.mailbox.configured_relays, 2);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Observation commits nothing: two reads agree exactly.
    #[test]
    fn observation_is_repeatable() {
        let (engine, dir) = scratch_authored();
        assert_eq!(observe(&engine, 0).unwrap(), observe(&engine, 0).unwrap());
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Pending obligations survive the reopen as obligations: the
    /// admission fixture owes two announcements, one transition, and
    /// one capability, and the reopened engine owes the same pairs to
    /// the same recipients with the same queued/delivered split —
    /// the obligation invariant's replay half at the status row. The
    /// whole-status equality is the tripwire
    /// (`queue_depth_is_a_durable_projection`); this test names the
    /// row the tripwire covers.
    #[test]
    fn restart_equivalence_pending_obligations_match() {
        let identity = DeviceIdentitySecret::from_bytes([0xC1; 32]).unwrap();
        let (engine, dir) = scratch_authored_with(identity);
        let before = observe(&engine, 0).unwrap();
        assert_eq!(before.obligations.announcements.len(), 2);
        assert_eq!(before.obligations.transitions.len(), 1);
        assert_eq!(before.obligations.capabilities.len(), 1);
        assert_eq!(before.obligations.len(), 4, "the fixture owes a backlog");
        drop(engine);
        let reopened = Engine::open_keystore(
            dir.clone(),
            "core-test-pass",
            DeviceIdentitySecret::from_bytes([0xC1; 32]).unwrap(),
        )
        .unwrap();
        let after = observe(&reopened, 0).unwrap();
        assert_eq!(after.obligations, before.obligations);
        assert_eq!(after.totals, before.totals);
        drop(reopened);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Peer handles are opaque and deterministic: the admission
    /// fixture names two identities (the admitted peer, owed four
    /// pairs, and our own device, authoring the live head), so the
    /// status carries exactly two handles in byte order, the pending
    /// counts sum to the owed pairs, and no handle leaks an identity
    /// — the stored handle is the rendered one, never a printed id.
    #[test]
    fn peer_handles_are_opaque_and_deterministic() {
        let (engine, dir) = scratch_authored();
        let status = observe(&engine, 0).unwrap();
        assert_eq!(status.peers.len(), 2, "recipient plus author");
        assert_eq!(status.known_members, 2, "owner plus admitted peer");
        let pending: usize = status.peers.iter().map(|entry| entry.pending).sum();
        assert_eq!(pending, status.obligations.len());
        assert_eq!(pending, 4);
        // Byte order, 1-based handles, every carried identity mapped.
        // Handles are assigned once in observe(); the loop below
        // proves the struct and the renderer agree by construction.
        let mut ordered: Vec<DeviceId> = status.peers.iter().map(|entry| entry.peer).collect();
        ordered.sort();
        let peers: Vec<DeviceId> = status.peers.iter().map(|entry| entry.peer).collect();
        assert_eq!(peers, ordered);
        for (index, entry) in status.peers.iter().enumerate() {
            assert_eq!(entry.handle, index + 1);
            assert_eq!(status.peer_handle(&entry.peer), index + 1);
        }
        assert_eq!(
            status.peer_handle(&DeviceId::from_bytes([0xFF; 32])),
            0,
            "unknown identities map to the opaque zero, never printed"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The whole projection is restart-equivalent (OD-17-3 option
    /// C's gate): reopening over the same committed facts observes
    /// the identical status — same queue depth, same handles, same
    /// convergence. The admission fixture owes a nonzero backlog, so
    /// the equality is not a vacuous all-empty comparison.
    #[test]
    fn queue_depth_is_a_durable_projection() {
        let identity = DeviceIdentitySecret::from_bytes([0xC0; 32]).unwrap();
        let (engine, dir) = scratch_authored_with(identity);
        let before = observe(&engine, 0).unwrap();
        assert_eq!(before.queue.outbox, 4, "the fixture owes a backlog");
        assert!(
            !before.convergence.converged,
            "owed obligations diverge: {before:?}"
        );
        drop(engine);
        let reopened = Engine::open_keystore(
            dir.clone(),
            "core-test-pass",
            DeviceIdentitySecret::from_bytes([0xC0; 32]).unwrap(),
        )
        .unwrap();
        let after = observe(&reopened, 0).unwrap();
        assert_eq!(before, after);
        drop(reopened);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The reconciliation row reads the durable counters: no
    /// statement received and nothing retired on these fixtures, and
    /// the row survives the reopen like every other status input.
    /// Nonzero progress is pinned where the statements live
    /// (`reconciliation_counters_replay_from_durable_facts`); this
    /// test pins that `observe` surfaces those counters rather than
    /// a live guess.
    #[test]
    fn reconciliation_row_is_a_durable_projection() {
        let identity = DeviceIdentitySecret::from_bytes([0xC2; 32]).unwrap();
        let (engine, dir) = scratch_authored_with(identity);
        let before = observe(&engine, 0).unwrap();
        assert_eq!(
            before.reconciliation,
            ReconciliationCounters::default(),
            "no statements flow through these fixtures: {before:?}"
        );
        drop(engine);
        let reopened = Engine::open_keystore(
            dir.clone(),
            "core-test-pass",
            DeviceIdentitySecret::from_bytes([0xC2; 32]).unwrap(),
        )
        .unwrap();
        let after = observe(&reopened, 0).unwrap();
        assert_eq!(before.reconciliation, after.reconciliation);
        drop(reopened);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

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

use wyrd_format::{DeviceId, SnapshotId};
use wyrd_sync::{
    authorization::Classification,
    membership::KnownState,
    runtime::{Engine, EngineError, OutboxTotals},
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
        .collect();
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
    Ok(SyncStatus {
        tip,
        held_epochs,
        obligations,
        totals,
        live_heads,
        head_classes,
        mailbox: MailboxView { configured_relays },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use wyrd_format::{Entry, ObjectKind, ObjectStore, Tree};
    use wyrd_sync::keys::DeviceIdentitySecret;

    /// A scratch two-member engine with one file authored: admitting
    /// the second device queues transition, capability, and
    /// announcement obligations to it.
    fn scratch_authored() -> (Engine, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "wyrd-core-status-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let identity = DeviceIdentitySecret::generate().unwrap();
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
        let dir = std::env::temp_dir().join(format!(
            "wyrd-core-status-fresh-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
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
}

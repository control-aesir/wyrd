//! Vault-position diagnostics: the keyless-replica projection over
//! durable state. `wyrd vault status` is a vault surface on every
//! composition (matrix rule: vault surfaces show a subset of the
//! keyless-replica column even when the process holds keys), so the
//! stopped-drive section cannot reuse [`crate::status`] — the member
//! projection carries tip transition ids, held epochs, head authors
//! and snapshot ids, per-peer handles, and mailbox configuration,
//! every one of them a hidden-class observation (matrix H5/H6/H8/H9).
//!
//! The boundary is structural, not editorial. [`observe_vault`]
//! reads only count- and state-producing queries off the engine —
//! outbox totals, queue depths, durability level, reconciliation
//! counters, materialization counts — and never calls
//! `membership_log`, `held_epochs`, `live_heads`, `snapshot_heads`,
//! or the itemized obligation lists. A vault projection cannot leak
//! what it never extracts: there is no `DeviceId`, `SnapshotId`,
//! `TransitionId`, or `ContentId` anywhere in [`VaultStatus`], so no
//! renderer, formatter, or error path built from it can print one.
//! The error half follows the same rule: observation failures
//! surface as the engine error the open already produced, never as a
//! view-path error — the vault projection never enters the view
//! path, so it never constructs the `FsStoreError::Corrupt`-style
//! failures whose `Debug` rendering is the leak the matrix names.
//!
//! What is deliberately absent: head-classification detail (counting
//! it needs `snapshot_heads`, whose rows carry snapshot ids), peer
//! and membership rows (identity-bearing by construction), mailbox
//! posture (control-plane configuration, matrix H9), and store-level
//! blob listings (a second store open with its own side effects).
//! The matrix permits vault surfaces a subset of the keyless column;
//! this projection is that subset. Convergence is reported as the
//! backlog predicate only (`backlog_empty`), never as a head-class
//! verdict — a quiet queue with pending heads is not convergence,
//! and the vault surface must not claim otherwise.
//!
//! Row map (matrix `docs/trust.md`, observation × trust-position):
//! every field below is O4 (counts) except `durability`, which is
//! drive state at the same coarse grain. No field maps to a hidden
//! row; PR3's field inventory pins this mapping in a test.

use wyrd_sync::runtime::{
    DurabilityLevel, Engine, EngineError, MaterializationSummary, OutboxTotals,
    ReconciliationCounters,
};

use crate::status::QueueDepth;

/// Vault-position status: counts and drive state only. No
/// identities, no heads, no membership, no mailbox — the type has no
/// field that could hold them, which is the enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultStatus {
    /// The durability level the drive reached (DG-2): Working with
    /// no recorded snapshot body, Committed while the announcement
    /// outbox is non-empty, Published once it is quiet.
    pub durability: DurabilityLevel,
    /// Queued vs delivered counts per obligation class. Counts
    /// only: the itemized per-recipient lists stay unread.
    pub outbox: OutboxTotals,
    /// Outstanding durable work: owed obligations plus missing
    /// fetches, from committed facts only.
    pub queue: QueueDepth,
    /// Reconciliation progress as counts: statements received plus
    /// per-class retirements. Classes, never identities.
    pub reconciliation: ReconciliationCounters,
    /// Materialization as counts: pinned, cached, and locally held
    /// objects. No paths, no content ids.
    pub materialization: MaterializationSummary,
    /// True when nothing is owed and nothing is missing. The
    /// backlog predicate only — head-class detail is member-only,
    /// so this is not the member convergence verdict.
    pub backlog_empty: bool,
}

/// Observe vault-position status from durable state. Reads committed
/// facts only; commits nothing, connects to nothing, and — unlike
/// [`crate::status::observe`] — never extracts an identity-bearing
/// row. The engine calls below are the complete read set: totals,
/// carries, reconciliation gaps, materialization, durability, and
/// reconciliation counters.
pub fn observe_vault(engine: &Engine) -> Result<VaultStatus, EngineError> {
    let state = engine.runtime_state()?;
    let outbox = state.outbox_totals();
    let carries = state.pending_carries().len();
    let reconcile = state.reconcile();
    // Pending pairs per class, exactly as the member projection
    // counts them (`PendingObligations::len`): queued minus
    // delivered, plus the staged carries the itemized lists do not
    // cover. Counts only — the per-recipient pairs stay unread.
    let pending = outbox.announcements_queued - outbox.announcements_delivered
        + (outbox.transitions_queued - outbox.transitions_delivered)
        + (outbox.capabilities_queued - outbox.capabilities_delivered);
    let queue = QueueDepth {
        outbox: pending + carries,
        carries,
        fetch: reconcile.pending_snapshots.len()
            + reconcile.pending_snapshot_bodies.len()
            + reconcile.pending_manifests.len()
            + reconcile.pending_objects.len(),
    };
    let reconciliation = engine.reconciliation_counters()?;
    let materialization = state.materialization_summary();
    let durability = state.durability_level();
    Ok(VaultStatus {
        durability,
        outbox,
        queue,
        reconciliation,
        materialization,
        backlog_empty: queue.is_empty(),
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
            "wyrd-core-vault-{prefix}-{}-{seq}",
            std::process::id()
        ))
    }

    /// A fresh drive under a fixed identity: genesis tip, secret
    /// held, nothing owed.
    fn scratch_fresh() -> (Engine, std::path::PathBuf) {
        let dir = scratch_dir("fresh");
        std::fs::create_dir_all(&dir).unwrap();
        let identity = DeviceIdentitySecret::from_bytes([0xA5; 32]).unwrap();
        let engine = Engine::create(dir.clone(), "core-test-pass", identity).unwrap();
        (engine, dir)
    }

    /// An identity-rich drive: one file authored, a second device
    /// admitted with carry, so the member projection shows peers, a
    /// live head with an author, and queued obligations — everything
    /// the vault projection must not carry.
    fn scratch_admission() -> (Engine, std::path::PathBuf) {
        let dir = scratch_dir("admission");
        std::fs::create_dir_all(&dir).unwrap();
        let identity = DeviceIdentitySecret::from_bytes([0xA6; 32]).unwrap();
        let mut engine = Engine::create(dir.clone(), "core-test-pass", identity).unwrap();
        let mut store = wyrd_format::FsObjectStore::open(dir.clone()).unwrap();
        let chunk = store.insert(ObjectKind::Chunk, b"vault-bytes").unwrap();
        let root = Tree::from_entries(vec![Entry::file("f", 11, false, vec![chunk]).unwrap()])
            .unwrap()
            .insert_into(&mut store)
            .unwrap();
        engine.author_snapshot(&store, root).unwrap();
        let peer = DeviceIdentitySecret::generate().unwrap();
        let encryption = wyrd_sync::keys::DeviceEncryptionSecret::generate().unwrap();
        engine.stage_carry_heads().unwrap();
        engine
            .admit_device(peer.device_id(), encryption.encryption_key())
            .unwrap();
        let store = wyrd_format::FsObjectStore::open(dir.clone()).unwrap();
        engine.carry_pending(&store).unwrap();
        (engine, dir)
    }

    /// The vault projection agrees with the member projection on
    /// every class both may see: totals, queue, durability,
    /// reconciliation, and materialization are the same committed
    /// facts through either lens. The member surface shows more;
    /// the vault surface shows nothing different.
    #[test]
    fn vault_projection_matches_member_counts() {
        use crate::status::observe;
        let (engine, dir) = scratch_fresh();
        let member = observe(&engine, 0).unwrap();
        let vault = observe_vault(&engine).unwrap();
        assert_eq!(vault.outbox, member.totals);
        assert_eq!(vault.queue, member.queue);
        assert_eq!(vault.durability, member.durability);
        assert_eq!(vault.reconciliation, member.reconciliation);
        assert_eq!(vault.materialization, member.materialization);
        assert_eq!(vault.backlog_empty, member.queue.is_empty());
        assert!(vault.backlog_empty, "a fresh drive owes nothing");
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The boundary is the type: [`VaultStatus`] has no field for a
    /// tip, an epoch list, a head, a peer, or a mailbox, so the
    /// renderer cannot print what the struct cannot hold. This test
    /// pins the absence against a fixture where the member
    /// projection is identity-rich: two peers, a live head with an
    /// author, queued obligations to a named recipient.
    #[test]
    fn vault_projection_carries_no_member_columns() {
        use crate::status::observe;
        let (engine, dir) = scratch_admission();
        let member = observe(&engine, 0).unwrap();
        assert_eq!(member.peers.len(), 2, "fixture is identity-rich");
        assert_eq!(member.live_heads.len(), 1, "fixture has an author");
        assert!(!member.queue.is_empty(), "fixture owes a backlog");
        let vault = observe_vault(&engine).unwrap();
        assert!(!vault.backlog_empty, "the backlog survives the projection");
        let rendered = format!("{vault:?}");
        for peer in &member.peers {
            assert!(
                !rendered.contains(&peer.peer.to_string()),
                "peer identity reaches the vault struct"
            );
        }
        for head in &member.live_heads {
            assert!(
                !rendered.contains(&head.id.to_string()),
                "snapshot id reaches the vault struct"
            );
            assert!(
                !rendered.contains(&head.author.to_string()),
                "head author reaches the vault struct"
            );
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Observation commits nothing: two reads agree exactly, like
    /// the member projection.
    #[test]
    fn vault_observation_is_repeatable() {
        let (engine, dir) = scratch_admission();
        assert_eq!(
            observe_vault(&engine).unwrap(),
            observe_vault(&engine).unwrap()
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}

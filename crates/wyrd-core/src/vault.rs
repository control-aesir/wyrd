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
//! reads only count-producing queries off the engine — outbox
//! totals, pending-obligation counts, queue depths, reconciliation
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
//! posture (control-plane configuration, matrix H9), the durability
//! level (snapshot-activity state the matrix's member column rates
//! H5 — a vault surface prints no reading of it, not even a coarse
//! one), and store-level blob listings (a second store open with its
//! own side effects). The matrix permits vault surfaces a subset of
//! the keyless column; this projection is that subset. Convergence
//! is reported as the backlog predicate only (`backlog_empty`),
//! never as a head-class verdict — a quiet queue with pending heads
//! is not convergence, and the vault surface must not claim
//! otherwise.
//!
//! Row map (matrix `docs/trust.md`, observation × trust-position):
//! every field below is O4 (counts). No field maps to a hidden row;
//! the field inventory pins this mapping, and the inventory is
//! exhaustive by construction (see `disclosure_map`).

use wyrd_sync::disclosure::DisclosureRow;
use wyrd_sync::runtime::{
    Engine, EngineError, MaterializationSummary, OutboxTotals, ReconciliationCounters,
};

use crate::status::QueueDepth;

/// Vault-position status: counts only. No identities, no heads, no
/// membership, no mailbox, no durability verdict — the type has no
/// field that could hold them, which is the enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultStatus {
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

impl VaultStatus {
    /// Disclosure inventory (matrix conformance): every field maps
    /// to O4 (counts). No hidden-row mapping is permitted here; the
    /// conformance test rejects any.
    ///
    /// The destructure is exhaustive on purpose: it names every
    /// field, so adding a field without extending both the pattern
    /// and the map below fails the build. That is the OD-18-4
    /// default-deny pressure in compile-error form — the map cannot
    /// silently miss a field the struct gained.
    pub fn disclosure_map(&self) -> &'static [(&'static str, DisclosureRow)] {
        let Self {
            outbox: _,
            queue: _,
            reconciliation: _,
            materialization: _,
            backlog_empty: _,
        } = self;
        use DisclosureRow::O4;
        &[
            ("outbox", O4),
            ("queue", O4),
            ("reconciliation", O4),
            ("materialization", O4),
            ("backlog_empty", O4),
        ]
    }
}

/// Observe vault-position status from durable state. Reads committed
/// facts only; commits nothing, connects to nothing, and — unlike
/// [`crate::status::observe`] — never extracts an identity-bearing
/// row. The engine calls below are the complete read set: one
/// runtime-state rebuild (totals, pending counts, carries,
/// reconciliation gaps, materialization) plus the reconciliation
/// counters — no per-class rebuilds beyond what the member
/// projection already performs.
pub fn observe_vault(engine: &Engine) -> Result<VaultStatus, EngineError> {
    let state = engine.runtime_state()?;
    let outbox = state.outbox_totals();
    // Pending pairs per class from the same set difference the
    // member projection counts (`RuntimeState::pending_*`: queued
    // minus delivered ∪ reconciled), tallied without materializing
    // the pairs — plus the staged carries the itemized lists do
    // not cover.
    let (announcements, transitions, capabilities) = state.pending_obligation_counts();
    let carries = state.pending_carries().len();
    let reconcile = state.reconcile();
    let queue = QueueDepth {
        outbox: announcements + transitions + capabilities + carries,
        carries,
        fetch: reconcile.pending_snapshots.len()
            + reconcile.pending_snapshot_bodies.len()
            + reconcile.pending_manifests.len()
            + reconcile.pending_objects.len(),
    };
    let reconciliation = engine.reconciliation_counters()?;
    let materialization = state.materialization_summary();
    Ok(VaultStatus {
        outbox,
        queue,
        reconciliation,
        materialization,
        backlog_empty: queue.is_empty(),
    })
}

#[cfg(test)]
pub(crate) mod fixtures {
    use wyrd_format::{Entry, ObjectKind, ObjectStore, Tree};
    use wyrd_sync::keys::DeviceIdentitySecret;
    use wyrd_sync::runtime::Engine;

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
    pub(crate) fn scratch_fresh() -> (Engine, std::path::PathBuf) {
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
    pub(crate) fn scratch_admission() -> (Engine, std::path::PathBuf) {
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
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::observe_vault;

    /// The vault projection agrees with the member projection on
    /// every class both may see: totals, queue, reconciliation,
    /// and materialization are the same committed facts through
    /// either lens. The member surface shows more; the vault
    /// surface shows nothing different. Runs on both a fresh drive
    /// (all zeros) and the admission fixture (non-zero backlog),
    /// because a zeros-only agreement is vacuous.
    #[test]
    fn vault_projection_matches_member_counts() {
        use crate::status::observe;
        for (engine, dir) in [scratch_fresh(), scratch_admission()] {
            let member = observe(&engine, 0).unwrap();
            let vault = observe_vault(&engine).unwrap();
            assert_eq!(vault.outbox, member.totals);
            assert_eq!(vault.queue, member.queue);
            assert_eq!(vault.reconciliation, member.reconciliation);
            assert_eq!(vault.materialization, member.materialization);
            assert_eq!(vault.backlog_empty, member.queue.is_empty());
            std::fs::remove_dir_all(dir).unwrap();
        }
        let (engine, dir) = scratch_admission();
        let member = observe(&engine, 0).unwrap();
        assert!(
            !member.queue.is_empty(),
            "the admission fixture must owe a backlog, or the agreement is vacuous"
        );
        assert_eq!(
            member.queue.outbox, 4,
            "two announcements, one transition, one capability"
        );
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
/// Matrix conformance: the field-to-row inventories pinned as
/// golden literals against live values. Every `disclosure_map`
/// destructures its struct exhaustively, so adding a field without
/// extending the map fails the build — that is the OD-18-4
/// classification pressure in compile-error form, and these tests
/// pin the row each field maps to. The vault-side test below is
/// the teeth: no hidden-row mapping may appear on the vault
/// projection, so a restricted position can never gain a field
/// silently.
#[cfg(test)]
mod conformance {
    use wyrd_sync::disclosure::DisclosureRow::{H5, H6, H8, H9, O1, O4};

    use super::fixtures::*;
    use super::observe_vault;
    use crate::status::observe;
    use wyrd_sync::runtime::{MaterializationSummary, OutboxTotals, ReconciliationCounters};

    /// No hidden-row mapping on the vault projection, ever. This is
    /// the default-deny rule as code: a future field mapped to any
    /// H-row fails here even if its golden literal was updated.
    #[test]
    fn vault_inventory_is_all_observable() {
        let (engine, dir) = scratch_admission();
        let vault = observe_vault(&engine).unwrap();
        for (field, row) in vault.disclosure_map() {
            assert!(
                !row.is_hidden(),
                "vault field {field} maps to hidden row {row:?}"
            );
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn member_projection_inventory_is_pinned() {
        let (engine, dir) = scratch_admission();
        let member = observe(&engine, 0).unwrap();
        assert_eq!(
            member.disclosure_map(),
            &[
                ("tip", H8),
                ("held_epochs", H8),
                ("obligations", H9),
                ("totals", O4),
                ("live_heads", H5),
                ("head_classes", H5),
                ("mailbox", H9),
                ("known_members", H8),
                ("peers", H8),
                ("queue", O4),
                ("reconciliation", O4),
                ("convergence", H5),
                ("materialization", O4),
                ("durability", H5),
            ]
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn vault_projection_inventory_is_pinned() {
        let (engine, dir) = scratch_fresh();
        let vault = observe_vault(&engine).unwrap();
        assert_eq!(
            vault.disclosure_map(),
            &[
                ("outbox", O4),
                ("queue", O4),
                ("reconciliation", O4),
                ("materialization", O4),
                ("backlog_empty", O4),
            ]
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn nested_observation_inventories_are_pinned() {
        let (engine, dir) = scratch_admission();
        let member = observe(&engine, 0).unwrap();
        assert_eq!(
            member
                .live_heads
                .first()
                .expect("admission fixture carries a live head")
                .disclosure_map(),
            &[("id", H6), ("epoch", H5), ("author", H5)]
        );
        assert_eq!(
            member.head_classes.disclosure_map(),
            &[
                ("eligible", H5),
                ("canonical_history", H5),
                ("superseded", H5),
                ("stranded", H5),
                ("voided", H5),
                ("pending", H5),
                ("rejected", H5),
            ]
        );
        assert_eq!(
            member
                .peers
                .first()
                .expect("admission fixture names peers")
                .disclosure_map(),
            &[("handle", O1), ("peer", H8), ("pending", O4)]
        );
        assert_eq!(
            member.queue.disclosure_map(),
            &[("outbox", O4), ("carries", O4), ("fetch", O4)]
        );
        assert_eq!(
            member.convergence.disclosure_map(),
            &[
                ("converged", H5),
                ("pending_heads", H5),
                ("unfetchable_heads", H5)
            ]
        );
        assert_eq!(
            member.mailbox.disclosure_map(),
            &[("configured_relays", H9)]
        );
        assert_eq!(
            member.obligations.disclosure_map(),
            &[
                ("announcements", H9),
                ("transitions", H9),
                ("capabilities", H9)
            ]
        );
        assert_eq!(
            OutboxTotals::default().disclosure_map(),
            &[
                ("announcements_queued", O4),
                ("announcements_delivered", O4),
                ("transitions_queued", O4),
                ("transitions_delivered", O4),
                ("capabilities_queued", O4),
                ("capabilities_delivered", O4),
            ]
        );
        assert_eq!(
            ReconciliationCounters::default().disclosure_map(),
            &[
                ("statements_received", O4),
                ("transitions_reconciled", O4),
                ("capabilities_reconciled", O4),
                ("announcements_reconciled", O4),
            ]
        );
        assert_eq!(
            MaterializationSummary::default().disclosure_map(),
            &[("pinned", O4), ("cached", O4), ("local_objects", O4)]
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}

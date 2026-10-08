//! Window (b): post-corruption projection (G4, OD-05-B).
//!
//! The rule is normative in `docs/epochs.md:557-568` — when replay or
//! classification cannot produce a valid projection, Wyrd preserves
//! the last successfully installed heads and surfaces the error, never
//! replacing, clearing, repairing, or resynchronizing — and this
//! module pins its crash-window direction: a damaged head in a later
//! pass fails the pass with the previous generation still serving.
//! `docs/crash-consistency.md` names this section and its tests; the
//! rule itself lives only in `epochs.md`.
//!
//! The damage vector is bitrot in the object store: a tree whose
//! bytes no longer hash to their address (valid bytes, wrong
//! identity — a mismatch, never damage to the probe itself). The
//! memory store cannot bitrot, so these tests run the same fake view
//! over a tampering wrapper ([`CorruptStore`]) — the productive
//! corruption case, not a lock-poison or store-failure substitute.

use super::prereq_tests::FileView;
use super::*;
use std::sync::{Arc, RwLock};
use wyrd_format::{
    DiscardOutcome, DiscardRejectedRepresentation, Entry, MemoryObjectStore, ObjectKind,
    ObjectStore, Tree,
};

/// An object store that serves substitute bytes for one identity:
/// bitrot under a live name. Everything else — including `has` —
/// delegates untouched, so the damage surfaces exactly where the
/// closure gate reads bytes, not in the fetch plan's presence
/// checks.
struct CorruptStore {
    inner: MemoryObjectStore,
    corrupt: Option<(ContentId, Vec<u8>)>,
}

impl CorruptStore {
    fn bitrot(&mut self, target: ContentId, bytes: Vec<u8>) {
        self.corrupt = Some((target, bytes));
    }

    fn heal(&mut self) {
        self.corrupt = None;
    }
}

impl ObjectStore for CorruptStore {
    type Error = wyrd_format::MemoryStoreError;

    fn insert(&mut self, kind: ObjectKind, data: &[u8]) -> Result<ContentId, Self::Error> {
        self.inner.insert(kind, data)
    }

    fn insert_verified(
        &mut self,
        kind: ObjectKind,
        expected: &ContentId,
        data: &[u8],
    ) -> Result<(), Self::Error> {
        self.inner.insert_verified(kind, expected, data)
    }

    fn get(&self, id: &ContentId) -> Result<Option<Vec<u8>>, Self::Error> {
        if let Some((target, bytes)) = &self.corrupt {
            if id == target {
                return Ok(Some(bytes.clone()));
            }
        }
        self.inner.get(id)
    }

    fn has(&self, id: &ContentId) -> Result<bool, Self::Error> {
        self.inner.has(id)
    }
}

impl DiscardRejectedRepresentation for CorruptStore {
    type Error = wyrd_format::MemoryStoreError;

    fn discard_rejected_representation(
        &mut self,
        id: &ContentId,
    ) -> Result<DiscardOutcome, Self::Error> {
        self.inner.discard_rejected_representation(id)
    }
}

/// A mailbox that accepts and delivers nothing: these passes never
/// exercise intake.
struct StillMailbox;

impl wyrd_sync::transport::mailbox::Mailbox for StillMailbox {
    fn send(
        &mut self,
        _envelope: wyrd_sync::transport::mailbox::MailboxEnvelope,
    ) -> Result<
        wyrd_sync::transport::mailbox::SendReport,
        wyrd_sync::transport::mailbox::MailboxError,
    > {
        Ok(wyrd_sync::transport::mailbox::SendReport { accepted: 1 })
    }

    fn recv(
        &mut self,
    ) -> Result<
        Option<wyrd_sync::transport::mailbox::Delivery>,
        wyrd_sync::transport::mailbox::MailboxError,
    > {
        Ok(None)
    }

    fn settle(
        &mut self,
        _id: wyrd_sync::transport::mailbox::DeliveryId,
        _disposition: wyrd_sync::transport::mailbox::Disposition,
    ) -> Result<(), wyrd_sync::transport::mailbox::MailboxError> {
        Ok(())
    }
}

/// A two-generation drive over a corruptible store: the first head is
/// installed as the composition baseline, the second is authored but
/// unpublished. Returns the node plus the second head's tree id and
/// the first head's tree bytes: serving those valid-but-wrong bytes
/// under the second tree's name is the bitrot vector, a tree identity
/// mismatch the closure gate fails damaged (never pending).
fn two_generation_drive(
    tag: &str,
) -> (
    LiveNode<FileView<CorruptStore>>,
    std::path::PathBuf,
    ContentId,
    Vec<u8>,
    AuthorizedSnapshot,
    AuthorizedSnapshot,
) {
    let dir = std::env::temp_dir().join(format!(
        "wyrd-core-postcorrupt-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let identity = wyrd_sync::keys::DeviceIdentitySecret::generate().unwrap();
    let mut engine = Engine::create(dir.clone(), "core-test-pass", identity).unwrap();
    let mut inner = MemoryObjectStore::default();
    let chunk = inner.insert(ObjectKind::Chunk, b"remote-base").unwrap();
    let root = Tree::from_entries(vec![Entry::file("f", 11, false, vec![chunk]).unwrap()])
        .unwrap()
        .insert_into(&mut inner)
        .unwrap();
    let head = engine.author_snapshot(&inner, root).unwrap();
    let chunk2 = inner.insert(ObjectKind::Chunk, b"remote-second").unwrap();
    let root2 = Tree::from_entries(vec![Entry::file("g", 13, false, vec![chunk2]).unwrap()])
        .unwrap()
        .insert_into(&mut inner)
        .unwrap();
    // Compose before the second authoring: the baseline generation
    // serves the first head, and the second commit advances the
    // revision past it — so the next pass must classify the new head
    // instead of idling.
    let revision = engine.current();
    let materialization = RuntimeMaterialization {
        runtime: engine.runtime_state().unwrap(),
        terminal: engine.terminal_snapshot(),
    };
    let store = Arc::new(RwLock::new(CorruptStore {
        inner,
        corrupt: None,
    }));
    let baseline = FileView::open_shared(
        Arc::clone(&store),
        materialization,
        vec![Head::new(head.clone())],
    );
    let (mut node, _) = LiveNode::split(
        engine,
        store,
        baseline,
        revision,
        std::time::Duration::from_secs(30),
        &LiveConfig::default(),
    )
    .expect("the default config carries no quota");
    let head2 = {
        let guard = node.store.read().unwrap();
        node.engine.author_snapshot(&*guard, root2).unwrap()
    };
    let decoy = node
        .store
        .read()
        .unwrap()
        .get(&root)
        .unwrap()
        .expect("the first tree is held");
    (node, dir, root2, decoy, head, head2)
}

/// Serve the installed generation's file through the node: the
/// observable "keeps serving" half of the rule. Reads through the
/// publication slot — what backends actually serve — never through
/// the engine's live heads, which already moved on to the damaged
/// head.
fn served_file(node: &LiveNode<FileView<CorruptStore>>, path: &str) -> Vec<u8> {
    let slot = node.projection().unwrap();
    let view = slot.view();
    let opened = view.open_file(&view.lookup(path).unwrap()).unwrap();
    view.read(&opened, 0, 64).unwrap()
}

/// A damaged later head fails the pass with the previous generation
/// still serving: the installed projection is not an endorsement of
/// the newly replayed state.
#[test]
fn failed_projection_preserves_the_last_installed_heads() {
    let (mut node, dir, root2, decoy, head, _head2) = two_generation_drive("preserves");
    assert_eq!(served_file(&node, "f"), b"remote-base");
    let slot_before = node.projection().unwrap();
    // Bitrot the unpublished head's tree: valid store reads
    // everywhere else, valid-but-wrong bytes under this one name.
    node.store.write().unwrap().bitrot(root2, decoy);
    let error = node
        .sync_once(
            &mut StillMailbox,
            None::<&mut wyrd_sync::bulk::MemoryBulkSource>,
        )
        .expect_err("a damaged head must fail the pass closed");
    assert!(
        matches!(error, LiveError::Engine(EngineError::Closure(_))),
        "the first damage is the reported error for {head:?}: {error:?}"
    );
    assert_eq!(
        served_file(&node, "f"),
        b"remote-base",
        "the last installed generation keeps serving through the failure"
    );
    assert!(
        Arc::ptr_eq(&slot_before, &node.projection().unwrap()),
        "the failed pass must not even swap the publication slot"
    );
    assert_eq!(node.generation(), 0, "no publish happened on failure");
    std::fs::remove_dir_all(dir).unwrap();
}

/// The projection error reaches the caller as the pass's own error:
/// damage is surfaced, never swallowed into a degraded-but-Ok
/// report.
#[test]
fn failed_projection_surfaces_the_error_to_the_caller() {
    let (mut node, dir, root2, decoy, _head, _head2) = two_generation_drive("surfaces");
    node.store.write().unwrap().bitrot(root2, decoy);
    let error = node
        .sync_once(
            &mut StillMailbox,
            None::<&mut wyrd_sync::bulk::MemoryBulkSource>,
        )
        .expect_err("damage must not report Ok");
    assert!(
        matches!(error, LiveError::Engine(EngineError::Closure(_))),
        "the caller sees the closure damage, not a synthesized status: {error:?}"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

/// The failed pass neither clears nor resynchronizes: the installed
/// heads are untouched, the engine reclassifies nothing, the pass
/// manufactures no durable facts — and healing converges without
/// rescue, the damaged head installing on the next pass like any
/// ordinary head once its bytes are right.
#[test]
fn failed_projection_never_clears_or_resynchronizes_installed_heads() {
    let (mut node, dir, root2, decoy, _head, head2) = two_generation_drive("never-clears");
    let slot_before = node.projection().unwrap();
    node.store.write().unwrap().bitrot(root2, decoy);
    let seq_before = node.engine.current();
    let _ = node
        .sync_once(
            &mut StillMailbox,
            None::<&mut wyrd_sync::bulk::MemoryBulkSource>,
        )
        .expect_err("damage must fail the pass");
    // Not cleared: the installed generation still serves its file,
    // the publication slot was never swapped, and the generation
    // count never moved — not an error, not an empty view.
    assert_eq!(served_file(&node, "f"), b"remote-base");
    assert!(
        Arc::ptr_eq(&slot_before, &node.projection().unwrap()),
        "the failure must not clear or replace the installed heads"
    );
    assert_eq!(node.generation(), 0);
    // Not resynchronized: the engine still holds the damaged head as
    // its live head (no reclassification, no rescue facts), and the
    // failed pass committed nothing.
    let live: Vec<_> = node
        .engine
        .live_heads()
        .unwrap()
        .iter()
        .map(|head| head.snapshot().snapshot_id())
        .collect();
    assert_eq!(
        live,
        vec![head2.snapshot().snapshot_id()],
        "no reclassification on failure"
    );
    assert_eq!(
        node.engine.current(),
        seq_before,
        "the failed pass manufactures no durable facts"
    );
    {
        // The installed generation is still the first head's: its
        // file serves, and the damaged head's file is not installed.
        let slot = node.projection().unwrap();
        assert!(slot.view().lookup("g").is_err());
    }
    // Healing converges without rescue: the head installs on the next
    // pass like any ordinary head once its bytes are right.
    node.store.write().unwrap().heal();
    let report = node
        .sync_once(
            &mut StillMailbox,
            None::<&mut wyrd_sync::bulk::MemoryBulkSource>,
        )
        .unwrap();
    assert!(report.published, "the healed head publishes");
    let installed: Vec<_> = node
        .live_heads_traced()
        .unwrap()
        .iter()
        .map(|head| head.snapshot().snapshot_id())
        .collect();
    assert_eq!(installed, vec![head2.snapshot().snapshot_id()]);
    assert_eq!(
        served_file(&node, "g"),
        b"remote-second",
        "the healed head serves after converging without rescue"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

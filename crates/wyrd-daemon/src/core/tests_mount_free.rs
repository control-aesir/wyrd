//! The mount-free surface reads the same bytes with the same
//! failure classes as the serving view: one named equivalence per
//! read class, over a real `DriveView`, never the core's fake.

use std::sync::Arc;
use std::time::Duration;

use wyrd_core::read::{LiveReader, ReadError};
use wyrd_core::view::NamespaceView;
use wyrd_core::want::WantRegistry;
use wyrd_format::{
    ContentId, DeviceId, Entry, FetchStatus, MemoryObjectStore, ObjectKind, ObjectStore, Snapshot,
    TransitionId, Tree,
};
use wyrd_fuse::{DriveView, VerifiedSnapshot, ViewError, ViewHead};

/// Residency for the equivalence drive: store presence serves;
/// absent identities are remote-only unless listed terminal, in
/// which case the settled verdict applies. Mirrors what
/// `RuntimeMaterialization` reports off engine state, without an
/// engine.
struct EquivalenceMaterialization {
    terminal: Vec<ContentId>,
}

impl wyrd_fuse::Materialization for EquivalenceMaterialization {
    fn status(&self, id: &ContentId) -> FetchStatus {
        if self.terminal.contains(id) {
            FetchStatus::Unavailable(1)
        } else {
            FetchStatus::RemoteOnly
        }
    }
}

/// A deliberately forged verification capability for the
/// equivalence fixture: asserts nothing real, never escapes test
/// code. Production heads cross through `wyrd-sync` authorization.
struct TestHead(Snapshot);

// SAFETY: test-only forgery, same discipline as the FUSE
// backend's own harness. See `VerifiedSnapshot` for the contract.
#[allow(unsafe_code)]
unsafe impl VerifiedSnapshot for TestHead {
    fn into_snapshot(self) -> Snapshot {
        self.0
    }
}

fn snapshot_of(tree: ContentId) -> Snapshot {
    Snapshot::new(
        Vec::new(),
        tree,
        DeviceId::from_bytes([0xD0; 32]),
        TransitionId::from_bytes([0x71; 32]),
        1,
        0,
        1,
    )
    .unwrap()
}

/// A drive with `served.txt` (bytes local), `remote.txt`
/// (entry without bytes), and `gone.txt` (entry without bytes,
/// terminally unavailable).
fn equivalence_view() -> (
    DriveView<MemoryObjectStore, EquivalenceMaterialization>,
    Vec<u8>,
    Vec<u8>,
) {
    let served = vec![0xABu8; 300 * 1024 + 13];
    let mut store = MemoryObjectStore::default();
    let served_id = store.insert(ObjectKind::Chunk, &served).unwrap();
    let remote_id = ContentId::from_bytes([0xE1; 32]);
    let gone_id = ContentId::from_bytes([0xE2; 32]);
    let root = Tree::from_entries(vec![
        Entry::file("served.txt", served.len() as u64, false, vec![served_id]).unwrap(),
        Entry::file("remote.txt", 7, false, vec![remote_id]).unwrap(),
        Entry::file("gone.txt", 4, false, vec![gone_id]).unwrap(),
    ])
    .unwrap()
    .insert_into(&mut store)
    .unwrap();
    let view = DriveView::new(
        store,
        EquivalenceMaterialization {
            terminal: vec![gone_id],
        },
        vec![ViewHead::new(TestHead(snapshot_of(root)))],
    );
    (view, served, b"remote!".to_vec())
}

/// Served bytes read identically through the mount-free surface
/// and direct view calls — including across the window loop (the
/// fixture exceeds one read window).
#[test]
fn mount_free_read_matches_direct_view_on_served_bytes() {
    let (view, served, _) = equivalence_view();
    let reader = LiveReader::new(Duration::from_secs(5));
    let via_reader = reader.read_file(&view, "/served.txt").unwrap();
    assert_eq!(via_reader, served);
    let node = view.lookup("/served.txt").unwrap();
    let file = view.open_file(&node).unwrap();
    let via_view = view.read(&file, 0, served.len()).unwrap();
    assert_eq!(via_view, served);
}

/// A remote-only identity reports `NotMaterialized` to direct
/// view reads (`DriveView::open` is lazy; the verdict surfaces at
/// `read`) and times out bounded through the reader: same failure
/// class, no mount required.
#[test]
fn mount_free_remote_only_times_out_where_view_reports_not_materialized() {
    let (view, _, _) = equivalence_view();
    let node = view.lookup("/remote.txt").unwrap();
    let file = view.open_file(&node).unwrap();
    assert!(matches!(
        view.read(&file, 0, 7),
        Err(ViewError::NotMaterialized { .. })
    ));
    let reader =
        LiveReader::new(Duration::from_millis(120)).with_wants(Arc::new(WantRegistry::default()));
    assert!(matches!(
        reader.read_file(&view, "/remote.txt"),
        Err(ReadError::Timeout { .. })
    ));
}

/// A terminally unavailable identity fails fast through both
/// paths, and the reader leaves reopen demand for the next pass.
#[test]
fn mount_free_terminal_matches_view_verdict() {
    let (view, _, _) = equivalence_view();
    let node = view.lookup("/gone.txt").unwrap();
    let file = view.open_file(&node).unwrap();
    assert!(matches!(
        view.read(&file, 0, 4),
        Err(ViewError::Unavailable { .. })
    ));
    let wants = Arc::new(WantRegistry::default());
    let reader = LiveReader::new(Duration::from_secs(5)).with_wants(Arc::clone(&wants));
    assert!(matches!(
        reader.read_file(&view, "/gone.txt"),
        Err(ReadError::Terminal(ViewError::Unavailable { .. }))
    ));
    assert_eq!(wants.take_reopen_notes().len(), 1);
}

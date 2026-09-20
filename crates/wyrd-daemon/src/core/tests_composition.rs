use super::*;

use wyrd_format::ObjectStore;
use wyrd_fuse::Node;
use wyrd_sync::runtime::Engine;

use super::tests_harness::{scratch_drive, scratch_engine, NoopMailbox};

use wyrd_format::{FsObjectStore, MemoryObjectStore, SnapshotId};
use wyrd_fuse::ViewError;
use wyrd_sync::bulk::BulkSource;

/// Read a whole file back through the daemon view.
fn read_through<S: ObjectStore>(daemon: &Daemon<S>, path: &str) -> Vec<u8>
where
    S::Error: std::fmt::Debug,
{
    let node = daemon.view().lookup(path).unwrap();
    let file = daemon.view().open(&node).unwrap();
    daemon.view().read(&file, 0, u32::MAX as usize).unwrap()
}

#[test]
fn composition_starts_headless_until_engine_projection_exists() {
    // A daemon starts headless until the engine has durable snapshot
    // bodies and its authorization projection identifies eligible heads.
    let store = MemoryObjectStore::default();
    let (engine, dir) = scratch_engine();

    let mut daemon = Daemon::new(engine, store).unwrap();
    daemon.refresh_live_heads().unwrap();
    assert_eq!(
        daemon.view().lookup("sub/a.txt"),
        Err(ViewError::NotFound),
        "an empty engine projects no heads"
    );

    drop(daemon);
    std::fs::remove_dir_all(dir).unwrap();
}

/// The write surface composes chunking, tree mutation, authoring,
/// and the head projection: a put is readable through the view, and
/// a second put extends the single live head instead of forking it.
#[test]
fn put_file_serves_bytes_and_extends_the_live_head() {
    let (engine, dir, _) = scratch_drive();
    let mut daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();

    daemon.put_file("docs/hello.txt", b"hello wyrd").unwrap();
    assert_eq!(read_through(&daemon, "docs/hello.txt"), b"hello wyrd");
    assert!(
        matches!(
            daemon.view().lookup("docs/hello.txt"),
            Ok(Node::File { size: 10, .. })
        ),
        "the served node carries the file size"
    );

    daemon.put_file("docs/hello.txt", b"hello again").unwrap();
    assert_eq!(read_through(&daemon, "docs/hello.txt"), b"hello again");
    assert_eq!(
        daemon.engine.live_heads().unwrap().len(),
        1,
        "a single-head drive extends its live state"
    );

    drop(daemon);
    std::fs::remove_dir_all(dir).unwrap();
}

/// Removal is a state change: the path stops resolving while the
/// drive keeps its history.
#[test]
fn remove_drops_the_path_from_the_view() {
    let (engine, dir, _) = scratch_drive();
    let mut daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();

    daemon.put_file("gone.txt", b"bye").unwrap();
    daemon.remove("gone.txt").unwrap();
    assert_eq!(
        daemon.view().lookup("gone.txt"),
        Err(ViewError::NotFound),
        "removal drops the path from the view"
    );

    drop(daemon);
    std::fs::remove_dir_all(dir).unwrap();
}

/// The full local roundtrip: put, drop the daemon, reopen from
/// persisted custody over the same on-disk object store, and the
/// bytes are still there. Snapshot bodies survive through the
/// engine's durable commit; content survives through the shared
/// store — both halves are required.
#[test]
fn writes_survive_keystore_reopen() {
    let (engine, dir, identity) = scratch_drive();
    let mut daemon = Daemon::new(engine, FsObjectStore::open(dir.clone()).unwrap()).unwrap();
    daemon.put_file("keep.txt", b"persist me").unwrap();
    drop(daemon);

    let reopened = Engine::open_keystore(dir.clone(), "daemon-test-pass", identity).unwrap();
    let mut daemon = Daemon::new(reopened, FsObjectStore::open(dir.clone()).unwrap()).unwrap();
    daemon.refresh_live_heads().unwrap();
    assert_eq!(read_through(&daemon, "keep.txt"), b"persist me");

    drop(daemon);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn authored_writes_can_be_announced_through_the_daemon() {
    let (engine, dir, _) = scratch_drive();
    let mut daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
    let snapshot = daemon.put_file("published.txt", b"publish me").unwrap();
    let sent = daemon
        .announce_snapshot(&snapshot, &mut NoopMailbox, None)
        .unwrap();
    assert_eq!(sent, 0, "a single-member drive has no peer recipients");

    drop(daemon);
    std::fs::remove_dir_all(dir).unwrap();
}

/// A local write serves from the durable vault, across restarts: the
/// authored snapshot's body, root manifest, and every mapped chunk
/// remain servable through the serving view after the original
/// engine is dropped and the drive reopens from custody.
#[test]
fn authored_writes_serve_from_the_durable_vault_across_restarts() {
    let (engine, dir, identity) = scratch_drive();
    let snapshot = {
        let mut daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
        let snapshot = daemon.put_file("published.txt", b"publish me").unwrap();
        let mut serving = daemon.serve().unwrap();
        let snapshot_id = snapshot.snapshot().snapshot_id();
        let state = daemon.engine.runtime_state().unwrap();

        // The body serves by snapshot id, the root manifest by the
        // snapshot id and by the transport root the announcement
        // names, and every mapped chunk by its storage address.
        let body = serving
            .fetch_snapshot(&snapshot_id, usize::MAX)
            .unwrap()
            .expect("the authored body serves");
        assert_eq!(
            SnapshotId::from_bytes(
                *wyrd_format::ContentId::derive(wyrd_format::ObjectKind::Snapshot, &body)
                    .as_bytes()
            ),
            snapshot_id
        );
        let record = state
            .root_manifest_record(&snapshot_id)
            .expect("the authored root manifest records");
        let manifest = serving
            .fetch_root_manifest(&snapshot_id, usize::MAX)
            .unwrap()
            .expect("the root manifest serves");
        assert_eq!(manifest.content_id, record.manifest_id);
        for entry in record.manifest.entries() {
            let bytes = serving
                .fetch_sealed(&entry.storage_id, usize::MAX)
                .unwrap()
                .expect("mapped chunks serve");
            assert_eq!(
                wyrd_sync::seal::EncryptedObject::decode(&bytes)
                    .unwrap()
                    .storage_id(),
                entry.storage_id
            );
        }
        snapshot_id
    };

    // Restart: the drive reopens from custody, the serving view
    // rehydrates from durable state, and the same routes serve.
    let reopened =
        wyrd_sync::runtime::Engine::open_keystore(dir.clone(), "daemon-test-pass", identity)
            .unwrap();
    let daemon = Daemon::new(reopened, MemoryObjectStore::default()).unwrap();
    let mut serving = daemon.serve().unwrap();
    assert!(
        serving
            .fetch_root_manifest(&snapshot, usize::MAX)
            .unwrap()
            .is_some(),
        "the root manifest serves after the restart"
    );

    drop(daemon);
    std::fs::remove_dir_all(dir).unwrap();
}

/// Failures are typed: removing from a headless drive and putting
/// to an empty path fail without touching the engine.
#[test]
fn write_errors_are_typed() {
    let (engine, dir, _) = scratch_drive();
    let mut daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();

    assert!(
        matches!(daemon.remove("nothing.txt"), Err(WriteError::EmptyDrive)),
        "a headless drive has no tree to remove from"
    );
    assert!(
        daemon.put_file("", b"nope").is_err(),
        "an empty path is rejected"
    );

    drop(daemon);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn conflicted_write_error_requires_explicit_resolution() {
    let error = WriteError::<std::convert::Infallible>::Conflicted { heads: 2 };
    assert_eq!(
        error.to_string(),
        "cannot write while the drive has 2 live heads"
    );
}

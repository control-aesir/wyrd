use super::*;

use wyrd_format::{ContentId, FetchStatus};
use wyrd_sync::transport::mailbox::Mailbox;

use std::sync::atomic::Ordering;
use std::time::Duration;

use crate::want::WantRegistry;

use super::live::admit_wants;
use super::tests_harness::{scratch_drive, spawn_live_loop, NoopMailbox, QueueMailbox};

use wyrd_format::{DeviceId, MemoryObjectStore};

use wyrd_sync::bulk::MemoryBulkSource;

use wyrd_sync::transport::mailbox::MailboxEnvelope;

/// The dirty-handle budget bounds the mounted surface: the 65th
/// dirty handle's write is `ENOSPC`, and releasing one frees a slot.
#[test]
fn dirty_handle_budget_refuses_through_the_mount() {
    let (engine, dir, _) = scratch_drive();
    let daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
    let (live, backend) = daemon.into_live(Duration::from_secs(30), &LiveConfig::default());
    let (stop, loop_handle) = spawn_live_loop(live);

    let (fh, _ino, _) = backend.create_at(1, "d.txt", libc::O_RDWR).unwrap();
    backend.write_handle(fh, 0, b"x").unwrap();
    backend.commit_handle(fh).unwrap();
    backend.release_handle(fh).unwrap();

    let mut handles = Vec::new();
    for _ in 0..crate::session::MAX_DIRTY_HANDLES {
        let handle = backend.open_write("d.txt", libc::O_RDWR).unwrap();
        backend.write_handle(handle, 1, b"y").unwrap();
        handles.push(handle);
    }
    let overflow = backend.open_write("d.txt", libc::O_RDWR).unwrap();
    let before = backend.budget_state();
    assert_eq!(
        backend.write_handle(overflow, 1, b"z"),
        Err(fuser::Errno::ENOSPC),
        "one dirty handle past the bound is refused"
    );
    assert_eq!(
        backend.budget_state(),
        before,
        "a refused write changes no budget accounting"
    );
    // The refused handle stayed clean: it still serves the base.
    assert_eq!(backend.read_handle(overflow, 0, 64).unwrap(), b"x");
    backend.release_handle(overflow).unwrap();

    let freed = handles.pop().unwrap();
    backend.release_handle(freed).unwrap();
    let reused = backend.open_write("d.txt", libc::O_RDWR).unwrap();
    assert!(backend.write_handle(reused, 1, b"w").is_ok());
    for handle in handles {
        backend.release_handle(handle).unwrap();
    }
    backend.release_handle(reused).unwrap();

    stop.store(true, Ordering::Relaxed);
    loop_handle
        .join()
        .unwrap()
        .expect("loop shuts down cleanly");
    drop(backend);
    std::fs::remove_dir_all(dir).unwrap();
}

/// Concurrent readers never observe a half-published projection:
/// every cloned generation serves its own complete snapshot while
/// the loop publishes around them. Readers pin whatever generation
/// is current when they clone; each pinned version keeps serving
/// its own bytes after newer generations land.
#[test]
fn concurrent_readers_see_atomic_generations() {
    let (engine, dir, _) = scratch_drive();
    let mut daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
    daemon.put_file("race.txt", b"v1").unwrap();
    let (mut live, backend) = daemon.into_live(Duration::from_secs(30), &LiveConfig::default());

    let pinned = live.projection().unwrap();
    assert_eq!(pinned.generation(), 0);
    let node = pinned.view().lookup("race.txt").unwrap();
    let file = pinned.view().open(&node).unwrap();
    assert_eq!(pinned.view().read(&file, 0, 64).unwrap(), b"v1");

    // Publish around the pinned reader: the old generation stays
    // complete and self-consistent throughout.
    live.dirty = true;
    let report = live
        .sync_once(&mut NoopMailbox, None::<&mut MemoryBulkSource>)
        .unwrap();
    assert!(report.published);
    assert_eq!(pinned.view().read(&file, 0, 64).unwrap(), b"v1");
    assert_eq!(live.projection().unwrap().generation(), 1);

    // The backend serves the new generation; the pin is unaffected.
    let handle = backend.open_at("race.txt").expect("backend serves");
    assert_eq!(backend.read_handle(handle, 0, 64).unwrap(), b"v1");
    assert_eq!(pinned.generation(), 0, "pins keep their version");

    drop(live);
    drop(backend);
    std::fs::remove_dir_all(dir).unwrap();
}

/// The reviewer's publication-gate regression: admitting a pending
/// want is a durable commit (`Cached` fact) even when nothing else
/// changed — the serving projection must republish so the view stops
/// reporting `RemoteOnly` for content the engine has admitted. The
/// gate observes the durable commit sequence, not the pass reports,
/// so the admission's sequence advance is what forces publication.
#[test]
fn want_admission_publishes_without_other_changes() {
    let (engine, dir, _) = scratch_drive();
    let mut daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
    daemon.put_file("anchor.txt", b"anchor").unwrap();
    let (mut live, _backend) = daemon.into_live(Duration::from_secs(30), &LiveConfig::default());
    let baseline = live.generation();

    // Demand content nobody holds yet; no mailbox traffic, no bulk.
    let missing = ContentId::from_bytes([0xEE; 32]);
    live.wants.register(missing).unwrap();
    let report = live
        .sync_once(&mut NoopMailbox, None::<&mut MemoryBulkSource>)
        .unwrap();
    assert!(report.published, "the admission commit must publish");
    assert_eq!(report.generation, baseline + 1);
    let status = live.projection().unwrap().view().status(&missing);
    assert_eq!(
        status,
        FetchStatus::Fetching,
        "want admission must publish even with no other pass changes"
    );
    // The sweep left the still-unfulfilled want in flight.
    assert!(live.wants.is_admitted(&missing));

    drop(live);
    std::fs::remove_dir_all(dir).unwrap();
}

/// The reviewer's admission-atomicity regression: a durable
/// admission failure must leave the uncommitted wants pending — never
/// stranded as admitted — so the next pass retries them and no waiter
/// ever coalesces onto a fetch that was never admitted. The commit
/// step fails mid-batch: the committed prefix is marked, the failing
/// suffix stays pending, and the retry admits the rest.
#[test]
fn failed_want_admission_stays_pending_and_retries() {
    let registry = WantRegistry::default();
    let first = ContentId::from_bytes([0xE1; 32]);
    let second = ContentId::from_bytes([0xE2; 32]);
    registry.register(first).unwrap();
    registry.register(second).unwrap();

    let committed = admit_wants(&registry, usize::MAX, &mut |want| {
        if want == second {
            Err("durable store failed")
        } else {
            Ok(())
        }
    });
    assert_eq!(
        committed,
        Err("durable store failed"),
        "the failing commit surfaces"
    );
    assert!(registry.is_admitted(&first), "the prefix is admitted");
    assert!(
        !registry.is_admitted(&second),
        "a failed admission never strands the identity as admitted"
    );
    assert_eq!(registry.peek_pending(), vec![second]);

    // The next pass retries the pending suffix and finishes the batch.
    let retry = admit_wants(&registry, usize::MAX, &mut |_| Ok::<_, ()>(())).unwrap();
    assert_eq!(retry, vec![second]);
    assert!(registry.peek_pending().is_empty());
}

/// The admission cap paces a flood: only the oldest `limit` wants
/// commit per call and the remainder stays pending for the next pass
/// — paced, never dropped.
#[test]
fn want_admission_cap_paces_floods_across_passes() {
    let registry = WantRegistry::default();
    let ids: Vec<ContentId> = (0..5u8).map(|b| ContentId::from_bytes([b; 32])).collect();
    for id in &ids {
        registry.register(*id).unwrap();
    }
    let first = admit_wants(&registry, 2, &mut |_| Ok::<_, ()>(())).unwrap();
    assert_eq!(first, ids[..2]);
    assert_eq!(registry.peek_pending(), ids[2..]);
    let second = admit_wants(&registry, 2, &mut |_| Ok::<_, ()>(())).unwrap();
    assert_eq!(second, ids[2..4]);
    let third = admit_wants(&registry, 2, &mut |_| Ok::<_, ()>(())).unwrap();
    assert_eq!(third, ids[4..]);
    assert!(registry.peek_pending().is_empty());
}
/// Poison arriving through the mailbox is consumed (acked) rather
/// than retained: an unopenable envelope is terminal, and the
/// serving projection is untouched by the pass.
#[test]
fn sync_once_discards_poison_and_keeps_serving() {
    let (engine, dir, _) = scratch_drive();
    let mut daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
    daemon.put_file("steady.txt", b"steady").unwrap();
    let (mut live, backend) = daemon.into_live(Duration::from_secs(30), &LiveConfig::default());

    let mut mailbox = QueueMailbox::new();
    mailbox.push(MailboxEnvelope {
        sender: DeviceId::from_bytes([0xD0; 32]),
        recipient: DeviceId::from_bytes([0xD0; 32]),
        ciphertext: "not-a-seal".to_string(),
    });
    let report = live
        .sync_once(&mut mailbox, None::<&mut MemoryBulkSource>)
        .unwrap();
    assert_eq!(report.drained.discarded, 1, "poison is consumed");
    assert!(
        mailbox.recv().unwrap().is_none(),
        "acked mail leaves the queue"
    );

    let handle = backend.open_at("steady.txt").expect("still serves");
    let bytes = backend.read_handle(handle, 0, 1024).expect("still reads");
    assert_eq!(bytes, b"steady");

    drop(live);
    drop(backend);
    std::fs::remove_dir_all(dir).unwrap();
}

/// A bulk source plugged into the loop runs the fetch path without
/// error on a drive with nothing pending. This pins the wiring
/// (source through to the shared store) on the idle path only;
/// plan semantics belong to the sync suite.
#[test]
fn sync_once_accepts_idle_bulk_source() {
    let (engine, dir, _) = scratch_drive();
    let mut daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
    daemon.put_file("fetched.txt", b"local").unwrap();
    let (mut live, backend) = daemon.into_live(Duration::from_secs(30), &LiveConfig::default());

    let mut mailbox = NoopMailbox;
    let mut bulk = MemoryBulkSource::default();
    let report = live.sync_once(&mut mailbox, Some(&mut bulk)).unwrap();
    assert_eq!(report.fetched.unfulfilled, 0);
    assert_eq!(report.fetched.manifests, 0);

    let handle = backend.open_at("fetched.txt").expect("serves");
    let _ = handle;

    drop(live);
    drop(backend);
    std::fs::remove_dir_all(dir).unwrap();
}

/// Open handles stay snapshot-stable across sync republication:
/// a descriptor opened before idle and poison passes keeps serving
/// its open-time bytes, while a fresh open serves the current
/// projection. Republication (same heads, rewritten under the
/// shared lock) is what the loop does most; head advancement
/// itself is the engine's classification, covered by the sync and
/// contract suites.
#[test]
fn open_handles_survive_sync_republication() {
    let (engine, dir, _) = scratch_drive();
    let mut daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
    daemon.put_file("stable.txt", b"v1").unwrap();
    let (mut live, backend) = daemon.into_live(Duration::from_secs(30), &LiveConfig::default());

    let old = backend.open_at("stable.txt").expect("opens");
    // Idle and poison passes republish (or skip) the projection
    // without disturbing the open capture.
    let mut mailbox = NoopMailbox;
    live.sync_once(&mut mailbox, None::<&mut MemoryBulkSource>)
        .unwrap();
    let mut poison = QueueMailbox::new();
    poison.push(MailboxEnvelope {
        sender: DeviceId::from_bytes([0xD0; 32]),
        recipient: DeviceId::from_bytes([0xD0; 32]),
        ciphertext: "not-a-seal".to_string(),
    });
    live.sync_once(&mut poison, None::<&mut MemoryBulkSource>)
        .unwrap();
    assert_eq!(
        backend.read_handle(old, 0, 1024).expect("old handle reads"),
        b"v1"
    );
    let fresh = backend.open_at("stable.txt").expect("reopens");
    assert_eq!(
        backend
            .read_handle(fresh, 0, 1024)
            .expect("fresh handle reads"),
        b"v1"
    );

    drop(live);
    drop(backend);
    std::fs::remove_dir_all(dir).unwrap();
}

/// A backlog from a failed pass forces republication on the next
/// clean pass even when it reports zero new changes, then clears.
/// Whether republication becomes visible depends on durable state
/// (heads need bodies); the flag transition itself is the
/// mechanism under test here, with end-to-end recovery covered by
/// the contracts suite.
#[test]
fn dirty_backlog_clears_on_clean_pass() {
    let (engine, dir, _) = scratch_drive();
    let mut daemon = Daemon::new(engine, MemoryObjectStore::default()).unwrap();
    daemon.put_file("steady.txt", b"steady").unwrap();
    let (mut live, backend) = daemon.into_live(Duration::from_secs(30), &LiveConfig::default());
    live.dirty = true;
    let mut mailbox = NoopMailbox;
    live.sync_once(&mut mailbox, None::<&mut MemoryBulkSource>)
        .unwrap();
    assert!(!live.dirty, "republication clears the backlog");
    let handle = backend.open_at("steady.txt").expect("still serves");
    let bytes = backend.read_handle(handle, 0, 1024).expect("still reads");
    assert_eq!(bytes, b"steady");

    drop(live);
    drop(backend);
    std::fs::remove_dir_all(dir).unwrap();
}

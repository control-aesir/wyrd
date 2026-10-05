use super::*;

use wyrd_fuse::DriveView;

use wyrd_format::{ContentId, FetchStatus};
use wyrd_sync::transport::mailbox::Mailbox;

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use wyrd_core::want::WantRegistry;

use super::tests_harness::{
    live_backend, scratch_drive, spawn_live_loop, NoopMailbox, QueueMailbox,
    SettlementFailingMailbox,
};
use wyrd_core::live::admit_wants;

use wyrd_format::{DeviceId, MemoryObjectStore};

use wyrd_sync::bulk::MemoryBulkSource;

use wyrd_sync::transport::mailbox::MailboxEnvelope;

/// A quota refusal arrives at `fsync`, not at `write`, and the handle
/// does not survive it. This is the shape the storage issue's
/// verification names, and it is the consequential one: `write` returns
/// success, the bytes sit in the handle's buffered image, and the
/// refusal only appears when the commit is attempted — the "a `write`
/// that succeeded never implies the later commit will" case. The image is
/// taken before the submit, so a refusal discards it and poisons the fd.
///
/// That is deliberate: it is what a genuinely full disk does, which is
/// the whole reason the quota reuses `StorageFull` and reads as a smaller
/// disk rather than a weaker promise. Pinned here so the equivalence is
/// a fact about this code and not an assumption in a document.
#[test]
fn a_quota_refused_fsync_reports_enospc_and_poisons_the_handle() {
    let (engine, dir, _) = scratch_drive();
    // One ceiling and one accountant, so the count the check reads is
    // the count the store keeps.
    let (config, retained) = LiveConfig::with_retained_quota(0);
    let mut daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, MemoryObjectStore::default().with_retained(retained)).unwrap();
    // The baseline goes in through the node's own write API, which is
    // not quota-checked (see the unrefused-writers note in
    // `resource-limits.md`), and is what puts the drive over a zero
    // ceiling so the refusal is genuinely reached.
    daemon.put_file("base.txt", b"over the ceiling").unwrap();
    // Composed inline rather than through `live_backend`, which builds
    // from the default config and so cannot carry a quota.
    let (mut live, parts) = daemon.into_live(Duration::from_secs(30), &config).unwrap();
    let backend = crate::fuse::FuseBackend::shared_with_wants(
        parts.projection,
        parts.wants,
        parts.mutations,
        parts.open_timeout,
        &parts.budgets,
    );
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let loop_stop = std::sync::Arc::clone(&stop);
    let loop_config = wyrd_core::live::LiveConfig {
        budgets: config.budgets,
        interval: Duration::from_millis(10),
        ..wyrd_core::live::LiveConfig::default()
    };
    let loop_handle = std::thread::spawn(move || {
        let mut mailbox = NoopMailbox;
        live.run_loop(
            &mut mailbox,
            None::<&mut MemoryBulkSource>,
            &loop_stop,
            &loop_config,
            &mut |_, _| {},
        )
    });

    let handle = backend.open_write("base.txt", libc::O_RDWR).unwrap();
    // The write succeeds: its bytes are buffered, not committed.
    backend
        .write_handle(handle, 0, b"x")
        .expect("write only buffers");
    assert_eq!(
        backend.commit_handle(handle),
        Err(fuser::Errno::ENOSPC),
        "the refusal arrives at the commit boundary"
    );
    // The buffered image went with the attempt, so the handle is spent.
    assert_eq!(
        backend.write_handle(handle, 0, b"y"),
        Err(fuser::Errno::EIO),
        "a refused commit leaves the handle unusable, as a full disk does"
    );
    // And the namespace still serves the pre-refusal content: the
    // refusal committed nothing, so there is nothing to serve from it.
    let reader = backend
        .open_at("base.txt")
        .expect("pre-refusal content still serves");
    assert!(backend.release_handle(reader).is_ok());

    stop.store(true, Ordering::Relaxed);
    loop_handle
        .join()
        .unwrap()
        .expect("loop shuts down cleanly");
    std::fs::remove_dir_all(dir).unwrap();
}

/// A removal below the ceiling re-admits local writes. The device sits
/// exactly at its quota, so the next commit is refused; a durable
/// removal (bookkept through `subtract`) moves it back under, and the
/// same commit is then accepted. This is the shape the retention
/// issue's verification names: a counter that cannot go down turns
/// every removal into a phantom refusal.
///
/// The subtract here stands in for a removal path: quarantine and
/// scrub do not exist yet, so no production caller removes bytes.
/// What this pins is the enforcement arithmetic (the count, not the
/// disk, is compared); the removal-then-bookkeeping order itself is
/// pinned at the store level by
/// `retained_bytes_subtract_matches_durable_removal_across_reopen`.
#[test]
fn a_removal_below_the_ceiling_readmits_local_writes() {
    let (engine, dir, _) = scratch_drive();
    let baseline = b"exactly at the ceiling";
    // The ceiling is measured, not assumed: `put_file` retains the
    // file's chunks plus its trees, and only the shared counter knows
    // the total. Start unlimited so the baseline lands, then set the
    // quota to exactly what it charged.
    let (mut config, retained) = LiveConfig::with_retained_quota(u64::MAX);
    let mut daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> = WyrdNode::new(
        engine,
        MemoryObjectStore::default().with_retained(Arc::clone(&retained)),
    )
    .unwrap();
    // The baseline goes in through the node's own write API, which is
    // not quota-checked, and charges the shared counter.
    daemon.put_file("base.txt", baseline).unwrap();
    config.budgets.retained_bytes_quota = Some(retained.get());
    let (mut live, parts) = daemon.into_live(Duration::from_secs(30), &config).unwrap();
    let backend = crate::fuse::FuseBackend::shared_with_wants(
        parts.projection,
        parts.wants,
        parts.mutations,
        parts.open_timeout,
        &parts.budgets,
    );
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let loop_stop = std::sync::Arc::clone(&stop);
    let loop_config = wyrd_core::live::LiveConfig {
        budgets: config.budgets,
        interval: Duration::from_millis(10),
        ..wyrd_core::live::LiveConfig::default()
    };
    let loop_handle = std::thread::spawn(move || {
        let mut mailbox = NoopMailbox;
        live.run_loop(
            &mut mailbox,
            None::<&mut MemoryBulkSource>,
            &loop_stop,
            &loop_config,
            &mut |_, _| {},
        )
    });

    // At the ceiling the commit is refused, including one that would
    // retain nothing new — the documented at-ceiling behaviour.
    let handle = backend.open_write("base.txt", libc::O_RDWR).unwrap();
    backend
        .write_handle(handle, 0, b"x")
        .expect("write only buffers");
    assert_eq!(
        backend.commit_handle(handle),
        Err(fuser::Errno::ENOSPC),
        "at the ceiling even a no-new-bytes commit is refused"
    );

    // The removal path's bookkeeping moves the count back under, and
    // the same write is then admitted.
    retained.subtract(1);
    let handle = backend.open_write("base.txt", libc::O_RDWR).unwrap();
    backend
        .write_handle(handle, 0, b"x")
        .expect("write only buffers");
    backend
        .commit_handle(handle)
        .expect("below the ceiling the commit is admitted");

    // The admitted commit retained new bytes, so the device is back
    // over its ceiling — and the *next* commit is refused. No commit is
    // ever refused for crossing the ceiling, only once already over:
    // the effective ceiling is the quota plus one admitted commit.
    let handle = backend.open_write("base.txt", libc::O_RDWR).unwrap();
    backend
        .write_handle(handle, 0, b"y")
        .expect("write only buffers");
    assert_eq!(
        backend.commit_handle(handle),
        Err(fuser::Errno::ENOSPC),
        "the overshoot is one admitted commit, then refusal resumes"
    );

    stop.store(true, Ordering::Relaxed);
    loop_handle
        .join()
        .unwrap()
        .expect("loop shuts down cleanly");
    std::fs::remove_dir_all(dir).unwrap();
}

/// The dirty-handle budget bounds the mounted surface: the 65th
/// dirty handle's write is `ENOSPC`, and releasing one frees a slot.
#[test]
fn dirty_handle_budget_refuses_through_the_mount() {
    let (engine, dir, _) = scratch_drive();
    let daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, MemoryObjectStore::default()).unwrap();
    let (live, backend) = live_backend(daemon);
    let (stop, loop_handle) = spawn_live_loop(live);

    let (fh, _ino, _) = backend.create_at(1, "d.txt", libc::O_RDWR).unwrap();
    backend.write_handle(fh, 0, b"x").unwrap();
    backend.commit_handle(fh).unwrap();
    backend.release_handle(fh).unwrap();

    let mut handles = Vec::new();
    for _ in 0..wyrd_core::session::MAX_DIRTY_HANDLES {
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
    let mut daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, MemoryObjectStore::default()).unwrap();
    daemon.put_file("race.txt", b"v1").unwrap();
    let (mut live, backend) = live_backend(daemon);

    let pinned = live.projection().unwrap();
    assert_eq!(pinned.generation(), 0);
    let node = pinned.view().lookup("race.txt").unwrap();
    let file = pinned.view().open(&node).unwrap();
    assert_eq!(pinned.view().read(&file, 0, 64).unwrap(), b"v1");

    // Publish around the pinned reader: fail one pass through the
    // public path (the sync_once wrapper marks the backlog on any
    // pass error), then recover — the old generation stays complete
    // and self-consistent throughout.
    let failed = live.sync_once(&mut SettlementFailingMailbox, None::<&mut MemoryBulkSource>);
    assert!(failed.is_err(), "settle failure fails the pass");
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
    let mut daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, MemoryObjectStore::default()).unwrap();
    daemon.put_file("anchor.txt", b"anchor").unwrap();
    let (mut live, _backend) = live_backend(daemon);
    let baseline = live.generation();

    // Demand content nobody holds yet; no mailbox traffic, no bulk.
    let missing = ContentId::from_bytes([0xEE; 32]);
    live.wants().register(missing).unwrap();
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
    assert!(live.wants().is_admitted(&missing));

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
    let mut daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, MemoryObjectStore::default()).unwrap();
    daemon.put_file("steady.txt", b"steady").unwrap();
    let (mut live, backend) = live_backend(daemon);

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
    let mut daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, MemoryObjectStore::default()).unwrap();
    daemon.put_file("fetched.txt", b"local").unwrap();
    let (mut live, backend) = live_backend(daemon);

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
    let mut daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, MemoryObjectStore::default()).unwrap();
    daemon.put_file("stable.txt", b"v1").unwrap();
    let (mut live, backend) = live_backend(daemon);

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
/// (heads need bodies); the recovery is pinned end to end here, with
/// broader coverage in the contracts suite.
#[test]
fn dirty_backlog_clears_on_clean_pass() {
    let (engine, dir, _) = scratch_drive();
    let mut daemon: WyrdNode<DriveView<_, RuntimeMaterialization>> =
        WyrdNode::new(engine, MemoryObjectStore::default()).unwrap();
    daemon.put_file("steady.txt", b"steady").unwrap();
    let (mut live, backend) = live_backend(daemon);
    let failed = live.sync_once(&mut SettlementFailingMailbox, None::<&mut MemoryBulkSource>);
    assert!(failed.is_err(), "settle failure fails the pass");
    let mut mailbox = NoopMailbox;
    let report = live
        .sync_once(&mut mailbox, None::<&mut MemoryBulkSource>)
        .unwrap();
    assert!(report.published, "the backlog forces republication");
    let handle = backend.open_at("steady.txt").expect("still serves");
    let bytes = backend.read_handle(handle, 0, 1024).expect("still reads");
    assert_eq!(bytes, b"steady");

    drop(live);
    drop(backend);
    std::fs::remove_dir_all(dir).unwrap();
}

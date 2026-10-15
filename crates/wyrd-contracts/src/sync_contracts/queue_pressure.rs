use super::harness::epoch3_child;
use crate::support::{Loaded, Rig};
use wyrd_format::{FetchStatus, SnapshotId, StorageId};
use wyrd_sync::bulk::{AttemptBudget, BulkError, BulkSource, MemoryBulkSource, SealedManifest};
use wyrd_sync::ingest::Limits;
use wyrd_sync::runtime::MAX_PENDING_MESSAGES as PENDING_BOUND;

/// The pending bound sheds to the relay without consuming: a drained
/// overflow stays the relay's problem, held messages commit over
/// bounded passes once their transition lands (paced by the per-pass
/// intake budget — pacing is the correct trade, since the alternative
/// is an unbounded single-pass commit), and the shed envelope
/// re-offers against resolved state instead of staying lost. Every
/// delivery carries a fresh seal and therefore a distinct message id;
/// one delivery beyond the engine's configured pending capacity.
#[test]
fn deferred_messages_survive_queue_pressure() {
    let mut rig = Rig::new();
    let child = epoch3_child(&rig);
    let child_id = child.transition_id();
    let id_for = |index: u32| {
        let mut bytes = [0x77u8; 32];
        bytes[0] = index as u8;
        bytes[1] = (index >> 8) as u8;
        SnapshotId::from_bytes(bytes)
    };

    // Announcements bound to a transition the engine has not seen:
    // every delivery defers under its own message id, and the last
    // one sheds to the relay.
    for index in 1..=(PENDING_BOUND as u32 + 1) {
        rig.enqueue_announcement(
            id_for(index),
            child_id,
            3,
            crate::support::AnnouncedRoots::placeholders(),
            None,
        );
    }
    let report = rig.drain();
    assert_eq!(report.accepted, 0);
    assert_eq!(report.deferred, PENDING_BOUND + 1);
    assert_eq!(
        rig.engine_pending(),
        PENDING_BOUND,
        "the bound holds the rest"
    );

    // The transition lands: the held messages start committing with
    // it — paced by the per-pass commit budget, since every envelope
    // shares the rig's single sender quota. The relay-held overflow
    // was offered first in arrival order, so it sheds once more and
    // waits for the next pass.
    rig.enqueue_transition(&child, 1);
    let report = rig.drain();
    assert_eq!(report.accepted, 1, "the child transition");
    assert!(
        rig.engine_pending() < PENDING_BOUND,
        "the flush paces forward under the budget"
    );

    // Pacing converges: bounded passes commit the parked remainder,
    // and the shed overflow re-offers against resolved state instead
    // of staying lost.
    for _ in 0..32 {
        let report = rig.drain();
        if rig.engine_pending() == 0
            && report.accepted == 0
            && report.deferred == 0
            && report.skipped == 0
            && report.duplicates == 0
            && report.discarded == 0
        {
            break;
        }
    }
    assert_eq!(rig.engine_pending(), 0, "pacing converges");

    let runtime = rig.runtime_state();
    assert!(
        runtime.announcement(&id_for(1)).is_some(),
        "held and committed"
    );
    assert!(
        runtime
            .announcement(&id_for(PENDING_BOUND as u32 + 1))
            .is_some(),
        "shed, re-offered, committed"
    );
    rig.teardown();
}

/// Both sides of the bounded-bulk boundary. The engine never offers
/// a fetch ceiling above the configured limit, classifies a source's
/// oversize report as invalid remote data (rejected, never committed,
/// retried later), and materializes the compliant path under the same
/// ceilings. A real source refuses any payload over the offered
/// ceiling and hands over no bytes. The hostile root is refused
/// without materializing hostile bytes anywhere (the in-crate plan
/// test covers the pre-decode gate with real materialized bytes; a
/// source presenting an oversized payload without allocating it is
/// structurally impossible against the by-value bulk trait).
#[test]
fn bulk_ceilings_stay_bounded_and_oversize_fails_closed() {
    // The source side: a real bulk source refuses an oversized
    // payload at a tight ceiling and serves exactly at it.
    let storage = wyrd_format::StorageId::from_bytes([0xB0; 32]);
    let mut peer = MemoryBulkSource::default();
    peer.publish_sealed(storage, vec![0x5A; 128]);
    assert_eq!(
        peer.fetch_sealed(&storage, 64),
        Err(BulkError::Oversize {
            bytes: 128,
            max: 64
        }),
        "a source must refuse, not truncate"
    );
    assert_eq!(
        peer.fetch_sealed(&storage, 128),
        Ok(Some(vec![0x5A; 128])),
        "the served bytes stop exactly at the ceiling"
    );

    let mut loaded = Loaded::new("bounded.txt", b"bounded body");
    // The snapshot body is served; only the root manifest is hostile.
    let snapshot_id = loaded.snapshot.snapshot_id();
    loaded.publish_body_and_announcement(None);
    let report = loaded.drain();
    assert_eq!(report.accepted, 2, "capability and announcement");

    let mut engine = loaded.rig.take_engine();
    let mut all_maxes = Vec::new();

    // First run: the root manifest fetch is refused with an oversize
    // report and nothing materializes.
    {
        let mut bounded = Bounded {
            inner: &mut loaded.bulk,
            maxes: Vec::new(),
            hostile_root: Some(snapshot_id),
        };
        let report = engine
            .execute_plan(&mut bounded, &mut loaded.objects)
            .unwrap();
        assert_eq!(report.manifests, 0, "the oversize root never commits");
        assert!(
            report.invalid >= 1,
            "oversize is invalid, not a transport error (retries may repeat it)"
        );
        let runtime = engine.runtime_state().unwrap();
        for id in &loaded.content.content_ids {
            assert_eq!(
                runtime.status(id),
                FetchStatus::RemoteOnly,
                "nothing became materialized"
            );
        }
        all_maxes.append(&mut bounded.maxes);
    }

    // The compliant manifest and its objects materialize on the next
    // run, under the same bounded path.
    loaded.publish_all();
    loaded.want_all(&mut engine);
    {
        let mut bounded = Bounded {
            inner: &mut loaded.bulk,
            maxes: Vec::new(),
            hostile_root: None,
        };
        let report = engine
            .execute_plan(&mut bounded, &mut loaded.objects)
            .unwrap();
        assert_eq!(report.manifests, 1);
        assert_eq!(report.objects, 2, "the tree and the chunk");
        let runtime = engine.runtime_state().unwrap();
        for id in &loaded.content.content_ids {
            assert_eq!(runtime.status(id), FetchStatus::Available);
        }
        all_maxes.append(&mut bounded.maxes);
    }

    assert!(
        all_maxes
            .iter()
            .all(|max| *max <= Limits::V0.max_object_bytes),
        "the fetch path never offers a ceiling above the configured limit"
    );
    assert!(
        all_maxes.contains(&Limits::V0.max_object_bytes),
        "the root manifest fetch rides the full configured ceiling"
    );
    loaded.rig.teardown();
}

/// A wrapper that records the ceilings it is offered, then delegates
/// to the in-memory peer — except for its hostile root, which it
/// refuses with an oversize report without materializing any bytes.
struct Bounded<'a> {
    inner: &'a mut MemoryBulkSource,
    maxes: Vec<usize>,
    hostile_root: Option<SnapshotId>,
}

impl AttemptBudget for Bounded<'_> {}

impl BulkSource for Bounded<'_> {
    fn fetch_root_manifest(
        &mut self,
        snapshot: &SnapshotId,
        max: usize,
    ) -> Result<Option<SealedManifest>, BulkError> {
        self.maxes.push(max);
        if self.hostile_root == Some(*snapshot) {
            return Err(BulkError::Oversize {
                bytes: max + 1,
                max,
            });
        }
        self.inner.fetch_root_manifest(snapshot, max)
    }

    fn fetch_snapshot(
        &mut self,
        snapshot: &SnapshotId,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        self.maxes.push(max);
        self.inner.fetch_snapshot(snapshot, max)
    }

    fn fetch_sealed(
        &mut self,
        storage: &StorageId,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        self.maxes.push(max);
        self.inner.fetch_sealed(storage, max)
    }

    fn fetch_transport(
        &mut self,
        _root: &wyrd_format::BaoRoot,
        _max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        Ok(None)
    }
}

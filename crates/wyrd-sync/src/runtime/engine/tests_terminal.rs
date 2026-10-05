use super::*;

use std::collections::BTreeSet;

use crate::bulk::{AttemptBudget, BulkError, BulkSource, MemoryBulkSource, SealedManifest};
use crate::keys::EpochSecret;
use crate::membership::test_util::{drive as member_drive, Builder};
use crate::runtime::test_util::{
    admit_engine, announcement_msg_with, body_root, control_key, deliver, drain, fixture, identity,
    identity_secret, intake_body, intake_published, publish_into, queue, AnnouncedRoots, Fixture,
};
use crate::runtime::MaterializationState;
use crate::seal::{entry_for, seal_manifest, SEAL_VERSION};
use wyrd_format::{
    BaoRoot, ContentId, FetchStatus, Manifest, MemoryObjectStore, ObjectKind, Snapshot, StorageId,
};

/// A bulk peer with per-representation behavior: `dead` storage ids
/// fail in transport (strikeable evidence), `missing` ones answer
/// absence (never evidence). Anything else delegates to the wrapped
/// in-memory peer. Corrupt bytes are arranged by overwriting the
/// sealed map entry directly (`publish_sealed` replaces).
struct DirectedBulk {
    inner: MemoryBulkSource,
    dead_storage: BTreeSet<StorageId>,
    dead_roots: BTreeSet<BaoRoot>,
    missing_storage: BTreeSet<StorageId>,
    missing_roots: BTreeSet<BaoRoot>,
}

impl AttemptBudget for DirectedBulk {}

impl BulkSource for DirectedBulk {
    fn fetch_root_manifest(
        &mut self,
        snapshot: &SnapshotId,
        max: usize,
    ) -> Result<Option<SealedManifest>, BulkError> {
        self.inner.fetch_root_manifest(snapshot, max)
    }

    fn fetch_snapshot(
        &mut self,
        snapshot: &SnapshotId,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        self.inner.fetch_snapshot(snapshot, max)
    }

    fn fetch_sealed(
        &mut self,
        storage: &StorageId,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        if self.dead_storage.contains(storage) {
            return Err(BulkError::Transport("route dead".into()));
        }
        if self.missing_storage.contains(storage) {
            return Ok(None);
        }
        self.inner.fetch_sealed(storage, max)
    }

    fn fetch_transport(
        &mut self,
        root: &BaoRoot,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        if self.dead_roots.contains(root) {
            return Err(BulkError::Transport("route dead".into()));
        }
        if self.missing_roots.contains(root) {
            return Ok(None);
        }
        self.inner.fetch_transport(root, max)
    }
}

/// One logical object under two representations across two snapshots
/// (one manifest per snapshot), announced and intake-ready. Manifests
/// are converged before return (objects withheld, so nothing can
/// fulfill): both representations reach the plan. The caller decides
/// per representation whether the bulk peer serves, withholds, kills,
/// or corrupts it. Returns the content id, both storage ids with
/// their transport roots, and the directed peer.
fn two_representation_setup(
    fixture: &mut Fixture,
) -> (
    ContentId,
    StorageId,
    BaoRoot,
    StorageId,
    BaoRoot,
    DirectedBulk,
) {
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
    let mut bulk = MemoryBulkSource::default();
    let body_a = intake_body(&builder, &admission);
    let snapshot_a = body_a.snapshot_id();
    bulk.publish_snapshot(snapshot_a, body_a.encode());
    let drive = member_drive();
    let plaintext = b"two-rep terminal probe";
    let content = ContentId::derive(ObjectKind::Chunk, plaintext);
    let mut storages = Vec::new();
    let mut roots = Vec::new();
    let mut snapshots = vec![snapshot_a];
    // A second authored snapshot carrying the second representation.
    let owner = *builder.owners.iter().next().expect("tracked owner");
    let mut body_b = Snapshot::new(
        Vec::new(),
        ContentId::from_bytes([0xC2; 32]),
        owner,
        admission.transition_id(),
        2,
        0,
        1003,
    )
    .unwrap();
    crate::authorization::test_util::sign_snapshot(&mut body_b, &builder.sk, &drive);
    bulk.publish_snapshot(body_b.snapshot_id(), body_b.encode());
    let snapshot_b = body_b.snapshot_id();
    snapshots.push(snapshot_b);
    for (epoch, snapshot, secret_byte) in [
        (2u64, snapshot_a, 0x09u8),
        (2u64, body_b.snapshot_id(), 0x0Au8),
    ] {
        let secret = EpochSecret::from_bytes([secret_byte; 32]);
        let object_key =
            secret.object_key(&drive, epoch, &content, ObjectKind::Chunk, SEAL_VERSION);
        let sealed_object =
            crate::seal::seal(&object_key, ObjectKind::Chunk, &content, plaintext).unwrap();
        let entry = entry_for(
            ObjectKind::Chunk,
            epoch,
            &sealed_object,
            &content,
            plaintext,
        )
        .unwrap();
        storages.push(entry.storage_id);
        roots.push(entry.transport);
        bulk.publish_sealed(entry.storage_id, sealed_object.encode());
        bulk.publish_transport(sealed_object.encode());
        let manifest = Manifest::new(snapshot, vec![entry], Vec::new()).unwrap();
        let manifest_key = epoch_secret.manifest_key(&member_drive(), epoch, &snapshot);
        let (id, sealed) = seal_manifest(&manifest_key, &manifest).unwrap();
        bulk.publish_root(
            snapshot,
            SealedManifest {
                content_id: id,
                sealed: sealed.encode(),
            },
        );
        bulk.publish_transport(sealed.encode());
        if snapshot == snapshot_a {
            let _ = intake_published(
                fixture,
                &mut bulk,
                &builder,
                &genesis,
                &admission,
                vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
                AnnouncedRoots {
                    manifest: id,
                    transport: crate::seal::transport_root(&sealed),
                },
            );
        } else {
            let bound = announcement_msg_with(
                &identity_secret(&builder.sk),
                snapshot,
                epoch,
                admission.transition_id(),
                body_root(&body_b),
                id,
                crate::seal::transport_root(&sealed),
            );
            let envelope = deliver(fixture, epoch, &bound);
            queue(fixture, vec![envelope]);
            assert_eq!(drain(fixture).accepted, 1);
        }
    }
    fixture
        .engine
        .set_materialization(content, MaterializationState::Pinned)
        .unwrap();
    // Converge the manifest prefix with both objects withheld, so
    // the plan lists both representations and nothing can fulfill.
    let mut directed = DirectedBulk {
        inner: bulk,
        dead_storage: BTreeSet::new(),
        dead_roots: BTreeSet::new(),
        missing_storage: BTreeSet::from([storages[0], storages[1]]),
        missing_roots: BTreeSet::from([roots[0], roots[1]]),
    };
    let mut objects = MemoryObjectStore::default();
    let mut converged = false;
    for _ in 0..6 {
        fixture
            .engine
            .execute_plan(&mut directed, &mut objects)
            .unwrap();
        let runtime = fixture.engine.runtime_state().unwrap();
        if runtime
            .reconcile()
            .pending_objects
            .get(&content)
            .map(Vec::len)
            == Some(2)
        {
            converged = true;
            break;
        }
    }
    assert!(converged, "both representations reach the plan");
    (
        content,
        storages[0],
        roots[0],
        storages[1],
        roots[1],
        directed,
    )
}

/// Drive execute+evaluate passes until the identity is terminal or
/// the budget runs out. Returns the number of passes run.
fn drive_to_terminal(
    fixture: &mut Fixture,
    bulk: &mut DirectedBulk,
    objects: &mut MemoryObjectStore,
    content: &ContentId,
    budget: usize,
) -> usize {
    for pass in 0..budget {
        fixture.engine.execute_plan(bulk, objects).unwrap();
        fixture.engine.evaluate_terminal().unwrap();
        if fixture.engine.terminal_status(content).is_some() {
            return pass + 1;
        }
    }
    panic!("identity never went terminal within {budget} passes");
}

#[test]
fn terminal_state_requires_every_eligible_representation_exhausted() {
    // The must-pin cross-dimensional invariant (OD-11-1 decision): a
    // bad/exhausted representation advances the identity's generation
    // only when no eligible representation remains, and a healthy
    // alternative prevents terminality.
    let mut fixture = fixture();
    let (content, storage_a, root_a, _storage_b, root_b, mut directed) =
        two_representation_setup(&mut fixture);
    let mut objects = MemoryObjectStore::default();
    // Representation A is dead in transport; representation B answers
    // absence (eligible, never evidence).
    directed.dead_storage.insert(storage_a);
    directed.dead_roots.insert(root_a);
    directed.missing_storage.remove(&storage_a);
    directed.missing_roots.remove(&root_a);
    // Run past the strike threshold: A cools, B stays eligible.
    for _ in 0..(FETCH_MAX_STRIKES as usize + FETCH_COOLDOWN_PASSES as usize + 2) {
        fixture
            .engine
            .execute_plan(&mut directed, &mut objects)
            .unwrap();
        fixture.engine.evaluate_terminal().unwrap();
    }
    assert_eq!(
        fixture.engine.terminal_status(&content),
        None,
        "one cooled representation beside an eligible one is not terminal"
    );
    assert_eq!(fixture.engine.generation(&content), Some(1));
    // Now B dies in transport too: both representations cool and the
    // identity completes generation 1 as unavailable, never corrupt.
    directed.missing_roots.remove(&root_b);
    directed.dead_roots.insert(root_b);
    directed.missing_storage.clear();
    drive_to_terminal(&mut fixture, &mut directed, &mut objects, &content, 32);
    assert_eq!(
        fixture.engine.terminal_status(&content),
        Some(FetchStatus::Unavailable(1))
    );
}

#[test]
fn a_cooled_candidate_never_accumulates_evidence() {
    // A representation in cooldown is skipped, never attempted, and
    // contributes zero strikes toward the next generation
    // (peer-repair.md:50-52). The terminal generation does not spin
    // while nothing can be attempted.
    let mut fixture = fixture();
    let (content, storage_a, root_a, storage_b, root_b, mut directed) =
        two_representation_setup(&mut fixture);
    let mut objects = MemoryObjectStore::default();
    directed.dead_storage.insert(storage_a);
    directed.dead_storage.insert(storage_b);
    directed.dead_roots.insert(root_a);
    directed.dead_roots.insert(root_b);
    directed.missing_storage.clear();
    directed.missing_roots.clear();
    drive_to_terminal(&mut fixture, &mut directed, &mut objects, &content, 32);
    let strikes: u32 = fixture
        .engine
        .fetch_strikes
        .get(&FetchKey::Storage(storage_a))
        .map(|(count, _)| *count)
        .unwrap_or(0);
    assert_eq!(strikes, FETCH_MAX_STRIKES, "threshold, frozen");
    // Passes inside the cooldown: no new strikes, no new
    // generation, same terminal verdict. The window stays strictly
    // inside the cooldown the trip opened, so expiry (which
    // legitimately restarts striking from zero) is never crossed.
    for _ in 0..FETCH_COOLDOWN_PASSES {
        assert!(
            fixture
                .engine
                .fetch_cool_until
                .contains_key(&FetchKey::Storage(storage_a)),
            "still cooling: the window never crosses expiry"
        );
        fixture
            .engine
            .execute_plan(&mut directed, &mut objects)
            .unwrap();
        fixture.engine.evaluate_terminal().unwrap();
        let frozen: u32 = fixture
            .engine
            .fetch_strikes
            .get(&FetchKey::Storage(storage_a))
            .map(|(count, _)| *count)
            .unwrap_or(0);
        assert_eq!(
            frozen, FETCH_MAX_STRIKES,
            "cooled candidates accrue nothing"
        );
        assert_eq!(
            fixture.engine.terminal_status(&content),
            Some(FetchStatus::Unavailable(1)),
            "generation does not spin while cooled"
        );
        assert_eq!(fixture.engine.generation(&content), Some(1));
    }
}

#[test]
fn three_transport_failures_project_unavailable_not_corrupt() {
    // The exact sentence at peer-repair.md:70-71 as a test: repeated
    // transport failures yield Unavailable(generation), never Corrupt
    // — across three full generations, each reopened after terminal.
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
    let mut bulk = MemoryBulkSource::default();
    let body = intake_body(&builder, &admission);
    let published = publish_into(
        &mut bulk,
        &epoch_secret,
        admission.epoch,
        &epoch_secret,
        admission.epoch,
        body.snapshot_id(),
        b"transport probe",
    );
    let _body = intake_published(
        &mut fixture,
        &mut bulk,
        &builder,
        &genesis,
        &admission,
        vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        AnnouncedRoots {
            manifest: published.root_manifest,
            transport: published.root_transport,
        },
    );
    let mut objects = MemoryObjectStore::default();
    fixture
        .engine
        .set_materialization(published.content, MaterializationState::Pinned)
        .unwrap();
    let mut directed = DirectedBulk {
        inner: bulk,
        dead_storage: BTreeSet::from([published.object_storage]),
        dead_roots: BTreeSet::from([published.object_transport]),
        missing_storage: BTreeSet::new(),
        missing_roots: BTreeSet::new(),
    };
    for generation in 1..=3u64 {
        drive_to_terminal(
            &mut fixture,
            &mut directed,
            &mut objects,
            &published.content,
            32,
        );
        assert_eq!(
            fixture.engine.terminal_status(&published.content),
            Some(FetchStatus::Unavailable(generation)),
            "transport evidence is unavailable, never corrupt"
        );
        // A new waiter reopens the attempt as a new generation: while
        // the representations are still cooled nothing can be
        // attempted, so no fresh terminal spins without evidence.
        fixture.engine.reopen_generation(&published.content);
        assert_eq!(
            fixture.engine.terminal_status(&published.content),
            None,
            "reopen clears the completed generation"
        );
        assert_eq!(
            fixture.engine.generation(&published.content),
            Some(generation + 1)
        );
        for _ in 0..FETCH_COOLDOWN_PASSES {
            fixture
                .engine
                .execute_plan(&mut directed, &mut objects)
                .unwrap();
            fixture.engine.evaluate_terminal().unwrap();
            assert_eq!(
                fixture.engine.terminal_status(&published.content),
                None,
                "no evidence, no terminal: the generation waits for attempts"
            );
        }
    }
}

#[test]
fn corrupt_stays_attached_to_the_representation_that_produced_it() {
    // An Invalid outcome cools its own FetchKey and does not
    // establish identity-level corruption while another
    // representation still serves (peer-repair.md:72-74).
    let mut fixture = fixture();
    let (content, storage_a, root_a, _storage_b, _root_b, mut directed) =
        two_representation_setup(&mut fixture);
    // Representation A serves corrupt bytes; B is absent for now
    // (eligible, never evidence).
    directed.inner.publish_sealed(storage_a, vec![0xFF; 64]);
    let mut objects = MemoryObjectStore::default();
    directed.dead_storage.clear();
    directed.dead_roots.clear();
    // Representation A is served corruptly on its storage route
    // while its transport route stays absent (the transport map
    // cannot place corrupt bytes under the attested root, so the
    // storage fallback is where verification rejects).
    directed.missing_storage.remove(&storage_a);
    let runtime = fixture.engine.runtime_state().unwrap();
    let plan = runtime.reconcile();
    let candidates = &plan.pending_objects[&content];
    assert_eq!(candidates.len(), 2);
    for candidate in candidates {
        if candidate.storage_id != storage_a {
            directed.missing_storage.insert(candidate.storage_id);
            directed.missing_roots.insert(candidate.transport);
        }
    }
    for _ in 0..(FETCH_MAX_STRIKES + 2) {
        fixture
            .engine
            .execute_plan(&mut directed, &mut objects)
            .unwrap();
        fixture.engine.evaluate_terminal().unwrap();
    }
    assert!(
        fixture
            .engine
            .fetch_cool_until
            .contains_key(&FetchKey::Storage(storage_a)),
        "the invalid representation cools on its own key"
    );
    assert!(
        fixture
            .engine
            .fetch_invalid_cooled
            .contains(&FetchKey::Storage(storage_a)),
        "verification rejection is remembered per representation, apart from transport evidence"
    );
    assert_eq!(
        fixture.engine.terminal_status(&content),
        None,
        "one cooled-invalid representation beside an eligible one establishes nothing"
    );
    // B heals: the healthy alternative fulfills and the identity is
    // available — the cooled-invalid key stays cooled, not promoted.
    directed.missing_storage.clear();
    directed.missing_roots.clear();
    let mut landed = false;
    for _ in 0..8 {
        let report = fixture
            .engine
            .execute_plan(&mut directed, &mut objects)
            .unwrap();
        fixture.engine.evaluate_terminal().unwrap();
        if report.objects > 0 {
            landed = true;
            break;
        }
    }
    assert!(landed, "the healthy representation fulfills");
    assert_eq!(
        fixture.engine.terminal_status(&content),
        None,
        "fulfillment dissolves terminality"
    );
}

#[test]
fn generation_advances_when_a_cooled_representation_is_reopened() {
    // Cooldown expiry opens a new generation rather than reviving the
    // old one — but only forward, and only from a completed terminal.
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
    let mut bulk = MemoryBulkSource::default();
    let body = intake_body(&builder, &admission);
    let published = publish_into(
        &mut bulk,
        &epoch_secret,
        admission.epoch,
        &epoch_secret,
        admission.epoch,
        body.snapshot_id(),
        b"cooldown probe",
    );
    let _body = intake_published(
        &mut fixture,
        &mut bulk,
        &builder,
        &genesis,
        &admission,
        vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        AnnouncedRoots {
            manifest: published.root_manifest,
            transport: published.root_transport,
        },
    );
    let mut objects = MemoryObjectStore::default();
    fixture
        .engine
        .set_materialization(published.content, MaterializationState::Pinned)
        .unwrap();
    let mut directed = DirectedBulk {
        inner: bulk,
        dead_storage: BTreeSet::from([published.object_storage]),
        dead_roots: BTreeSet::from([published.object_transport]),
        missing_storage: BTreeSet::new(),
        missing_roots: BTreeSet::new(),
    };
    drive_to_terminal(
        &mut fixture,
        &mut directed,
        &mut objects,
        &published.content,
        32,
    );
    assert_eq!(fixture.engine.generation(&published.content), Some(1));
    // Past the cooldown the representations are eligible again: the
    // completed generation stays completed and a new one opens. The
    // new generation has no attempts yet, so it is not terminal —
    // expiry alone is eligibility, never evidence.
    let mut advanced = false;
    for _ in 0..(FETCH_COOLDOWN_PASSES + 2) {
        fixture
            .engine
            .execute_plan(&mut directed, &mut objects)
            .unwrap();
        fixture.engine.evaluate_terminal().unwrap();
        if fixture.engine.generation(&published.content) == Some(2) {
            advanced = true;
            assert_eq!(
                fixture.engine.terminal_status(&published.content),
                None,
                "the new generation opens un-terminal"
            );
            break;
        }
    }
    assert!(advanced, "cooldown expiry opens a new generation");
    // Fresh attempts fail again: the new generation completes
    // terminally, monotonically after the first.
    drive_to_terminal(
        &mut fixture,
        &mut directed,
        &mut objects,
        &published.content,
        32,
    );
    assert_eq!(
        fixture.engine.terminal_status(&published.content),
        Some(FetchStatus::Unavailable(2))
    );
}

#[test]
fn terminal_generation_writes_no_durable_fact() {
    // OD-11-3 option A as a test: terminality is attempt state, so
    // completing a generation must not advance the commit sequence.
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
    let mut bulk = MemoryBulkSource::default();
    let body = intake_body(&builder, &admission);
    let published = publish_into(
        &mut bulk,
        &epoch_secret,
        admission.epoch,
        &epoch_secret,
        admission.epoch,
        body.snapshot_id(),
        b"no-fact probe",
    );
    let _body = intake_published(
        &mut fixture,
        &mut bulk,
        &builder,
        &genesis,
        &admission,
        vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        AnnouncedRoots {
            manifest: published.root_manifest,
            transport: published.root_transport,
        },
    );
    let mut objects = MemoryObjectStore::default();
    fixture
        .engine
        .set_materialization(published.content, MaterializationState::Pinned)
        .unwrap();
    let mut directed = DirectedBulk {
        inner: bulk,
        dead_storage: BTreeSet::from([published.object_storage]),
        dead_roots: BTreeSet::from([published.object_transport]),
        missing_storage: BTreeSet::new(),
        missing_roots: BTreeSet::new(),
    };
    // Converge the fetchable prefix first so the sequence is settled
    // before the terminal evaluation runs.
    for _ in 0..2 {
        fixture
            .engine
            .execute_plan(&mut directed, &mut objects)
            .unwrap();
        fixture.engine.evaluate_terminal().unwrap();
    }
    let sequence = fixture.engine.current();
    drive_to_terminal(
        &mut fixture,
        &mut directed,
        &mut objects,
        &published.content,
        32,
    );
    assert_eq!(
        fixture.engine.current(),
        sequence,
        "terminal completion commits nothing durable"
    );
}

#[test]
fn terminal_state_does_not_survive_reopen() {
    // Hard acceptance criterion 3: Unavailable(n) never survives an
    // Engine::open — a reopened engine has no terminal state at all.
    let mut fixture = fixture();
    let device = fixture.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let epoch_secret = EpochSecret::from_bytes([0x09; 32]);
    let mut bulk = MemoryBulkSource::default();
    let body = intake_body(&builder, &admission);
    let published = publish_into(
        &mut bulk,
        &epoch_secret,
        admission.epoch,
        &epoch_secret,
        admission.epoch,
        body.snapshot_id(),
        b"restart probe",
    );
    let _body = intake_published(
        &mut fixture,
        &mut bulk,
        &builder,
        &genesis,
        &admission,
        vec![EpochSecret::from_bytes([0x08; 32]), epoch_secret.clone()],
        AnnouncedRoots {
            manifest: published.root_manifest,
            transport: published.root_transport,
        },
    );
    let mut objects = MemoryObjectStore::default();
    fixture
        .engine
        .set_materialization(published.content, MaterializationState::Pinned)
        .unwrap();
    let mut directed = DirectedBulk {
        inner: bulk,
        dead_storage: BTreeSet::from([published.object_storage]),
        dead_roots: BTreeSet::from([published.object_transport]),
        missing_storage: BTreeSet::new(),
        missing_roots: BTreeSet::new(),
    };
    drive_to_terminal(
        &mut fixture,
        &mut directed,
        &mut objects,
        &published.content,
        32,
    );
    assert!(fixture.engine.terminal_status(&published.content).is_some());
    // Abrupt death, not an orderly second process: release the lock
    // and reopen the same directory with the same keys.
    fixture.engine.release_store_lock();
    let (identity_sk, _) = identity(0x02);
    let encryption_sk = DeviceEncryptionSecret::from_bytes([0xE0; 32]).unwrap();
    let mut reopened = Engine::open(
        fixture.dir.path.clone(),
        member_drive(),
        device,
        "test-pass",
        identity_sk,
        encryption_sk,
    )
    .unwrap();
    for epoch in [1, 2] {
        reopened.add_epoch_key(epoch, Zeroizing::new(control_key(epoch)));
    }
    assert_eq!(
        reopened.terminal_status(&published.content),
        None,
        "terminality is memory-only: reopen forgets it"
    );
    assert_eq!(
        reopened.generation(&published.content),
        None,
        "generations restart from current durable knowledge"
    );
    assert!(
        reopened.terminal_snapshot().is_empty(),
        "no terminal projection survives a restart"
    );
}

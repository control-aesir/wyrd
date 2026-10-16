use super::tests_harness::{drain_side, execute_side, local_tree, scenario, secret};
use super::*;

use crate::authorization::test_util::sign_snapshot;
use crate::durable::AuthorizedCapability;
use crate::keys::capability::Capability;
use crate::seal::{EncryptedObject, SEAL_VERSION};
use wyrd_format::{ContentId, Entry, MemoryObjectStore, ObjectKind, Snapshot, TransitionId, Tree};

use crate::durable::AuthorizeSnapshot;
use crate::durable::AuthorizedSnapshot;
use crate::durable::Fact;
use crate::keys::EpochSecret;
use crate::membership::test_util::{drive as member_drive, Builder};
use crate::runtime::test_util::{admit_engine, deliver, drain, fixture, queue, transition_message};
use crate::transport::mailbox::{Mailbox, MemoryMailbox};

// --- local snapshot authoring -------------------------------------

#[test]
fn member_authors_a_snapshot_that_becomes_the_live_head() {
    let (mut pair, _, _) = scenario();
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
    // Fetch the published bodies so a live head exists to parent onto.
    let plan = execute_side(&mut pair.bulk, &mut pair.a);
    assert_eq!(plan.snapshot_bodies, 2, "A holds both published bodies");

    let mut objects = MemoryObjectStore::default();
    let tree = local_tree(&mut objects);
    let authored = pair.a.engine.author_snapshot(&objects, tree).unwrap();
    assert_eq!(authored.snapshot().author, pair.a.device);
    assert_eq!(authored.snapshot().epoch, 3, "bound to the canonical tip");
    assert_eq!(authored.snapshot().parents.len(), 1, "onto the live head");

    let heads = pair.a.engine.live_heads().unwrap();
    assert_eq!(
        heads
            .iter()
            .map(|h| h.snapshot().snapshot_id())
            .collect::<Vec<_>>(),
        vec![authored.snapshot().snapshot_id()],
        "the authored head supersedes the one it extends"
    );
}

#[test]
fn successive_authored_snapshots_get_increasing_timestamps() {
    let (mut pair, _, _) = scenario();
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);

    let mut objects = MemoryObjectStore::default();
    let tree = local_tree(&mut objects);
    let first = pair.a.engine.author_snapshot(&objects, tree).unwrap();
    let second = pair.a.engine.author_snapshot(&objects, tree).unwrap();
    assert!(
        second.snapshot().timestamp > first.snapshot().timestamp,
        "local authoring is monotonic even within one millisecond"
    );
}

// --- single-rebuild write sessions -------------------------------

/// The write session carries one rebuild from base selection to
/// authoring: a headless session names no base, and the session after
/// the first authoring names exactly the authored head.
#[test]
fn write_session_chains_single_head_bases_without_a_second_rebuild() {
    let (mut pair, _, _) = scenario();
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);

    let mut objects = MemoryObjectStore::default();
    let tree = local_tree(&mut objects);

    let pending = pair.a.engine.begin_write().unwrap();
    assert_eq!(pending.head_count(), 0, "the drive starts headless");
    assert_eq!(pending.base_tree(), None, "nothing to build on yet");
    let first = pair
        .a
        .engine
        .author_pending_write(&objects, tree, pending)
        .unwrap();
    assert!(
        first.snapshot().parents.is_empty(),
        "a headless session authors a root"
    );

    let pending = pair.a.engine.begin_write().unwrap();
    assert_eq!(
        pending.head_count(),
        1,
        "one live head after the first write"
    );
    assert_eq!(
        pending.base_tree(),
        Some(tree),
        "the session names the head's tree as the base"
    );
    let second = pair
        .a
        .engine
        .author_pending_write(&objects, tree, pending)
        .unwrap();
    assert_eq!(
        second.snapshot().parents,
        vec![first.snapshot().snapshot_id()],
        "the session authors onto the head it captured"
    );
    assert_eq!(
        pair.a
            .engine
            .live_heads()
            .unwrap()
            .iter()
            .map(|head| head.snapshot().snapshot_id())
            .collect::<Vec<_>>(),
        vec![second.snapshot().snapshot_id()],
        "the authored head supersedes the one it extends"
    );
}

/// Two parentless snapshots are the durable shape of two devices
/// authoring concurrently. A session over them names no base, and
/// authoring fails closed instead of extending one side.
#[test]
fn write_session_onto_a_conflicted_drive_fails_closed_at_authoring() {
    let (mut pair, _, _) = scenario();
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);

    let mut objects = MemoryObjectStore::default();
    let tree = local_tree(&mut objects);
    pair.a.engine.author_snapshot(&objects, tree).unwrap();
    // The explicit-parents path stands in for the rival device's
    // announcement: same tree, no parents, committed beside the first.
    crate::runtime::author::author_with_parents(&mut pair.a.engine, &objects, tree, Vec::new())
        .unwrap();

    let pending = pair.a.engine.begin_write().unwrap();
    assert_eq!(pending.head_count(), 2, "two rival heads");
    assert_eq!(
        pending.base_tree(),
        None,
        "a conflicted drive names no base"
    );
    let error = pair
        .a
        .engine
        .author_pending_write(&objects, tree, pending)
        .unwrap_err();
    assert!(
        matches!(error, EngineError::WriteConflicted { heads: 2 }),
        "authoring onto a conflict fails closed, got {error:?}"
    );
    assert_eq!(
        pair.a.engine.live_heads().unwrap().len(),
        2,
        "the refused authoring commits nothing"
    );
}

/// Decision 26's correspondence, end to end: every mapping the local
/// write path authors names a sealed envelope this device holds, the
/// AEAD tag verifies over the bound AAD, the plaintext hashes back to
/// the ContentId, and the mapping's transport root is exactly the raw
/// BLAKE3 of the envelope bytes it names. Fresh nonces make the bytes
/// unreproducible across seals, so this is per-representation, not
/// per-seal.
#[test]
fn authored_manifests_name_envelopes_the_device_actually_seals() {
    let (mut pair, _, _) = scenario();
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);

    let mut objects = MemoryObjectStore::default();
    let root_chunk = objects.insert(ObjectKind::Chunk, b"root payload").unwrap();
    let nested_chunk = objects
        .insert(ObjectKind::Chunk, b"nested payload")
        .unwrap();
    let leaf = Tree::from_entries(vec![
        Entry::file("leaf.txt", 14, false, vec![nested_chunk]).unwrap()
    ])
    .unwrap()
    .insert_into(&mut objects)
    .unwrap();
    let root = Tree::from_entries(vec![
        Entry::file("file.txt", 12, false, vec![root_chunk]).unwrap(),
        Entry::dir("nested", leaf).unwrap(),
    ])
    .unwrap()
    .insert_into(&mut objects)
    .unwrap();

    let authored = pair.a.engine.author_snapshot(&objects, root).unwrap();
    let snapshot_id = authored.snapshot().snapshot_id();
    let epoch = authored.snapshot().epoch;
    assert_eq!(epoch, 3, "bound to the canonical tip");

    let state = pair.a.engine.runtime_state().unwrap();
    let root_record = state
        .root_manifest_record(&snapshot_id)
        .expect("the authored root manifest records with the head");
    assert_eq!(root_record.manifest.snapshot(), snapshot_id);
    // Every manifest self-maps its tree node plus its content entries.
    assert_eq!(
        root_record.manifest.entries().len(),
        2,
        "self-mapped tree plus the root file chunk"
    );
    assert!(root_record
        .manifest
        .entries()
        .iter()
        .any(|entry| entry.kind == ObjectKind::Tree && entry.content_id == root));
    let link = &root_record.manifest.children()[0];
    assert_eq!(link.tree, leaf, "the child link names the subtree tree");
    let child = state
        .manifest_record(&link.manifest)
        .expect("the authored child manifest records before the parent");
    assert_eq!(child.manifest.snapshot(), snapshot_id);
    assert_eq!(child.manifest.entries().len(), 2);
    assert!(child
        .manifest
        .entries()
        .iter()
        .any(|entry| entry.kind == ObjectKind::Tree && entry.content_id == leaf));
    assert!(
        child.manifest.children().is_empty(),
        "leaf manifests map flat"
    );

    // Every mapping (tree and chunk alike) names a sealed envelope this
    // device holds, and the envelope opens to the local plaintext under
    // the key for its own kind, content, and version.
    let epoch_secret = secret(0x07 + epoch as u8);
    for record in [root_record, child] {
        for entry in record.manifest.entries() {
            let expected = objects.get(&entry.content_id).unwrap().unwrap();
            let envelope = pair
                .a
                .engine
                .vault()
                .sealed(&entry.transport)
                .unwrap()
                .expect("held envelope");
            let obj = EncryptedObject::decode(&envelope).unwrap();
            assert_eq!(obj.storage_id(), entry.storage_id, "vault address");
            assert_eq!(
                crate::seal::transport_root(&obj),
                entry.transport,
                "the transport root is exactly the envelope bytes"
            );
            let opened = crate::seal::verify(
                entry,
                &epoch_secret.object_key(
                    &member_drive(),
                    epoch,
                    &entry.content_id,
                    entry.kind,
                    SEAL_VERSION,
                ),
                &envelope,
            )
            .unwrap();
            assert_eq!(opened, expected);
        }
    }
}

#[test]
fn authoring_rejects_an_unavailable_noncanonical_or_misaddressed_root() {
    let (mut pair, _, _) = scenario();
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
    let before = pair.a.engine.current();

    // Absent from the store.
    let empty = MemoryObjectStore::default();
    assert!(matches!(
        pair.a
            .engine
            .author_snapshot(&empty, ContentId::from_bytes([0xAB; 32])),
        Err(EngineError::TreeUnavailable(_))
    ));

    // Address-consistent bytes that are not a canonical tree.
    let mut noncanonical = MemoryObjectStore::default();
    let bad = noncanonical
        .insert(ObjectKind::Tree, b"not a canonical tree")
        .unwrap();
    assert!(matches!(
        pair.a.engine.author_snapshot(&noncanonical, bad),
        Err(EngineError::InvalidTree(_))
    ));

    // A chunk addressed as a root does not hash under the tree kind.
    let mut chunks = MemoryObjectStore::default();
    let chunk = chunks.insert(ObjectKind::Chunk, b"a chunk").unwrap();
    assert!(matches!(
        pair.a.engine.author_snapshot(&chunks, chunk),
        Err(EngineError::TreeMismatch(_))
    ));

    assert_eq!(pair.a.engine.current(), before, "nothing committed");
}

#[test]
fn authoring_rejects_a_root_that_does_not_hash_to_its_id() {
    let (mut pair, _, _) = scenario();
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
    let before = pair.a.engine.current();

    // A canonical tree's bytes served under a different claimed id.
    let mut real = MemoryObjectStore::default();
    let tree = local_tree(&mut real);
    let bytes = real.get(&tree).unwrap().unwrap();
    let lying = LyingStore { bytes };
    assert!(matches!(
        pair.a
            .engine
            .author_snapshot(&lying, ContentId::from_bytes([0xAB; 32])),
        Err(EngineError::TreeMismatch(_))
    ));
    assert_eq!(pair.a.engine.current(), before, "nothing committed");
}

/// A store that serves the same bytes for every address, modeling a
/// faulty implementation that violates the scrub invariant.
struct LyingStore {
    bytes: Vec<u8>,
}

/// The lying store never fails: every method that could fail is
/// unreachable or infallible, so the classification is moot.
#[derive(Debug)]
struct LyingStoreError;

impl wyrd_format::StoreError for LyingStoreError {}

impl ObjectStore for LyingStore {
    type Error = LyingStoreError;

    fn insert(&mut self, _kind: ObjectKind, _data: &[u8]) -> Result<ContentId, Self::Error> {
        unreachable!("the lying store is read-only")
    }

    fn insert_verified(
        &mut self,
        _kind: ObjectKind,
        _expected: &ContentId,
        _data: &[u8],
    ) -> Result<(), Self::Error> {
        unreachable!("the lying store is read-only")
    }

    fn get(&self, _id: &ContentId) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(Some(self.bytes.clone()))
    }

    fn has(&self, _id: &ContentId) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

#[test]
fn authoring_without_canonical_membership_fails_closed() {
    let mut f = fixture();
    let mut objects = MemoryObjectStore::default();
    let tree = local_tree(&mut objects);
    assert!(matches!(
        f.engine.author_snapshot(&objects, tree),
        Err(EngineError::NoCanonicalMembership)
    ));
}

#[test]
fn authoring_requires_a_member_device() {
    let mut f = fixture();
    let (_, genesis) = Builder::genesis(10);
    let envelope = deliver(&f, 1, &transition_message(&genesis));
    queue(&mut f, vec![envelope]);
    assert_eq!(drain(&mut f).accepted, 1);
    let mut objects = MemoryObjectStore::default();
    let tree = local_tree(&mut objects);
    assert!(matches!(
        f.engine.author_snapshot(&objects, tree),
        Err(EngineError::NotAMember)
    ));
}

#[test]
fn announcing_delivers_the_snapshot_to_peers() {
    let (mut pair, _, _) = scenario();
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
    assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 6);

    let mut objects = MemoryObjectStore::default();
    let tree = local_tree(&mut objects);
    let authored = pair.a.engine.author_snapshot(&objects, tree).unwrap();
    let sent = {
        let mut mailbox = MemoryMailbox {
            relay: &mut pair.relay,
            owner: pair.a.device,
        };
        pair.a
            .engine
            .announce_snapshot(&authored, &mut mailbox, None)
            .unwrap()
    };
    assert_eq!(sent, 2, "owner and B; the author is skipped");

    // B accepts the announcement; the body is fetched later.
    assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 1);
    let state = pair.b.engine.runtime_state().unwrap();
    assert!(state
        .announcement(&authored.snapshot().snapshot_id())
        .is_some());
}

#[test]
fn announcing_to_a_single_member_sends_nothing() {
    // Genesis admits only the fixture device, so it is the sole member.
    let mut f = fixture();
    let (_, genesis) = Builder::genesis(0x02);
    let envelope = deliver(&f, 1, &transition_message(&genesis));
    queue(&mut f, vec![envelope]);
    assert_eq!(drain(&mut f).accepted, 1);

    // The authoring device holds its epoch material through a
    // self-capability fact (the production custody path mints it at
    // bootstrap): the keyring rebuilt from facts then covers epoch 1.
    let state = f.engine.log.state_of(&genesis.transition_id()).unwrap();
    let registered = state.encryption_key_of(&f.recipient).copied().unwrap();
    let cap = Capability::new(
        member_drive(),
        f.recipient,
        registered,
        genesis.transition_id(),
        1,
        vec![EpochSecret::from_bytes([0x07; 32])],
    )
    .unwrap();
    let authorized = AuthorizedCapability::authorize(
        cap,
        member_drive(),
        &f.engine.log,
        &genesis.transition_id(),
    )
    .unwrap();
    f.engine
        .commit_facts(&[Fact::Capability(authorized)])
        .unwrap();

    let mut objects = MemoryObjectStore::default();
    let tree = local_tree(&mut objects);
    let authored = f.engine.author_snapshot(&objects, tree).unwrap();
    let mut mailbox = MemoryMailbox {
        relay: &mut f.relay,
        owner: f.recipient,
    };
    assert_eq!(
        f.engine
            .announce_snapshot(&authored, &mut mailbox, None)
            .unwrap(),
        0
    );
}

#[test]
fn announcing_without_the_epoch_key_fails_closed() {
    let (mut pair, _, _) = scenario();
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);

    // A snapshot at an epoch the engine holds no control key for.
    let mut body = Snapshot::new(
        Vec::new(),
        ContentId::from_bytes([0xAB; 32]),
        pair.a.device,
        TransitionId::from_bytes([0x33; 32]),
        9,
        0,
        1,
    )
    .unwrap();
    sign_snapshot(&mut body, &pair.a.identity_sk.secret_key(), &member_drive());
    let authorized = AuthorizedSnapshot::authorize(body, &member_drive()).unwrap();

    let mut mailbox = MemoryMailbox {
        relay: &mut pair.relay,
        owner: pair.a.device,
    };
    assert!(matches!(
        pair.a
            .engine
            .announce_snapshot(&authorized, &mut mailbox, None),
        Err(EngineError::MissingEpochKey(9))
    ));
}

#[test]
fn announcing_a_foreign_snapshot_fails_closed() {
    let mut f = fixture();
    let device = f.recipient;
    let (mut builder, genesis) = Builder::genesis(10);
    let admission = admit_engine(&mut builder, device);
    let mail = vec![
        deliver(&f, 1, &transition_message(&genesis)),
        deliver(&f, 1, &transition_message(&admission)),
    ];
    queue(&mut f, mail);
    assert_eq!(drain(&mut f).accepted, 2);

    // A valid snapshot authored by another member: this engine's
    // identity cannot announce it, and nothing reaches the mailbox.
    let mut body = Snapshot::new(
        Vec::new(),
        ContentId::from_bytes([0xC1; 32]),
        *builder.owners.iter().next().expect("tracked owner"),
        admission.transition_id(),
        admission.epoch,
        0,
        1000,
    )
    .unwrap();
    crate::authorization::test_util::sign_snapshot(&mut body, &builder.sk, &member_drive());
    let authorized = AuthorizedSnapshot::authorize(body, &member_drive()).unwrap();

    let mut mailbox = MemoryMailbox {
        relay: &mut f.relay,
        owner: f.recipient,
    };
    assert!(matches!(
        f.engine.announce_snapshot(&authorized, &mut mailbox, None),
        Err(EngineError::NotAnnounceAuthor(_))
    ));
    assert!(
        mailbox.recv().unwrap().is_none(),
        "a refused announcement never sends"
    );
}

/// Recovery grafts content under the current epoch, but only the
/// current canonical owner may author it: a plain member holds the
/// tree and the epoch material yet is refused before anything
/// commits (`docs/epochs.md`, recovery authorization).
#[test]
fn recovery_authoring_requires_the_current_owner() {
    let (mut pair, _, _) = scenario();
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
    let mut objects = MemoryObjectStore::default();
    let tree = local_tree(&mut objects);
    assert!(matches!(
        pair.a.engine.author_recovery_snapshot(&objects, tree),
        Err(EngineError::RecoveryNotOwner)
    ));
}

/// Cold-join authorship names every missing chunk in one evaluation:
/// a member whose trees are local but whose file content never
/// arrived defers on the whole missing set, not one chunk per pass.
/// One-chunk-per-pass pacing is what outwaits `max_mutation_wait` on
/// a fresh join (the closure drains single objects per pass while
/// the walk re-discovers the next miss each time), so the walk
/// collects the set the fetch plan drains together.
#[test]
fn cold_authoring_collects_every_missing_chunk() {
    use std::collections::BTreeSet;

    let (mut pair, _, _) = scenario();
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
    // Trees local, chunk bytes never stored: the cold-join shape.
    // Chunk ids derive from bytes the store never sees.
    let cold = |byte: u8| ContentId::derive(ObjectKind::Chunk, &[byte; 64]);
    let (a, b, c) = (cold(0xA1), cold(0xB1), cold(0xC1));
    let mut objects = MemoryObjectStore::default();
    let leaf = Tree::from_entries(vec![Entry::file("leaf.txt", 64, false, vec![c]).unwrap()])
        .unwrap()
        .insert_into(&mut objects)
        .unwrap();
    let root = Tree::from_entries(vec![
        Entry::file("a.txt", 64, false, vec![a]).unwrap(),
        Entry::file("b.txt", 64, false, vec![b]).unwrap(),
        Entry::dir("nested", leaf).unwrap(),
    ])
    .unwrap()
    .insert_into(&mut objects)
    .unwrap();
    let error = pair.a.engine.author_snapshot(&objects, root).unwrap_err();
    let missing = match error {
        EngineError::ChunksUnavailable(missing) => missing,
        other => panic!("cold authoring must name the missing set, got {other:?}"),
    };
    assert_eq!(missing, BTreeSet::from([a, b, c]));
    // The set is complete: landing exactly those bytes authors clean,
    // with no second miss hiding behind the first.
    for (id, byte) in [(a, 0xA1), (b, 0xB1), (c, 0xC1)] {
        objects
            .insert_verified(ObjectKind::Chunk, &id, &[byte; 64])
            .unwrap();
    }
    pair.a
        .engine
        .author_snapshot(&objects, root)
        .expect("the named set was complete");
}

// --- live-head memoization -----------------------------------------

/// Calls at one durable tip share a single replay: the first call
/// classifies, every later call re-serves the memoized heads. Five
/// calls, one replay — the live loop asks per pass while commits
/// land rarely.
#[test]
fn live_heads_memoizes_across_calls_at_one_tip() {
    let (mut pair, _, _) = scenario();
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
    let mut objects = MemoryObjectStore::default();
    let tree = local_tree(&mut objects);
    let first = pair.a.engine.author_snapshot(&objects, tree).unwrap();

    let replays_before = pair.a.engine.store.rebuild_count();
    let heads: Vec<Vec<AuthorizedSnapshot>> = (0..5)
        .map(|_| pair.a.engine.live_heads().unwrap())
        .collect();
    assert_eq!(
        pair.a.engine.store.rebuild_count() - replays_before,
        1,
        "one replay serves every call at a tip"
    );
    for heads in &heads {
        assert_eq!(
            heads
                .iter()
                .map(|head| head.snapshot().snapshot_id())
                .collect::<Vec<_>>(),
            vec![first.snapshot().snapshot_id()],
            "the memo serves the same verified heads"
        );
    }
}

/// A commit advances the durable tip past the memo: the next call
/// reclassifies instead of serving the stale projection. Without
/// tip-keying this test pins the old head forever.
#[test]
fn live_heads_sees_heads_authored_after_the_memo() {
    let (mut pair, _, _) = scenario();
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
    let mut objects = MemoryObjectStore::default();
    let tree = local_tree(&mut objects);
    let first = pair.a.engine.author_snapshot(&objects, tree).unwrap();
    assert_eq!(pair.a.engine.live_heads().unwrap().len(), 1);

    let second = pair.a.engine.author_snapshot(&objects, tree).unwrap();
    assert_ne!(
        second.snapshot().snapshot_id(),
        first.snapshot().snapshot_id()
    );
    let heads = pair.a.engine.live_heads().unwrap();
    assert_eq!(
        heads
            .iter()
            .map(|head| head.snapshot().snapshot_id())
            .collect::<Vec<_>>(),
        vec![second.snapshot().snapshot_id()],
        "the tip advance retired the memoized heads"
    );
}

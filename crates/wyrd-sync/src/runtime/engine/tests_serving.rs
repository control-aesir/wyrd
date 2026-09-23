use super::tests_harness::{drain_side, restart, scenario, secret};
use super::*;

use crate::seal::EncryptedObject;
use wyrd_format::{Entry, MemoryObjectStore, ObjectKind, Tree};

use crate::membership::test_util::drive as member_drive;
use crate::runtime::test_util::{MemoryMailbox, TestDir};

#[test]
fn a_peer_materializes_authored_content_from_the_vault_alone() {
    // The full loop: A authors (real manifests, vault-backed), B
    // accepts the announcement, and B's plan converges entirely over
    // A's serving view — the durable vault plus A's durable runtime
    // state. Nothing else is shared.
    let (mut pair, _, _) = scenario();
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
    assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 6);

    let mut objects = MemoryObjectStore::default();
    let chunk = objects
        .insert(ObjectKind::Chunk, b"vault served payload")
        .unwrap();
    let tree = Tree::from_entries(vec![
        Entry::file("file.txt", 20, false, vec![chunk]).unwrap()
    ])
    .unwrap()
    .insert_into(&mut objects)
    .unwrap();
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
    assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 1);

    let serving = crate::serving::VaultSource::from_state(
        &pair.a.engine.runtime_state().unwrap(),
        pair.a.engine.vault(),
    )
    .unwrap();
    let mut serving = serving;
    let mut peer_objects = MemoryObjectStore::default();
    pair.b
        .engine
        .set_materialization(chunk, MaterializationState::Cached)
        .unwrap();
    let report = pair
        .b
        .engine
        .execute_plan(&mut serving, &mut peer_objects)
        .unwrap();
    // The authored snapshot's items all land; the scenario's unrelated
    // published snapshots stay unfulfilled against this vault (they
    // are not this test's subject).
    assert_eq!(report.snapshot_bodies, 1, "the body rides the signed root");
    assert_eq!(report.manifests, 1, "a flat tree maps one root manifest");
    assert_eq!(
        report.objects, 2,
        "the structural tree plus the requested chunk"
    );
    assert_eq!(
        peer_objects.get(&chunk).unwrap().as_deref(),
        Some(b"vault served payload".as_slice())
    );
}

/// Repeated references are the norm, never an error: the same chunk
/// twice in one file and across sibling files, and identical subtrees
/// reached through two names, all map to exactly one canonical entry
/// or link per logical identity. Before deduplication, an ordinary
/// file with repeated content produced a manifest the canonical
/// decoder refuses (adjacent equal entries are ambiguity, not
/// canonical order) — this test pins the contract at the authoring
/// boundary.
#[test]
fn authored_manifests_deduplicate_repeated_references() {
    let (mut pair, _, _) = scenario();
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);

    let mut objects = MemoryObjectStore::default();
    let chunk = objects
        .insert(ObjectKind::Chunk, b"shared payload")
        .unwrap();
    let leaf = Tree::from_entries(vec![
        Entry::file("leaf.txt", 14, false, vec![chunk]).unwrap()
    ])
    .unwrap()
    .insert_into(&mut objects)
    .unwrap();
    let root = Tree::from_entries(vec![
        // The same chunk twice in one file, and in a sibling file.
        Entry::file("twice.txt", 28, false, vec![chunk, chunk]).unwrap(),
        Entry::dir("branch", leaf).unwrap(),
        // A second, byte-identical subtree: same ContentId, one link.
        Entry::dir("mirror", leaf).unwrap(),
        Entry::file("once.txt", 14, false, vec![chunk]).unwrap(),
    ])
    .unwrap()
    .insert_into(&mut objects)
    .unwrap();

    let authored = pair.a.engine.author_snapshot(&objects, root).unwrap();
    let snapshot_id = authored.snapshot().snapshot_id();
    let state = pair.a.engine.runtime_state().unwrap();
    let root_record = state
        .root_manifest_record(&snapshot_id)
        .expect("the authored root manifest records");
    assert_eq!(
        root_record.manifest.entries().len(),
        2,
        "self-mapped tree plus one canonical mapping per logical chunk"
    );
    assert_eq!(
        root_record.manifest.children().len(),
        1,
        "one canonical link per logical subtree"
    );
    assert_eq!(root_record.manifest.children()[0].tree, leaf);

    // The child manifest maps the same chunk to the same
    // representation the root maps: the session cache reused one
    // seal, so both mappings name servable bytes identically.
    let child = state
        .manifest_record(&root_record.manifest.children()[0].manifest)
        .expect("the child manifest records");
    assert_eq!(child.manifest.entries().len(), 2);
    let chunk_transport = |record: &super::super::ManifestRecord| {
        record
            .manifest
            .entries()
            .iter()
            .find(|entry| entry.kind == ObjectKind::Chunk && entry.content_id == chunk)
            .expect("maps the shared chunk")
            .transport
    };
    assert_eq!(
        chunk_transport(child),
        chunk_transport(root_record),
        "one seal serves every reference to the chunk"
    );

    // And the whole hierarchy is canonically decodable under the
    // snapshot's manifest key — the invariant the duplicate entries
    // would have broken.
    let epoch_secret = secret(0x07 + authored.snapshot().epoch as u8);
    let key = epoch_secret.manifest_key(&member_drive(), authored.snapshot().epoch, &snapshot_id);
    let envelope = pair
        .a
        .engine
        .vault()
        .sealed(&root_record.transport)
        .unwrap()
        .expect("the root manifest envelope is in the vault");
    assert_eq!(
        crate::seal::open_manifest(
            &key,
            &root_record.manifest_id,
            &EncryptedObject::decode(&envelope).unwrap()
        )
        .unwrap(),
        root_record.manifest,
        "the authored manifest is canonically decodable"
    );
}

/// Stack-safety regression for manifest authoring: the walk is an
/// explicit heap DFS, so a chain far deeper than the call stack could
/// hold still authors to completion. The authoring runs on a thread
/// with a deliberately tiny stack (256 KiB): the per-level recursion
/// this replaced overflowed such a stack far shallower, while the
/// heap walk fits with room to spare. Depth stays modest on purpose:
/// every level costs two fsync-backed vault imports, so depth here
/// buys proof against the old recursion, not broader coverage.
///
/// The root also mirrors a mid-chain subtree, exercising the
/// completed-subtree fast path at depth, and the test walks the full
/// link chain from root to leaf, so a malformed link fails here (on
/// top of the closure self-check authoring already runs before
/// committing).
#[test]
fn deep_tree_authoring_is_stack_safe() {
    let (mut pair, _, _) = scenario();
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);

    const DEPTH: usize = 300;
    const STACK: usize = 256 << 10;
    let mut objects = MemoryObjectStore::default();
    let mut chain = vec![Tree::empty().insert_into(&mut objects).unwrap()];
    for _ in 1..DEPTH {
        let top = *chain.last().expect("chain nonempty");
        chain.push(
            Tree::from_entries(vec![Entry::dir("d", top).unwrap()])
                .unwrap()
                .insert_into(&mut objects)
                .unwrap(),
        );
    }
    let mid = chain[DEPTH / 2];
    let top = *chain.last().expect("chain nonempty");
    let root = Tree::from_entries(vec![
        Entry::dir("d", top).unwrap(),
        Entry::dir("mirror", mid).unwrap(),
    ])
    .unwrap()
    .insert_into(&mut objects)
    .unwrap();

    let mut device = pair.a;
    std::thread::Builder::new()
        .name("deep-authoring".into())
        .stack_size(STACK)
        .spawn(move || {
            let authored = device.engine.author_snapshot(&objects, root).unwrap();
            let snapshot_id = authored.snapshot().snapshot_id();
            let state = device.engine.runtime_state().unwrap();
            let root_record = state
                .root_manifest_record(&snapshot_id)
                .expect("the deep root manifest records");
            assert_eq!(
                root_record.manifest.children().len(),
                2,
                "the chain link plus the mid-chain mirror"
            );
            assert_eq!(
                state
                    .manifest_records()
                    .filter(|record| record.manifest.snapshot() == snapshot_id)
                    .count(),
                DEPTH + 1,
                "one manifest per tree node in the chain"
            );
            // Walk the chain link by link to the leaf: every level
            // names exactly its child subtree, and the mirror reuses
            // the mid-chain manifest assembled on the way down.
            let mut manifest_ids = Vec::with_capacity(DEPTH);
            let mut current = root_record;
            for i in (0..DEPTH).rev() {
                let link = current
                    .manifest
                    .children()
                    .iter()
                    .find(|link| link.tree == chain[i])
                    .expect("chain link present");
                let child = state
                    .manifest_record(&link.manifest)
                    .expect("child manifest records");
                let expected_kids = if i == 0 { 0 } else { 1 };
                assert_eq!(
                    child.manifest.children().len(),
                    expected_kids,
                    "chain manifest {i} links exactly its child"
                );
                manifest_ids.push(link.manifest);
                current = child;
            }
            let mirror = root_record
                .manifest
                .children()
                .iter()
                .find(|link| link.tree == mid)
                .expect("mirror link present");
            assert_eq!(
                mirror.manifest,
                manifest_ids[DEPTH - 1 - DEPTH / 2],
                "the mirror reuses the completed record, not a re-seal"
            );
        })
        .expect("spawn authoring thread")
        .join()
        .expect("authoring completes on a 256 KiB stack");
}

/// Critical regression for the serving contract: a fetched
/// representation lands in the fetcher's durable vault, so a restart
/// plus re-authoring can reuse the recorded mapping and serve it.
/// Before this held, a device could record a mapping it could never
/// serve.
#[test]
fn fetched_representations_serve_after_restart_and_reauthoring() {
    let (mut pair, controls, _) = scenario();
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
    assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 6);

    // A authors and announces.
    let mut objects = MemoryObjectStore::default();
    let chunk = objects
        .insert(ObjectKind::Chunk, b"integration payload")
        .unwrap();
    let tree = Tree::from_entries(vec![
        Entry::file("file.txt", 19, false, vec![chunk]).unwrap()
    ])
    .unwrap()
    .insert_into(&mut objects)
    .unwrap();
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
    assert_eq!(sent, 2);
    assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 1);

    // B fetches over A's vault: the ciphertext is verified, imported
    // into B's own vault, and the plaintext materializes.
    let serving_a = crate::serving::VaultSource::from_state(
        &pair.a.engine.runtime_state().unwrap(),
        pair.a.engine.vault(),
    )
    .unwrap();
    let mut serving_a = serving_a;
    let mut peer_objects = MemoryObjectStore::default();
    pair.b
        .engine
        .set_materialization(chunk, MaterializationState::Cached)
        .unwrap();
    let report = pair
        .b
        .engine
        .execute_plan(&mut serving_a, &mut peer_objects)
        .unwrap();
    assert_eq!(
        report.objects, 2,
        "the structural tree plus the requested chunk"
    );

    // B restarts: durable facts and vault bytes both survive.
    restart(&mut pair.b, &controls);

    // B re-authors a snapshot over the fetched content: the
    // recorded mapping resolves (capability held, vault copy held)
    // and is reused, not re-sealed.
    let tree_b = Tree::from_entries(vec![
        Entry::file("mirror.txt", 19, false, vec![chunk]).unwrap()
    ])
    .unwrap()
    .insert_into(&mut peer_objects)
    .unwrap();
    let reauthored = pair
        .b
        .engine
        .author_snapshot(&peer_objects, tree_b)
        .unwrap();
    let state_b = pair.b.engine.runtime_state().unwrap();
    let record_b = state_b
        .root_manifest_record(&reauthored.snapshot().snapshot_id())
        .expect("B's re-authored root manifest records");
    let state_a = pair.a.engine.runtime_state().unwrap();
    let a_record = state_a
        .root_manifest_record(&authored.snapshot().snapshot_id())
        .expect("A's root manifest records");
    let chunk_entry = |record: &super::super::ManifestRecord| {
        record
            .manifest
            .entries()
            .iter()
            .find(|entry| entry.kind == ObjectKind::Chunk && entry.content_id == chunk)
            .cloned()
            .expect("maps the shared chunk")
    };
    assert_eq!(
        chunk_entry(record_b).transport,
        chunk_entry(a_record).transport,
        "B's manifest advertises the fetched representation, not a re-seal"
    );

    // And B serves what it advertises: the reused mapping's bytes
    // live in B's durable vault.
    let entry = chunk_entry(record_b);
    let serving_b = crate::serving::VaultSource::from_state(
        &pair.b.engine.runtime_state().unwrap(),
        pair.b.engine.vault(),
    )
    .unwrap();
    let mut serving_b = serving_b;
    let bytes = serving_b
        .fetch_sealed(&entry.storage_id, usize::MAX)
        .unwrap()
        .expect("the reused mapping's representation serves from B's vault");
    assert_eq!(
        EncryptedObject::decode(&bytes).unwrap().storage_id(),
        entry.storage_id
    );
}

/// Head published, object servable after the AUTHOR restarts: A
/// authors and announces, restarts, and B fetches the announced
/// head's objects from the restarted author's vault and materializes
/// the exact plaintext. Residency is written before the record that
/// names it, so the restart cannot strand a published head without
/// its bytes.
#[test]
fn announced_head_serves_from_the_author_vault_after_author_restart() {
    let (mut pair, controls, _) = scenario();
    assert_eq!(drain_side(&mut pair.relay, &mut pair.a).accepted, 7);
    assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 6);

    let mut objects = MemoryObjectStore::default();
    let chunk = objects
        .insert(ObjectKind::Chunk, b"restart served payload")
        .unwrap();
    let tree = Tree::from_entries(vec![
        Entry::file("file.txt", 22, false, vec![chunk]).unwrap()
    ])
    .unwrap()
    .insert_into(&mut objects)
    .unwrap();
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
    assert_eq!(sent, 2);
    assert_eq!(drain_side(&mut pair.relay, &mut pair.b).accepted, 1);

    // The author restarts: durable facts and vault bytes both survive.
    restart(&mut pair.a, &controls);

    // B fetches over the restarted author's vault and materializes
    // the exact plaintext.
    let serving_a = crate::serving::VaultSource::from_state(
        &pair.a.engine.runtime_state().unwrap(),
        pair.a.engine.vault(),
    )
    .unwrap();
    let mut serving_a = serving_a;
    let mut peer_objects = MemoryObjectStore::default();
    pair.b
        .engine
        .set_materialization(chunk, MaterializationState::Cached)
        .unwrap();
    let report = pair
        .b
        .engine
        .execute_plan(&mut serving_a, &mut peer_objects)
        .unwrap();
    assert_eq!(
        report.objects, 2,
        "tree plus chunk land from the restarted vault"
    );
    assert_eq!(
        peer_objects.get(&chunk).unwrap().as_deref(),
        Some(&b"restart served payload"[..]),
        "materialized plaintext is exact"
    );
}

/// Authoring writes vault bytes first and commits facts second, so a
/// torn commit leaves orphaned vault envelopes but never a durable
/// record naming a missing representation. Restart is headless, and
/// re-authoring succeeds.
#[test]
fn a_torn_authoring_commit_leaves_no_half_advertised_state() {
    let dir = TestDir::new("crash-authoring");
    let identity = DeviceIdentitySecret::generate().unwrap();
    let mut engine = Engine::create(dir.path.clone(), "test-pass", identity.clone()).unwrap();
    let mut objects = MemoryObjectStore::default();
    let chunk = objects.insert(ObjectKind::Chunk, b"crash probe").unwrap();
    let tree = Tree::from_entries(vec![
        Entry::file("file.txt", 11, false, vec![chunk]).unwrap()
    ])
    .unwrap()
    .insert_into(&mut objects)
    .unwrap();

    // The commit tears after the commit file lands but before
    // CURRENT names it: the write returns Ok, exactly like power loss.
    engine.crash_after(crate::durable::CrashStage::AfterRenameCommit);
    let _ = engine
        .author_snapshot(&objects, tree)
        .expect("the torn write still returns");
    drop(engine);

    let mut engine = Engine::open_keystore(dir.path.clone(), "test-pass", identity).unwrap();
    assert!(
        engine.live_heads().unwrap().is_empty(),
        "a torn commit leaves no snapshot to advertise"
    );
    assert!(
        engine
            .runtime_state()
            .unwrap()
            .manifest_records()
            .next()
            .is_none(),
        "no durable manifest records exist, so none name missing representations"
    );

    // Re-authoring after the crash commits cleanly; the torn
    // attempt's orphaned vault envelopes stay unreferenced and
    // harmless (append-only, no GC in v0).
    let authored_again = engine.author_snapshot(&objects, tree).unwrap();
    let state = engine.runtime_state().unwrap();
    let record = state
        .root_manifest_record(&authored_again.snapshot().snapshot_id())
        .expect("the re-authored snapshot records");
    let source =
        crate::serving::VaultSource::from_state(&engine.runtime_state().unwrap(), engine.vault())
            .unwrap();
    let mut source = source;
    assert!(
        source
            .fetch_root_manifest(&authored_again.snapshot().snapshot_id(), usize::MAX)
            .unwrap()
            .is_some(),
        "the re-authored snapshot serves after the crash recovery"
    );
    for entry in record.manifest.entries() {
        assert!(
            source
                .fetch_sealed(&entry.storage_id, usize::MAX)
                .unwrap()
                .is_some(),
            "every recorded mapping is backed by the vault"
        );
    }
}

//! Upgrade-contract invariants (`docs/upgrade-contract.md`): one named
//! test per invariant direction, composed end to end over the public
//! APIs — the same single-shape rule as the rest of the suite (all
//! contracts are `#[cfg(test)]` mods in `src/`, no `tests/` integration
//! targets). The one entry outside that scope is contract 42,
//! `content_identity_is_payload_based_across_framing`, which pins
//! `object-model.md` decision 30 end to end and lives here because the
//! memory/disk store seam is its acceptance boundary.
//!
//! Fixture convention, decided on the contract issue: fixtures are
//! data-only under `tests/fixtures/stores/<release>/`, read at runtime
//! off `CARGO_MANIFEST_DIR`. The suite keeps its one shape; the
//! directory tree is data, not a second test target. The first
//! checked-in fixture is `dev/`: a harness smoke fixture produced by
//! the ignored `regenerate_dev_fixture` below, never cross-version
//! evidence. Per-release fixtures land under their tag; the
//! `v0.2.0-alpha` release cut the first one, and the generator for
//! the next is `regenerate_release_fixture` below.
//!
//! Reachability note (contract-issue point 4): `COMMIT_VERSION` is
//! `pub(super)` inside wyrd-sync's private codec, so the suite does
//! not name it. The byte-0 tests below assert the wire position of
//! the commit envelope version through the public `DurableStore`
//! API instead, which is what the invariant is actually about.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use wyrd_format::envelope::{Envelope, EnvelopeError, HEADER_LEN, MAGIC};
use wyrd_format::{
    ContentId, DeviceId, FsObjectStore, FsStoreError, MemoryObjectStore, MemoryStoreError,
    ObjectKind, ObjectStore,
};
use wyrd_sync::control::{self, ControlError, ControlMessageId, Message, TransitionPayload};
use wyrd_sync::durable::{DurableStore, Fact, ReconciliationView};
use wyrd_sync::keys::EpochSecret;
use wyrd_sync::runtime::Engine;

use crate::support::{device, drive, scratch_dir, Rig};

/// Checked-in fixtures live here; `dev` is the harness smoke fixture.
fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("stores")
}

/// Previous-release fixture by tag directory name.
fn fixture_release(release: &str) -> PathBuf {
    fixture_root().join(release)
}

/// The checked-in `dev` fixture's directory. Regeneration targets
/// exactly this: pointing it at the fixture root destroys the
/// per-release siblings and scatters the new store beside them.
/// Name the helper at the call site so the target stays explicit.
fn dev_fixture_dir() -> PathBuf {
    fixture_release("dev")
}

/// Tag directory of the checked-in release fixture: the store bytes
/// `upgrade_previous_release_store_replays` replays above. Frozen at
/// release-cut time; the next release adds its own tag directory and
/// repoints this constant, keeping exactly one live baseline.
const RELEASE_FIXTURE: &str = "v0.2.0-alpha";

#[test]
fn regenerate_targets_dev_never_the_root() {
    let dst = dev_fixture_dir();
    assert_eq!(
        dst.file_name().and_then(|n| n.to_str()),
        Some("dev"),
        "regeneration lands inside dev/"
    );
    assert_ne!(dst, fixture_root(), "never the fixture root itself");
    assert_eq!(dst.parent(), Some(fixture_root().as_path()));
}

#[test]
fn fixture_root_holds_only_release_dirs() {
    // A regeneration pointed at the root would scatter store files
    // (CURRENT, DRIVE, commits/) beside the release directories. Every
    // entry here must be a per-release directory instead.
    for entry in std::fs::read_dir(fixture_root()).unwrap() {
        let entry = entry.unwrap();
        assert!(
            entry.path().is_dir(),
            "stray file at the fixture root: {:?}",
            entry.file_name()
        );
    }
}

/// Pin the frozen bytes: blake3 over sorted (path, len, bytes) of
/// every fixture file except the prose README. Regenerating the
/// fixture by hand — or a format drift in the committed records —
/// changes the digest and fails loudly here instead of silently
/// re-baselining the replay evidence the release cut.
fn fixture_digest(dir: &Path) -> String {
    let mut rels: Vec<PathBuf> = vec![];
    collect_files(dir, dir, &mut rels);
    rels.sort();
    let mut hasher = blake3::Hasher::new();
    for rel in rels {
        if rel.file_name().and_then(|n| n.to_str()) == Some("README.md") {
            continue;
        }
        let bytes = std::fs::read(dir.join(&rel)).unwrap();
        hasher.update(rel.to_string_lossy().as_bytes());
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
    }
    hasher.finalize().to_hex().to_string()
}

fn collect_files(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        if entry.file_name() == "LOCK" {
            continue;
        }
        let path = entry.path();
        if path.is_dir() {
            collect_files(root, &path, out);
        } else {
            out.push(path.strip_prefix(root).unwrap().to_path_buf());
        }
    }
}

/// Copy a store directory to scratch, minus the advisory lock: LOCK is
/// kernel state recreated on open, never fixture content.
fn copy_store(src: &Path, label: &str) -> PathBuf {
    let dst = scratch_dir(label);
    copy_dir(src, &dst);
    dst
}

fn copy_dir(src: &Path, dst: &Path) {
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        if name == "LOCK" {
            continue;
        }
        let from = entry.path();
        let to = dst.join(&name);
        if from.is_dir() {
            std::fs::create_dir_all(&to).unwrap();
            copy_dir(&from, &to);
        } else {
            std::fs::copy(&from, &to).unwrap();
        }
    }
}

/// Every byte of history except the lock, keyed by relative path: the
/// read-path tests assert this map is unchanged by opens and replays.
fn history_bytes(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut out = BTreeMap::new();
    collect_bytes(dir, dir, &mut out);
    out
}

fn collect_bytes(root: &Path, dir: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        if entry.file_name() == "LOCK" {
            continue;
        }
        let path = entry.path();
        if path.is_dir() {
            collect_bytes(root, &path, out);
        } else {
            out.insert(
                path.strip_prefix(root).unwrap().to_path_buf(),
                std::fs::read(&path).unwrap(),
            );
        }
    }
}

fn commit_files(dir: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(dir.join("commits"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "commit"))
        .collect();
    out.sort();
    out
}

/// Rebuild the `dev` fixture from scratch through the public delivery
/// path: genesis and admission commit on intake, then an epoch-1..2
/// capability for the recipient. Run explicitly; CI uses the checked-in
/// bytes so the upgrade tests pin stored history, not fresh output.
///
/// `cargo test -p wyrd-contracts regenerate_dev_fixture -- --ignored`
fn regenerate_fixture_store() -> PathBuf {
    let mut rig = Rig::new();
    let admit = rig.admit.clone();
    rig.enqueue_capability(&admit, &[rig.epoch1.clone(), rig.epoch2.clone()]);
    let report = rig.drain();
    assert_eq!(report.accepted, 1, "the fixture capability must commit");
    let dir = rig.dir.clone();
    drop(rig.take_engine());
    dir
}

#[test]
#[ignore = "regenerates the checked-in dev fixture; run explicitly, see above"]
fn regenerate_dev_fixture() {
    let dir = regenerate_fixture_store();
    // The dev fixture lives under its release directory: regenerating
    // into the fixture root would destroy the per-release fixtures
    // and scatter the new store beside them instead of inside `dev/`.
    // Pinned by regenerate_targets_dev_never_the_root above.
    let dst = dev_fixture_dir();
    if dst.exists() {
        std::fs::remove_dir_all(&dst).unwrap();
    }
    std::fs::create_dir_all(&dst).unwrap();
    copy_dir(&dir, &dst);
    std::fs::write(
        dst.join("README.md"),
        "# dev fixture\n\nHarness smoke fixture for the upgrade contracts, produced by\n\
         `regenerate_dev_fixture` (ignored, run explicitly) through the public\n\
         delivery path: genesis and admission transitions plus an epoch-1..2\n\
         capability for the deterministic `device(0x20)` recipient, store\n\
         passphrase `contracts`. Never cross-version evidence: per-release\n\
         fixtures land under their tag starting with the next release.\n",
    )
    .unwrap();
}

/// Cut the release fixture: the same store bytes as `dev`, frozen
/// under the release tag for `upgrade_previous_release_store_replays`
/// to replay. Run explicitly at release-cut time; CI uses the
/// checked-in bytes so the replay test pins stored history, not fresh
/// output. The next release re-runs this under its own tag and
/// repoints `RELEASE_FIXTURE`, keeping exactly one live baseline.
///
/// `cargo test -p wyrd-contracts regenerate_release_fixture -- --ignored`
#[test]
#[ignore = "cuts the checked-in release fixture; run explicitly, see above"]
fn regenerate_release_fixture() {
    let dir = regenerate_fixture_store();
    let dst = fixture_release(RELEASE_FIXTURE);
    assert_eq!(
        dst.parent(),
        Some(fixture_root().as_path()),
        "the release fixture lives beside dev/, never inside it"
    );
    assert_ne!(
        dst,
        dev_fixture_dir(),
        "repointing the release tag at dev/ would wipe the smoke fixture"
    );
    if dst.exists() {
        std::fs::remove_dir_all(&dst).unwrap();
    }
    std::fs::create_dir_all(&dst).unwrap();
    copy_dir(&dir, &dst);
    std::fs::write(
        dst.join("README.md"),
        format!(
            "# {RELEASE_FIXTURE} fixture\n\nRelease baseline for the upgrade contracts, produced by\n\
             `regenerate_release_fixture` (ignored, run explicitly) through the public\n\
             delivery path: genesis and admission transitions plus an epoch-1..2\n\
             capability for the deterministic `device(0x20)` recipient, store\n\
             passphrase `contracts`. Frozen store bytes: `upgrade_previous_release_store_replays`\n\
             replays exactly these files, so regenerating them by hand breaks\n\
             the pin — re-run the generator instead.\n",
        ),
    )
    .unwrap();
}

/// Invariant 1: a new encoding is a new representation. This is the
/// single-version form the current tree can prove: identical content
/// re-stores under the same ContentId (CAS idempotence), and later
/// writes never touch stored bytes. The cross-release half —
/// previous-release bytes read under the current build — lives in
/// `upgrade_previous_release_store_replays`, which pairs with this
/// test to cover the invariant until a second object encoding exists.
#[test]
fn upgrade_new_encoding_is_new_representation() {
    let dir = scratch_dir("upgrade-objects");
    let mut store = FsObjectStore::open(dir.clone()).unwrap();
    let id = store.insert(ObjectKind::Chunk, b"hello upgrade").unwrap();
    let before = history_bytes(&dir);
    let again = store.insert(ObjectKind::Chunk, b"hello upgrade").unwrap();
    assert_eq!(id, again, "identical content re-stores under the same id");
    let other = store.insert(ObjectKind::Chunk, b"different bytes").unwrap();
    assert_ne!(id, other, "new content is a new representation");
    // Later writes may add files; they must never touch stored ones.
    let after = history_bytes(&dir);
    for (rel, bytes) in &before {
        assert_eq!(&after[rel], bytes, "{rel:?} touched by later writes");
    }
    assert_eq!(store.get(&id).unwrap(), Some(b"hello upgrade".to_vec()));
}

/// Invariant 2 (wire half): every persistent format carries its
/// explicit version. Committing through the public API stamps byte 0
/// of the commit file with the commit envelope version — asserted as
/// a wire position, not the unreachable constant.
#[test]
fn upgrade_format_versions_are_carried_on_the_wire() {
    let dir = scratch_dir("upgrade-versions");
    let mut store = DurableStore::open(dir.clone(), drive(), "contracts").unwrap();
    store
        .commit(&[Fact::ControlMessage(ControlMessageId::from_bytes(
            [0xAB; 32],
        ))])
        .unwrap();
    let commits = commit_files(&dir);
    assert_eq!(commits.len(), 1);
    let bytes = std::fs::read(&commits[0]).unwrap();
    assert_eq!(bytes[0], 0x00, "byte 0 is the commit envelope version");
}

/// Invariant 2 (payload half, blocked): replaying previous durable
/// facts requires versioned fact payloads, which land with the v0.9.0
/// payload-versioning issue. This test must stay ignored until then —
/// pinning only the clauses that hold today would certify a partial
/// invariant as whole.
#[test]
#[ignore = "blocked on fact-payload versioning (v0.9.0); see invariant 2"]
fn upgrade_replays_previous_fact_payload_versions() {
    todo!("replay v0 fact payloads into current records once payloads are versioned");
}

/// Invariant 3 (cross-release form): the previous release's
/// store replays under the current build. No released store predates
/// the reader-set format — alpha.1's fixture went out with the
/// pre-v1 breakage the upgrade contract announces (every alpha may
/// break compatibility before the format freezes), and carrying a
/// legacy transition decoder for unshipped software would be the
/// wrong trade. The v0.2.0-alpha fixture below is the baseline the
/// next release replays against; until a second fixture exists, the
/// dev fixture plus the same-version reopen tests carry the rest of
/// the replay evidence.
#[test]
fn upgrade_previous_release_store_replays() {
    let dir = copy_store(
        &fixture_release(RELEASE_FIXTURE),
        "upgrade-previous-release",
    );
    let recipient = device(0x20);
    let state = Engine::open(
        dir.clone(),
        drive(),
        recipient.id,
        "contracts",
        recipient.identity.clone(),
        recipient.encryption.clone(),
    )
    .unwrap()
    .runtime_state()
    .unwrap();
    assert!(
        state.pending_transitions().is_empty() && state.pending_capabilities().is_empty(),
        "the release fixture replays with nothing left pending"
    );
    let facts = DurableStore::open(dir.clone(), drive(), "contracts")
        .unwrap()
        .load()
        .unwrap();
    assert_eq!(facts.transitions.len(), 2, "genesis and admission replay");
    assert_eq!(facts.capabilities.len(), 1, "the epoch-1..2 grant replays");
    assert_eq!(
        fixture_digest(&dir),
        "2abd4973a20cbed7bc9cba9a021daa3bfdf6cdd434d84fc61309d11cd9ad1d67",
        "release fixture bytes are frozen: regenerate via regenerate_release_fixture, never by hand"
    );
}

/// The 21a half of the acceptance: a commit carrying the new
/// reconciliation-view tag replays through the public path. The
/// delivery path commits the base facts, the derived view is stated
/// through the public commit API, and a reopen replays the statement
/// verbatim while derivation stays identical. The older-replay half
/// is the tag skip this relies on: an old node does not know `0x18`
/// and skips the record (pinned in wyrd-sync by
/// `committed_corruption_fails`), so a store containing a stated
/// view still opens there — it simply derives nothing.
#[test]
fn upgrade_reconciliation_view_replays_through_the_public_path() {
    let mut rig = Rig::new();
    let admit = rig.admit.clone();
    rig.enqueue_capability(&admit, &[rig.epoch1.clone(), rig.epoch2.clone()]);
    let report = rig.drain();
    assert_eq!(report.accepted, 1, "the fixture capability must commit");
    let dir = rig.dir.clone();
    drop(rig.take_engine());

    let evidence = {
        let store = DurableStore::open(dir.clone(), drive(), "contracts").unwrap();
        let loaded = store.load().unwrap();
        assert!(loaded.reconciliation_views.is_empty(), "no view stated yet");
        ReconciliationView::derive(&loaded).evidence().clone()
    };
    assert!(
        !evidence.transitions.is_empty() && !evidence.capabilities.is_empty(),
        "the delivery path leaves real evidence: {evidence:?}"
    );
    {
        let mut store = DurableStore::open(dir.clone(), drive(), "contracts").unwrap();
        store
            .commit(&[Fact::ReconciliationView(evidence.clone())])
            .unwrap();
    }
    let store = DurableStore::open(dir.clone(), drive(), "contracts").unwrap();
    let loaded = store.load().unwrap();
    assert_eq!(
        loaded.reconciliation_views,
        vec![evidence.clone()],
        "the stated view replays verbatim"
    );
    assert_eq!(
        ReconciliationView::derive(&loaded).evidence(),
        &evidence,
        "stating the view changed nothing derivable"
    );
}

/// The 21b half of the acceptance: a commit carrying the received
/// reconciliation-request tag replays through the public path. The
/// intake path commits the (requester, evidence) pair through the
/// public commit API, and a reopen replays the statement verbatim
/// into its own bucket — never into the stated-view bucket, never
/// into derivation. Same older-replay half as `0x18`: an old node
/// skips the unknown `0x19` record and still opens the store.
#[test]
fn upgrade_reconciliation_request_replays_through_the_public_path() {
    let mut rig = Rig::new();
    let admit = rig.admit.clone();
    rig.enqueue_capability(&admit, &[rig.epoch1.clone(), rig.epoch2.clone()]);
    let report = rig.drain();
    assert_eq!(report.accepted, 1, "the fixture capability must commit");
    let dir = rig.dir.clone();
    drop(rig.take_engine());

    let evidence = {
        let store = DurableStore::open(dir.clone(), drive(), "contracts").unwrap();
        let loaded = store.load().unwrap();
        ReconciliationView::derive(&loaded).evidence().clone()
    };
    assert!(
        !evidence.transitions.is_empty() && !evidence.capabilities.is_empty(),
        "the delivery path leaves real evidence: {evidence:?}"
    );
    let requester = DeviceId::from_bytes([0x31; 32]);
    {
        let mut store = DurableStore::open(dir.clone(), drive(), "contracts").unwrap();
        store
            .commit(&[Fact::ReconciliationRequestReceived(
                requester,
                evidence.clone(),
            )])
            .unwrap();
    }
    let store = DurableStore::open(dir.clone(), drive(), "contracts").unwrap();
    let loaded = store.load().unwrap();
    assert_eq!(
        loaded.reconciliation_requests,
        vec![(requester, evidence.clone())],
        "the received statement replays verbatim"
    );
    assert!(
        loaded.reconciliation_views.is_empty(),
        "receiving never states"
    );
    assert_eq!(
        ReconciliationView::derive(&loaded).evidence(),
        &evidence,
        "receiving changed nothing derivable"
    );
}

/// Invariant 3 (same-version form): a reopened object store serves
/// the bytes it served before, with nothing rewritten.
#[test]
fn upgrade_old_objects_stay_readable() {
    let dir = scratch_dir("upgrade-reopen-objects");
    let id = {
        let mut store = FsObjectStore::open(dir.clone()).unwrap();
        store.insert(ObjectKind::Chunk, b"survives reopen").unwrap()
    };
    let before = history_bytes(&dir);
    let store = FsObjectStore::open(dir.clone()).unwrap();
    assert_eq!(store.get(&id).unwrap(), Some(b"survives reopen".to_vec()));
    assert!(store.has(&id).unwrap());
    assert_eq!(history_bytes(&dir), before, "reopen rewrites nothing");
}

/// Invariant 4: derived state rebuilds from facts. A fresh engine over
/// a fixture copy recovers the committed coverage with no facts lost.
#[test]
fn upgrade_derived_state_rebuilds_from_facts() {
    let dir = copy_store(&fixture_release("dev"), "upgrade-rebuild");
    let recipient = device(0x20);
    let open_engine = || {
        Engine::open(
            dir.clone(),
            drive(),
            recipient.id,
            "contracts",
            recipient.identity.clone(),
            recipient.encryption.clone(),
        )
        .unwrap()
    };
    let state = open_engine().runtime_state().unwrap();
    assert!(
        state.pending_transitions().is_empty() && state.pending_capabilities().is_empty(),
        "everything committed replays with nothing left pending"
    );
    // The engine holds the advisory lock, so the durable read runs
    // after it drops; reopening then proves rebuild is stable across
    // restarts, not just the first projection.
    let facts = DurableStore::open(dir.clone(), drive(), "contracts")
        .unwrap()
        .load()
        .unwrap();
    assert_eq!(facts.transitions.len(), 2, "genesis and admission replay");
    assert_eq!(facts.capabilities.len(), 1, "the epoch-1..2 grant replays");
    // Pending queues are derived, never persisted (`state.rs`): empty
    // after a restart proves the indexes rebuilt from the replayed
    // facts rather than surviving as stored state.
    let rebuilt = open_engine().runtime_state().unwrap();
    assert!(
        rebuilt.pending_transitions().is_empty() && rebuilt.pending_capabilities().is_empty(),
        "derived outbox indexes rebuild empty across restarts"
    );
}

/// Invariant 5 (gate half): protocol negotiation is capability-based,
/// and anything outside the matrix fails with a named error. A sealed
/// message with a forged envelope version fails open loudly — the
/// pre-v1 gate today is `CONTROL_VERSION` equality.
#[test]
fn upgrade_mixed_versions_fail_named() {
    let key = EpochSecret::from_bytes([0x77; 32]).control_key(&drive(), 1);
    let sealed = control::seal(
        &key,
        &drive(),
        1,
        &Message::MembershipTransition(TransitionPayload {
            transition: vec![0xAB; 64],
        }),
    )
    .unwrap();
    let mut bytes = sealed.encode();
    bytes[0] = 0xFF;
    let forged = control::SealedControl::decode(&bytes).unwrap();
    assert!(
        matches!(
            control::open(&key, &forged),
            Err(ControlError::UnknownVersion(0xFF))
        ),
        "a version outside the matrix fails with its name, not silence"
    );
}

/// Invariant 5 (matrix half, blocked): the full mixed-version matrix
/// needs advertised capabilities and oldest-mutual selection, which do
/// not exist pre-v1 — today there is one version and one gate.
#[test]
#[ignore = "blocked on capability negotiation; see invariant 5"]
fn upgrade_full_version_matrix_synchronizes() {
    todo!("oldest-mutual selection once peers advertise capabilities");
}

/// Invariant 6: versions are independent — opening, loading, and
/// projecting a store is read-only history. No membership transition
/// is minted, and no history byte moves.
#[test]
fn upgrade_reads_never_mint_authority() {
    let dir = copy_store(&fixture_release("dev"), "upgrade-readonly");
    let before = history_bytes(&dir);
    let recipient = device(0x20);
    {
        let engine = Engine::open(
            dir.clone(),
            drive(),
            recipient.id,
            "contracts",
            recipient.identity.clone(),
            recipient.encryption.clone(),
        )
        .unwrap();
        let _ = engine.runtime_state().unwrap();
    }
    let facts = DurableStore::open(dir.clone(), drive(), "contracts")
        .unwrap()
        .load()
        .unwrap();
    assert_eq!(facts.transitions.len(), 2, "reads mint no transitions");
    assert_eq!(
        history_bytes(&dir),
        before,
        "open, load, and projection write no history"
    );
}

/// Invariant 7: cryptographic evolution is additive — old-epoch
/// material stays decryptable under the current build. The fixture's
/// epoch-1..2 grant unwraps with the recipient's encryption secret.
#[test]
fn upgrade_old_epoch_material_stays_decryptable() {
    let dir = copy_store(&fixture_release("dev"), "upgrade-decrypt");
    let store = DurableStore::open(dir, drive(), "contracts").unwrap();
    let facts = store.load().unwrap();
    assert_eq!(facts.capabilities.len(), 1);
    let grant = &facts.capabilities[0];
    assert_eq!(grant.up_to_epoch(), 2, "the grant covers two epochs");
    let recipient = device(0x20);
    let opened = grant.wrap().unwrap().unwrap(&recipient.encryption).unwrap();
    assert_eq!(opened.up_to_epoch(), 2, "both epoch secrets still open");
}

/// Invariant 8: history is never rewritten into the newest
/// representation — every commit appends, so a migration-shaped write
/// (here an ordinary new fact) leaves existing files byte-identical.
#[test]
fn upgrade_appends_never_rewrite() {
    let dir = copy_store(&fixture_release("dev"), "upgrade-append");
    let before: BTreeMap<PathBuf, Vec<u8>> = commit_files(&dir)
        .iter()
        .map(|p| {
            (
                p.strip_prefix(&dir).unwrap().to_path_buf(),
                std::fs::read(p).unwrap(),
            )
        })
        .collect();
    let current = DurableStore::open(dir.clone(), drive(), "contracts")
        .unwrap()
        .current();
    let mut store = DurableStore::open(dir.clone(), drive(), "contracts").unwrap();
    store
        .commit(&[Fact::ControlMessage(ControlMessageId::from_bytes(
            [0xCD; 32],
        ))])
        .unwrap();
    assert_eq!(store.current(), current + 1);
    for (rel, bytes) in &before {
        assert_eq!(
            &std::fs::read(dir.join(rel)).unwrap(),
            bytes,
            "{rel:?} rewritten"
        );
    }
}

/// Invariant 9 (orphaned-temps form): interrupted upgrades leave
/// stale temp siblings, and reopening walks past them. This test
/// scopes exactly to that: planted `*.commit.tmp` garbage is never
/// read and never adopted. The full crash boundary — temp write,
/// file fsync, rename, directory fsync, `CURRENT` ordering, and a
/// partial authoritative commit failing closed — is pinned by
/// wyrd-sync's own durable crash-matrix tests, which fault each
/// stage; this contract only proves the reopen half from outside.
#[test]
fn upgrade_orphaned_temps_are_ignored() {
    let dir = copy_store(&fixture_release("dev"), "upgrade-torn");
    for commit in commit_files(&dir) {
        let tmp = commit.with_extension("commit.tmp");
        std::fs::write(&tmp, b"torn garbage, never a commit").unwrap();
    }
    let before = history_bytes(&dir);
    let store = DurableStore::open(dir.clone(), drive(), "contracts").unwrap();
    let facts = store.load().unwrap();
    assert_eq!(facts.transitions.len(), 2);
    assert_eq!(facts.capabilities.len(), 1);
    // Stale temps persist on disk — they are never read, not cleaned
    // up — so compare history with them set aside, then prove they
    // were walked past rather than adopted.
    let without_tmps = |map: &BTreeMap<PathBuf, Vec<u8>>| {
        map.iter()
            .filter(|(p, _)| p.extension().is_none_or(|e| e != "tmp"))
            .map(|(p, b)| (p.clone(), b.clone()))
            .collect::<BTreeMap<_, _>>()
    };
    assert_eq!(
        without_tmps(&history_bytes(&dir)),
        without_tmps(&before),
        "a read-only open moves no history"
    );
    let planted: Vec<_> = history_bytes(&dir)
        .keys()
        .filter(|p| p.extension().is_some_and(|e| e == "tmp"))
        .cloned()
        .collect();
    assert!(!planted.is_empty(), "the test plants stale temps");
    assert_eq!(store.current(), 3, "no torn temp became a commit");
}

/// Invariant 10: fail closed on the unknown, one named case per
/// boundary row. Unknown envelope and control versions refuse loudly;
/// a commit whose envelope version is flipped refuses to load. The
/// fourth row — unknown record tags skip — cannot be planted through
/// the public API (the trailer seals every byte), and is pinned
/// inside wyrd-sync's own codec tests instead.
#[test]
fn upgrade_unknown_refuses_loudly() {
    let mut envelope = vec![0u8; HEADER_LEN];
    envelope[..4].copy_from_slice(&MAGIC);
    envelope[4] = 0xFF;
    assert!(
        matches!(
            Envelope::decode(&envelope),
            Err(EnvelopeError::UnknownVersion(0xFF))
        ),
        "unknown envelope version refuses with its name"
    );

    let key = EpochSecret::from_bytes([0x77; 32]).control_key(&drive(), 1);
    let sealed = control::seal(
        &key,
        &drive(),
        1,
        &Message::MembershipTransition(TransitionPayload {
            transition: vec![0xAB; 64],
        }),
    )
    .unwrap();
    let mut bytes = sealed.encode();
    bytes[0] = 0xFF;
    let forged = control::SealedControl::decode(&bytes).unwrap();
    assert!(
        matches!(
            control::open(&key, &forged),
            Err(ControlError::UnknownVersion(0xFF))
        ),
        "unknown control version refuses with its name"
    );

    let dir = copy_store(&fixture_release("dev"), "upgrade-flip");
    let commits = commit_files(&dir);
    let last = commits.last().unwrap();
    let mut damaged = std::fs::read(last).unwrap();
    damaged[0] = 0xFF;
    std::fs::write(last, &damaged).unwrap();
    let store = DurableStore::open(dir, drive(), "contracts").unwrap();
    assert!(
        store.load().is_err(),
        "a flipped commit version refuses to load"
    );
}

/// Object-identity decision 30 (`object-model.md`): ContentId derives
/// exclusively from the canonical payload under the identity-domain
/// context (contract 42). Scoped honestly: this entry pins
/// framing-invariance at the store boundary (memory and disk) and kind
/// separation from the derivation context; the store-boundary kind
/// refusal is `insert_verified_uses_payload_identity_not_envelope_identity`
/// in `wyrd-format`, and identity-domain forking rides the golden vectors
/// there.
/// End-to-end over the public APIs: memory and disk stores as the
/// acceptance boundary, Envelope as the framing.
#[test]
fn content_identity_is_payload_based_across_framing() {
    let payload = b"contract payload preimage";
    let expected = ContentId::derive(ObjectKind::Chunk, payload);
    // Same payload + same context through the framing round-trip.
    let framed = Envelope {
        kind: ObjectKind::Chunk,
        payload: payload.to_vec(),
    }
    .encode();
    let decoded = Envelope::decode(&framed).unwrap();
    let mut mem = MemoryObjectStore::default();
    mem.insert_verified(ObjectKind::Chunk, &expected, &decoded.payload)
        .unwrap();
    // Framing bytes are not payload: rejected under the same expectation,
    // naming the variant the way the disk leg does.
    assert!(matches!(
        mem.insert_verified(ObjectKind::Chunk, &expected, &framed),
        Err(MemoryStoreError::IdentityMismatch { .. })
    ));
    // Same boundary on disk: the payload verifies and reads back, while
    // the framed bytes are refused as a foreign preimage.
    let dir = scratch_dir("identity-framing");
    let mut disk = FsObjectStore::open(dir).unwrap();
    disk.insert_verified(ObjectKind::Chunk, &expected, payload)
        .unwrap();
    assert_eq!(disk.get(&expected).unwrap().as_deref(), Some(&payload[..]));
    assert!(matches!(
        disk.insert_verified(ObjectKind::Chunk, &expected, &framed),
        Err(FsStoreError::IdentityMismatch)
    ));
    // Kind separation rides the context, not the framing; the
    // identity-domain fork property itself is carried by the golden
    // vectors (object-model.md decision 30).
    let other = ContentId::derive(ObjectKind::Tree, payload);
    assert_ne!(expected, other);
}

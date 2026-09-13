//! Local snapshot authoring: the write half of the drive.
//!
//! A member device turns a root tree it holds into a signed snapshot
//! bound to the canonical membership state, authors the manifest
//! hierarchy from representations it actually sealed (or recorded
//! mappings it holds the epoch capability for), commits everything
//! durably, and can announce the snapshot to the other members. This is
//! the producer the rest of the runtime assumed and never had: intake
//! and the live-head projection consumed snapshots, but every body under
//! test was built by a fixture.
//!
//! Semantics follow `docs/epochs.md` ("local write"): the snapshot
//! parents onto the locally live-lineage eligible heads, binds
//! `membership` to the canonical epoch-K transition, and sets `epoch` to
//! that transition's epoch. Failures are fail-closed: no canonical
//! membership, a non-member author, an unavailable root tree, or a
//! signature that will not verify commits nothing.

use std::collections::BTreeMap;

use wyrd_format::{
    ChildManifest, ContentId, Manifest, ManifestEntry, ObjectKind, ObjectStore, Snapshot, Tree,
};

use super::engine::{Engine, EngineError};
use super::ManifestRecord;
use crate::authorization::SnapshotDag;
use crate::control::{seal as seal_control, Message, SnapshotAnnouncement};
use crate::durable::{AuthorizedSnapshot, Fact};
use crate::ingest::{check_manifest, check_tree, Limits};
use crate::seal::{entry_for, seal as seal_content, seal_manifest, SEAL_VERSION};
use crate::transport::mailbox::{seal_for_recipient, Mailbox};

/// Author a snapshot over `tree` on behalf of this engine's device. The
/// root must be a canonical tree object present in `objects` whose bytes
/// hash back to `tree` (the store's scrub invariant, re-checked here so a
/// faulty store cannot launder a wrong address). Parents are the current
/// eligible heads, so a single-head drive extends its live state and a
/// conflicted drive resolves onto every head (object-model.md,
/// "Resolution"). The body is signed, verified once (fail-closed), and
/// committed together with the authored manifest hierarchy; it becomes
/// live when a projection rebuilds the DAG.
///
/// Manifest authoring (object-model.md, "Hierarchical, per-subtree
/// manifests"): every subtree tree maps into a manifest sealed under the
/// snapshot's manifest key, mirroring the tree structure. Each vault
/// mapping names a representation this device actually holds: a chunk
/// with local plaintext seals fresh under the canonical epoch (fresh
/// nonce, new representation); a chunk without local plaintext reuses a
/// durably recorded mapping — and only when the device holds that
/// mapping's epoch capability, per the object-model rule (otherwise the
/// device re-encrypts, which needs the plaintext). A chunk that is
/// neither holdable nor mappable fails the authoring closed.
pub(super) fn author<S: ObjectStore>(
    engine: &mut Engine,
    objects: &S,
    tree: ContentId,
) -> Result<AuthorizedSnapshot, EngineError>
where
    S::Error: std::fmt::Debug,
{
    let bytes = objects
        .get(&tree)
        .map_err(|e| EngineError::ObjectStore(format!("{e:?}")))?
        .ok_or(EngineError::TreeUnavailable(tree))?;
    if ContentId::derive(ObjectKind::Tree, &bytes) != tree {
        return Err(EngineError::TreeMismatch(tree));
    }
    let root_tree = Tree::decode(&bytes).map_err(|_| EngineError::InvalidTree(tree))?;
    check_tree(&Limits::V0, &root_tree).map_err(EngineError::Ingest)?;

    let rebuilt = engine.store.rebuild(engine.device)?;
    let known = rebuilt
        .log
        .known_state()
        .ok_or(EngineError::NoCanonicalMembership)?;
    let members = rebuilt
        .log
        .members_of(&known.transition_id)
        .ok_or(EngineError::NoCanonicalMembership)?;
    if !members.contains(&engine.device) {
        return Err(EngineError::NotAMember);
    }

    let mut dag = SnapshotDag::new(engine.drive);
    for body in rebuilt.runtime.snapshot_bodies.values() {
        dag.observe(body.clone());
    }
    let parents = dag.eligible_heads(&rebuilt.log);

    let max_seen = rebuilt
        .runtime
        .snapshot_bodies
        .values()
        .map(|snapshot| snapshot.timestamp)
        .max()
        .unwrap_or(0);
    let timestamp =
        next_timestamp(max_seen, wall_clock_ms()).ok_or(EngineError::TimestampExhausted)?;

    let mut snapshot = Snapshot::new(
        parents,
        tree,
        engine.device,
        known.transition_id,
        known.epoch,
        0,
        timestamp,
    );
    crate::authorization::predicates::sign_snapshot(
        &mut snapshot,
        &engine.identity_secret.secret_key(),
        &engine.drive,
    );

    let authorized =
        AuthorizedSnapshot::authorize(snapshot, &engine.drive).map_err(EngineError::InvalidHead)?;

    // The manifest hierarchy is authored, not reconstructed: every
    // mapping names a sealed envelope this device holds the bytes for
    // (fresh seals below) or a recorded representation it holds the
    // epoch capability and the vault copy for. The snapshot body rides
    // the same vault: peers fetch it by the announcement's body root.
    let secret = rebuilt
        .keyring
        .secret(known.epoch)
        .ok_or(EngineError::MissingEpochKey(known.epoch))?;
    engine.vault.import(&authorized.snapshot().encode())?;
    let mut authoring = ManifestAuthor {
        engine,
        objects,
        runtime: &rebuilt.runtime,
        keyring: &rebuilt.keyring,
        secret,
        epoch: known.epoch,
        snapshot: authorized.snapshot().snapshot_id(),
        children: Vec::new(),
        sealed: BTreeMap::new(),
    };
    let root = authoring.walk(tree)?;
    let children = std::mem::take(&mut authoring.children);
    drop(authoring);
    // Fail-closed self-check: the manifests we just built must correspond to
    // the tree we are signing over. This proves our construction maintains
    // the closure invariant; it is not a receiving-side boundary (a peer
    // cannot yet fetch the tree closure).
    let child_index: BTreeMap<ContentId, &Manifest> = children
        .iter()
        .map(|record| (record.manifest_id, &record.manifest))
        .collect();
    crate::closure::verify_snapshot_manifest(
        authorized.snapshot(),
        objects,
        &root.manifest_id,
        &root.manifest,
        &child_index,
        &Limits::V0,
    )
    .map_err(EngineError::Closure)?;
    let mut facts = vec![Fact::SnapshotBody(authorized.clone())];
    facts.extend(children.into_iter().map(Fact::Manifest));
    facts.push(Fact::Manifest(root));
    engine.commit_facts(&facts)?;
    Ok(authorized)
}

/// The per-authoring context for the manifest walk: everything the
/// recursive build needs, held once. Freshly sealed mappings cache here,
/// so one logical chunk seals exactly once per authoring session even
/// when several subtrees reference it.
struct ManifestAuthor<'a, S: ObjectStore>
where
    S::Error: std::fmt::Debug,
{
    engine: &'a mut Engine,
    objects: &'a S,
    runtime: &'a super::RuntimeState,
    keyring: &'a crate::keys::DriveKeyring,
    secret: &'a crate::keys::EpochSecret,
    epoch: u64,
    snapshot: wyrd_format::SnapshotId,
    /// Child records accumulate post-order (leaves first), so durable
    /// replay installs children before the parent that claims them.
    children: Vec<ManifestRecord>,
    /// Fresh seals this authoring session already produced, by content.
    sealed: BTreeMap<ContentId, ManifestEntry>,
}

impl<S: ObjectStore> ManifestAuthor<'_, S>
where
    S::Error: std::fmt::Debug,
{
    /// Map one subtree tree into its manifest: local chunks seal fresh
    /// or resolve through the session cache, dirs recurse into child
    /// manifests, symlinks map to nothing. Entries and child links are
    /// deduplicated by their logical identity — the canonical manifest
    /// encoding admits exactly one entry per `(content, kind, version)`
    /// and one link per subtree, and repeated references (identical
    /// chunks, identical subtrees) are the norm, not an error. The
    /// authored envelope lands in the engine's durable vault under the
    /// transport root the record carries.
    fn walk(&mut self, tree_id: ContentId) -> Result<ManifestRecord, EngineError> {
        let bytes = self
            .objects
            .get(&tree_id)
            .map_err(|e| EngineError::ObjectStore(format!("{e:?}")))?
            .ok_or(EngineError::TreeUnavailable(tree_id))?;
        if ContentId::derive(ObjectKind::Tree, &bytes) != tree_id {
            return Err(EngineError::TreeMismatch(tree_id));
        }
        let tree = Tree::decode(&bytes).map_err(|_| EngineError::InvalidTree(tree_id))?;
        check_tree(&Limits::V0, &tree).map_err(EngineError::Ingest)?;

        let mut entries: BTreeMap<ContentId, ManifestEntry> = BTreeMap::new();
        let mut links: BTreeMap<ContentId, ChildManifest> = BTreeMap::new();
        for entry in tree.entries() {
            match &entry.content {
                wyrd_format::EntryContent::File { chunks, .. } => {
                    for chunk in chunks {
                        let mapping = self.resolve(*chunk)?;
                        entries.insert(*chunk, mapping);
                    }
                }
                wyrd_format::EntryContent::Dir { subtree } => {
                    let child = self.walk(*subtree)?;
                    let storage = child
                        .representations
                        .keys()
                        .next()
                        .copied()
                        .ok_or(EngineError::RepresentationMissing(child.manifest_id))?;
                    links.insert(
                        *subtree,
                        ChildManifest {
                            tree: *subtree,
                            manifest: child.manifest_id,
                            storage,
                            transport: child.transport,
                        },
                    );
                    self.children.push(ManifestRecord {
                        is_root: false,
                        ..child
                    });
                }
                wyrd_format::EntryContent::Symlink { .. } => {}
            }
        }

        let manifest = Manifest {
            snapshot: self.snapshot,
            entries: entries.into_values().collect(),
            children: links.into_values().collect(),
        };
        check_manifest(&Limits::V0, &manifest).map_err(EngineError::Ingest)?;
        let manifest_key = self
            .secret
            .manifest_key(&self.engine.drive, self.epoch, &self.snapshot);
        let (manifest_id, obj) = seal_manifest(&manifest_key, &manifest)?;
        self.engine.vault.import(&obj.encode())?;
        let transport = crate::seal::transport_root(&obj);
        Ok(ManifestRecord {
            is_root: true,
            manifest_id,
            representations: BTreeMap::from([(obj.storage_id(), transport)]),
            transport,
            manifest,
        })
    }

    /// The mapping for one chunk, deduplicated across the session: a
    /// freshly sealed mapping from earlier in this authoring, else a
    /// recorded representation the device both holds the epoch
    /// capability for and holds the vault copy of — advertising a
    /// mapping it cannot serve is the failure mode this order forbids —
    /// else a fresh seal under the canonical epoch (needs the local
    /// plaintext), else fail closed. First match in manifest-id order
    /// wins; deterministic under replay.
    fn resolve(&mut self, chunk: ContentId) -> Result<ManifestEntry, EngineError> {
        if let Some(entry) = self.sealed.get(&chunk) {
            return Ok(entry.clone());
        }
        for entry in self.runtime.recorded_mappings(&chunk) {
            let held = self.keyring.secret(entry.encryption_epoch).is_some();
            let served = self
                .engine
                .vault
                .sealed(&entry.transport)
                .map_err(EngineError::from)?
                .is_some();
            if held && served {
                self.sealed.insert(chunk, entry.clone());
                return Ok(entry);
            }
        }
        let plaintext = self
            .objects
            .get(&chunk)
            .map_err(|e| EngineError::ObjectStore(format!("{e:?}")))?
            .ok_or(EngineError::ChunkUnavailable(chunk))?;
        let object_key = self.secret.object_key(
            &self.engine.drive,
            self.epoch,
            &chunk,
            ObjectKind::Chunk,
            SEAL_VERSION,
        );
        let obj = seal_content(&object_key, ObjectKind::Chunk, &chunk, &plaintext)?;
        let entry = entry_for(ObjectKind::Chunk, self.epoch, &obj, &chunk, &plaintext)?;
        self.engine.vault.import(&obj.encode())?;
        self.sealed.insert(chunk, entry.clone());
        Ok(entry)
    }
}

/// Announce an authored snapshot to every other member over the control
/// plane: seal one epoch-keyed announcement and address it to each
/// member's identity. Returns the number of envelopes sent (the author
/// is skipped: it already holds the body). The epoch must be one this
/// engine holds a control key for, and the snapshot's root manifest must
/// be recorded — the announcement carries the transport identities the
/// peers will fetch by (object-model.md decision 26): the body's Bao
/// root, the root manifest's ContentId, and the transport root of the
/// author's own sealed representation. The author signs the payload
/// before sealing, so peers can verify authorship and the identities at
/// intake.
pub(super) fn announce(
    engine: &Engine,
    snapshot: &AuthorizedSnapshot,
    mailbox: &mut impl Mailbox,
    node_addr: Option<&[u8]>,
) -> Result<usize, EngineError> {
    let body = snapshot.snapshot();
    // The announcement is signed by this engine's identity, so it may
    // only carry a snapshot this engine authored: anything else produces
    // authorship every recipient rejects, before any mailbox traffic.
    if body.author != engine.device {
        return Err(EngineError::NotAnnounceAuthor(body.snapshot_id()));
    }
    let key = engine
        .epoch_keys
        .get(&body.epoch)
        .ok_or(EngineError::MissingEpochKey(body.epoch))?;

    let rebuilt = engine.store.rebuild(engine.device)?;
    let root_record = rebuilt
        .runtime
        .root_manifest_record(&body.snapshot_id())
        .ok_or_else(|| EngineError::RootManifestUnavailable(body.snapshot_id()))?;

    let mut announcement = SnapshotAnnouncement {
        snapshot: body.snapshot_id(),
        author: body.author,
        epoch: body.epoch,
        membership: body.membership,
        // The body's transport root: raw BLAKE3 over the canonical
        // bytes, the verified-fetch address for the bulk body.
        body_root: crate::seal::blob_root(&body.encode()),
        root_manifest: root_record.manifest_id,
        root_manifest_transport: root_record.transport,
        // The composer's current retrieval route, sealed with the rest
        // (T17): authenticated routing metadata, opaque to control.
        node_addr: node_addr.map(<[u8]>::to_vec),
        signature: [0; 64],
    };
    crate::control::sign_announcement(&mut announcement, &engine.identity_secret, &engine.drive);
    let sealed = seal_control(
        key,
        &engine.drive,
        body.epoch,
        &Message::SnapshotAnnouncement(announcement),
    )?;

    let members = rebuilt
        .log
        .members_of(&body.membership)
        .ok_or(EngineError::NoCanonicalMembership)?;

    let mut sent = 0usize;
    for member in members {
        if member == engine.device {
            continue;
        }
        let envelope = seal_for_recipient(&engine.identity_secret, member, &sealed.encode())?;
        mailbox.send(envelope)?;
        sent += 1;
    }
    Ok(sent)
}

/// The timestamp for the next locally authored snapshot: strictly
/// greater than every timestamp already observed in the local DAG, and
/// never below the wall clock. This keeps the local authoring sequence
/// monotonic across clock rollback, same-millisecond writes, and
/// restarts (the durable DAG carries the previous maximum). The field is
/// display and `(timestamp, author)` tiebreak only; authorization never
/// reads it. Returns `None` once the observed maximum reaches
/// `u64::MAX`, where no strictly greater value exists, so the caller
/// fails instead of repeating the maximum.
pub(super) fn next_timestamp(max_seen: u64, now: u64) -> Option<u64> {
    let next = max_seen.checked_add(1)?;
    Some(now.max(next))
}

/// Wall-clock milliseconds. A clock before the Unix epoch yields zero,
/// which `next_timestamp` still prefers over the observed maximum.
fn wall_clock_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::next_timestamp;

    #[test]
    fn local_timestamps_never_go_backwards() {
        // Wall clock ahead of history: take the clock.
        assert_eq!(next_timestamp(500, 900), Some(900));
        // Same millisecond as the last write: step past it.
        assert_eq!(next_timestamp(500, 500), Some(501));
        // Clock rolled back: still step past the durable maximum.
        assert_eq!(next_timestamp(500, 100), Some(501));
        // Empty history: the clock stands.
        assert_eq!(next_timestamp(0, 42), Some(42));
        // Exhausted space: fail rather than repeat the maximum.
        assert_eq!(next_timestamp(u64::MAX, 0), None);
    }
}

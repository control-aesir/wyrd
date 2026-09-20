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

use std::collections::{BTreeMap, BTreeSet};

use wyrd_format::membership::{set_root, Admission, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT};
use wyrd_format::{
    Change, ChildManifest, ContentId, DeviceEncryptionKey, DeviceId, DriveId, Entry, Manifest,
    ManifestEntry, MembershipTransition, ObjectKind, ObjectStore, Snapshot, TransitionId, Tree,
};

use super::engine::{Engine, EngineError};
use super::ManifestRecord;
use crate::authorization::SnapshotDag;
use crate::control::bootstrap::{seal_bootstrap, SealedBootstrap};
use crate::control::{
    seal as seal_control, CapabilityPayload, Message, SnapshotAnnouncement, TransitionPayload,
};
use crate::durable::{AuthorizedCapability, AuthorizedSnapshot, Fact, Rebuilt};
use crate::ingest::{check_manifest, check_tree, Limits};
use crate::keys::capability::{Capability, DriveKeyring};
use crate::keys::EpochSecret;
use crate::membership::sign_transition;
use crate::seal::{entry_for, seal as seal_content, seal_manifest, SEAL_VERSION};
use crate::transport::mailbox::{seal_for_recipient, Mailbox};
use zeroize::Zeroizing;

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
    )?;
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
        local: BTreeSet::new(),
    };
    let root = authoring.walk(tree)?;
    let children = std::mem::take(&mut authoring.children);
    let local = std::mem::take(&mut authoring.local);
    drop(authoring);
    // Self-check: the manifests we just built must correspond to the tree
    // we are signing over. Authoring reads the tree nodes and seals the
    // chunks it holds, so everything needed is local.
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
    // The tree nodes and freshly sealed chunks are local plaintext now;
    // recording them keeps the fetch plan from re-requesting held content.
    facts.extend(local.into_iter().map(Fact::LocalObject));
    // The announcement obligation, atomically with the body: a crash
    // between commit and the first send still leaves a discoverable
    // outbox entry, so restart resumes without re-authoring. One entry
    // per other member; a lone member announces to nobody.
    let snapshot_id = authorized.snapshot().snapshot_id();
    for member in &members {
        if *member != engine.device {
            facts.push(Fact::AnnouncementQueued(snapshot_id, *member));
        }
    }
    engine.commit_facts(&facts)?;
    Ok(authorized)
}

/// The per-authoring context for the manifest walk: everything the
/// iterative build needs, held once. Freshly sealed mappings cache here,
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
    /// Content whose plaintext this device holds after the walk (the tree
    /// nodes it read, and the chunks it sealed fresh), recorded as local
    /// facts so the fetch plan never re-requests content already present.
    local: BTreeSet<ContentId>,
}

/// One subtree frame of the iterative manifest walk: the tree's
/// canonical entries in order, the next entry to process, and the
/// mappings and child links assembled so far. Frames live on the heap
/// (`Vec<WalkFrame>`), so a deep member-authored chain costs heap, never
/// process stack.
struct WalkFrame {
    tree_id: ContentId,
    entries_list: Vec<Entry>,
    next: usize,
    entries: BTreeMap<ContentId, ManifestEntry>,
    links: BTreeMap<ContentId, ChildManifest>,
}

/// The child link for an assembled subtree manifest: the subtree's first
/// sealed representation, the one the author serves and announces. A
/// manifest with no representation to link is an authoring bug, failed
/// closed.
fn child_link(subtree: ContentId, child: &ManifestRecord) -> Result<ChildManifest, EngineError> {
    let storage = child
        .representations
        .keys()
        .next()
        .copied()
        .ok_or(EngineError::RepresentationMissing(child.manifest_id))?;
    Ok(ChildManifest {
        tree: subtree,
        manifest: child.manifest_id,
        storage,
        transport: child.transport,
    })
}

impl<S: ObjectStore> ManifestAuthor<'_, S>
where
    S::Error: std::fmt::Debug,
{
    /// Load, address-check, decode, and limit-check one tree node: the
    /// store's scrub invariant, re-checked here so a faulty store cannot
    /// launder a wrong address at any depth of the walk.
    fn load_tree(&self, tree_id: ContentId) -> Result<(Vec<u8>, Tree), EngineError> {
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
        Ok((bytes, tree))
    }

    /// Map one subtree tree into its manifest: local chunks seal fresh
    /// or resolve through the session cache, dirs descend into child
    /// manifests, symlinks map to nothing. Entries and child links are
    /// deduplicated by their logical identity — the canonical manifest
    /// encoding admits exactly one entry per `(content, kind, version)`
    /// and one link per subtree, and repeated references (identical
    /// chunks, identical subtrees) are the norm, not an error. A subtree
    /// shared by several parents assembles once and every parent links
    /// the same record. The authored envelope lands in the engine's
    /// durable vault under the transport root the record carries.
    ///
    /// Iterative post-order DFS over the tree closure on the heap: a deep
    /// member-authored chain must not exhaust the process stack (this walk
    /// previously recursed per directory level). File mappings resolve in
    /// canonical entry order as each frame is reached, so the session seal
    /// cache reuses the same first seal the recursive walk produced;
    /// child manifests assemble before the parent that links them, so
    /// durable replay still installs children before their parent.
    fn walk(&mut self, tree_id: ContentId) -> Result<ManifestRecord, EngineError> {
        let (root_bytes, root_tree) = self.load_tree(tree_id)?;
        // Self-mapping: each tree node's own sealed representation. This
        // is what makes the structural tree closure fetchable (the fetch
        // plan queues manifest entries by kind), so a receiver can
        // assemble the tree closure and verify correspondence.
        let mut root_entries: BTreeMap<ContentId, ManifestEntry> = BTreeMap::new();
        root_entries.insert(tree_id, self.seal_tree(tree_id, &root_bytes)?);
        let mut stack = vec![WalkFrame {
            tree_id,
            entries_list: root_tree.entries().to_vec(),
            next: 0,
            entries: root_entries,
            links: BTreeMap::new(),
        }];
        // Assembled child links, by subtree tree id: everything the
        // parent frames need to link a completed subtree, without
        // retaining a second full manifest graph (the records live only
        // in `self.children`). Content addressing makes a true reference
        // cycle infeasible (it would need a hash cycle), so a re-entered
        // in-progress id means a faulty store, failed closed.
        let mut completed: BTreeMap<ContentId, ChildManifest> = BTreeMap::new();
        let mut in_progress: BTreeSet<ContentId> = BTreeSet::from([tree_id]);
        while !stack.is_empty() {
            // Peek at the top frame's next entry without holding the
            // borrow across the sealing calls below.
            let next_entry = {
                let frame = stack.last().expect("walk stack nonempty");
                frame.entries_list.get(frame.next).cloned()
            };
            match next_entry {
                Some(entry) => match entry.content {
                    wyrd_format::EntryContent::File { chunks, .. } => {
                        let mut mappings = Vec::with_capacity(chunks.len());
                        for chunk in &chunks {
                            mappings.push((*chunk, self.resolve(*chunk)?));
                        }
                        let frame = stack.last_mut().expect("walk stack nonempty");
                        for (chunk, mapping) in mappings {
                            frame.entries.insert(chunk, mapping);
                        }
                        frame.next += 1;
                    }
                    wyrd_format::EntryContent::Dir { subtree } => {
                        if let Some(link) = completed.get(&subtree) {
                            let frame = stack.last_mut().expect("walk stack nonempty");
                            frame.links.insert(subtree, link.clone());
                            frame.next += 1;
                        } else {
                            if in_progress.contains(&subtree) {
                                return Err(EngineError::TreeMismatch(subtree));
                            }
                            stack.last_mut().expect("walk stack nonempty").next += 1;
                            let (bytes, tree) = self.load_tree(subtree)?;
                            let self_mapping = self.seal_tree(subtree, &bytes)?;
                            let mut entries: BTreeMap<ContentId, ManifestEntry> = BTreeMap::new();
                            entries.insert(subtree, self_mapping);
                            in_progress.insert(subtree);
                            stack.push(WalkFrame {
                                tree_id: subtree,
                                entries_list: tree.entries().to_vec(),
                                next: 0,
                                entries,
                                links: BTreeMap::new(),
                            });
                        }
                    }
                    wyrd_format::EntryContent::Symlink { .. } => {
                        stack.last_mut().expect("walk stack nonempty").next += 1;
                    }
                },
                None => {
                    let frame = stack.pop().expect("walk stack nonempty");
                    in_progress.remove(&frame.tree_id);
                    // BTreeMap-collected parts: ascending unique keys with
                    // values sealed under those keys, verified by
                    // `from_sorted` rather than re-sorted.
                    let manifest =
                        Manifest::from_sorted(self.snapshot, frame.entries, frame.links)?;
                    check_manifest(&Limits::V0, &manifest).map_err(EngineError::Ingest)?;
                    let manifest_key =
                        self.secret
                            .manifest_key(&self.engine.drive, self.epoch, &self.snapshot);
                    let (manifest_id, obj) = seal_manifest(&manifest_key, &manifest)?;
                    self.engine.vault.import(&obj.encode())?;
                    let transport = crate::seal::transport_root(&obj);
                    let record = ManifestRecord {
                        is_root: true,
                        manifest_id,
                        representations: BTreeMap::from([(obj.storage_id(), transport)]),
                        transport,
                        manifest,
                    };
                    let frame_id = frame.tree_id;
                    if stack.is_empty() {
                        return Ok(record);
                    }
                    let link = child_link(frame_id, &record)?;
                    completed.insert(frame_id, link.clone());
                    self.children.push(ManifestRecord {
                        is_root: false,
                        ..record
                    });
                    stack
                        .last_mut()
                        .expect("walk stack nonempty")
                        .links
                        .insert(frame_id, link);
                }
            }
        }
        unreachable!("the walk returns when the root frame assembles");
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
        self.local.insert(chunk);
        Ok(entry)
    }

    /// The sealed representation mapping one tree node: sealed under this
    /// snapshot's epoch like any object, cached across the session so a
    /// tree referenced by several parents is sealed once.
    fn seal_tree(
        &mut self,
        tree_id: ContentId,
        bytes: &[u8],
    ) -> Result<ManifestEntry, EngineError> {
        if let Some(entry) = self.sealed.get(&tree_id) {
            return Ok(entry.clone());
        }
        let object_key = self.secret.object_key(
            &self.engine.drive,
            self.epoch,
            &tree_id,
            ObjectKind::Tree,
            SEAL_VERSION,
        );
        let obj = seal_content(&object_key, ObjectKind::Tree, &tree_id, bytes)?;
        let entry = entry_for(ObjectKind::Tree, self.epoch, &obj, &tree_id, bytes)?;
        self.engine.vault.import(&obj.encode())?;
        self.sealed.insert(tree_id, entry.clone());
        self.local.insert(tree_id);
        Ok(entry)
    }
}

/// Announce an authored snapshot to every other member over the control
/// plane, returning the number of envelopes sent this call (the author
/// is skipped: it already holds the body). The epoch must be one this
/// engine holds a control key for, and the snapshot's root manifest must
/// be recorded — the announcement carries the transport identities the
/// peers will fetch by (object-model.md decision 26): the body's Bao
/// root, the root manifest's ContentId, and the transport root of the
/// author's own sealed representation. The author signs the payload
/// before sealing, so peers can verify authorship and the identities at
/// intake.
///
/// Delivery is durable and retryable, not best-effort. The obligation
/// was queued atomically at authoring; this call tops it up for
/// pre-outbox snapshots (idempotent), seals the announcement once (the
/// sealed bytes persist, so every retry resends byte-identical bytes
/// and the receiver's message-id dedupe collapses the retry to a
/// no-op), and records one delivered marker per successful send. A
/// mid-loop send failure returns the error with the remaining
/// recipients still pending — resume with [`announce_pending`], which
/// resends only the undischarged obligations. The first seal wins, so
/// the route rides the first send's `node_addr`.
pub(super) fn announce(
    engine: &mut Engine,
    snapshot: &AuthorizedSnapshot,
    mailbox: &mut impl Mailbox,
    node_addr: Option<&[u8]>,
) -> Result<usize, EngineError> {
    let body = snapshot.snapshot();
    // The announcement is signed by this engine's identity, so it may
    // only carry a snapshot this engine authored: anything else produces
    // authorship every recipient rejects, before any mailbox traffic or
    // any outbox fact.
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

    let members = rebuilt
        .log
        .members_of(&body.membership)
        .ok_or(EngineError::NoCanonicalMembership)?;

    // Top up the author-time obligation for pre-outbox snapshots
    // (authored before the outbox existed, so no queue facts). The
    // membership of a fixed transition is immutable, so for current
    // snapshots this always matches what authoring queued — the branch
    // exists for legacy stores, not for recipient-set growth.
    // Already-covered pairs are skipped, so a re-announce commits
    // nothing new here.
    let mut obligation = Vec::new();
    for member in &members {
        if *member != engine.device
            && !rebuilt
                .runtime
                .announcement_covered(body.snapshot_id(), *member)
        {
            obligation.push(Fact::AnnouncementQueued(body.snapshot_id(), *member));
        }
    }

    // Seal once: reuse the persisted bytes when a previous attempt
    // sealed them, so retries are byte-identical.
    let sealed_bytes = match rebuilt
        .runtime
        .announcement_sealed_bytes(&body.snapshot_id())
    {
        Some(bytes) => bytes.to_vec(),
        None => {
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
            crate::control::sign_announcement(
                &mut announcement,
                &engine.identity_secret,
                &engine.drive,
            );
            let sealed = seal_control(
                key,
                &engine.drive,
                body.epoch,
                &Message::SnapshotAnnouncement(announcement),
            )?;
            let bytes = sealed.encode();
            // Validate before committing: persisting oversize bytes
            // would poison the obligation — first-seal-wins means the
            // retry could never replace them, failing every resend
            // even with a valid route. The queue facts stay
            // uncommitted too; the author-time obligation (already
            // durable) still covers the retry.
            crate::transport::mailbox::check_outbound_size(&bytes)?;
            obligation.push(Fact::AnnouncementSealed(body.snapshot_id(), bytes.clone()));
            bytes
        }
    };
    if !obligation.is_empty() {
        engine.commit_facts(&obligation)?;
    }

    send_pending_for(engine, body.snapshot_id(), &sealed_bytes, mailbox)
}

/// Resume every undischarged announcement obligation across snapshots,
/// returning the number of envelopes sent this call. This is the
/// restart path: after a crash or a partial send, the durable outbox
/// still holds the queued-minus-delivered pairs, and this sends them
/// without re-authoring anything. Snapshots with no persisted sealed
/// bytes are sealed now (the epoch key must be held; the root manifest
/// must be recorded) under the given `node_addr`; already-sealed
/// snapshots resend their exact bytes. Entries for snapshots this
/// device did not author are skipped — both writers check authorship
/// first, so such an entry cannot arise through the public API.
pub(super) fn announce_pending(
    engine: &mut Engine,
    mailbox: &mut impl Mailbox,
    node_addr: Option<&[u8]>,
) -> Result<usize, EngineError> {
    let rebuilt = engine.store.rebuild(engine.device)?;
    // Distinct snapshots with pending obligations, in snapshot-id
    // order (`pending_announcements` already yields sorted pairs).
    let mut snapshots: Vec<wyrd_format::SnapshotId> = rebuilt
        .runtime
        .pending_announcements()
        .into_iter()
        .map(|(snapshot, _)| snapshot)
        .collect();
    snapshots.dedup();
    let mut sent = 0usize;
    for snapshot_id in snapshots {
        let Some(body) = rebuilt.runtime.snapshot_body(&snapshot_id) else {
            continue;
        };
        if body.author != engine.device {
            continue;
        }
        let authorized = AuthorizedSnapshot::authorize(body.clone(), &engine.drive)
            .map_err(EngineError::InvalidHead)?;
        // The per-snapshot path tops up nothing (the obligation is
        // already queued) but seals when unsealed and sends exactly
        // this snapshot's current pending set, which it re-reads
        // fresh — nothing else can write (this engine holds the
        // store lock), so the set cannot drift mid-resume.
        match rebuilt.runtime.announcement_sealed_bytes(&snapshot_id) {
            Some(bytes) => {
                let bytes = bytes.to_vec();
                sent += send_pending_for(engine, snapshot_id, &bytes, mailbox)?;
            }
            None => {
                sent += announce(engine, &authorized, mailbox, node_addr)?;
            }
        }
    }
    Ok(sent)
}

/// Send the sealed bytes to every still-pending recipient of one
/// snapshot, recording one delivered marker per successful send. A
/// send failure returns immediately with the rest still pending.
fn send_pending_for(
    engine: &mut Engine,
    snapshot: wyrd_format::SnapshotId,
    sealed_bytes: &[u8],
    mailbox: &mut impl Mailbox,
) -> Result<usize, EngineError> {
    let rebuilt = engine.store.rebuild(engine.device)?;
    let recipients: Vec<wyrd_format::DeviceId> = rebuilt
        .runtime
        .pending_announcements()
        .into_iter()
        .filter(|(id, _)| *id == snapshot)
        .map(|(_, recipient)| recipient)
        .collect();
    let mut sent = 0usize;
    for recipient in recipients {
        let envelope = seal_for_recipient(&engine.identity_secret, recipient, sealed_bytes)?;
        mailbox.send(envelope)?;
        engine.commit_facts(&[Fact::AnnouncementDelivered(snapshot, recipient)])?;
        sent += 1;
    }
    Ok(sent)
}

/// The authored admission: the signed transition every member must
/// observe, plus the sealed invitation ferried to the new device
/// out-of-band (it bootstraps a device with no engine yet, so it
/// cannot arrive as a control message).
pub struct AdmitOutcome {
    pub transition: MembershipTransition,
    pub invitation: SealedBootstrap,
}

/// Admit a device: author, sign, and commit the admission transition,
/// install the new epoch's self capability, and seal the newcomer's
/// invitation. One transition is exactly one new epoch (epochs.md), so
/// admission mints a fresh epoch secret and every capability minted
/// here covers `1..=epoch` contiguously from the keyring plus the
/// fresh secret — no backward secrecy for admission, by design.
///
/// Authority comes from the pre-transition owner set (epochs.md rule
/// 3): only an owner admits, and the transition commits together with
/// the self capability in one batch, so a crash cannot leave the
/// admission durable while this device's own new-epoch material is
/// not. Transport of the transition and the capability wraps to other
/// devices is the catch-up/gossip obligation layer, not this call.
pub(super) fn admit_device(
    engine: &mut Engine,
    device: DeviceId,
    encryption_key: DeviceEncryptionKey,
) -> Result<AdmitOutcome, EngineError> {
    let tip = engine
        .log
        .known_state()
        .ok_or(EngineError::NoCanonicalMembership)?;
    let pre = engine
        .log
        .state_of(&tip.transition_id)
        .ok_or(EngineError::NoCanonicalMembership)?;
    if !pre.owners.contains(&engine.device) {
        return Err(EngineError::NotOwner);
    }
    if pre.members.contains(&device) {
        return Err(EngineError::AlreadyMember);
    }
    let epoch = next_epoch(tip.epoch)?;
    let secret = EpochSecret::generate()?;
    let mut members: Vec<DeviceId> = pre.members.iter().copied().collect();
    members.push(device);
    let owners: Vec<DeviceId> = pre.owners.iter().copied().collect();
    let mut transition = MembershipTransition::new(
        epoch,
        Some(tip.transition_id),
        Vec::new(),
        vec![Change::Admit(Admission {
            device,
            encryption_key,
        })],
        set_root(MEMBER_SET_CONTEXT, &members)?,
        set_root(OWNER_SET_CONTEXT, &owners)?,
        engine.device,
    )?;
    sign_transition(
        &mut transition,
        &engine.identity_secret.secret_key(),
        &engine.drive,
    );
    // Validate against a staged log: the live log stays pristine until
    // the batch commits, so any failure below (missing epoch material,
    // minting, sealing, the durable commit itself) leaves no phantom
    // tip for a retry to trip over. The post-commit `resync` adopts
    // the committed state.
    let mut staged = engine.log.clone();
    staged.observe(transition.clone());
    // Secrets `1..=epoch`: the keyring holds every past epoch (each
    // installed from an authorized capability), plus the fresh one.
    let rebuilt = engine.store.rebuild(engine.device)?;
    let mut secrets = Vec::with_capacity(epoch as usize);
    for past in 1..=tip.epoch {
        secrets.push(
            rebuilt
                .keyring
                .secret(past)
                .cloned()
                .ok_or(EngineError::MissingEpochSecret(past))?,
        );
    }
    secrets.push(secret.clone());
    let post = staged
        .state_of(&transition.transition_id())
        .ok_or(EngineError::NoCanonicalMembership)?;
    // The newcomer's grant, sealed into the invitation: it authorizes
    // against the admission state through the normal intake path once
    // the catch-up set delivers the transition, never here.
    let grant = Capability::mint(engine.drive, device, &post, &transition, secrets.clone())?;
    let invitation = seal_bootstrap(
        &engine.identity_secret,
        &engine.drive,
        device,
        &encryption_key,
        &genesis_bytes(engine)?,
        grant.wrap()?.as_bytes(),
    )?;
    // The self grant authorizes immediately: the authoring device is an
    // owner, hence a member of the state its own transition produces.
    let own = Capability::mint(engine.drive, engine.device, &post, &transition, secrets)?;
    let authorized =
        AuthorizedCapability::authorize(own, engine.drive, &staged, &transition.transition_id())?;
    // Delivery obligations join the same batch: the admission is not
    // durable without its catch-up. The newcomer gets the chain suffix
    // after genesis (genesis rode the invitation) plus its admission-
    // epoch wrap; every existing member gets the new tip plus its
    // new-epoch wrap, which is also the first production use of
    // transition gossip — nothing else transports transitions yet.
    let tip_id = transition.transition_id();
    let mut batch = vec![
        Fact::Transition(transition.clone()),
        Fact::Capability(authorized),
    ];
    let mut cursor = Some(tip_id);
    while let Some(id) = cursor {
        let t = staged
            .transition(&id)
            .ok_or(EngineError::NoCanonicalMembership)?;
        if t.epoch == 1 {
            break;
        }
        batch.push(Fact::TransitionQueued(id, device));
        cursor = t.prev;
    }
    batch.push(Fact::CapabilityQueued(epoch, device));
    for member in post.members.iter() {
        if *member == engine.device || *member == device {
            continue;
        }
        batch.push(Fact::TransitionQueued(tip_id, *member));
        batch.push(Fact::CapabilityQueued(epoch, *member));
    }
    engine.commit_facts(&batch)?;
    engine.resync()?;
    engine.add_epoch_key(
        epoch,
        Zeroizing::new(secret.control_key(&engine.drive, epoch)),
    );
    Ok(AdmitOutcome {
        transition,
        invitation,
    })
}

/// The epoch after the tip, checked: the authoring path already treats
/// the timestamp space as exhaustible, and the epoch counter is a
/// `u64` protocol field with the same boundary.
fn next_epoch(tip_epoch: u64) -> Result<u64, EngineError> {
    tip_epoch.checked_add(1).ok_or(EngineError::EpochExhausted)
}

/// The canonical genesis bytes the invitation anchors to: epoch 1 with
/// no predecessor. The tip's chain is fully observed whenever a
/// canonical tip exists (rootedness), so exactly one candidate qualifies
/// outside a genesis conflict — and a genesis conflict leaves no known
/// state, so callers never reach here without one.
fn genesis_bytes(engine: &Engine) -> Result<Vec<u8>, EngineError> {
    engine
        .log
        .observed_ids()
        .into_iter()
        .filter_map(|id| engine.log.transition(&id))
        .find(|t| t.epoch == 1 && t.prev.is_none())
        .map(MembershipTransition::canonical_bytes)
        .ok_or(EngineError::BadGenesis)
}

/// Send every undischarged transition- and capability-delivery
/// obligation, returning the number of envelopes sent this call.
/// Transitions go before capabilities (the ordering optimization:
/// intake holds membership-unseen capabilities pending, so either
/// order converges, but tip-first minimizes deferrals). Durable and
/// retryable like the announcement outbox: sealed bytes persist on
/// first send so retries are byte-identical, one delivered marker
/// commits per successful send, and a mid-loop failure leaves the rest
/// pending for the next call. Entries that cannot resolve now —
/// orphaned transitions, epochs without a canonical transition or
/// held secret, recipients no longer members — are skipped and stay
/// pending; transport failures return immediately.
pub(super) fn deliver_pending(
    engine: &mut Engine,
    mailbox: &mut impl Mailbox,
) -> Result<usize, EngineError> {
    // One validated delivery snapshot per pass: every read below comes
    // from this rebuild. Mid-pass commits only append Sealed and
    // Delivered facts — never new Queued pairs — so the frozen pending
    // lists stay exact, and an in-memory overlay absorbs newly sealed
    // bytes. No re-read per pair: a newcomer catch-up or a large
    // fan-out costs one log decode, not one per obligation.
    let rebuilt = engine.store.rebuild(engine.device)?;
    let mut sent = 0usize;
    sent += deliver_transitions(engine, mailbox, &rebuilt)?;
    sent += deliver_capabilities(engine, mailbox, &rebuilt)?;
    Ok(sent)
}

/// An epoch's control key, held or derived: the in-memory map first,
/// else derived from the delivery snapshot's keyring and installed. A
/// device that never held the epoch has no key and no secret, which
/// surfaces as [`EngineError::MissingEpochKey`].
fn control_key_for(
    engine: &mut Engine,
    keyring: &DriveKeyring,
    epoch: u64,
) -> Result<[u8; 32], EngineError> {
    if let Some(key) = engine.epoch_keys.get(&epoch) {
        return Ok(**key);
    }
    let secret = keyring
        .secret(epoch)
        .cloned()
        .ok_or(EngineError::MissingEpochKey(epoch))?;
    let key = secret.control_key(&engine.drive, epoch);
    engine.add_epoch_key(epoch, Zeroizing::new(key));
    Ok(key)
}

/// Send all pending transition obligations. One sealed envelope per
/// transition (recipient binding is the outer mailbox seal, so the
/// bytes are shared), one delivered marker per recipient send.
fn deliver_transitions(
    engine: &mut Engine,
    mailbox: &mut impl Mailbox,
    rebuilt: &Rebuilt,
) -> Result<usize, EngineError> {
    let mut pending = rebuilt.runtime.pending_transitions();
    pending.sort();
    let mut sealed_overlay: BTreeMap<TransitionId, Vec<u8>> = BTreeMap::new();
    let mut sent = 0usize;
    let mut index = 0usize;
    while index < pending.len() {
        let id = pending[index].0;
        // Clone out of the log borrow before the mutable seal step.
        let Some((epoch, canonical)) = engine
            .log
            .transition(&id)
            .map(|t| (t.epoch, t.canonical_bytes()))
        else {
            // Orphaned obligation: the transition never resolved. It
            // stays pending; skip the whole recipient run for it.
            while index < pending.len() && pending[index].0 == id {
                index += 1;
            }
            continue;
        };
        let sealed_bytes = match sealed_overlay.get(&id).cloned().or_else(|| {
            rebuilt
                .runtime
                .transition_sealed_bytes(id)
                .map(<[u8]>::to_vec)
        }) {
            Some(bytes) => bytes,
            None => {
                let key = control_key_for(engine, &rebuilt.keyring, epoch)?;
                let message = Message::MembershipTransition(TransitionPayload {
                    transition: canonical,
                });
                let sealed = seal_control(&key, &engine.drive, epoch, &message)?;
                let bytes = sealed.encode();
                // Validate before committing, mirroring the
                // announcement path: persisting oversize bytes would
                // poison the obligation past retry.
                crate::transport::mailbox::check_outbound_size(&bytes)?;
                engine.commit_facts(&[Fact::TransitionSealed(id, bytes.clone())])?;
                sealed_overlay.insert(id, bytes.clone());
                bytes
            }
        };
        // Every pair for this transition in the frozen pending list:
        // no re-read, since only this loop writes and it appends
        // Delivered facts, never new Queued ones.
        while index < pending.len() && pending[index].0 == id {
            let recipient = pending[index].1;
            let envelope = seal_for_recipient(&engine.identity_secret, recipient, &sealed_bytes)?;
            mailbox.send(envelope)?;
            engine.commit_facts(&[Fact::TransitionDelivered(id, recipient)])?;
            sent += 1;
            index += 1;
        }
    }
    Ok(sent)
}

/// Send all pending capability obligations. Each pair seals its own
/// recipient-specific wrap (the ECDH wrap binds one recipient, so
/// unlike transitions the sealed bytes are per-pair), minted at send
/// time from the keyring against the epoch's canonical transition —
/// the registered key comes from chain state, never from the caller —
/// so the bytes always reflect current membership.
fn deliver_capabilities(
    engine: &mut Engine,
    mailbox: &mut impl Mailbox,
    rebuilt: &Rebuilt,
) -> Result<usize, EngineError> {
    let mut pending = rebuilt.runtime.pending_capabilities();
    pending.sort();
    // The canonical chain's epoch-to-transition map, walked once:
    // capability wraps bind to the epoch's canonical transition.
    let mut chain: BTreeMap<u64, TransitionId> = BTreeMap::new();
    let mut cursor = engine.log.known_state().map(|state| state.transition_id);
    while let Some(id) = cursor {
        let Some(t) = engine.log.transition(&id) else {
            break;
        };
        chain.insert(t.epoch, id);
        cursor = t.prev;
    }
    let mut sealed_overlay: BTreeMap<(u64, DeviceId), Vec<u8>> = BTreeMap::new();
    let mut sent = 0usize;
    for (epoch, recipient) in pending {
        let Some(transition_id) = chain.get(&epoch).copied() else {
            continue;
        };
        let sealed_bytes = match sealed_overlay
            .get(&(epoch, recipient))
            .cloned()
            .or_else(|| {
                rebuilt
                    .runtime
                    .capability_sealed_bytes(epoch, recipient)
                    .map(<[u8]>::to_vec)
            }) {
            Some(bytes) => bytes,
            None => {
                let Some(state) = engine.log.state_of(&transition_id) else {
                    continue;
                };
                let Some(transition) = engine.log.transition(&transition_id) else {
                    continue;
                };
                let Some(wrap) = mint_wrap(
                    engine.drive,
                    &rebuilt.keyring,
                    &state,
                    transition,
                    recipient,
                ) else {
                    continue;
                };
                let key = control_key_for(engine, &rebuilt.keyring, epoch)?;
                let message = Message::Capability(CapabilityPayload {
                    device: recipient,
                    epoch,
                    wrapped: wrap,
                });
                let sealed = seal_control(&key, &engine.drive, epoch, &message)?;
                let bytes = sealed.encode();
                crate::transport::mailbox::check_outbound_size(&bytes)?;
                engine.commit_facts(&[Fact::CapabilitySealed(epoch, recipient, bytes.clone())])?;
                sealed_overlay.insert((epoch, recipient), bytes.clone());
                bytes
            }
        };
        let envelope = seal_for_recipient(&engine.identity_secret, recipient, &sealed_bytes)?;
        mailbox.send(envelope)?;
        engine.commit_facts(&[Fact::CapabilityDelivered(epoch, recipient)])?;
        sent += 1;
    }
    Ok(sent)
}

/// Mint one recipient's wrap for an epoch from the delivery
/// snapshot's keyring: `None` when the keyring lacks any secret
/// through the epoch (the pair stays pending for a later pass) or the
/// recipient is not a member of the epoch's state with a registered
/// key.
fn mint_wrap(
    drive: DriveId,
    keyring: &DriveKeyring,
    state: &crate::membership::MembershipState,
    transition: &MembershipTransition,
    recipient: DeviceId,
) -> Option<Vec<u8>> {
    let epoch = transition.epoch;
    let mut secrets = Vec::with_capacity(epoch as usize);
    for past in 1..=epoch {
        secrets.push(keyring.secret(past)?.clone());
    }
    let cap = Capability::mint(drive, recipient, state, transition, secrets).ok()?;
    Some(cap.wrap().ok()?.as_bytes().to_vec())
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
    use super::{admit_device, Engine};

    use wyrd_format::TransitionId;
    use zeroize::Zeroizing;

    use crate::control::bootstrap::open_bootstrap;
    use crate::control::seal;
    use crate::durable::{AuthorizedCapability, Fact};
    use crate::keys::capability::{Capability, WrappedCapability};
    use crate::keys::{DeviceEncryptionSecret, DeviceIdentitySecret, EpochSecret};
    use crate::membership::test_util::{drive as member_drive, key, Builder};
    use crate::runtime::test_util::{
        control_key, encryption_key, identity, identity_secret, transition_message, MemoryMailbox,
        MemoryRelay, TestDir,
    };
    use crate::transport::mailbox::seal_for_recipient;

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

    /// An owner engine holding epoch 1: genesis drained, epoch key
    /// installed, self capability committed (the production shape of a
    /// drive creator one transition in). Returns the engine plus the
    /// genesis id the admission must parent onto.
    fn owner_engine() -> (TestDir, Engine, TransitionId) {
        let dir = TestDir::new("admit-device");
        let (owner_sk, owner_id) = key(10);
        let owner_encryption = DeviceEncryptionSecret::from_bytes([0xE1; 32]).unwrap();
        let mut engine = Engine::open(
            dir.path.clone(),
            member_drive(),
            owner_id,
            "test-pass",
            identity_secret(&owner_sk),
            owner_encryption,
        )
        .unwrap();
        engine.add_epoch_key(1, Zeroizing::new(control_key(1)));
        let (_builder, genesis) = Builder::genesis(10);
        let sealed = seal(
            &control_key(1),
            &member_drive(),
            1,
            &transition_message(&genesis),
        )
        .unwrap();
        let (sender_sk, _) = identity(0x01);
        let mut relay = MemoryRelay::default();
        relay.push(seal_for_recipient(&sender_sk, owner_id, &sealed.encode()).unwrap());
        let mut mailbox = MemoryMailbox {
            relay: &mut relay,
            owner: owner_id,
        };
        let report = engine.drain(&mut mailbox).unwrap();
        assert_eq!(report.accepted, 1, "genesis drains");
        // The epoch-1 secret the control helper derives from, installed
        // as an authorized self capability the way drive creation does.
        let epoch1 = EpochSecret::from_bytes([0x07; 32]);
        let state = engine
            .log
            .state_of(&genesis.transition_id())
            .expect("genesis state");
        let registered = state
            .encryption_key_of(&owner_id)
            .copied()
            .expect("owner key registered");
        let cap = Capability::new(
            member_drive(),
            owner_id,
            registered,
            genesis.transition_id(),
            1,
            vec![epoch1],
        )
        .unwrap();
        let authorized = AuthorizedCapability::authorize(
            cap,
            member_drive(),
            &engine.log,
            &genesis.transition_id(),
        )
        .unwrap();
        engine
            .commit_facts(&[Fact::Capability(authorized)])
            .unwrap();
        (dir, engine, genesis.transition_id())
    }

    #[test]
    fn epoch_increment_checked_at_boundary() {
        assert_eq!(super::next_epoch(7).unwrap(), 8);
        assert!(matches!(
            super::next_epoch(u64::MAX),
            Err(super::EngineError::EpochExhausted)
        ));
    }

    #[test]
    fn failed_admit_leaves_no_phantom_tip() {
        use crate::durable::CrashStage;

        let (_dir, mut engine, _genesis) = owner_engine();
        let tip_before = engine.log.known_state().expect("tip").transition_id;
        let newcomer_id = identity(0x57).1;
        let newcomer_key = encryption_key(&DeviceEncryptionSecret::from_bytes([0xE7; 32]).unwrap());

        // Torn commit: Ok with nothing durable, like power loss. The
        // staged validation drops with the failed call — the live log
        // never observed the phantom.
        engine.crash_after(CrashStage::AfterWriteTemp);
        engine.admit_device(newcomer_id, newcomer_key).unwrap();
        assert_eq!(
            engine.log.known_state().expect("tip").transition_id,
            tip_before,
            "failed admit leaves no phantom tip"
        );

        // Retry on the same engine authorizes fresh and commits exactly
        // one admission.
        let outcome = engine.admit_device(newcomer_id, newcomer_key).unwrap();
        let tip = engine.log.known_state().expect("tip");
        assert_eq!(tip.transition_id, outcome.transition.transition_id());
        assert_eq!(tip.epoch, 2);
        assert!(engine
            .log
            .members_of(&tip.transition_id)
            .expect("state")
            .contains(&newcomer_id));
    }

    #[test]
    fn admit_device_authors_transition_and_invitation() {
        let (_dir, mut engine, genesis_id) = owner_engine();
        let newcomer = DeviceIdentitySecret::generate().unwrap();
        let newcomer_encryption = DeviceEncryptionSecret::generate().unwrap();
        let newcomer_id = {
            use secp256k1::{Keypair, XOnlyPublicKey, SECP256K1};
            let kp = Keypair::from_secret_key(SECP256K1, &newcomer.secret_key());
            let (xonly, _) = XOnlyPublicKey::from_keypair(&kp);
            wyrd_format::DeviceId::from_bytes(xonly.serialize())
        };
        let newcomer_key = encryption_key(&newcomer_encryption);

        let outcome = admit_device(&mut engine, newcomer_id, newcomer_key).unwrap();
        assert_eq!(outcome.transition.epoch, 2, "admission opens a new epoch");
        assert_eq!(outcome.transition.prev, Some(genesis_id));
        let state = engine.log.known_state().expect("canonical tip");
        assert_eq!(state.transition_id, outcome.transition.transition_id());
        assert!(
            engine
                .log
                .members_of(&state.transition_id)
                .expect("post state")
                .contains(&newcomer_id),
            "newcomer is a member of the admission state"
        );

        // The invitation opens under the newcomer's encryption secret
        // and grants both epochs contiguously.
        let invitation = open_bootstrap(&newcomer_encryption, &outcome.invitation).unwrap();
        assert_eq!(invitation.invitee, newcomer_id);
        let grant = WrappedCapability::from_bytes(invitation.capability)
            .unwrap(&newcomer_encryption)
            .unwrap();
        assert_eq!(grant.up_to_epoch(), 2, "contiguous 1..=2 coverage");

        // Round trip through the step-1 join path: the newcomer accepts
        // the invitation into a draining engine anchored at genesis.
        let join_dir = TestDir::new("admit-device-join");
        let joined = Engine::accept_invitation(
            join_dir.path.clone(),
            "test-pass",
            newcomer,
            newcomer_encryption,
            &outcome.invitation,
        )
        .unwrap();
        assert_eq!(joined.drive(), member_drive());
        assert!(
            joined.log.known_state().is_some(),
            "join commits the invitation genesis"
        );

        // Admitting the same device twice is refused: the second grant
        // would have no state to authorize against.
        assert!(matches!(
            admit_device(&mut engine, newcomer_id, newcomer_key),
            Err(super::EngineError::AlreadyMember)
        ));
    }

    #[test]
    fn admit_device_requires_owner_authority() {
        let (_dir, engine, _genesis) = owner_engine();
        // Reopen as a non-member device sharing the store directory is
        // refused by the lock; instead drain genesis into a fresh
        // non-owner engine and attempt the admit there.
        let dir = TestDir::new("admit-device-stranger");
        let (stranger_sk, stranger_id) = identity(0x55);
        let stranger_encryption = DeviceEncryptionSecret::from_bytes([0xE5; 32]).unwrap();
        let mut stranger = Engine::open(
            dir.path.clone(),
            member_drive(),
            stranger_id,
            "test-pass",
            stranger_sk,
            stranger_encryption,
        )
        .unwrap();
        stranger.add_epoch_key(1, Zeroizing::new(control_key(1)));
        let (_builder, genesis) = Builder::genesis(10);
        let sealed = seal(
            &control_key(1),
            &member_drive(),
            1,
            &transition_message(&genesis),
        )
        .unwrap();
        let (sender_sk, _) = identity(0x01);
        let mut relay = MemoryRelay::default();
        relay.push(seal_for_recipient(&sender_sk, stranger_id, &sealed.encode()).unwrap());
        let mut mailbox = MemoryMailbox {
            relay: &mut relay,
            owner: stranger_id,
        };
        stranger.drain(&mut mailbox).unwrap();
        let newcomer_key = encryption_key(&DeviceEncryptionSecret::from_bytes([0xE6; 32]).unwrap());
        assert!(matches!(
            admit_device(&mut stranger, identity(0x56).1, newcomer_key),
            Err(super::EngineError::NotOwner)
        ));
        let _ = engine;
    }

    /// The device id an identity secret names.
    fn device_of(identity: &DeviceIdentitySecret) -> wyrd_format::DeviceId {
        use secp256k1::{Keypair, XOnlyPublicKey, SECP256K1};
        let kp = Keypair::from_secret_key(SECP256K1, &identity.secret_key());
        let (xonly, _) = XOnlyPublicKey::from_keypair(&kp);
        wyrd_format::DeviceId::from_bytes(xonly.serialize())
    }

    #[test]
    fn admit_queues_and_delivers_newcomer_catch_up() {
        let (_dir, mut engine, _genesis) = owner_engine();
        let (owner_sk, owner_id) = key(10);
        let newcomer = DeviceIdentitySecret::generate().unwrap();
        let newcomer_encryption = DeviceEncryptionSecret::generate().unwrap();
        let newcomer_id = device_of(&newcomer);
        let outcome = engine
            .admit_device(newcomer_id, encryption_key(&newcomer_encryption))
            .unwrap();
        let admission_id = outcome.transition.transition_id();

        // The admit batch queues the chain suffix and the admission-
        // epoch wrap for the newcomer, durably.
        let rebuilt = engine.store.rebuild(engine.device()).unwrap();
        assert!(
            rebuilt
                .runtime
                .pending_transitions()
                .contains(&(admission_id, newcomer_id)),
            "admission transition queued for the newcomer"
        );
        assert!(
            rebuilt
                .runtime
                .pending_capabilities()
                .contains(&(2, newcomer_id)),
            "admission-epoch capability queued for the newcomer"
        );

        // Restart before the first send: the reopened engine holds no
        // in-memory epoch keys, so delivery derives them from the
        // keyring — the crash window the durability requirement
        // closes.
        engine.release_store_lock();
        let mut engine = Engine::open(
            _dir.path.clone(),
            member_drive(),
            owner_id,
            "test-pass",
            identity_secret(&owner_sk),
            DeviceEncryptionSecret::from_bytes([0xE1; 32]).unwrap(),
        )
        .unwrap();
        let mut relay = MemoryRelay::default();
        let mut sender = MemoryMailbox {
            relay: &mut relay,
            owner: owner_id,
        };
        let rebuilds_before = engine.store.rebuild_count();
        let sent = engine.deliver_pending(&mut sender).unwrap();
        assert_eq!(sent, 2, "transition plus capability");
        assert_eq!(
            engine.store.rebuild_count() - rebuilds_before,
            1,
            "one delivery snapshot per pass, not one per pair"
        );
        let rebuilt = engine.store.rebuild(engine.device()).unwrap();
        assert!(
            rebuilt.runtime.pending_transitions().is_empty(),
            "transition obligations discharged"
        );
        assert!(
            rebuilt.runtime.pending_capabilities().is_empty(),
            "capability obligations discharged"
        );

        // The newcomer joins from the invitation, restarts before
        // draining, then drains the pushed set: the pending-
        // invitation record re-derives the control keys on open, so
        // the join survives process loss mid-catch-up.
        let join_dir = TestDir::new("admit-deliver-join");
        let joined = Engine::accept_invitation(
            join_dir.path.clone(),
            "test-pass",
            newcomer.clone(),
            newcomer_encryption.clone(),
            &outcome.invitation,
        )
        .unwrap();
        joined.release_store_lock();
        let mut joined = Engine::open(
            join_dir.path.clone(),
            member_drive(),
            newcomer_id,
            "test-pass",
            newcomer,
            newcomer_encryption,
        )
        .unwrap();
        let mut receiver = MemoryMailbox {
            relay: &mut relay,
            owner: newcomer_id,
        };
        let report = joined.drain(&mut receiver).unwrap();
        assert_eq!(report.skipped, 0, "invitation keys open every message");
        let state = joined.log.known_state().expect("canonical tip");
        assert_eq!(state.epoch, 2, "catch-up reaches the admission");
        assert!(
            joined
                .log
                .members_of(&state.transition_id)
                .expect("post state")
                .contains(&newcomer_id),
            "newcomer observes its own admission"
        );
        let held = joined.store.rebuild(newcomer_id).unwrap();
        assert!(
            held.keyring.secret(2).is_some(),
            "admission-epoch secret installed from the pushed wrap"
        );
    }
}

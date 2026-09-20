//! Commit envelope and fact records: tags, limits, hashing, encoding,
//! decoding, and the capability/manifest record codecs. The commit
//! format and CURRENT protocol are byte-for-byte stable; unknown record
//! tags are skipped for forward compatibility.
//!
//! v0 development note: fact *payloads* are not yet migration-stable —
//! the manifest record gained its transport column (object-model.md
//! decision 26) by changing the layout in place. A store whose manifest
//! facts predate the change fails its rebuild loudly (an unparsable
//! record poisons the commit file, so `open`/`resync` refuse it), which
//! is the deliberate pre-alpha contract: fail closed on old formats,
//! no silent interpretation, no migration until v1 freezes the format.

use wyrd_format::{
    BaoRoot, ContentId, DeviceId, DriveId, Manifest, MembershipTransition, ObjectKind, Snapshot,
    SnapshotId, StorageId, TransitionId,
};

use super::{DurableError, Fact};
use crate::control::message::{ControlKind, Message};
use crate::control::{ControlMessageId, SealedControl, SnapshotAnnouncement};
use crate::keys::capability::{encoding, Capability};

use crate::keys::{aead, random_bytes};
use crate::runtime::{ManifestRecord, MaterializationState, RuntimeError};

// --- record tags -----------------------------------------------------------

pub(super) const COMMIT_VERSION: u8 = 0x00;
pub(super) const TAG_TRANSITION: u8 = 0x01;
const TAG_CAPABILITY: u8 = 0x02;
const TAG_ANNOUNCEMENT: u8 = 0x03;
const TAG_MANIFEST: u8 = 0x04;
const TAG_LOCAL_OBJECT: u8 = 0x05;
const TAG_MATERIALIZATION: u8 = 0x06;
const TAG_CONTROL_MESSAGE: u8 = 0x07;
const TAG_OBJECT_REMOVED: u8 = 0x08;
/// Crate-visible for the raw-commit test seam: the planted-forgery tests
/// encode records no typed `Fact` can carry.
pub(crate) const TAG_SNAPSHOT_BODY: u8 = 0x09;
/// One announcement obligation: snapshot id (32) ‖ recipient (32).
const TAG_ANNOUNCEMENT_QUEUED: u8 = 0x0A;
/// Sealed announcement bytes: snapshot id (32) ‖ sealed control bytes.
/// Crate-visible for the raw-commit test seam.
pub(crate) const TAG_ANNOUNCEMENT_SEALED: u8 = 0x0B;
/// One discharged obligation: snapshot id (32) ‖ recipient (32).
const TAG_ANNOUNCEMENT_DELIVERED: u8 = 0x0C;
/// One transition-delivery obligation: transition id (32) ‖ recipient (32).
const TAG_TRANSITION_QUEUED: u8 = 0x0D;
/// Sealed transition bytes: transition id (32) ‖ sealed control bytes.
const TAG_TRANSITION_SEALED: u8 = 0x0E;
/// One discharged transition obligation: transition id (32) ‖ recipient (32).
const TAG_TRANSITION_DELIVERED: u8 = 0x0F;
/// One capability-delivery obligation: epoch u64 LE (8) ‖ recipient (32).
const TAG_CAPABILITY_QUEUED: u8 = 0x10;
/// Sealed capability bytes: epoch u64 LE (8) ‖ recipient (32) ‖ sealed
/// control bytes.
const TAG_CAPABILITY_SEALED: u8 = 0x11;
/// One discharged capability obligation: epoch u64 LE (8) ‖ recipient (32).
const TAG_CAPABILITY_DELIVERED: u8 = 0x12;
/// Pending invitation material: raw wrapped-capability bytes (non-empty).
const TAG_BOOTSTRAP_PENDING: u8 = 0x13;

/// Record tags this version understands. Unknown tags are skipped on
/// decode for forward compatibility.
const KNOWN_TAGS: [u8; 19] = [
    TAG_TRANSITION,
    TAG_CAPABILITY,
    TAG_ANNOUNCEMENT,
    TAG_MANIFEST,
    TAG_LOCAL_OBJECT,
    TAG_MATERIALIZATION,
    TAG_CONTROL_MESSAGE,
    TAG_OBJECT_REMOVED,
    TAG_SNAPSHOT_BODY,
    TAG_ANNOUNCEMENT_QUEUED,
    TAG_ANNOUNCEMENT_SEALED,
    TAG_ANNOUNCEMENT_DELIVERED,
    TAG_TRANSITION_QUEUED,
    TAG_TRANSITION_SEALED,
    TAG_TRANSITION_DELIVERED,
    TAG_CAPABILITY_QUEUED,
    TAG_CAPABILITY_SEALED,
    TAG_CAPABILITY_DELIVERED,
    TAG_BOOTSTRAP_PENDING,
];

/// Resource limits: a corrupt local file must not cause unbounded
/// allocation. Commits hold small canonical facts; anything beyond
/// these bounds is damage, not data.
pub(super) const MAX_COMMIT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RECORDS_PER_COMMIT: usize = 65_536;
const MAX_RECORD_BYTES: usize = 64 * 1024 * 1024;

/// Domain tag for the commit-chain hash: integrity and ordering of the
/// durable log itself, not confidentiality.
const COMMIT_HASH_DOMAIN: &[u8] = b"wyrd durable commit v1";
// The chain genesis: commit 1 links from all-zero bytes.

/// AAD domain for the store key envelope (keystore-shaped, own domain so
/// a wrapped store key can never open as a root or device secret).
pub(super) const STORE_KEY_AAD: &[u8] = b"wyrd store key v1";
/// AAD domain for sealed capabilities at rest. The store key is fresh
/// random per store, so no cross-context confusion is possible; the
/// distinct domain states the intent anyway.
const CAPABILITY_STORE_AAD: &[u8] = b"wyrd capability store v1";

/// Commit header length: version (1) + sequence (8) + previous hash (32).
/// The records section hashed into the trailer starts right after it.
const HEADER_LEN: usize = 41;

/// The chain hash of one commit: domain tag, drive id, sequence,
/// previous hash, and the exact serialized records section. Binds
/// integrity and ordering; confidentiality is not the point (secrets
/// carry their own AEAD inside capability records).
fn commit_hash(drive: &DriveId, seq: u64, prev: &[u8; 32], records: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(COMMIT_HASH_DOMAIN);
    hasher.update(drive.as_bytes());
    hasher.update(&seq.to_le_bytes());
    hasher.update(prev);
    hasher.update(records);
    *hasher.finalize().as_bytes()
}

/// Serialize one commit and hash it: header (version, sequence,
/// previous hash) + records + trailer hash. Crate-visible for the
/// raw-commit test seam alongside `TAG_SNAPSHOT_BODY`.
pub(crate) fn encode_commit(
    drive: &DriveId,
    seq: u64,
    prev: &[u8; 32],
    records: &[(u8, Vec<u8>)],
) -> (Vec<u8>, [u8; 32]) {
    let mut records_bytes = Vec::new();
    records_bytes.extend_from_slice(&(records.len() as u32).to_le_bytes());
    for (tag, record) in records {
        records_bytes.push(*tag);
        records_bytes.extend_from_slice(&(record.len() as u32).to_le_bytes());
        records_bytes.extend_from_slice(record);
    }
    let hash = commit_hash(drive, seq, prev, &records_bytes);
    let mut out = Vec::with_capacity(HEADER_LEN + records_bytes.len() + 32);
    out.push(COMMIT_VERSION);
    out.extend_from_slice(&seq.to_le_bytes());
    out.extend_from_slice(prev);
    out.extend_from_slice(&records_bytes);
    out.extend_from_slice(&hash);
    (out, hash)
}

/// The AAD for sealed capabilities: domain plus drive. Device and
/// epoch live inside the sealed plaintext and are cross-checked on
/// open (exact length, epoch/count agreement, `Capability::new`
/// shape, rebuild re-validation); the fresh random nonce per record
/// already separates records under the store key.
fn capability_aad(drive: &DriveId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(CAPABILITY_STORE_AAD.len() + 32);
    aad.extend_from_slice(CAPABILITY_STORE_AAD);
    aad.extend_from_slice(drive.as_bytes());
    aad
}

/// Encode one fact to its (tag, record) pair, running the commit-time
/// checks: manifest identity is derived (fail the commit, store
/// untouched), capabilities arrive pre-authorized by type.
pub(super) fn encode_fact(
    store_key: &[u8],
    drive: &DriveId,
    fact: &Fact,
) -> Result<(u8, Vec<u8>), DurableError> {
    match fact {
        Fact::Transition(t) => Ok((TAG_TRANSITION, t.canonical_bytes())),
        Fact::Capability(authorized) => {
            let cap = authorized.capability();
            let pt = encoding::plaintext_bytes(cap);
            let mut nonce = [0u8; 24];
            random_bytes(&mut nonce)?;
            let aad = capability_aad(drive);
            let ct = aead::seal(store_key, &nonce, pt.as_slice(), &aad)?;
            let mut record = Vec::with_capacity(24 + ct.len());
            record.extend_from_slice(&nonce);
            record.extend_from_slice(&ct);
            Ok((TAG_CAPABILITY, record))
        }
        Fact::Announcement(a) => {
            let bytes = Message::SnapshotAnnouncement(a.clone()).encode_payload();
            Ok((TAG_ANNOUNCEMENT, bytes))
        }
        Fact::SnapshotBody(authorized) => Ok((TAG_SNAPSHOT_BODY, authorized.snapshot().encode())),
        Fact::Manifest(record) => {
            let derived =
                ContentId::derive(ObjectKind::Manifest, &record.manifest.canonical_bytes());
            if record.manifest_id != derived {
                return Err(DurableError::Runtime(
                    RuntimeError::ManifestIdentityMismatch {
                        manifest: record.manifest_id,
                        derived,
                    },
                ));
            }
            // Same gate as `RuntimeState::record_manifest` and
            // `parse_manifest_record`: rejecting here fails the commit
            // with the store untouched, instead of persisting a fact
            // replay would later refuse as corruption.
            if !crate::runtime::transport_is_represented(record) {
                return Err(DurableError::Runtime(
                    RuntimeError::TransportNotRepresented {
                        manifest: record.manifest_id,
                    },
                ));
            }
            let mut bytes = Vec::new();
            bytes.extend_from_slice(record.manifest_id.as_bytes());
            bytes.push(u8::from(record.is_root));
            bytes.extend_from_slice(record.transport.as_bytes());
            bytes.extend_from_slice(&(record.representations.len() as u32).to_le_bytes());
            for (id, transport) in &record.representations {
                bytes.extend_from_slice(id.as_bytes());
                bytes.extend_from_slice(transport.as_bytes());
            }
            bytes.extend_from_slice(&record.manifest.canonical_bytes());
            Ok((TAG_MANIFEST, bytes))
        }
        Fact::LocalObject(id) => Ok((TAG_LOCAL_OBJECT, id.as_bytes().to_vec())),
        Fact::ObjectRemoved(id) => Ok((TAG_OBJECT_REMOVED, id.as_bytes().to_vec())),
        Fact::Materialization(id, state) => {
            let byte = match state {
                MaterializationState::RemoteOnly => 0,
                MaterializationState::Cached => 1,
                MaterializationState::Pinned => 2,
            };
            let mut bytes = Vec::with_capacity(33);
            bytes.extend_from_slice(id.as_bytes());
            bytes.push(byte);
            Ok((TAG_MATERIALIZATION, bytes))
        }
        Fact::ControlMessage(id) => Ok((TAG_CONTROL_MESSAGE, id.as_bytes().to_vec())),
        Fact::AnnouncementQueued(snapshot, recipient) => {
            let mut bytes = Vec::with_capacity(64);
            bytes.extend_from_slice(snapshot.as_bytes());
            bytes.extend_from_slice(recipient.as_bytes());
            Ok((TAG_ANNOUNCEMENT_QUEUED, bytes))
        }
        Fact::AnnouncementSealed(snapshot, sealed) => {
            // Same structural gate as the decoder, at commit time:
            // only a decodable announcement-kind envelope commits, so
            // a malformed sealed fact fails here with the store
            // untouched instead of poisoning a later rebuild. (The
            // size gate lives in the outbox call path, which checks
            // before committing.)
            let decoded = SealedControl::decode(sealed)
                .ok()
                .filter(|envelope| envelope.kind == ControlKind::SnapshotAnnouncement);
            if decoded.is_none() {
                return Err(DurableError::InvalidOutbox);
            }
            let mut bytes = Vec::with_capacity(32 + sealed.len());
            bytes.extend_from_slice(snapshot.as_bytes());
            bytes.extend_from_slice(sealed);
            Ok((TAG_ANNOUNCEMENT_SEALED, bytes))
        }
        Fact::AnnouncementDelivered(snapshot, recipient) => {
            let mut bytes = Vec::with_capacity(64);
            bytes.extend_from_slice(snapshot.as_bytes());
            bytes.extend_from_slice(recipient.as_bytes());
            Ok((TAG_ANNOUNCEMENT_DELIVERED, bytes))
        }
        Fact::TransitionQueued(id, recipient) => {
            let mut bytes = Vec::with_capacity(64);
            bytes.extend_from_slice(id.as_bytes());
            bytes.extend_from_slice(recipient.as_bytes());
            Ok((TAG_TRANSITION_QUEUED, bytes))
        }
        Fact::TransitionSealed(id, sealed) => {
            // Same structural gate as the announcement variant, at
            // commit time: only a decodable transition-kind envelope
            // commits, so a malformed sealed fact fails here with the
            // store untouched instead of poisoning a later rebuild.
            let decoded = SealedControl::decode(sealed)
                .ok()
                .filter(|envelope| envelope.kind == ControlKind::MembershipTransition);
            if decoded.is_none() {
                return Err(DurableError::InvalidOutbox);
            }
            let mut bytes = Vec::with_capacity(32 + sealed.len());
            bytes.extend_from_slice(id.as_bytes());
            bytes.extend_from_slice(sealed);
            Ok((TAG_TRANSITION_SEALED, bytes))
        }
        Fact::TransitionDelivered(id, recipient) => {
            let mut bytes = Vec::with_capacity(64);
            bytes.extend_from_slice(id.as_bytes());
            bytes.extend_from_slice(recipient.as_bytes());
            Ok((TAG_TRANSITION_DELIVERED, bytes))
        }
        Fact::CapabilityQueued(epoch, recipient) => {
            let mut bytes = Vec::with_capacity(40);
            bytes.extend_from_slice(&epoch.to_le_bytes());
            bytes.extend_from_slice(recipient.as_bytes());
            Ok((TAG_CAPABILITY_QUEUED, bytes))
        }
        Fact::CapabilitySealed(epoch, recipient, sealed) => {
            // Commit-time correlation gate: the envelope must decode,
            // carry a capability, and be sealed under the obligation's
            // own epoch — delivery seals each obligation under its
            // epoch key, so a foreign epoch here means a swapped
            // pairing. The recipient binding lives inside the sealed
            // payload (keys required) and is verified at send time,
            // where the sealing key is held, before the obligation
            // discharges.
            let decoded = SealedControl::decode(sealed).ok().filter(|envelope| {
                envelope.kind == ControlKind::Capability && envelope.epoch == *epoch
            });
            if decoded.is_none() {
                return Err(DurableError::InvalidOutbox);
            }
            let mut bytes = Vec::with_capacity(40 + sealed.len());
            bytes.extend_from_slice(&epoch.to_le_bytes());
            bytes.extend_from_slice(recipient.as_bytes());
            bytes.extend_from_slice(sealed);
            Ok((TAG_CAPABILITY_SEALED, bytes))
        }
        Fact::CapabilityDelivered(epoch, recipient) => {
            let mut bytes = Vec::with_capacity(40);
            bytes.extend_from_slice(&epoch.to_le_bytes());
            bytes.extend_from_slice(recipient.as_bytes());
            Ok((TAG_CAPABILITY_DELIVERED, bytes))
        }
        Fact::BootstrapPending(wrapped) => {
            // Opaque to the codec: the bytes open only under the
            // invitee's encryption secret, which replay does not hold.
            // Non-empty is the only structural gate; intake validates
            // the grant itself once the admission transition lands.
            if wrapped.is_empty() {
                return Err(DurableError::InvalidOutbox);
            }
            Ok((TAG_BOOTSTRAP_PENDING, wrapped.clone()))
        }
    }
}

/// Decode and verify one commit file, returning the decoded facts and
/// the verified trailer hash. Every structural failure — wrong version,
/// sequence or previous-hash mismatch, over-limit counts or lengths,
/// malformed known records, trailing bytes, a hash mismatch — fails the
/// file: inside the committed prefix there is no such thing as an
/// ignorable commit. Unknown record tags are the only skips, for
/// forward compatibility.
pub(super) fn decode_commit_file(
    drive: &DriveId,
    store_key: &[u8],
    bytes: &[u8],
    seq: u64,
    prev_hash: &[u8; 32],
) -> Result<(Vec<DecodedFact>, [u8; 32]), DurableError> {
    let corrupt = || DurableError::CorruptCommit(seq);
    let mut pos = 0usize;
    let take = |pos: &mut usize, n: usize| -> Option<&[u8]> {
        let end = pos.checked_add(n)?;
        if end > bytes.len() {
            return None;
        }
        let slice = &bytes[*pos..end];
        *pos = end;
        Some(slice)
    };
    if take(&mut pos, 1).ok_or_else(&corrupt)? != [COMMIT_VERSION] {
        return Err(corrupt());
    }
    if u64::from_le_bytes(
        take(&mut pos, 8)
            .ok_or_else(&corrupt)?
            .try_into()
            .expect("take"),
    ) != seq
    {
        return Err(corrupt());
    }
    if take(&mut pos, 32).ok_or_else(&corrupt)? != prev_hash {
        return Err(corrupt());
    }
    let count = u32::from_le_bytes(
        take(&mut pos, 4)
            .ok_or_else(&corrupt)?
            .try_into()
            .expect("take"),
    ) as usize;
    if count > MAX_RECORDS_PER_COMMIT {
        return Err(corrupt());
    }
    let mut out = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        let tag = take(&mut pos, 1).ok_or_else(&corrupt)?[0];
        let len = u32::from_le_bytes(
            take(&mut pos, 4)
                .ok_or_else(&corrupt)?
                .try_into()
                .expect("take"),
        ) as usize;
        if len > MAX_RECORD_BYTES {
            return Err(corrupt());
        }
        let record = take(&mut pos, len).ok_or_else(&corrupt)?.to_vec();
        if !KNOWN_TAGS.contains(&tag) {
            continue;
        }
        let fact = decode_record(drive, store_key, tag, &record).ok_or_else(&corrupt)?;
        out.push(fact);
    }
    // The trailer hash sits exactly at the end: no trailing bytes.
    if pos.checked_add(32) != Some(bytes.len()) {
        return Err(corrupt());
    }
    let expected = commit_hash(drive, seq, prev_hash, &bytes[HEADER_LEN..pos]);
    let trailer: &[u8; 32] = bytes[pos..].try_into().expect("trailer bounds");
    if trailer != &expected {
        return Err(corrupt());
    }
    Ok((out, expected))
}

/// Decode one known record: `None` poisons the file (the caller
/// filters unknown tags before calling).
fn decode_record(drive: &DriveId, store_key: &[u8], tag: u8, record: &[u8]) -> Option<DecodedFact> {
    match tag {
        TAG_TRANSITION => {
            let t = MembershipTransition::from_canonical_bytes(record).ok()?;
            Some(DecodedFact::Transition(t))
        }
        TAG_CAPABILITY => {
            if record.len() < 24 + 16 {
                return None;
            }
            let nonce: &[u8; 24] = record[..24].try_into().ok()?;
            let pt = aead::open(store_key, nonce, &record[24..], &capability_aad(drive)).ok()?;
            let cap = encoding::parse_plaintext(&pt)?;
            if cap.drive != *drive {
                return None;
            }
            Some(DecodedFact::Capability(cap))
        }
        TAG_ANNOUNCEMENT => {
            let Message::SnapshotAnnouncement(a) =
                Message::decode_payload(ControlKind::SnapshotAnnouncement, record).ok()?
            else {
                return None;
            };
            Some(DecodedFact::Announcement(a))
        }
        TAG_SNAPSHOT_BODY => Some(DecodedFact::SnapshotBody(Snapshot::decode(record).ok()?)),
        TAG_MANIFEST => Some(DecodedFact::Manifest(parse_manifest_record(record)?)),
        TAG_LOCAL_OBJECT => {
            let id = ContentId::from_bytes(record.try_into().ok()?);
            Some(DecodedFact::LocalObject(id))
        }
        TAG_OBJECT_REMOVED => {
            let id = ContentId::from_bytes(record.try_into().ok()?);
            Some(DecodedFact::ObjectRemoved(id))
        }
        TAG_MATERIALIZATION => {
            if record.len() != 33 {
                return None;
            }
            let id = ContentId::from_bytes(record[..32].try_into().ok()?);
            let state = match record[32] {
                0 => MaterializationState::RemoteOnly,
                1 => MaterializationState::Cached,
                2 => MaterializationState::Pinned,
                _ => return None,
            };
            Some(DecodedFact::Materialization(id, state))
        }
        TAG_CONTROL_MESSAGE => {
            let raw: [u8; 32] = record.try_into().ok()?;
            Some(DecodedFact::ControlMessage(ControlMessageId::from_bytes(
                raw,
            )))
        }
        TAG_ANNOUNCEMENT_QUEUED => {
            if record.len() != 64 {
                return None;
            }
            let snapshot = SnapshotId::from_bytes(record[..32].try_into().ok()?);
            let recipient = DeviceId::from_bytes(record[32..64].try_into().ok()?);
            Some(DecodedFact::AnnouncementQueued(snapshot, recipient))
        }
        TAG_ANNOUNCEMENT_SEALED => {
            if record.len() <= 32 {
                return None;
            }
            let snapshot = SnapshotId::from_bytes(record[..32].try_into().ok()?);
            // Structural check only: the bytes must decode as a sealed
            // announcement envelope. Opening (and cross-checking
            // snapshot/author/epoch) needs epoch keys Replay does not
            // hold — that verification belongs to intake, not to the
            // structural rebuild. Garbage fails the file, like any
            // malformed known record.
            let sealed = SealedControl::decode(&record[32..]).ok()?;
            if sealed.kind != ControlKind::SnapshotAnnouncement {
                return None;
            }
            Some(DecodedFact::AnnouncementSealed(
                snapshot,
                record[32..].to_vec(),
            ))
        }
        TAG_ANNOUNCEMENT_DELIVERED => {
            if record.len() != 64 {
                return None;
            }
            let snapshot = SnapshotId::from_bytes(record[..32].try_into().ok()?);
            let recipient = DeviceId::from_bytes(record[32..64].try_into().ok()?);
            Some(DecodedFact::AnnouncementDelivered(snapshot, recipient))
        }
        TAG_TRANSITION_QUEUED => {
            if record.len() != 64 {
                return None;
            }
            let id = TransitionId::from_bytes(record[..32].try_into().ok()?);
            let recipient = DeviceId::from_bytes(record[32..64].try_into().ok()?);
            Some(DecodedFact::TransitionQueued(id, recipient))
        }
        TAG_TRANSITION_SEALED => {
            if record.len() <= 32 {
                return None;
            }
            let id = TransitionId::from_bytes(record[..32].try_into().ok()?);
            // Structural check only, mirroring the announcement
            // variant: kind must be a transition envelope. Opening
            // needs epoch keys replay does not hold.
            let sealed = SealedControl::decode(&record[32..]).ok()?;
            if sealed.kind != ControlKind::MembershipTransition {
                return None;
            }
            Some(DecodedFact::TransitionSealed(id, record[32..].to_vec()))
        }
        TAG_TRANSITION_DELIVERED => {
            if record.len() != 64 {
                return None;
            }
            let id = TransitionId::from_bytes(record[..32].try_into().ok()?);
            let recipient = DeviceId::from_bytes(record[32..64].try_into().ok()?);
            Some(DecodedFact::TransitionDelivered(id, recipient))
        }
        TAG_CAPABILITY_QUEUED => {
            if record.len() != 40 {
                return None;
            }
            let epoch = u64::from_le_bytes(record[..8].try_into().ok()?);
            let recipient = DeviceId::from_bytes(record[8..40].try_into().ok()?);
            Some(DecodedFact::CapabilityQueued(epoch, recipient))
        }
        TAG_CAPABILITY_SEALED => {
            if record.len() <= 40 {
                return None;
            }
            let epoch = u64::from_le_bytes(record[..8].try_into().ok()?);
            let recipient = DeviceId::from_bytes(record[8..40].try_into().ok()?);
            // Structural check only, mirroring the announcement
            // variant: kind must be a capability envelope.
            let sealed = SealedControl::decode(&record[40..]).ok()?;
            if sealed.kind != ControlKind::Capability {
                return None;
            }
            Some(DecodedFact::CapabilitySealed(
                epoch,
                recipient,
                record[40..].to_vec(),
            ))
        }
        TAG_CAPABILITY_DELIVERED => {
            if record.len() != 40 {
                return None;
            }
            let epoch = u64::from_le_bytes(record[..8].try_into().ok()?);
            let recipient = DeviceId::from_bytes(record[8..40].try_into().ok()?);
            Some(DecodedFact::CapabilityDelivered(epoch, recipient))
        }
        TAG_BOOTSTRAP_PENDING => {
            if record.is_empty() {
                return None;
            }
            Some(DecodedFact::BootstrapPending(record.to_vec()))
        }
        // Unreachable: the caller filters unknown tags.
        _ => None,
    }
}

fn parse_manifest_record(record: &[u8]) -> Option<ManifestRecord> {
    if record.len() < 32 + 1 + 32 + 4 {
        return None;
    }
    let manifest_id = ContentId::from_bytes(record[0..32].try_into().ok()?);
    let is_root = match record[32] {
        0 => false,
        1 => true,
        _ => return None,
    };
    let transport = BaoRoot::from_bytes(record[33..65].try_into().ok()?);
    let storage_count = u32::from_le_bytes(record[65..69].try_into().ok()?) as usize;
    let mut pos: usize = 69;
    let mut representations = std::collections::BTreeMap::new();
    for _ in 0..storage_count {
        let end = pos.checked_add(64)?;
        if end > record.len() {
            return None;
        }
        let storage = StorageId::from_bytes(record[pos..pos + 32].try_into().ok()?);
        let transport = BaoRoot::from_bytes(record[pos + 32..end].try_into().ok()?);
        // The encoder emits unique map keys, so a repeated StorageId is
        // malformed input; silently keeping one entry would lose the
        // representation the record actually committed to.
        if representations.insert(storage, transport).is_some() {
            return None;
        }
        pos = end;
    }
    let manifest = Manifest::from_canonical_bytes(&record[pos..]).ok()?;
    let derived = ContentId::derive(ObjectKind::Manifest, &manifest.canonical_bytes());
    if manifest_id != derived {
        return None;
    }
    // Transport/representation consistency (same predicate as
    // `RuntimeState::record_manifest`, so the gates cannot drift): a
    // record naming representations must name its eager root among
    // them. An empty map is a representationless root and stays
    // decodable.
    let record = ManifestRecord {
        is_root,
        manifest_id,
        representations,
        transport,
        manifest,
    };
    if !crate::runtime::transport_is_represented(&record) {
        return None;
    }
    Some(record)
}

// --- decoded facts -------------------------------------------------------------

#[derive(Debug, Clone)]
pub(super) enum DecodedFact {
    Transition(MembershipTransition),
    Capability(Capability),
    Announcement(SnapshotAnnouncement),
    SnapshotBody(Snapshot),
    Manifest(ManifestRecord),
    LocalObject(ContentId),
    ObjectRemoved(ContentId),
    Materialization(ContentId, MaterializationState),
    ControlMessage(ControlMessageId),
    AnnouncementQueued(SnapshotId, DeviceId),
    AnnouncementSealed(SnapshotId, Vec<u8>),
    AnnouncementDelivered(SnapshotId, DeviceId),
    TransitionQueued(TransitionId, DeviceId),
    TransitionSealed(TransitionId, Vec<u8>),
    TransitionDelivered(TransitionId, DeviceId),
    CapabilityQueued(u64, DeviceId),
    CapabilitySealed(u64, DeviceId, Vec<u8>),
    CapabilityDelivered(u64, DeviceId),
    BootstrapPending(Vec<u8>),
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use wyrd_format::membership::Admission;
    use wyrd_format::{Change, Manifest, SnapshotId};

    use crate::control::{seal, CapabilityPayload, KeyRotation, Message, TransitionPayload};

    use super::*;

    /// The encoder emits unique map keys, so a record declaring the same
    /// StorageId twice is malformed; keeping one entry silently would
    /// drop the representation the record committed to.
    #[test]
    fn manifest_decode_rejects_duplicate_storage_ids() {
        let drive = DriveId::from_bytes([0xEE; 32]);
        let key = [0x11u8; 32];
        let manifest =
            Manifest::new(SnapshotId::from_bytes([0x11; 32]), Vec::new(), Vec::new()).unwrap();
        let manifest_id = ContentId::derive(ObjectKind::Manifest, &manifest.canonical_bytes());
        let record = ManifestRecord {
            is_root: true,
            manifest_id,
            representations: BTreeMap::from([(
                StorageId::from_bytes([0xA0; 32]),
                BaoRoot::from_bytes([0xC0; 32]),
            )]),
            transport: BaoRoot::from_bytes([0xC0; 32]),
            manifest,
        };
        let (tag, good) = encode_fact(&key, &drive, &Fact::Manifest(record)).unwrap();
        assert!(decode_record(&drive, &key, tag, &good).is_some());

        // Duplicate the one representation entry and bump the count.
        let mut bad = good.clone();
        bad[65..69].copy_from_slice(&2u32.to_le_bytes());
        let entry = good[69..133].to_vec();
        bad.splice(133..133, entry);
        assert!(decode_record(&drive, &key, tag, &bad).is_none());
    }

    /// Transport/representation consistency: a record naming
    /// representations must name its eager root among them, or the eager
    /// route would serve under a root the record's own map does not
    /// advertise. An empty map is a representationless root and stays
    /// decodable.
    #[test]
    fn manifest_decode_rejects_unrepresented_transport() {
        let drive = DriveId::from_bytes([0xEE; 32]);
        let key = [0x11u8; 32];
        let manifest =
            Manifest::new(SnapshotId::from_bytes([0x11; 32]), Vec::new(), Vec::new()).unwrap();
        let manifest_id = ContentId::derive(ObjectKind::Manifest, &manifest.canonical_bytes());
        let record = ManifestRecord {
            is_root: true,
            manifest_id,
            representations: BTreeMap::from([(
                StorageId::from_bytes([0xA0; 32]),
                BaoRoot::from_bytes([0xC0; 32]),
            )]),
            transport: BaoRoot::from_bytes([0xC0; 32]),
            manifest: manifest.clone(),
        };
        let (tag, good) = encode_fact(&key, &drive, &Fact::Manifest(record)).unwrap();
        assert!(decode_record(&drive, &key, tag, &good).is_some());

        // Patch the transport root to one the map does not advertise
        // (record layout: manifest id 0..32, is_root 32, transport
        // 33..65, storage count 65..69).
        let mut bad = good.clone();
        bad[33..65].copy_from_slice(&[0xD0; 32]);
        assert!(decode_record(&drive, &key, tag, &bad).is_none());

        // A representationless root still decodes: it serves nothing.
        let bare = ManifestRecord {
            is_root: true,
            manifest_id,
            representations: BTreeMap::new(),
            transport: BaoRoot::from_bytes([0xC0; 32]),
            manifest,
        };
        let (tag, bytes) = encode_fact(&key, &drive, &Fact::Manifest(bare)).unwrap();
        assert!(decode_record(&drive, &key, tag, &bytes).is_some());
    }

    /// Seal one control message of each delivery-obligation kind under
    /// a throwaway key: the codec gate checks envelope kind only, so
    /// the payloads need no chain behind them.
    fn sealed_kind(drive: &DriveId, key: &[u8; 32], epoch: u64, message: &Message) -> Vec<u8> {
        seal(key, drive, epoch, message).unwrap().encode()
    }

    fn transition_bytes() -> Vec<u8> {
        let transition = MembershipTransition::new(
            1,
            None,
            Vec::new(),
            vec![Change::Admit(Admission {
                device: DeviceId::from_bytes([0x01; 32]),
                encryption_key: wyrd_format::DeviceEncryptionKey::from_bytes([0x02; 32]),
            })],
            [0x03; 32],
            [0x04; 32],
            DeviceId::from_bytes([0x01; 32]),
        )
        .unwrap();
        transition.canonical_bytes()
    }

    /// The delivery-obligation sealed facts round-trip, and their kind
    /// gates refuse cross-kind envelopes in both directions: a rotation
    /// envelope must neither encode as a transition obligation nor
    /// decode as one, so a wrong-but-decodable seal can never poison a
    /// first-seal-wins obligation past retry.
    #[test]
    fn delivery_obligation_seals_gate_envelope_kind() {
        let drive = DriveId::from_bytes([0xEE; 32]);
        let key = [0x11u8; 32];
        let seal_key = [0x07u8; 32];
        let tid = TransitionId::from_bytes([0x11; 32]);
        let recipient = DeviceId::from_bytes([0x22; 32]);

        let good_transition = sealed_kind(
            &drive,
            &seal_key,
            2,
            &Message::MembershipTransition(TransitionPayload {
                transition: transition_bytes(),
            }),
        );
        let (tag, bytes) = encode_fact(
            &key,
            &drive,
            &Fact::TransitionSealed(tid, good_transition.clone()),
        )
        .unwrap();
        assert_eq!(tag, TAG_TRANSITION_SEALED);
        assert!(decode_record(&drive, &key, tag, &bytes).is_some());

        let good_capability = sealed_kind(
            &drive,
            &seal_key,
            2,
            &Message::Capability(CapabilityPayload {
                device: recipient,
                epoch: 2,
                wrapped: vec![0xAA; 64],
            }),
        );
        let (tag, bytes) = encode_fact(
            &key,
            &drive,
            &Fact::CapabilitySealed(2, recipient, good_capability),
        )
        .unwrap();
        assert_eq!(tag, TAG_CAPABILITY_SEALED);
        assert!(decode_record(&drive, &key, tag, &bytes).is_some());

        // Wrong kind in both directions, for both gates.
        let rotation = sealed_kind(
            &drive,
            &seal_key,
            2,
            &Message::KeyRotation(KeyRotation {
                transition: TransitionId::from_bytes([0x31; 32]),
            }),
        );
        assert!(encode_fact(&key, &drive, &Fact::TransitionSealed(tid, rotation.clone())).is_err());
        assert!(encode_fact(
            &key,
            &drive,
            &Fact::CapabilitySealed(2, recipient, rotation.clone())
        )
        .is_err());
        let mut bad_transition = tid.as_bytes().to_vec();
        bad_transition.extend_from_slice(&rotation);
        assert!(decode_record(&drive, &key, TAG_TRANSITION_SEALED, &bad_transition).is_none());
        let mut bad_capability = 2u64.to_le_bytes().to_vec();
        bad_capability.extend_from_slice(recipient.as_bytes());
        bad_capability.extend_from_slice(&rotation);
        assert!(decode_record(&drive, &key, TAG_CAPABILITY_SEALED, &bad_capability).is_none());

        // Queued/delivered pairs and the pending-invitation blob are
        // plain round-trips; an empty blob is refused.
        let (tag, bytes) =
            encode_fact(&key, &drive, &Fact::TransitionQueued(tid, recipient)).unwrap();
        assert_eq!(tag, TAG_TRANSITION_QUEUED);
        assert!(decode_record(&drive, &key, tag, &bytes).is_some());
        let (tag, bytes) =
            encode_fact(&key, &drive, &Fact::CapabilityQueued(2, recipient)).unwrap();
        assert_eq!(tag, TAG_CAPABILITY_QUEUED);
        assert!(decode_record(&drive, &key, tag, &bytes).is_some());
        let (tag, bytes) =
            encode_fact(&key, &drive, &Fact::BootstrapPending(vec![0xBB; 48])).unwrap();
        assert_eq!(tag, TAG_BOOTSTRAP_PENDING);
        assert!(decode_record(&drive, &key, tag, &bytes).is_some());
        assert!(encode_fact(&key, &drive, &Fact::BootstrapPending(Vec::new())).is_err());
        assert!(decode_record(&drive, &key, TAG_BOOTSTRAP_PENDING, &[]).is_none());
    }
}

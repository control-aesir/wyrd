//! The frozen public-read subset (release-read v1): fetch a release
//! snapshot by id, fetch its blobs by id, verify. Nothing else.
//!
//! A release drive is an explicitly public distribution surface, never a
//! weaker security mode for an ordinary drive. Its epoch-1 secret is
//! generated randomly like any other ([`EpochSecret::generate`]) and then
//! **published** as release metadata: content confidentiality for that
//! drive is waived deliberately, per drive, irreversibly. The waiver is
//! scoped by the authorship rule below — public readability is not public
//! mutability. Only the pinned maintainer authors an accepted snapshot;
//! the frozen reader enforces the absence of membership transitions
//! (`membership == genesis`, `epoch == 1`) rather than assuming the
//! publisher emits none.
//!
//! What the reader deliberately omits: the Nostr mailbox (announcements
//! arrive in the clear, signed but unsealed), membership replay (the
//! genesis id is release metadata, compared by equality), and capability
//! installation (the epoch-1 secret is release metadata, not a wrapped
//! capability — its disclosure is publication, never an admission).
//! Everything the reader *does* reuses the existing construction
//! byte-for-byte: the `wyrd announcement v1` signing domain, the
//! `wyrd manifest key v1` / `wyrd object key v1` derivations, the seal
//! envelopes, and the transport-root fetch addresses (object-model.md
//! decision 26). That is why an old client keeps reading release drives
//! while the rest of the protocol evolves around the frozen subset. The
//! profile is a subset of what peers already speak, so a future
//! capability-negotiation matrix can take it as its floor — no
//! negotiation exists yet, and the subset does not depend on one.
//!
//! Verification is not authenticity by itself. A valid signature proves
//! the pinned maintainer signed the announcement; it does not prove the
//! snapshot is the latest release, that its contents are benign, or that
//! the release metadata reached the reader from a trusted source.
//! Freshness, benign-ness, and metadata provenance belong to the signed
//! release manifest (the next distribution item), not to this reader.
//! Maintainer authorship is public by construction: signatures verify
//! against the pinned npub, so operating a release drive discloses who
//! publishes it.
//!
//! Every scope violation fails closed with a named [`PublicReadError`]:
//! non-maintainer authorship, non-genesis membership, any epoch but 1 —
//! with no fallback to membership replay, capability installation, or a
//! more permissive reader mode.

use secp256k1::XOnlyPublicKey;
use thiserror::Error;
use wyrd_format::{
    BaoRoot, DeviceId, DriveId, Manifest, ManifestEntry, Snapshot, SnapshotId, TransitionId,
};

use crate::bulk::{BulkError, BulkSource};
use crate::control::{verify_announcement, SnapshotAnnouncement};
use crate::keys::EpochSecret;
use crate::seal::{self, EncryptedObject};
/// The frozen profile version: release-read v1. Carried as the first
/// byte of the release-metadata encoding so a future profile is
/// distinguishable, never silently accepted as v1.
pub const RELEASE_READ_VERSION: u8 = 0x01;

/// The only epoch a release drive ever has. Release drives never advance
/// past genesis: there are no membership transitions to mint epoch 2, so
/// every sealed byte on a release drive opens under epoch 1.
pub const RELEASE_EPOCH: u64 = 1;

/// Release-metadata encoding length: version (1) ‖ drive (32) ‖
/// maintainer (32) ‖ genesis (32) ‖ epoch-1 secret (32). Fixed length —
/// anything else is malformed, never a shorter profile.
pub const PUBLIC_RELEASE_LEN: usize = 129;

/// The public metadata for one release drive: everything a keyless
/// stranger needs to fetch and verify its snapshots, and nothing that
/// identifies any member beyond the publishing maintainer (whose
/// authorship is public by construction — see the module docs).
///
/// `Clone` but never `Copy`: the epoch-1 secret is published metadata,
/// not ambient key material, and must not spread by accident. The
/// `Debug` impl names the public fields and redacts the secret even
/// though published — a log line must not become a second distribution
/// channel the publisher did not choose.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicRelease {
    /// The drive being published.
    pub drive: DriveId,
    /// The only author the frozen reader accepts.
    pub maintainer: DeviceId,
    /// The drive's genesis transition: the membership every accepted
    /// snapshot must bind. Compared by equality — never replayed.
    pub genesis: TransitionId,
    /// The drive's randomly generated epoch-1 secret, published. Opens
    /// every manifest and object key on this drive and no other drive:
    /// derivations bind the DriveId explicitly, so reusing this secret
    /// for a private drive would still scope its keys to this drive —
    /// but that reuse is forbidden regardless (requirement: release-key
    /// scope). Never install this secret into a member keyring and never
    /// treat its disclosure as a reader admission.
    pub epoch_secret: EpochSecret,
}

impl std::fmt::Debug for PublicRelease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicRelease")
            .field("drive", &self.drive)
            .field("maintainer", &self.maintainer)
            .field("genesis", &self.genesis)
            .field("epoch_secret", &"PUBLISHED-SEPARATELY")
            .finish()
    }
}

impl PublicRelease {
    /// Assemble release metadata from the publisher's creation-time
    /// values: the drive id, the owner's device id, the committed
    /// genesis transition id, and the epoch-1 secret to publish.
    /// Callers must only publish the result as explicitly public release
    /// metadata — never as an ordinary capability, invitation, or backup.
    ///
    /// Fails closed on a maintainer key no signature can verify against:
    /// without this, a malformed pinned npub would report every valid
    /// release as [`PublicReadError::NotMaintainer`] instead of naming
    /// the malformed metadata.
    pub fn new(
        drive: DriveId,
        maintainer: DeviceId,
        genesis: TransitionId,
        epoch_secret: EpochSecret,
    ) -> Result<Self, PublicReadError> {
        check_maintainer_key(&maintainer)?;
        Ok(PublicRelease {
            drive,
            maintainer,
            genesis,
            epoch_secret,
        })
    }

    /// The canonical release-metadata encoding: `version ‖ drive ‖
    /// maintainer ‖ genesis ‖ epoch-1 secret`. The frozen byte layout the
    /// signed release manifest embeds; the freeze-pin test vectors assert
    /// it exactly.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PUBLIC_RELEASE_LEN);
        out.push(RELEASE_READ_VERSION);
        out.extend_from_slice(self.drive.as_bytes());
        out.extend_from_slice(self.maintainer.as_bytes());
        out.extend_from_slice(self.genesis.as_bytes());
        out.extend_from_slice(self.epoch_secret.as_bytes());
        out
    }

    /// Decode release metadata. Rejects truncation, trailing bytes, a
    /// malformed maintainer key, and any version but
    /// [`RELEASE_READ_VERSION`]: a future profile must fail here, never
    /// parse as v1.
    pub fn decode(bytes: &[u8]) -> Result<Self, PublicReadError> {
        if bytes.len() != PUBLIC_RELEASE_LEN {
            return Err(PublicReadError::MalformedRelease);
        }
        if bytes[0] != RELEASE_READ_VERSION {
            return Err(PublicReadError::UnsupportedVersion(bytes[0]));
        }
        let id32 = |pos: usize| -> Result<[u8; 32], PublicReadError> {
            bytes
                .get(pos..pos + 32)
                .and_then(|slice| slice.try_into().ok())
                .ok_or(PublicReadError::MalformedRelease)
        };
        Self::new(
            DriveId::from_bytes(id32(1)?),
            DeviceId::from_bytes(id32(33)?),
            TransitionId::from_bytes(id32(65)?),
            EpochSecret::from_bytes(id32(97)?),
        )
    }

    /// The manifest key for one release snapshot: epoch 1, always. The
    /// derivation is the ordinary one — the frozen subset changes which
    /// bytes are public, never how keys derive.
    pub fn manifest_key(&self, snapshot: &SnapshotId) -> [u8; 32] {
        self.epoch_secret
            .manifest_key(&self.drive, RELEASE_EPOCH, snapshot)
    }
}

/// The maintainer key must name a curve point a BIP-340 signature can
/// verify against. Checked at the metadata boundary (both constructors),
/// so a malformed pinned npub fails as malformed metadata — never as a
/// `NotMaintainer` on every release read thereafter.
fn check_maintainer_key(maintainer: &DeviceId) -> Result<(), PublicReadError> {
    XOnlyPublicKey::from_slice(maintainer.as_bytes())
        .map(|_| ())
        .map_err(|_| PublicReadError::MalformedRelease)
}

/// What a failed public read means. Scope violations (authorship,
/// membership, epoch) are distinct from evidence failures (bad
/// signatures, mismatched identities, absent bytes) so an operator can
/// tell "this is not a release snapshot" from "the bytes did not verify".
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PublicReadError {
    /// The announcement's author is not the pinned maintainer. Public
    /// readability is not public mutability: anyone may fetch, only the
    /// maintainer's snapshots verify.
    #[error("announcement author is not the release maintainer")]
    NotMaintainer,
    /// The announcement binds a membership transition other than the
    /// release genesis. A release drive has no transitions past genesis;
    /// anything else is outside the frozen subset, never a cue to replay
    /// membership.
    #[error("announcement binds non-genesis membership")]
    NotGenesis,
    /// The announcement or a manifest mapping names an epoch other than
    /// one. Release drives never leave epoch 1; any other epoch fails
    /// closed, never falls back to capability installation.
    #[error("release content at epoch {0}, expected epoch 1")]
    WrongEpoch(u64),
    /// The announcement carries a malformed author key. Reported
    /// distinctly from a failed challenge: malformed evidence, not a
    /// maintainer's bad signature.
    #[error("announcement carries a malformed author key")]
    InvalidAuthorKey,
    /// The announcement's author signature does not verify against the
    /// pinned maintainer.
    #[error("announcement signature does not verify")]
    BadAnnouncementSignature,
    /// The fetched body does not decode as a snapshot.
    #[error("snapshot body is malformed")]
    MalformedSnapshot,
    /// The fetched body's SnapshotId differs from the announced one.
    #[error("snapshot body does not match the announced id")]
    SnapshotMismatch,
    /// The body's own signature does not verify against its author.
    /// Checked after the id match, so a tampered body fails on identity
    /// first and a maintainer-impersonating body fails here.
    #[error("snapshot signature does not verify")]
    BadSnapshotSignature,
    /// The body's author, membership, or epoch disagrees with the
    /// announcement's frozen scope. The announcement gate already
    /// enforced these; the body is re-checked so a body fetched by id
    /// (rather than through the announcement) cannot smuggle a
    /// maintainer-signed but out-of-scope snapshot past the reader.
    #[error("snapshot body is outside the release scope")]
    BodyOutsideScope,
    /// The fetched root manifest does not describe the announced
    /// snapshot.
    #[error("root manifest does not describe the announced snapshot")]
    ManifestMismatch,
    /// A needed representation is absent from the source: the peer does
    /// not hold the bytes. Absence, never damage — retry against another
    /// source.
    #[error("representation absent: {0}")]
    Absent(&'static str),
    /// The transport failed or a representation exceeds the caller's
    /// ceiling. Passes [`BulkError`] through unchanged: the frozen
    /// reader adds no transport of its own.
    #[error("bulk fetch failed: {0}")]
    Bulk(#[from] BulkError),
    /// A seal envelope, tag, or identity check failed while opening a
    /// manifest or object.
    #[error("sealed bytes do not verify: {0}")]
    Seal(String),
    /// Release metadata is truncated, trailed, or otherwise malformed.
    #[error("release metadata is malformed")]
    MalformedRelease,
    /// Release metadata names a profile other than release-read v1.
    #[error("unsupported release-read version {0:#04x}")]
    UnsupportedVersion(u8),
}

/// The authorship scope gate: author, epoch, membership, then the
/// maintainer's signature — in that order, so a scope violation reports
/// as a scope violation even when the signature would also fail. Runs
/// before any fetch: out-of-scope announcements never cost a fetch.
pub fn verify_public_announcement(
    release: &PublicRelease,
    announcement: &SnapshotAnnouncement,
) -> Result<(), PublicReadError> {
    if announcement.author != release.maintainer {
        return Err(PublicReadError::NotMaintainer);
    }
    if announcement.epoch != RELEASE_EPOCH {
        return Err(PublicReadError::WrongEpoch(announcement.epoch));
    }
    if announcement.membership != release.genesis {
        return Err(PublicReadError::NotGenesis);
    }
    verify_announcement(&release.drive, announcement).map_err(|error| {
        use crate::control::ControlError;
        match error {
            ControlError::InvalidAuthorKey => PublicReadError::InvalidAuthorKey,
            _ => PublicReadError::BadAnnouncementSignature,
        }
    })
}

/// A release snapshot fetched and verified end to end: the decoded body
/// (whose id, author signature, and scope all checked) plus its opened
/// root manifest. Object fetches go through
/// [`fetch_public_object`] against `manifest`'s entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPublicSnapshot {
    /// The verified snapshot body.
    pub snapshot: Snapshot,
    /// The opened root manifest, known to describe this snapshot.
    pub manifest: Manifest,
}

/// Fetch and verify one release snapshot: scope gate, body, manifest —
/// the whole frozen subset for snapshot metadata. `max` is the caller's
/// pre-decode byte ceiling per representation, enforced by the source.
///
/// Fetch order prefers the announcement's transport roots (the
/// verified-streaming addresses) and falls back to the id-addressed
/// exchange: `fetch_snapshot` for the body. Either way the bytes are
/// verified against the announced identities before anything is trusted.
pub fn fetch_public_snapshot<S: BulkSource>(
    release: &PublicRelease,
    announcement: &SnapshotAnnouncement,
    source: &mut S,
    max: usize,
) -> Result<VerifiedPublicSnapshot, PublicReadError> {
    verify_public_announcement(release, announcement)?;
    let body = fetch_snapshot_body(announcement, source, max)?;
    let snapshot = Snapshot::decode(&body).map_err(|_| PublicReadError::MalformedSnapshot)?;
    if snapshot.snapshot_id() != announcement.snapshot {
        return Err(PublicReadError::SnapshotMismatch);
    }
    // Scope before signature, matching the frozen order: a body outside
    // the release scope reports as such even when its signature would
    // also fail. Unreachable through this path by construction — the id
    // above already covers the scope fields, so any scope change reports
    // as `SnapshotMismatch` first — and retained as a backstop: the check
    // is what makes the scope rule hold for bodies that arrive by any
    // other route, and its branch is pinned directly below.
    check_body_scope(release, &snapshot)?;
    crate::authorization::predicates::verify_snapshot(&release.drive, &snapshot)
        .map_err(|_| PublicReadError::BadSnapshotSignature)?;
    let manifest = fetch_root_manifest(release, announcement, source, max)?;
    if manifest.snapshot() != announcement.snapshot {
        return Err(PublicReadError::ManifestMismatch);
    }
    Ok(VerifiedPublicSnapshot { snapshot, manifest })
}

/// The body's scope rule: the announcement gate checked the author's
/// *statement*; this keeps a body fetched by id from smuggling an
/// out-of-scope snapshot past the reader. Factored out so the branch is
/// directly testable (through [`fetch_public_snapshot`] it is a
/// backstop — see the call site).
fn check_body_scope(release: &PublicRelease, snapshot: &Snapshot) -> Result<(), PublicReadError> {
    if snapshot.author != release.maintainer
        || snapshot.membership != release.genesis
        || snapshot.epoch != RELEASE_EPOCH
    {
        return Err(PublicReadError::BodyOutsideScope);
    }
    Ok(())
}

/// Fetch and verify one object named by a release manifest entry: the
/// entry's epoch must be 1 (anything else is a scope violation, never a
/// cue to install a capability), then the sealed bytes open under the
/// epoch-1 object key with the full [`seal::verify`] envelope, identity,
/// and size checks. Returns the verified plaintext.
pub fn fetch_public_object<S: BulkSource>(
    release: &PublicRelease,
    entry: &ManifestEntry,
    source: &mut S,
    max: usize,
) -> Result<Vec<u8>, PublicReadError> {
    if entry.encryption_epoch != RELEASE_EPOCH {
        return Err(PublicReadError::WrongEpoch(entry.encryption_epoch));
    }
    let sealed = source
        .fetch_transport(&entry.transport, max)?
        .ok_or(PublicReadError::Absent("object"))?;
    let key = release.epoch_secret.object_key(
        &release.drive,
        RELEASE_EPOCH,
        &entry.content_id,
        entry.kind,
        entry.version,
    );
    seal::verify(entry, &key, &sealed).map_err(|error| PublicReadError::Seal(error.to_string()))
}

/// The snapshot body by transport root, falling back to the id-addressed
/// exchange. Both addresses name the same bytes; the id and signature
/// checks in [`fetch_public_snapshot`] run either way.
fn fetch_snapshot_body<S: BulkSource>(
    announcement: &SnapshotAnnouncement,
    source: &mut S,
    max: usize,
) -> Result<Vec<u8>, PublicReadError> {
    if let Some(bytes) = source.fetch_transport(&announcement.body_root, max)? {
        return Ok(bytes);
    }
    source
        .fetch_snapshot(&announcement.snapshot, max)?
        .ok_or(PublicReadError::Absent("snapshot body"))
}

/// The root manifest by transport root, opened under the epoch-1
/// manifest key with the announced ContentId as AAD. A manifest sealed
/// under any other key — or naming any other content — fails the tag,
/// never parses.
fn fetch_root_manifest<S: BulkSource>(
    release: &PublicRelease,
    announcement: &SnapshotAnnouncement,
    source: &mut S,
    max: usize,
) -> Result<Manifest, PublicReadError> {
    let sealed = source
        .fetch_transport(&announcement.root_manifest_transport, max)?
        .ok_or(PublicReadError::Absent("root manifest"))?;
    let envelope = EncryptedObject::decode(&sealed)
        .map_err(|error| PublicReadError::Seal(error.to_string()))?;
    let key = release.manifest_key(&announcement.snapshot);
    seal::open_manifest(&key, &announcement.root_manifest, &envelope)
        .map_err(|error| PublicReadError::Seal(error.to_string()))
}

/// The transport root of a byte run: the same addressing the seeder
/// serves and the fetcher requests (object-model.md decision 26).
/// Re-exported for the publisher side and the freeze pins; the reader
/// itself only consumes roots from signed announcements.
pub fn transport_root(bytes: &[u8]) -> BaoRoot {
    seal::blob_root(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bulk::MemoryBulkSource;
    use crate::control::{sign_announcement, ControlKind, Message};
    use crate::keys::DeviceIdentitySecret;
    use std::collections::BTreeMap;
    use wyrd_format::{ContentId, ObjectKind, SnapshotId};

    /// Fixed fixture scalars: valid curve scalars, never secrets that
    /// matter — the freeze pins record the exact bytes they produce.
    fn maintainer_identity() -> DeviceIdentitySecret {
        DeviceIdentitySecret::from_bytes([0x07; 32]).expect("fixture scalar")
    }

    fn stranger_identity() -> DeviceIdentitySecret {
        DeviceIdentitySecret::from_bytes([0x09; 32]).expect("fixture scalar")
    }

    fn fixture_release() -> PublicRelease {
        PublicRelease::new(
            DriveId::from_bytes([0x11; 32]),
            maintainer_identity().device_id(),
            TransitionId::from_bytes([0x13; 32]),
            EpochSecret::from_bytes([0x17; 32]),
        )
        .expect("fixture metadata is well-formed")
    }

    /// One sealed chunk plus its manifest entry, under the fixture epoch.
    fn sealed_chunk(release: &PublicRelease, plaintext: &[u8]) -> (ManifestEntry, EncryptedObject) {
        let content_id = ContentId::derive(ObjectKind::Chunk, plaintext);
        let key = release.epoch_secret.object_key(
            &release.drive,
            RELEASE_EPOCH,
            &content_id,
            ObjectKind::Chunk,
            seal::SEAL_VERSION,
        );
        let obj =
            seal::seal(&key, ObjectKind::Chunk, &content_id, plaintext).expect("fixture seals");
        let entry = ManifestEntry {
            content_id,
            kind: ObjectKind::Chunk,
            version: seal::SEAL_VERSION,
            storage_id: obj.storage_id(),
            encryption_epoch: RELEASE_EPOCH,
            size: plaintext.len() as u64,
            transport: seal::transport_root(&obj),
        };
        (entry, obj)
    }

    /// A maintainer-signed genesis snapshot over one root manifest, with
    /// its announcement and the exact sealed root bytes — the publisher
    /// side of the frozen subset. The sealed bytes are returned (not
    /// re-sealed by the test server) so the announced transport root
    /// addresses exactly what the source serves.
    fn published(
        release: &PublicRelease,
        entries: Vec<ManifestEntry>,
    ) -> (Snapshot, Manifest, Vec<u8>, SnapshotAnnouncement) {
        // The snapshot id precedes the manifest (the manifest names its
        // snapshot), so sign a draft over the tree id, then rebuild: the
        // tree id here is a fixed fixture value standing in for the real
        // root tree the publisher commits.
        let tree = ContentId::from_bytes([0x21; 32]);
        let mut snapshot = Snapshot::new(
            Vec::new(),
            tree,
            release.maintainer,
            release.genesis,
            RELEASE_EPOCH,
            0,
            1,
        )
        .expect("fixture snapshot");
        crate::authorization::predicates::sign_snapshot(
            &mut snapshot,
            &maintainer_identity().secret_key(),
            &release.drive,
        );
        let snapshot_id = snapshot.snapshot_id();
        let manifest = Manifest::from_sorted(
            snapshot_id,
            entries.into_iter().map(|e| (e.content_id, e)).collect(),
            BTreeMap::new(),
        )
        .expect("fixture manifest");
        let (root_manifest, root_obj) =
            seal::seal_manifest(&release.manifest_key(&snapshot_id), &manifest)
                .expect("fixture root seals");
        let body = snapshot.encode();
        let mut announcement = SnapshotAnnouncement {
            snapshot: snapshot_id,
            author: release.maintainer,
            epoch: RELEASE_EPOCH,
            membership: release.genesis,
            body_root: seal::blob_root(&body),
            root_manifest,
            root_manifest_transport: seal::transport_root(&root_obj),
            node_addr: None,
            signature: [0; 64],
        };
        sign_announcement(&mut announcement, &maintainer_identity(), &release.drive);
        (snapshot, manifest, root_obj.encode(), announcement)
    }

    /// A source serving exactly one publication's bytes, addressed as the
    /// frozen reader requests them: transport roots for body, manifest,
    /// and objects. Publishes the publication's own sealed bytes — a
    /// re-seal would mint a fresh nonce and strand the announced root.
    fn serving(
        snapshot: &Snapshot,
        root_sealed: Vec<u8>,
        objects: Vec<EncryptedObject>,
    ) -> MemoryBulkSource {
        let mut source = MemoryBulkSource::default();
        source.publish_transport(snapshot.encode());
        source.publish_transport(root_sealed);
        for obj in objects {
            source.publish_transport(obj.encode());
        }
        source
    }

    #[test]
    fn keyless_stranger_fetches_and_verifies_a_release_snapshot() {
        // The stranger holds no identity, no mailbox, no membership, no
        // capability — only the public announcement bytes and the public
        // release metadata. That is the whole frozen reader input.
        let release = fixture_release();
        let (entry, obj) = sealed_chunk(&release, b"release bytes");
        let (snapshot, manifest, root_sealed, announcement) =
            published(&release, vec![entry.clone()]);
        let mut source = serving(&snapshot, root_sealed, vec![obj]);

        let verified = fetch_public_snapshot(&release, &announcement, &mut source, 1 << 20)
            .expect("public read verifies");
        assert_eq!(verified.snapshot, snapshot);
        assert_eq!(verified.manifest, manifest);

        let plaintext = fetch_public_object(&release, &entry, &mut source, 1 << 20)
            .expect("public object verifies");
        assert_eq!(plaintext, b"release bytes");
    }

    /// A hand-built announcement over fixed field values — no sealing,
    /// no randomness anywhere in its construction — so the freeze pins
    /// below assert the exact same bytes on every run. (The `published`
    /// fixture seals a fresh root per run by design; its nonce would move
    /// the transport root and signature each time.)
    fn fixed_announcement(release: &PublicRelease) -> SnapshotAnnouncement {
        let mut announcement = SnapshotAnnouncement {
            snapshot: SnapshotId::from_bytes([0x41; 32]),
            author: release.maintainer,
            epoch: RELEASE_EPOCH,
            membership: release.genesis,
            body_root: BaoRoot::from_bytes([0x43; 32]),
            root_manifest: ContentId::from_bytes([0x45; 32]),
            root_manifest_transport: BaoRoot::from_bytes([0x47; 32]),
            node_addr: None,
            signature: [0; 64],
        };
        sign_announcement(&mut announcement, &maintainer_identity(), &release.drive);
        announcement
    }

    /// Decode one pinned hex vector. `hex` is a dev-dependency for
    /// exactly this: the frozen contract asserts bytes, not round trips.
    fn vector(hex: &str) -> Vec<u8> {
        hex::decode(hex).expect("pinned vector is valid hex")
    }

    #[test]
    fn public_announcement_encoding_is_frozen() {
        // Byte-exact vectors over the whole public discovery input,
        // recorded from the fixture scalars above (deterministic nonces
        // keep the signatures stable). A future field reorder, domain
        // change, or canonicalization drift fails here — not merely a
        // round trip, but the exact bytes a frozen reader parses and the
        // exact signing region it verifies.
        let release = fixture_release();
        let announcement = fixed_announcement(&release);
        assert_eq!(
            Message::SnapshotAnnouncement(announcement.clone()).encode_payload(),
            vector("4141414141414141414141414141414141414141414141414141414141414141989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f01000000000000001313131313131313131313131313131313131313131313131313131313131313434343434343434343434343434343434343434343434343434343434343434345454545454545454545454545454545454545454545454545454545454545454747474747474747474747474747474747474747474747474747474747474747003756a0306c30274f78a5eeff18e64b65b41af1a6d5773784bb5a7b5526742c1d003c2e58420cebd77ea655def23836f7b70f53fd26c0a61670906797422eb1a1"),
        );
        assert_eq!(
            announcement.signing_message(&release.drive),
            vector("7779726420616e6e6f756e63656d656e7420763111111111111111111111111111111111111111111111111111111111111111114141414141414141414141414141414141414141414141414141414141414141989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f0100000000000000131313131313131313131313131313131313131313131313131313131313131343434343434343434343434343434343434343434343434343434343434343434545454545454545454545454545454545454545454545454545454545454545474747474747474747474747474747474747474747474747474747474747474700"),
        );
        // The snapshot side of the identity path, same treatment: body
        // bytes (signature included) and signing region both pinned.
        let snapshot = Snapshot::new(
            Vec::new(),
            ContentId::from_bytes([0x21; 32]),
            release.maintainer,
            release.genesis,
            RELEASE_EPOCH,
            0,
            1,
        )
        .unwrap();
        let mut signed = snapshot.clone();
        crate::authorization::predicates::sign_snapshot(
            &mut signed,
            &maintainer_identity().secret_key(),
            &release.drive,
        );
        assert_eq!(
            signed.encode(),
            vector("000000002121212121212121212121212121212121212121212121212121212121212121989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f13131313131313131313131313131313131313131313131313131313131313130100000000000000000100000000000000a3af1f6597ff4fcc5a12fc38ffa8db7cef448cde2e828e9ac3ae63964f87ce488394e3183ccf958685848ce4ff1706f4f299c0694f010a62c5d7b9a46cfa9df6"),
        );
        assert_eq!(
            snapshot.signing_message(&release.drive),
            vector("7779726420736e617073686f742076311111111111111111111111111111111111111111111111111111111111111111000000002121212121212121212121212121212121212121212121212121212121212121989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f13131313131313131313131313131313131313131313131313131313131313130100000000000000000100000000000000"),
        );
        // Announcement payloads still decode: the freeze pins bytes, the
        // decoder still reads them.
        let encoded = Message::SnapshotAnnouncement(announcement.clone()).encode_payload();
        assert_eq!(
            Message::decode_payload(ControlKind::SnapshotAnnouncement, &encoded).unwrap(),
            Message::SnapshotAnnouncement(announcement)
        );
    }

    #[test]
    fn release_key_derivations_are_frozen() {
        // Exact epoch-1 keys for fixed inputs: catches an accidental KDF
        // context or preimage change, which would silently fork every
        // release identity the frozen reader verifies.
        let release = fixture_release();
        let snapshot = SnapshotId::from_bytes([0x31; 32]);
        let content = ContentId::from_bytes([0x33; 32]);
        assert_eq!(
            release.manifest_key(&snapshot).to_vec(),
            vector("fc1983674b40d8cf8c01a2c8398d3f5dec858b831d217cad5b57ecfba0b242dc"),
        );
        let object_key = release.epoch_secret.object_key(
            &release.drive,
            RELEASE_EPOCH,
            &content,
            ObjectKind::Chunk,
            seal::SEAL_VERSION,
        );
        assert_eq!(
            object_key.to_vec(),
            vector("f1a076dd5eea3664a79f68c52d15ba5608afd5be286117f97fdbdb18cba355ae"),
        );
        // Epoch binding is load-bearing for WrongEpoch: the same secret
        // at epoch 2 must derive different keys, so a scope violation
        // can never open as epoch 1.
        assert_ne!(
            release.manifest_key(&snapshot),
            release
                .epoch_secret
                .manifest_key(&release.drive, 2, &snapshot),
            "epoch-bound"
        );
    }

    #[test]
    fn release_metadata_encoding_is_fixed_length_and_versioned() {
        let release = fixture_release();
        let encoded = release.encode();
        assert_eq!(encoded.len(), PUBLIC_RELEASE_LEN);
        assert_eq!(encoded[0], RELEASE_READ_VERSION);
        // Exact layout: version ‖ drive ‖ maintainer ‖ genesis ‖ secret.
        assert_eq!(
            encoded,
            vector("011111111111111111111111111111111111111111111111111111111111111111989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f13131313131313131313131313131313131313131313131313131313131313131717171717171717171717171717171717171717171717171717171717171717"),
        );
        assert_eq!(PublicRelease::decode(&encoded).unwrap(), release);
        // Truncation, trailing bytes, and a future version all fail —
        // never parse as v1.
        assert_eq!(
            PublicRelease::decode(&encoded[..PUBLIC_RELEASE_LEN - 1]),
            Err(PublicReadError::MalformedRelease)
        );
        let mut trailed = encoded.clone();
        trailed.push(0);
        assert_eq!(
            PublicRelease::decode(&trailed),
            Err(PublicReadError::MalformedRelease)
        );
        let mut future = encoded.clone();
        future[0] = 0x02;
        assert_eq!(
            PublicRelease::decode(&future),
            Err(PublicReadError::UnsupportedVersion(0x02))
        );
    }

    #[test]
    fn non_maintainer_authorship_is_refused_before_any_fetch() {
        let release = fixture_release();
        let (_, _, _, mut announcement) = published(&release, Vec::new());
        // A stranger's announcement, signed by the stranger: well-formed,
        // correctly signed — and refused on authorship alone. The
        // stranger's own signature verifies first, so the test proves a
        // genuinely stranger-signed statement, not hand-built bytes.
        announcement.author = stranger_identity().device_id();
        announcement.signature = [0; 64];
        sign_announcement(&mut announcement, &stranger_identity(), &release.drive);
        verify_announcement(&release.drive, &announcement)
            .expect("stranger signature is well-formed");
        let mut source = MemoryBulkSource::default();
        assert_eq!(
            fetch_public_snapshot(&release, &announcement, &mut source, 1 << 20),
            Err(PublicReadError::NotMaintainer)
        );
    }

    #[test]
    fn non_genesis_membership_and_later_epochs_are_refused() {
        let release = fixture_release();
        let (_, _, _, announcement) = published(&release, Vec::new());
        let mut rotated = announcement.clone();
        rotated.membership = TransitionId::from_bytes([0x77; 32]);
        rotated.signature = [0; 64];
        sign_announcement(&mut rotated, &maintainer_identity(), &release.drive);
        assert_eq!(
            verify_public_announcement(&release, &rotated),
            Err(PublicReadError::NotGenesis)
        );
        // The absence of membership transitions is enforced, not assumed:
        // even the maintainer cannot move a release drive to epoch 2.
        let mut epoch_two = announcement.clone();
        epoch_two.epoch = 2;
        epoch_two.signature = [0; 64];
        sign_announcement(&mut epoch_two, &maintainer_identity(), &release.drive);
        assert_eq!(
            verify_public_announcement(&release, &epoch_two),
            Err(PublicReadError::WrongEpoch(2))
        );
    }

    #[test]
    fn tampered_and_misbound_bytes_fail_on_evidence_not_scope() {
        let release = fixture_release();
        let (entry, obj) = sealed_chunk(&release, b"release bytes");
        let (snapshot, _manifest, root_sealed, announcement) = published(&release, vec![entry]);
        // Tampered body served at the snapshot id (the fallback
        // exchange path): the id check fires before the signature check.
        // (The transport path cannot stage this — publish_transport keys
        // bytes under the root they hash to, so a hostile root mismatch
        // arrives as absence there, never as bytes.)
        let mut source = MemoryBulkSource::default();
        let mut tampered = snapshot.encode();
        tampered[4] ^= 0xFF;
        source.publish_snapshot(announcement.snapshot, tampered);
        assert_eq!(
            fetch_public_snapshot(&release, &announcement, &mut source, 1 << 20),
            Err(PublicReadError::SnapshotMismatch)
        );
        // Right bytes under a wrong secret: the manifest tag fails. A
        // wrong release secret is corrupt metadata, never a fallback to
        // capability installation.
        let wrong = PublicRelease::new(
            release.drive,
            release.maintainer,
            release.genesis,
            EpochSecret::from_bytes([0x99; 32]),
        )
        .expect("fixture metadata is well-formed");
        let mut source = serving(&snapshot, root_sealed, vec![obj]);
        assert!(matches!(
            fetch_public_snapshot(&wrong, &announcement, &mut source, 1 << 20),
            Err(PublicReadError::Seal(_))
        ));
    }

    #[test]
    fn later_epoch_mappings_are_refused_without_fallback() {
        let release = fixture_release();
        let (mut entry, _) = sealed_chunk(&release, b"release bytes");
        entry.encryption_epoch = 2;
        let mut source = MemoryBulkSource::default();
        assert_eq!(
            fetch_public_object(&release, &entry, &mut source, 1 << 20),
            Err(PublicReadError::WrongEpoch(2))
        );
    }

    #[test]
    fn absent_bytes_are_absence_never_damage() {
        let release = fixture_release();
        let (_, _, _, announcement) = published(&release, Vec::new());
        let mut source = MemoryBulkSource::default();
        assert_eq!(
            fetch_public_snapshot(&release, &announcement, &mut source, 1 << 20),
            Err(PublicReadError::Absent("snapshot body"))
        );
    }

    #[test]
    fn release_metadata_debug_names_no_secret() {
        // The secret is published elsewhere, by the publisher's explicit
        // act — a Debug line must not become a second channel.
        let rendered = format!("{:?}", fixture_release());
        assert!(rendered.contains("1111"), "drive is public metadata");
        assert!(rendered.contains("PUBLISHED-SEPARATELY"));
        assert!(!rendered.contains("1717"), "secret bytes stay out of logs");
    }

    #[test]
    fn malformed_maintainer_key_fails_as_malformed_metadata() {
        // 32 arbitrary bytes are not an x-only key: the constructors fail
        // closed here, so a bad pinned npub never reports every valid
        // release as NotMaintainer downstream.
        let bad = DeviceId::from_bytes([0xFF; 32]);
        assert_eq!(
            PublicRelease::new(
                DriveId::from_bytes([0x11; 32]),
                bad,
                TransitionId::from_bytes([0x13; 32]),
                EpochSecret::from_bytes([0x17; 32]),
            ),
            Err(PublicReadError::MalformedRelease)
        );
        let mut encoded = fixture_release().encode();
        encoded[33..65].copy_from_slice(&[0xFF; 32]);
        assert_eq!(
            PublicRelease::decode(&encoded),
            Err(PublicReadError::MalformedRelease)
        );
    }

    #[test]
    fn body_scope_backstop_reports_each_axis() {
        // `check_body_scope` directly: through the fetch path the id check
        // covers these fields first, so this pins the backstop branch
        // itself — one axis at a time.
        let release = fixture_release();
        let (snapshot, _, _, _) = published(&release, Vec::new());
        assert_eq!(check_body_scope(&release, &snapshot), Ok(()));
        let mut wrong_author = snapshot.clone();
        wrong_author.author = stranger_identity().device_id();
        assert_eq!(
            check_body_scope(&release, &wrong_author),
            Err(PublicReadError::BodyOutsideScope)
        );
        let mut wrong_membership = snapshot.clone();
        wrong_membership.membership = TransitionId::from_bytes([0x77; 32]);
        assert_eq!(
            check_body_scope(&release, &wrong_membership),
            Err(PublicReadError::BodyOutsideScope)
        );
        let mut wrong_epoch = snapshot.clone();
        wrong_epoch.epoch = 2;
        assert_eq!(
            check_body_scope(&release, &wrong_epoch),
            Err(PublicReadError::BodyOutsideScope)
        );
    }

    #[test]
    fn corrupted_maintainer_signature_fails_on_evidence() {
        // Author, epoch, and membership all match: only the signature is
        // wrong, so the gate reports evidence failure, not a scope
        // violation.
        let release = fixture_release();
        let (_, _, _, mut announcement) = published(&release, Vec::new());
        announcement.signature[0] ^= 0xFF;
        assert_eq!(
            verify_public_announcement(&release, &announcement),
            Err(PublicReadError::BadAnnouncementSignature)
        );
    }

    #[test]
    fn announcement_for_another_drive_does_not_verify() {
        // Same maintainer key, different drive: the signature is
        // drive-bound, so a release announcement never authorizes a
        // snapshot on another drive.
        let release = fixture_release();
        let other_drive = DriveId::from_bytes([0x2A; 32]);
        let (_, _, _, mut announcement) = published(&release, Vec::new());
        announcement.signature = [0; 64];
        sign_announcement(&mut announcement, &maintainer_identity(), &other_drive);
        assert_eq!(
            verify_public_announcement(&release, &announcement),
            Err(PublicReadError::BadAnnouncementSignature)
        );
    }
}

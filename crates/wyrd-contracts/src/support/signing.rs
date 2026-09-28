//! Signing fixtures: devices, hand-signed membership transitions
//! and snapshot bodies. Everything rides the real crypto path —
//! real secp256k1 keys, real BIP-340 over the normative challenge
//! contexts — so a drift in the pinned contexts fails locally
//! instead of as a generic rejection in whichever contract runs
//! first.
use secp256k1::{Keypair, SecretKey, XOnlyPublicKey};
use wyrd_format::membership::{
    set_root, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT, READER_SET_CONTEXT,
};
use wyrd_format::{
    Change, ContentId, DeviceEncryptionKey, DeviceId, DriveId, MembershipTransition, Snapshot,
    SnapshotId, TransitionId,
};
use wyrd_sync::keys::{DeviceEncryptionSecret, DeviceIdentitySecret};

// The snapshot challenge context has no public spelling in wyrd-sync
// (the membership one does), so the fixture pins the normative string
// and `fixture_signatures_verify_through_the_public_path` fails with
// a local diagnostic if it drifts.
const SNAPSHOT_CHALLENGE: &str = "wyrd snapshot challenge v1";

pub(crate) fn drive() -> DriveId {
    DriveId::from_bytes([0xEE; 32])
}

/// One test device: the Nostr identity (device id, transition and
/// snapshot signing) and the encryption keypair (capability target)
/// are separate scalars, exactly as the production key split has
/// them.
pub(crate) struct Device {
    pub identity: DeviceIdentitySecret,
    pub id: DeviceId,
    pub signing: SecretKey,
    pub encryption: DeviceEncryptionSecret,
    pub encryption_key: DeviceEncryptionKey,
}

pub(crate) fn device(seed: u8) -> Device {
    let signing = SecretKey::from_slice(&[seed; 32]).unwrap();
    let identity = DeviceIdentitySecret::from_bytes(signing.secret_bytes()).unwrap();
    let encryption_bytes = [seed.wrapping_add(0x40); 32];
    let encryption = DeviceEncryptionSecret::from_bytes(encryption_bytes).unwrap();
    let encryption_sk = SecretKey::from_slice(&encryption_bytes).unwrap();
    let encryption_kp = Keypair::from_secret_key(secp256k1::SECP256K1, &encryption_sk);
    let (xonly, _) = XOnlyPublicKey::from_keypair(&encryption_kp);
    Device {
        identity,
        id: xonly_device_id(&signing),
        signing,
        encryption,
        encryption_key: DeviceEncryptionKey::from_bytes(xonly.serialize()),
    }
}

fn xonly_device_id(sk: &SecretKey) -> DeviceId {
    let kp = Keypair::from_secret_key(secp256k1::SECP256K1, sk);
    let (xonly, _) = XOnlyPublicKey::from_keypair(&kp);
    DeviceId::from_bytes(xonly.serialize())
}

pub(crate) fn sign_transition(t: &mut MembershipTransition, sk: &SecretKey, drive: &DriveId) {
    let kp = Keypair::from_secret_key(secp256k1::SECP256K1, sk);
    let challenge = blake3::derive_key(
        wyrd_sync::membership::CHALLENGE_CONTEXT,
        &t.signing_message(drive),
    );
    t.signature = secp256k1::SECP256K1
        .sign_schnorr_no_aux_rand(&challenge, &kp)
        .to_byte_array();
}

pub(crate) fn sign_snapshot(s: &mut Snapshot, sk: &SecretKey, drive: &DriveId) {
    let kp = Keypair::from_secret_key(secp256k1::SECP256K1, sk);
    let challenge = blake3::derive_key(SNAPSHOT_CHALLENGE, &s.signing_message(drive));
    s.signature = secp256k1::SECP256K1
        .sign_schnorr_no_aux_rand(&challenge, &kp)
        .to_byte_array();
}

/// A fully signed membership transition.
#[allow(clippy::too_many_arguments)]
pub(crate) fn signed_transition(
    epoch: u64,
    prev: Option<TransitionId>,
    resolves: Vec<TransitionId>,
    changes: Vec<Change>,
    members: &[DeviceId],
    owners: &[DeviceId],
    author: &Device,
) -> MembershipTransition {
    let mut t = MembershipTransition::new(
        epoch,
        prev,
        resolves,
        changes,
        set_root(MEMBER_SET_CONTEXT, members).unwrap(),
        set_root(OWNER_SET_CONTEXT, owners).unwrap(),
        set_root(READER_SET_CONTEXT, &[]).unwrap(),
        author.id,
    )
    .unwrap();
    sign_transition(&mut t, &author.signing, &drive());
    t
}

/// A fully signed snapshot body. The `flags` field stays zero and the
/// timestamp is display-only, mirroring the conformance fixtures.
pub(crate) fn signed_snapshot(
    parents: Vec<SnapshotId>,
    tree: ContentId,
    author: &Device,
    membership: TransitionId,
    epoch: u64,
    timestamp: u64,
) -> Snapshot {
    let mut s = Snapshot::new(parents, tree, author.id, membership, epoch, 0, timestamp).unwrap();
    sign_snapshot(&mut s, &author.signing, &drive());
    s
}

/// A hand-signed snapshot body from the fixture author device: full
/// BIP-340 over the snapshot challenge, so it passes
/// `AuthorizedSnapshot::authorize`. The membership reference is opaque
/// to the view, so fixtures reuse the conformance placeholder id.
pub(crate) fn signed_head(tree: ContentId) -> Snapshot {
    let device = device(0x0A);
    signed_snapshot(
        Vec::new(),
        tree,
        &device,
        TransitionId::from_bytes([0x71; 32]),
        1,
        1,
    )
}

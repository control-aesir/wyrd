//! Shared harness for authoring tests: an owner engine holding epoch
//! 1 plus the device-id helper. Mirrors drive creation (genesis
//! drained, epoch key installed, self capability committed) so every
//! authoring test starts from the production shape one transition in.

use super::admission::ADMISSION_OBLIGATION_BATCH;
use crate::control::seal;
use crate::durable::{AuthorizeSnapshot, AuthorizedCapability, AuthorizedSnapshot, Fact};
use crate::keys::capability::{Capability, DriveKeyring};
use crate::keys::{DeviceEncryptionSecret, DeviceIdentitySecret, EpochSecret};
use crate::membership::test_util::{drive as member_drive, key, sign, Builder};
use crate::membership::TransitionStatus;
use crate::runtime::engine::Engine;
use crate::runtime::test_util::{
    control_key, encryption_key, identity, identity_secret, transition_message, TestDir,
};
use crate::transport::mailbox::{seal_for_recipient, MemoryMailbox, MemoryRelay};

use wyrd_format::membership::{
    set_root, Admission, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT, READER_SET_CONTEXT,
};
use wyrd_format::{Change, DeviceId, MembershipTransition, TransitionId};
use zeroize::Zeroizing;

/// An owner engine holding epoch 1: genesis drained, epoch key
/// installed, self capability committed (the production shape of a
/// drive creator one transition in). Returns the engine plus the
/// genesis id the next transition must parent onto.
pub(super) fn owner_engine(label: &str) -> (TestDir, Engine, TransitionId) {
    let dir = TestDir::new(label);
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
    let authorized =
        AuthorizedCapability::authorize(cap, member_drive(), &engine.log, &genesis.transition_id())
            .unwrap();
    engine
        .commit_facts(&[Fact::Capability(authorized)])
        .unwrap();
    (dir, engine, genesis.transition_id())
}

/// A non-owner engine holding epoch 1: fresh directory, stranger
/// identity, genesis drained (mirrors the admit precedent). The store
/// lock forbids sharing directories, so the stranger builds its own
/// view of the same drive. Authority checks against it must fail.
pub(super) fn stranger_engine(label: &str) -> Engine {
    let dir = TestDir::new(label);
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
    stranger
}

/// Owner engine, recipient, keyring, and transition id wired for a
/// mint: the owner mints its epoch-1 vector to itself. The
/// directory rides along so the caller keeps the store alive.
pub(super) fn mint_setup() -> (
    crate::runtime::test_util::TestDir,
    Engine,
    DriveKeyring,
    DeviceId,
    wyrd_format::TransitionId,
) {
    let (dir, engine, genesis_id) = owner_engine("signer-session-mint");
    let owner = key(10).1;
    let state = engine.log.state_of(&genesis_id).expect("genesis has state");
    let registered = state
        .encryption_key_of(&owner)
        .copied()
        .expect("owner key registered");
    let cap = Capability::new(
        member_drive(),
        owner,
        registered,
        genesis_id,
        1,
        vec![EpochSecret::from_bytes([0x07; 32])],
    )
    .expect("mintable");
    let mut keyring = DriveKeyring::new(member_drive(), owner);
    keyring.install(&cap, &engine.log).expect("installs");
    (dir, engine, keyring, owner, genesis_id)
}

/// The device id an identity secret names.
pub(super) fn device_of(identity: &DeviceIdentitySecret) -> wyrd_format::DeviceId {
    use secp256k1::{Keypair, XOnlyPublicKey, SECP256K1};
    let kp = Keypair::from_secret_key(SECP256K1, &identity.secret_key());
    let (xonly, _) = XOnlyPublicKey::from_keypair(&kp);
    wyrd_format::DeviceId::from_bytes(xonly.serialize())
}

/// A rival admission at epoch 2 over `genesis`: the crafted half
/// of every frozen-drive fixture. Owner-signed like production
/// intake would deliver it; committing it beside a canonical
/// epoch-2 child freezes the drive at 2 with the pre-conflict tip
/// still canonical.
pub(super) fn craft_rival(genesis: TransitionId) -> MembershipTransition {
    let (owner_sk, owner_id) = key(10);
    let (third_sk, third_id) = key(30);
    let _ = third_sk;
    let third_key = encryption_key(&DeviceEncryptionSecret::from_bytes([0xE3; 32]).unwrap());
    let mut rival = MembershipTransition::new(
        2,
        Some(genesis),
        Vec::new(),
        vec![Change::Admit(Admission {
            device: third_id,
            encryption_key: third_key,
        })],
        set_root(MEMBER_SET_CONTEXT, &[owner_id, third_id]).unwrap(),
        set_root(OWNER_SET_CONTEXT, &[owner_id]).unwrap(),
        set_root(READER_SET_CONTEXT, &[]).unwrap(),
        owner_id,
    )
    .unwrap();
    sign(&mut rival, &owner_sk, &member_drive());
    rival
}

/// An owner engine frozen at epoch 2: canonical rotate plus a rival
/// admission observed directly. Returns the engine, the owner id,
/// and the two contender ids (rotate first). The fork is built with
/// one production-authored contender (rotate) plus one crafted rival
/// committed durably, so validators meet a genuine frozen analysis
/// rather than a staged one.
pub(super) fn frozen_engine(
    label: &str,
) -> (
    TestDir,
    Engine,
    DeviceId,
    TransitionId,
    TransitionId,
    TransitionId,
) {
    let (dir, mut engine, genesis) = owner_engine(label);
    let (_owner_sk, owner_id) = key(10);
    let winner = engine.rotate_epoch().expect("canonical rotate");
    let winner_id = winner.transition_id();
    let rival = craft_rival(genesis);
    let rival_id = rival.transition_id();
    // The rival must be durable, not just observed: commit resyncs
    // from the store, so an in-memory-only observation would vanish
    // mid-resolve (in production the rival arrives via intake, which
    // commits it the same way).
    engine.log.observe(rival.clone());
    engine
        .commit_facts(&[Fact::Transition(rival.clone())])
        .unwrap();
    assert_eq!(engine.log.frozen_at(), Some(2), "fork freezes at 2");
    for id in [winner_id, rival_id] {
        assert!(
            matches!(engine.log.status(&id), Some(TransitionStatus::Contested)),
            "contender {id:?} contested"
        );
    }
    (dir, engine, owner_id, genesis, winner_id, rival_id)
}

/// Mint a bare signed snapshot chain straight onto the store: one
/// Schnorr signature per link, no content, no manifests, no
/// announcements. The admission walk needs recorded bodies under a
/// live tip, and classification needs only signature plus membership
/// binding plus epoch match — so contentless links exercise the true
/// closure path at ceiling scale without tens of thousands of full
/// authorings. Bodies commit in bounded chunks (the setup dogfoods
/// the bound the fill relies on). Returns every link id in chain
/// order, tip last.
pub(super) fn mint_bare_chain(
    engine: &mut Engine,
    genesis_id: wyrd_format::TransitionId,
    tree: wyrd_format::ContentId,
    len: usize,
) -> Vec<wyrd_format::SnapshotId> {
    use crate::authorization::test_util::sign_snapshot;
    use crate::membership::test_util::{drive as member_drive, key};

    let (owner_sk, owner_id) = key(10);
    let drive = member_drive();
    let mut parents = Vec::new();
    let mut ids = Vec::with_capacity(len);
    let mut batch = Vec::new();
    for n in 0..len {
        let mut body =
            wyrd_format::Snapshot::new(parents, tree, owner_id, genesis_id, 1, 0, n as u64)
                .unwrap();
        sign_snapshot(&mut body, &owner_sk, &drive);
        let authorized = AuthorizedSnapshot::authorize(body, &drive).unwrap();
        let id = authorized.snapshot().snapshot_id();
        parents = vec![id];
        ids.push(id);
        batch.push(Fact::SnapshotBody(authorized));
        if batch.len() == ADMISSION_OBLIGATION_BATCH {
            engine.commit_facts(&batch).unwrap();
            batch.clear();
        }
    }
    if !batch.is_empty() {
        engine.commit_facts(&batch).unwrap();
    }
    ids
}

/// One shared content root for bare chains: the closure walk and
/// classification never resolve the tree, so every link reuses it.
pub(super) fn bare_tree(objects: &mut wyrd_format::MemoryObjectStore) -> wyrd_format::ContentId {
    use wyrd_format::{Entry, ObjectKind, ObjectStore, Tree};

    let chunk = objects.insert(ObjectKind::Chunk, b"bare").unwrap();
    Tree::from_entries(vec![Entry::file("bare.txt", 4, false, vec![chunk]).unwrap()])
        .unwrap()
        .insert_into(objects)
        .unwrap()
}

/// Drive one newcomer's membership catch-up over the relay: the
/// owner sends transitions and capabilities (`deliver_pending`) plus
/// announcements (`announce_pending`), the newcomer drains until
/// quiet (at most four rounds cover the key-install two-pass shape
/// plus redelivery). Returns nothing; tests assert on durable
/// state afterwards.
pub(super) fn relay_catch_up(
    engine: &mut Engine,
    joined: &mut Engine,
    relay: &mut MemoryRelay,
    newcomer_id: wyrd_format::DeviceId,
) {
    for _ in 0..4 {
        {
            let mut sender = MemoryMailbox {
                relay: &mut *relay,
                owner: engine.device(),
            };
            engine.deliver_pending(&mut sender).unwrap();
            engine.announce_pending(&mut sender, None).unwrap();
        }
        let report = {
            let mut receiver = MemoryMailbox {
                relay: &mut *relay,
                owner: newcomer_id,
            };
            joined.drain(&mut receiver).unwrap()
        };
        if report.accepted == 0 {
            break;
        }
    }
}

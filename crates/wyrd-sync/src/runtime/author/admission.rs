use wyrd_format::membership::{
    set_root, Admission, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT, READER_SET_CONTEXT,
};
use wyrd_format::{Change, DeviceEncryptionKey, DeviceId, MembershipTransition, TransitionId};

use super::common::escrow_fresh_secret;
use crate::control::bootstrap::{seal_bootstrap, SealedBootstrap};
use crate::durable::{AuthorizedCapability, Fact};
use crate::keys::capability::Capability;
use crate::keys::EpochSecret;
use crate::membership::{sign_transition, TransitionStatus};
use crate::runtime::engine::{Engine, EngineError};
use zeroize::Zeroizing;

/// The authored admission: the signed transition every member must
/// observe, plus the sealed invitation ferried to the new device
/// out-of-band (it bootstraps a device with no engine yet, so it
/// cannot arrive as a control message).
pub struct AdmitOutcome {
    pub transition: MembershipTransition,
    pub invitation: SealedBootstrap,
}

/// Which role an admission grants. Members author snapshots peers
/// accept; readers hold every epoch secret and materialize the drive,
/// but no authorship gate accepts their work. One shared commit path
/// serves both: the change tag, the root vectors, and the pre-checks
/// differ, while epoch minting, sealing, staging, and catch-up are
/// identical — a reader's invitation must open and converge exactly
/// like a member's, minus authorship.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AdmissionKind {
    Member,
    Reader,
}

/// Admit a device: author, sign, and commit the admission transition,
/// install the new epoch's self capability, and seal the newcomer's
/// invitation. One transition is exactly one new epoch (epochs.md), so
/// admission mints a fresh epoch secret and every capability minted
/// here covers `1..=epoch` contiguously from the keyring plus the
/// fresh one — no backward secrecy for admission, by design.
///
/// Authority comes from the pre-transition owner set (epochs.md rule
/// 3): only an owner admits, and the transition commits together with
/// the self capability in one batch, so a crash cannot leave the
/// admission durable while this device's own new-epoch material is
/// not. Transport of the transition and the capability wraps to other
/// devices is the catch-up/gossip obligation layer, not this call.
pub(crate) fn admit_device(
    engine: &mut Engine,
    device: DeviceId,
    encryption_key: DeviceEncryptionKey,
) -> Result<AdmitOutcome, EngineError> {
    admit(engine, device, encryption_key, AdmissionKind::Member)
}

/// Admit a device as a reader: same commit path as [`admit_device`],
/// with a reader-tagged change. The invitation, capability grant, and
/// catch-up are identical — the role lives in the membership log, and
/// the authorship gates (local and peer) enforce it from there.
pub(crate) fn admit_reader(
    engine: &mut Engine,
    device: DeviceId,
    encryption_key: DeviceEncryptionKey,
) -> Result<AdmitOutcome, EngineError> {
    admit(engine, device, encryption_key, AdmissionKind::Reader)
}

fn admit(
    engine: &mut Engine,
    device: DeviceId,
    encryption_key: DeviceEncryptionKey,
    kind: AdmissionKind,
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
    // One role per device: admission requires the device in neither
    // set. Roles change through removal, and single-use identity means
    // the re-admission names a fresh DeviceId (retirement refuses the
    // old one below).
    if pre.members.contains(&device) {
        return Err(EngineError::AlreadyMember);
    }
    if pre.readers.contains(&device) {
        return Err(EngineError::AlreadyReader);
    }
    if engine.log.is_retired(&device) {
        // Retired identities are single-use within the chain: a
        // removed device returns only under a fresh identity. The
        // chain rule stays authoritative; this refuses early with a
        // renderable error instead of authoring a doomed transition.
        return Err(EngineError::RetiredDevice);
    }
    let epoch = next_epoch(tip.epoch)?;
    let secret = EpochSecret::generate()?;
    let mut members: Vec<DeviceId> = pre.members.iter().copied().collect();
    let mut readers: Vec<DeviceId> = pre.readers.iter().copied().collect();
    let change = match kind {
        AdmissionKind::Member => {
            members.push(device);
            Change::Admit(Admission {
                device,
                encryption_key,
            })
        }
        AdmissionKind::Reader => {
            readers.push(device);
            Change::AdmitReader(Admission {
                device,
                encryption_key,
            })
        }
    };
    let owners: Vec<DeviceId> = pre.owners.iter().copied().collect();
    let mut transition = MembershipTransition::new(
        epoch,
        Some(tip.transition_id),
        Vec::new(),
        vec![change],
        set_root(MEMBER_SET_CONTEXT, &members)?,
        set_root(OWNER_SET_CONTEXT, &owners)?,
        set_root(READER_SET_CONTEXT, &readers)?,
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
    // Every other admitted device — member or reader — is owed the
    // new tip plus its new-epoch wrap: readers must keep decrypting
    // to keep reading.
    for other in post.members.iter().chain(post.readers.iter()) {
        if *other == engine.device || *other == device {
            continue;
        }
        batch.push(Fact::TransitionQueued(tip_id, *other));
        batch.push(Fact::CapabilityQueued(epoch, *other));
    }
    // Current heads ride the catch-up: the newcomer learns what exists
    // before post-admission gossip reaches it. Heads alone are not
    // enough — a head without its ancestry is unadoptable
    // (UnknownParent poisons the whole chain), and pre-admission
    // snapshots were queued for nobody, so the obligation must cover
    // the lineage closure: each head plus every ancestor reachable
    // through recorded bodies. Every closure member is at or below
    // the admission epoch, so the invited keys open all of them.
    // Sending reuses the announcement outbox; the re-announce send
    // path (not the authoring one) serves snapshots this engine did
    // not author. Already-covered pairs stay untouched, and only
    // snapshots this engine can actually serve get obligations
    // (authored here, or a recorded announcement the re-announce path
    // can resend) — anything else could never discharge.
    {
        use std::collections::BTreeSet;
        use wyrd_format::SnapshotId;

        let rebuilt = engine.store.rebuild(engine.device)?;
        let mut stack: Vec<SnapshotId> = engine
            .live_heads()?
            .into_iter()
            .map(|head| head.snapshot().snapshot_id())
            .collect();
        let mut seen = BTreeSet::new();
        while let Some(id) = stack.pop() {
            if !seen.insert(id) {
                continue;
            }
            let Some(body) = rebuilt.runtime.snapshot_body(&id) else {
                continue;
            };
            let servable =
                body.author == engine.device || rebuilt.runtime.announcement(&id).is_some();
            if servable && !rebuilt.runtime.announcement_covered(id, device) {
                batch.push(Fact::AnnouncementQueued(id, device));
            }
            stack.extend(body.parents.iter().copied());
        }
    }
    engine.commit_facts(&batch)?;
    engine.resync()?;
    engine.add_epoch_key(
        epoch,
        Zeroizing::new(secret.control_key(&engine.drive, epoch)),
    );
    // Mint-time escrow (T13), after the key install: the sidecar
    // lands only after the admission batch commits (commit-then-
    // escrow), and an escrow failure must never drop the held key —
    // the install above is infallible memory state, the persist
    // below is fallible disk state.
    escrow_fresh_secret(engine, epoch, &secret)?;
    Ok(AdmitOutcome {
        transition,
        invitation,
    })
}

/// The epoch after the tip, checked: the authoring path already treats
/// the timestamp space as exhaustible, and the epoch counter is a
/// `u64` protocol field with the same boundary.
pub(super) fn next_epoch(tip_epoch: u64) -> Result<u64, EngineError> {
    tip_epoch.checked_add(1).ok_or(EngineError::EpochExhausted)
}

/// Reissue a device's sealed invitation from durable state: finds the
/// device's canonical admission, re-mints its grant from the held
/// epoch secrets, and reseals it. The recovery path for an admission
/// whose invitation never reached a file (process death between
/// commit and publication): nothing here authors, so it runs
/// repeatedly from any process holding the secrets. The reseal uses
/// fresh randomness, so the bytes differ from the original —
/// equivalence is functional (the invitee joins), never byte
/// equality.
///
/// Authority mirrors admission: only a current canonical owner
/// reissues, and only for an active canonical member. Revocation
/// bounds acquisition — a removed device's lost invitation stays
/// lost — and a valid-but-noncanonical branch never anchors a
/// grant, since the durable authorization path would not accept it.
pub(crate) fn reissue_invitation(
    engine: &Engine,
    device: DeviceId,
) -> Result<SealedBootstrap, EngineError> {
    let tip = engine
        .log
        .known_state()
        .ok_or(EngineError::NoCanonicalMembership)?;
    let current = engine
        .log
        .state_of(&tip.transition_id)
        .ok_or(EngineError::NoCanonicalMembership)?;
    if !current.owners.contains(&engine.device) {
        return Err(EngineError::NotOwner);
    }
    // Either role holds a recoverable invitation: readers lose files
    // the same way members do.
    if !current.members.contains(&device) && !current.readers.contains(&device) {
        return Err(EngineError::NotMember);
    }
    let (epoch, id) = canonical_admission_of(engine, &device)?;
    let transition = engine
        .log
        .transition(&id)
        .ok_or(EngineError::NoCanonicalMembership)?;
    let post = engine
        .log
        .state_of(&id)
        .ok_or(EngineError::NoCanonicalMembership)?;
    let encryption_key = transition
        .changes()
        .iter()
        .find_map(|change| match change {
            Change::Admit(admission) | Change::AdmitReader(admission)
                if admission.device == device =>
            {
                Some(admission.encryption_key)
            }
            _ => None,
        })
        .ok_or(EngineError::NotMember)?;
    // Secrets `1..=epoch`, as at admission: the keyring holds every
    // past epoch from an authorized capability each.
    let rebuilt = engine.store.rebuild(engine.device)?;
    let mut secrets = Vec::with_capacity(epoch as usize);
    for past in 1..=epoch {
        secrets.push(
            rebuilt
                .keyring
                .secret(past)
                .cloned()
                .ok_or(EngineError::MissingEpochSecret(past))?,
        );
    }
    let grant = Capability::mint(engine.drive, device, &post, transition, secrets)?;
    Ok(seal_bootstrap(
        &engine.identity_secret,
        &engine.drive,
        device,
        &encryption_key,
        &genesis_bytes(engine)?,
        grant.wrap()?.as_bytes(),
    )?)
}

/// The device's admission on the canonical chain. At most one per
/// device: a second admit is refused while the first holds
/// membership, and retirement forbids return. Anything off the
/// canonical chain — contested, voided, or invalid — never anchors
/// a grant; with no canonical admission the reissue fails closed.
fn canonical_admission_of(
    engine: &Engine,
    device: &DeviceId,
) -> Result<(u64, TransitionId), EngineError> {
    let statuses = engine.log.statuses();
    engine
        .log
        .observed_ids()
        .into_iter()
        .filter_map(|id| {
            if !matches!(statuses.get(&id), Some(TransitionStatus::Canonical)) {
                return None;
            }
            let transition = engine.log.transition(&id)?;
            let admits = transition.changes().iter().any(|change| {
                matches!(change, Change::Admit(a) | Change::AdmitReader(a) if a.device == *device)
            });
            admits.then_some((transition.epoch, id))
        })
        .min_by_key(|(epoch, _)| *epoch)
        .ok_or(EngineError::NotMember)
}

/// The canonical genesis bytes the invitation anchors to, from the
/// membership analysis — never by shape. The observed set can hold
/// an invalid epoch-1 transition (intake persists any structurally
/// bounded transition as evidence), and its id can sort before the
/// valid genesis; anchoring to it would seal an invitation the
/// newcomer rejects with `BadGenesis` after the owner's transition
/// is already durable.
fn genesis_bytes(engine: &Engine) -> Result<Vec<u8>, EngineError> {
    let genesis = engine
        .log
        .canonical_genesis()
        .ok_or(EngineError::BadGenesis)?;
    engine
        .log
        .transition(&genesis)
        .map(MembershipTransition::canonical_bytes)
        .ok_or(EngineError::BadGenesis)
}

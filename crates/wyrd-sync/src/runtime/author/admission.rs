use wyrd_format::membership::{set_root, Admission, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT};
use wyrd_format::{Change, DeviceEncryptionKey, DeviceId, MembershipTransition};

use crate::control::bootstrap::{seal_bootstrap, SealedBootstrap};
use crate::durable::{AuthorizedCapability, Fact};
use crate::keys::capability::Capability;
use crate::keys::EpochSecret;
use crate::membership::sign_transition;
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
pub(crate) fn admit_device(
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
    // Current heads ride the catch-up: the newcomer learns what exists
    // before post-admission gossip reaches it. Every head is at or
    // below the admission epoch, so the invited keys open all of them.
    // Sending reuses the announcement outbox; the re-announce send
    // path (not the authoring one) serves snapshots this engine did
    // not author.
    for head in engine.live_heads()? {
        batch.push(Fact::AnnouncementQueued(
            head.snapshot().snapshot_id(),
            device,
        ));
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
pub(super) fn next_epoch(tip_epoch: u64) -> Result<u64, EngineError> {
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

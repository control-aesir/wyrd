//! Shared tail for membership-transition authoring: commit a signed
//! transition with the author's self capability and the catch-up
//! obligations for the resulting members in one durable batch.
//!
//! Every authoring path (admission excepted: the newcomer additionally
//! needs the chain suffix, the invitation, and the head announcements)
//! ends here, so a crash cannot leave a transition durable while the
//! author's own new-epoch material or the members' catch-up is not.

use wyrd_format::MembershipTransition;

use crate::durable::{AuthorizedCapability, Fact};
use crate::keys::capability::Capability;
use crate::keys::{escrow, EpochSecret};
use crate::membership::MembershipState;
use crate::runtime::engine::{Engine, EngineError};
use zeroize::Zeroizing;

/// Wrap the transition's fresh epoch secret under the owner's root
/// and persist the keystore sidecar (T13). Owner engines opened
/// through the keystore always hold the root; member engines and
/// keystoreless opens hold none and escrow nothing — escrow is a
/// custody function, and custody lives in the keystore flow.
/// Production owner drives always open via the keystore, so authoring
/// without a root is a test-only shape, never a silent production
/// gap: the sidecar set simply covers the keystored epochs.
pub(super) fn escrow_fresh_secret(
    engine: &Engine,
    epoch: u64,
    secret: &EpochSecret,
) -> Result<(), EngineError> {
    let Some(root) = engine.root.as_ref() else {
        return Ok(());
    };
    let record = escrow::wrap(
        &root.escrow_key(&engine.drive(), epoch),
        &engine.drive(),
        epoch,
        secret,
    )?;
    escrow::persist_record(engine.store.dir(), &record)?;
    Ok(())
}

/// Commit a signed membership transition: stage it against a cloned
/// log (the live log stays pristine until the batch commits, so any
/// failure leaves no phantom tip), install the author's self
/// capability when the author remains a member of the resulting
/// state, queue the new tip and the new-epoch wrap for every other
/// resulting admitted device (members and readers alike), and resync
/// onto the committed state. Returns the post-transition state.
///
/// `secret` is the transition's fresh epoch secret, so capabilities
/// cover `1..=epoch` contiguously from the keyring plus the fresh
/// secret. A removed author holds no new-epoch material: no self
/// capability, no epoch key, and no queue entries — revocation ends
/// acquisition, including the author's own when the author leaves.
pub(super) fn commit_new_epoch(
    engine: &mut Engine,
    transition: MembershipTransition,
    secret: EpochSecret,
) -> Result<MembershipState, EngineError> {
    let epoch = transition.epoch;
    let tip_id = transition.transition_id();
    let mut staged = engine.log.clone();
    staged.observe(transition.clone());
    let rebuilt = engine.store.rebuild(engine.device())?;
    let mut secrets = Vec::with_capacity(epoch as usize);
    for past in 1..epoch {
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
    let mut batch = vec![Fact::Transition(transition.clone())];
    let author_stays = post.members.contains(&engine.device());
    if author_stays {
        // The self grant authorizes immediately: the authoring device
        // is a member of the state its own transition produces.
        let own = Capability::mint(engine.drive(), engine.device(), &post, &transition, secrets)?;
        let authorized = AuthorizedCapability::authorize(
            own,
            engine.drive(),
            &staged,
            &transition.transition_id(),
        )?;
        batch.push(Fact::Capability(authorized));
    }
    // Delivery obligations join the same batch: the transition is not
    // durable without its catch-up. Only resulting admitted devices —
    // members and readers alike — are owed new-epoch material: readers
    // must keep decrypting to keep reading. A removed device,
    // including a removed author, receives nothing further.
    for other in post.members.iter().chain(post.readers.iter()) {
        if *other == engine.device() {
            continue;
        }
        batch.push(Fact::TransitionQueued(tip_id, *other));
        batch.push(Fact::CapabilityQueued(epoch, *other));
    }
    engine.commit_facts(&batch)?;
    engine.resync()?;
    // Mint-time escrow (T13): the fresh secret seals under the root
    // only after the transition commits. Commit-then-escrow is the
    // safe order — a crash between them leaves a missing sidecar
    // (recovery falls back to keyring catch-up), never an orphan
    // record a retry could mismatch with a fresh secret for the same
    // epoch. Escrow failure reports loudly; the commit already
    // happened, so the caller retries at a new epoch, never by
    // rewriting this one.
    escrow_fresh_secret(engine, epoch, &secret)?;
    if author_stays {
        engine.add_epoch_key(
            epoch,
            Zeroizing::new(secret.control_key(&engine.drive(), epoch)),
        );
    }
    Ok(post)
}

//! Local snapshot authoring: the write half of the drive.
//!
//! A member device turns a root tree it holds into a signed snapshot
//! bound to the canonical membership state, commits the body durably,
//! and can announce it to the other members. This is the producer the
//! rest of the runtime assumed and never had: intake and the live-head
//! projection consumed snapshots, but every body under test was built by
//! a fixture.
//!
//! Semantics follow `docs/epochs.md` ("local write"): the snapshot
//! parents onto the locally live-lineage eligible heads, binds
//! `membership` to the canonical epoch-K transition, and sets `epoch` to
//! that transition's epoch. Failures are fail-closed: no canonical
//! membership, a non-member author, or a signature that will not verify
//! commits nothing.

use wyrd_format::{ContentId, Snapshot};

use super::engine::{Engine, EngineError};
use crate::authorization::SnapshotDag;
use crate::control::{seal, Message, SnapshotAnnouncement};
use crate::durable::{AuthorizedSnapshot, Fact};
use crate::transport::mailbox::{seal_for_recipient, Mailbox};

/// Author a snapshot over `tree` on behalf of this engine's device.
/// Parents are the current eligible heads, so a single-head drive
/// extends its live state and a conflicted drive resolves onto every
/// head (object-model.md, "Resolution"). The body is signed, verified
/// once (fail-closed), and committed; it becomes live when a projection
/// rebuilds the DAG.
pub(super) fn author(
    engine: &mut Engine,
    tree: ContentId,
) -> Result<AuthorizedSnapshot, EngineError> {
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

    let mut snapshot = Snapshot::new(
        parents,
        tree,
        engine.device,
        known.transition_id,
        known.epoch,
        0,
        now_ms(),
    );
    crate::authorization::predicates::sign_snapshot(
        &mut snapshot,
        &engine.identity_secret.secret_key(),
        &engine.drive,
    );

    let authorized =
        AuthorizedSnapshot::authorize(snapshot, &engine.drive).map_err(EngineError::InvalidHead)?;
    engine.commit_facts(&[Fact::SnapshotBody(authorized.clone())])?;
    Ok(authorized)
}

/// Announce an authored snapshot to every other member over the control
/// plane: seal one epoch-keyed announcement and address it to each
/// member's identity. Returns the number of envelopes sent (the author
/// is skipped: it already holds the body). The epoch must be one this
/// engine holds a control key for.
pub(super) fn announce(
    engine: &Engine,
    snapshot: &AuthorizedSnapshot,
    mailbox: &mut impl Mailbox,
) -> Result<usize, EngineError> {
    let body = snapshot.snapshot();
    let key = engine
        .epoch_keys
        .get(&body.epoch)
        .ok_or(EngineError::MissingEpochKey(body.epoch))?;
    let message = Message::SnapshotAnnouncement(SnapshotAnnouncement {
        snapshot: body.snapshot_id(),
        author: body.author,
        epoch: body.epoch,
        membership: body.membership,
    });
    let sealed = seal(key, &engine.drive, body.epoch, &message)?;

    let rebuilt = engine.store.rebuild(engine.device)?;
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

/// Wall-clock milliseconds for the display/tiebreak timestamp. HLC
/// ordering is a display concern (object-model.md); authorization never
/// reads it.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

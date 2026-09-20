use super::deliver::{seal_fresh_for, send_sealed_to, verify_reused_sealed};
use crate::control::{seal as seal_control, Message, SnapshotAnnouncement};
use crate::durable::{AuthorizedSnapshot, Fact, Rebuilt};
use crate::runtime::engine::{Engine, EngineError};
use crate::transport::mailbox::Mailbox;

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
pub(crate) fn announce(
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
/// snapshots resend their exact bytes. Snapshots this device did not
/// author — queued as newcomer catch-up at admit time — go through
/// [`reannounce_one`], which re-sends the known signed announcement
/// instead of authoring.
pub(crate) fn announce_pending(
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
            sent += reannounce_one(engine, &rebuilt, snapshot_id, mailbox)?;
            continue;
        };
        if body.author != engine.device {
            sent += reannounce_one(engine, &rebuilt, snapshot_id, mailbox)?;
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
                // Reused sealed bytes are verified against the
                // obligation before use: the fact's key must name the
                // snapshot the bytes actually announce, or the send
                // would discharge one obligation while delivering
                // another.
                let obligation = format!("announcement {snapshot_id:?}");
                let Some(bytes) = verify_reused_sealed(
                    engine,
                    &rebuilt.keyring,
                    bytes.to_vec(),
                    &obligation,
                    |sealed_epoch, message| {
                        let Message::SnapshotAnnouncement(announcement) = message else {
                            return Err(EngineError::SealedOutboxMismatch(format!(
                                "{obligation}: sealed bytes carry {:?}, not an announcement",
                                message.kind()
                            )));
                        };
                        if announcement.snapshot != snapshot_id {
                            return Err(EngineError::SealedOutboxMismatch(format!(
                                "{obligation}: sealed bytes announce {:?}, not the obligated snapshot",
                                announcement.snapshot
                            )));
                        }
                        // The envelope epoch must be the body's own
                        // epoch, as for transitions: a correct
                        // announcement under a foreign epoch key would
                        // send to recipients that cannot open it and
                        // discharge the obligation anyway.
                        if sealed_epoch != body.epoch {
                            return Err(EngineError::SealedOutboxMismatch(format!(
                                "{obligation}: sealed under epoch {sealed_epoch}, not the body's epoch {}",
                                body.epoch
                            )));
                        }
                        Ok(())
                    },
                )?
                else {
                    // No sealing key: retain the obligation for a later
                    // pass instead of failing the whole pass on every
                    // drain.
                    continue;
                };
                sent += send_pending_for(engine, snapshot_id, &bytes, mailbox)?;
            }
            None => {
                match announce(engine, &authorized, mailbox, node_addr) {
                    Ok(sent_now) => sent += sent_now,
                    // No sealing key: the obligation stays pending and
                    // observable via the pending projection instead of
                    // failing the whole pass on every drain.
                    // `announce` fetches the key before any commit or
                    // traffic, so skipping here loses nothing.
                    Err(EngineError::MissingEpochKey(_)) => continue,
                    Err(other) => return Err(other),
                }
            }
        }
    }
    Ok(sent)
}

/// Re-send a snapshot this engine did not author to its pending
/// recipients: the known signed announcement goes out byte-identical
/// to the author's statement (same routes included), sealed under its
/// epoch key. Unknown snapshots are skipped orphan-tolerant — the
/// obligation stays pending for a later pass.
fn reannounce_one(
    engine: &mut Engine,
    rebuilt: &Rebuilt,
    snapshot: wyrd_format::SnapshotId,
    mailbox: &mut impl Mailbox,
) -> Result<usize, EngineError> {
    let Some(known) = rebuilt.runtime.announcement(&snapshot).cloned() else {
        return Ok(0);
    };
    let epoch = known.epoch;
    let sealed_bytes = match rebuilt.runtime.announcement_sealed_bytes(&snapshot) {
        Some(bytes) => {
            // Verify reused bytes against the obligation, as in
            // `announce_pending`: a mismatched sealed fact must fail
            // closed, never re-send foreign bytes under this snapshot.
            let obligation = format!("announcement {snapshot:?}");
            let Some(bytes) = verify_reused_sealed(
                engine,
                &rebuilt.keyring,
                bytes.to_vec(),
                &obligation,
                |sealed_epoch, message| {
                    let Message::SnapshotAnnouncement(announcement) = message else {
                        return Err(EngineError::SealedOutboxMismatch(format!(
                            "{obligation}: sealed bytes carry {:?}, not an announcement",
                            message.kind()
                        )));
                    };
                    if announcement.snapshot != snapshot {
                        return Err(EngineError::SealedOutboxMismatch(format!(
                            "{obligation}: sealed bytes announce {:?}, not the obligated snapshot",
                            announcement.snapshot
                        )));
                    }
                    // The envelope epoch must be the announcement's own
                    // epoch, matching what a fresh seal would use below.
                    if sealed_epoch != epoch {
                        return Err(EngineError::SealedOutboxMismatch(format!(
                            "{obligation}: sealed under epoch {sealed_epoch}, not the announcement's epoch {epoch}"
                        )));
                    }
                    Ok(())
                },
            )?
            else {
                // No sealing key: retain the obligation for a later pass.
                return Ok(0);
            };
            bytes
        }
        None => {
            let message = Message::SnapshotAnnouncement(known);
            let Some(bytes) =
                seal_fresh_for(engine, &rebuilt.keyring, epoch, &message, |sealed| {
                    Fact::AnnouncementSealed(snapshot, sealed)
                })?
            else {
                // No sealing key: the obligation stays pending and
                // observable via the pending projection instead of
                // failing the whole pass on every drain.
                return Ok(0);
            };
            bytes
        }
    };
    send_pending_for(engine, snapshot, &sealed_bytes, mailbox)
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
    // Re-read fresh: `announce` commits new queue facts before this
    // send, so the delivery snapshot above may predate the obligation.
    // The resume paths (`announce_pending`, `reannounce_one`) commit
    // no queue facts mid-pass, so their frozen lists stay exact — but
    // the fresh read is exact in both cases.
    let rebuilt = engine.store.rebuild(engine.device)?;
    let recipients: Vec<wyrd_format::DeviceId> = rebuilt
        .runtime
        .pending_announcements()
        .into_iter()
        .filter(|(id, _)| *id == snapshot)
        .map(|(_, recipient)| recipient)
        .collect();
    send_sealed_to(engine, mailbox, sealed_bytes, recipients, |recipient| {
        Fact::AnnouncementDelivered(snapshot, recipient)
    })
}

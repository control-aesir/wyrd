use std::collections::BTreeMap;

use wyrd_format::{DeviceId, DriveId, MembershipTransition, TransitionId};

use crate::control::{
    is_superseded_rotation, open as open_control, seal as seal_control, seal_rotation, Message,
    SealedControl, SealedRotation, TransitionPayload, ROTATION_VERSION,
};
use crate::durable::{Fact, Rebuilt};
use crate::keys::capability::{Capability, DriveKeyring};
use crate::keys::owner_proof::OwnerProof;
use crate::runtime::engine::{Engine, EngineError};
use crate::transport::mailbox::{seal_for_recipient, Mailbox};
use zeroize::Zeroizing;

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
pub(crate) fn deliver_pending(
    engine: &mut Engine,
    mailbox: &mut impl Mailbox,
) -> Result<usize, EngineError> {
    // One validated delivery snapshot per pass: every read below comes
    // from this rebuild. Mid-pass commits only append Sealed,
    // SealedReplaced, and Delivered facts — never new Queued pairs — so
    // the frozen pending lists stay exact, and an in-memory overlay
    // absorbs newly sealed bytes. No re-read per pair: a newcomer
    // catch-up or a large fan-out costs one log decode, not one per
    // obligation.
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
pub(super) fn control_key_for(
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

/// Open sealed bytes reused from a durable outbox fact, for verification
/// against the obligation about to be discharged. The envelope must
/// decode under a held epoch key and name this drive; the caller checks
/// the opened message against its obligation key. A missing sealing key
/// is not corruption — the obligation stays pending for a later pass —
/// so it reports `Ok(None)`; anything else wrong fails closed, because
/// sending undecodable bytes would discharge the obligation while
/// delivering nothing.
pub(super) fn open_reused_sealed(
    engine: &mut Engine,
    keyring: &DriveKeyring,
    sealed_bytes: &[u8],
    obligation: &str,
) -> Result<Option<(u64, Message)>, EngineError> {
    let sealed = SealedControl::decode(sealed_bytes).map_err(|_| {
        EngineError::SealedOutboxMismatch(format!("{obligation}: sealed bytes do not decode"))
    })?;
    let key = match control_key_for(engine, keyring, sealed.epoch) {
        Ok(key) => key,
        Err(EngineError::MissingEpochKey(_)) => return Ok(None),
        Err(other) => return Err(other),
    };
    let (drive, epoch, message) = open_control(&key, &sealed).map_err(|error| {
        EngineError::SealedOutboxMismatch(format!(
            "{obligation}: sealed bytes do not open: {error}"
        ))
    })?;
    if drive != engine.drive {
        return Err(EngineError::SealedOutboxMismatch(format!(
            "{obligation}: sealed drive {drive} is not this drive"
        )));
    }
    Ok(Some((epoch, message)))
}

/// Verify reused sealed bytes against the obligation about to be
/// discharged: open under a held key, then run the caller's
/// kind-specific correlation check (message variant, obligation
/// identity, envelope epoch). A missing sealing key is not corruption
/// — returns `Ok(None)` and the obligation stays pending for a later
/// pass. Anything else wrong fails closed. Returns the bytes on
/// success, so the send below moves verified bytes only.
pub(super) fn verify_reused_sealed(
    engine: &mut Engine,
    keyring: &DriveKeyring,
    sealed_bytes: Vec<u8>,
    obligation: &str,
    correlate: impl FnOnce(u64, Message) -> Result<(), EngineError>,
) -> Result<Option<Vec<u8>>, EngineError> {
    let Some((sealed_epoch, message)) =
        open_reused_sealed(engine, keyring, &sealed_bytes, obligation)?
    else {
        return Ok(None);
    };
    correlate(sealed_epoch, message)?;
    Ok(Some(sealed_bytes))
}

/// Seal a fresh message under the obligation's epoch key and commit
/// the sealed fact, so retries resend byte-identical bytes. A missing
/// key is not corruption — returns `Ok(None)` and the obligation
/// stays pending. The size check runs before the commit: persisting
/// oversize bytes would poison the obligation past retry.
pub(super) fn seal_fresh_for(
    engine: &mut Engine,
    keyring: &DriveKeyring,
    epoch: u64,
    message: &Message,
    seal_fact: impl FnOnce(Vec<u8>) -> Fact,
) -> Result<Option<Vec<u8>>, EngineError> {
    let key = match control_key_for(engine, keyring, epoch) {
        Ok(key) => key,
        Err(EngineError::MissingEpochKey(_)) => return Ok(None),
        Err(other) => return Err(other),
    };
    let sealed = seal_control(&key, &engine.drive, epoch, message)?;
    let bytes = sealed.encode();
    crate::transport::mailbox::check_outbound_size(&bytes)?;
    engine.commit_facts(&[seal_fact(bytes.clone())])?;
    Ok(Some(bytes))
}

/// Send verified sealed bytes to each recipient under the mailbox's
/// outer recipient seal, committing one delivered marker per
/// successful send. A send failure returns immediately with the rest
/// still pending.
pub(super) fn send_sealed_to(
    engine: &mut Engine,
    mailbox: &mut impl Mailbox,
    kind: &'static str,
    sealed_bytes: &[u8],
    recipients: impl IntoIterator<Item = DeviceId>,
    delivered: impl Fn(DeviceId) -> Fact,
) -> Result<usize, EngineError> {
    let mut sent = 0usize;
    for recipient in recipients {
        let envelope = seal_for_recipient(&engine.identity_secret, recipient, sealed_bytes)?;
        mailbox.send(envelope)?;
        // Per-send forensics, mirroring the intake verdict lines: with
        // relay ids on one side and control kinds on the other, a
        // stuck peer's whole outbox can be reconstructed envelope by
        // envelope.
        tracing::debug!(kind, recipient = ?recipient, "outbox send");
        engine.commit_facts(&[delivered(recipient)])?;
        sent += 1;
    }
    Ok(sent)
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
        let sealed_bytes = if let Some(bytes) = sealed_overlay.get(&id).cloned().or_else(|| {
            rebuilt
                .runtime
                .transition_sealed_bytes(id)
                .map(<[u8]>::to_vec)
        }) {
            // Reused sealed bytes are verified against the obligation
            // before use: the fact's key must name the transition the
            // bytes actually carry, or the send would discharge one
            // obligation while delivering another.
            let obligation = format!("transition {id:?}");
            let Some(bytes) = verify_reused_sealed(
                engine,
                &rebuilt.keyring,
                bytes,
                &obligation,
                |sealed_epoch, message| {
                    let Message::MembershipTransition(payload) = message else {
                        return Err(EngineError::SealedOutboxMismatch(format!(
                            "{obligation}: sealed bytes carry {:?}, not a transition",
                            message.kind()
                        )));
                    };
                    // The envelope epoch must be the transition's own
                    // epoch: the bytes are shared per transition, so a
                    // correct payload under a foreign epoch key would
                    // send to recipients that cannot open it and
                    // discharge the obligation anyway.
                    if sealed_epoch != epoch {
                        return Err(EngineError::SealedOutboxMismatch(format!(
                            "{obligation}: sealed under epoch {sealed_epoch}, not the transition's epoch {epoch}"
                        )));
                    }
                    let transition = MembershipTransition::from_canonical_bytes(
                        &payload.transition,
                    )
                    .map_err(|error| {
                        EngineError::SealedOutboxMismatch(format!(
                            "{obligation}: sealed transition does not decode: {error}"
                        ))
                    })?;
                    if transition.transition_id() != id {
                        return Err(EngineError::SealedOutboxMismatch(format!(
                            "{obligation}: sealed bytes carry {:?}, not the obligated transition",
                            transition.transition_id()
                        )));
                    }
                    Ok(())
                },
            )?
            else {
                // No sealing key: retain the obligation for a later
                // pass, like an orphaned one.
                while index < pending.len() && pending[index].0 == id {
                    index += 1;
                }
                continue;
            };
            bytes
        } else {
            let message = Message::MembershipTransition(TransitionPayload {
                transition: canonical,
            });
            let Some(bytes) =
                seal_fresh_for(engine, &rebuilt.keyring, epoch, &message, |sealed| {
                    Fact::TransitionSealed(id, sealed)
                })?
            else {
                // No sealing key: the obligation stays pending and
                // observable via the pending projection instead of
                // failing the whole pass on every drain.
                while index < pending.len() && pending[index].0 == id {
                    index += 1;
                }
                continue;
            };
            sealed_overlay.insert(id, bytes.clone());
            bytes
        };
        // Every pair for this transition in the frozen pending list:
        // no re-read, since only this loop writes and it appends
        // Delivered facts, never new Queued ones.
        let mut recipients = Vec::new();
        while index < pending.len() && pending[index].0 == id {
            recipients.push(pending[index].1);
            index += 1;
        }
        sent += send_sealed_to(
            engine,
            mailbox,
            "transition",
            &sealed_bytes,
            recipients,
            |recipient| Fact::TransitionDelivered(id, recipient),
        )?;
    }
    Ok(sent)
}

/// Send all pending capability obligations, rotation-framed. Each
/// pair seals its own recipient-specific delivery (the ECDH wrap binds
/// one recipient, so unlike transitions the sealed bytes are per-pair),
/// minted at send time from the keyring against the epoch's canonical
/// transition — the registered key comes from chain state, never from
/// the caller — so the bytes always reflect current membership.
///
/// The framing is rotation delivery, never the epoch-sealed envelope:
/// the recipient may hold no later epoch key — that is the ordinary
/// case this path serves — and an epoch seal would ask it for the very
/// key it is being given. The epoch seal needs no sender key either
/// (ECDH to the registered key), so a missing sender epoch key never
/// stalls capability delivery; only missing keyring secrets do.
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
        let reused = sealed_overlay
            .get(&(epoch, recipient))
            .cloned()
            .or_else(|| {
                rebuilt
                    .runtime
                    .capability_sealed_bytes(epoch, recipient)
                    .map(<[u8]>::to_vec)
            });
        let sealed_bytes = match reused {
            // Rotation reuse: the fact's key must still name what the
            // bytes carry (drive, epoch, recipient, current
            // registration), or the send would discharge one obligation
            // while delivering another. Re-opening is impossible — the
            // ephemeral secret is gone by design — and unnecessary: the
            // correlation below is the whole check, exactly as the
            // envelope-epoch correlation is for epoch-sealed reuse.
            Some(bytes) if bytes.first() == Some(&ROTATION_VERSION) => {
                let obligation = format!("capability epoch {epoch} for {recipient}");
                match verify_reused_rotation(
                    engine,
                    bytes,
                    &obligation,
                    epoch,
                    recipient,
                    &transition_id,
                )? {
                    Reused::Use(bytes) => bytes,
                    // Stale registration: the recipient holds a new
                    // secret the old bytes can never open under — mint
                    // fresh instead of erroring, since healing beats
                    // loudness here.
                    Reused::Mint => {
                        let Some(bytes) = mint_fresh_rotation(
                            engine,
                            &rebuilt.keyring,
                            &mut sealed_overlay,
                            epoch,
                            recipient,
                            &transition_id,
                        )?
                        else {
                            continue;
                        };
                        bytes
                    }
                }
            }
            // A pre-framing epoch-sealed fact, or a rotation sealed
            // under a superseded version: its bytes can never open for
            // the current reader (no proof blob, or keys the recipient
            // may never hold), so it never sends — mint fresh under the
            // current framing, which always opens. The stale fact lingers
            // durably and harmlessly; the new seal takes the overlay.
            // This is the announced re-mint recovery for the `0x01 ->
            // 0x02` bump, and it is what keeps an upgrade from stranding
            // a pending obligation. Bytes decoding as neither framing
            // still fail closed: genuinely undecodable outbox bytes never
            // silently heal.
            Some(bytes) if is_superseded_rotation(&bytes) => {
                // Supersede durably, exactly once. First-seal-wins
                // cannot express "these bytes are no longer the
                // obligation", so the change is its own fact: a
                // pass-local overlay would be discarded on restart,
                // leaving the stale fact to be re-minted into *new*
                // bytes every pass — one appended-and-fsynced,
                // then-ignored record per obligation per pass during a
                // relay outage, and retries that are no longer
                // byte-identical. With the fact committed, replay makes
                // the replacement the current obligation and every
                // later pass reuses these exact bytes.
                let supersedes =
                    crate::durable::SealedCapabilityFactId::of(epoch, &recipient, &bytes);
                let Some(replacement) = mint_fresh_rotation_bytes(
                    engine,
                    &rebuilt.keyring,
                    epoch,
                    recipient,
                    &transition_id,
                )?
                else {
                    continue;
                };
                engine.commit_facts(&[Fact::CapabilitySealedReplaced {
                    epoch,
                    recipient,
                    supersedes,
                    replacement: replacement.clone(),
                }])?;
                replacement
            }
            Some(bytes) => {
                if SealedControl::decode(&bytes).is_err() {
                    let obligation = format!("capability epoch {epoch} for {recipient}");
                    return Err(EngineError::SealedOutboxMismatch(format!(
                        "{obligation}: sealed bytes do not decode"
                    )));
                }
                let Some(bytes) = mint_fresh_rotation(
                    engine,
                    &rebuilt.keyring,
                    &mut sealed_overlay,
                    epoch,
                    recipient,
                    &transition_id,
                )?
                else {
                    continue;
                };
                bytes
            }
            None => {
                let Some(bytes) = mint_fresh_rotation(
                    engine,
                    &rebuilt.keyring,
                    &mut sealed_overlay,
                    epoch,
                    recipient,
                    &transition_id,
                )?
                else {
                    // No mintable wrap (missing secrets, or the
                    // recipient left the epoch's state): the obligation
                    // stays pending and observable via the pending
                    // projection instead of failing the whole pass on
                    // every drain.
                    continue;
                };
                bytes
            }
        };
        sent += send_sealed_to(
            engine,
            mailbox,
            "capability",
            &sealed_bytes,
            [recipient],
            |delivered| Fact::CapabilityDelivered(epoch, delivered),
        )?;
    }
    Ok(sent)
}

/// What reused rotation bytes offer: resend them verbatim, or mint
/// fresh when they went stale.
enum Reused {
    /// The bytes still name the obligation: resend them verbatim.
    Use(Vec<u8>),
    /// The bytes went stale (or predate the framing): mint fresh.
    Mint,
}

/// Verify reused rotation bytes against the obligation about to be
/// discharged: the header must still name this drive, epoch,
/// recipient, and the recipient's current registration. Anything
/// undecodable or misaddressed fails closed (a fact-key/bytes mismatch
/// would discharge one obligation while delivering another); a stale
/// registration mints fresh instead, since the recipient holds a new
/// secret the old bytes can never open under.
fn verify_reused_rotation(
    engine: &Engine,
    bytes: Vec<u8>,
    obligation: &str,
    epoch: u64,
    recipient: DeviceId,
    transition_id: &TransitionId,
) -> Result<Reused, EngineError> {
    let sealed = SealedRotation::decode(&bytes).map_err(|_| {
        EngineError::SealedOutboxMismatch(format!("{obligation}: sealed bytes do not decode"))
    })?;
    if sealed.version != ROTATION_VERSION
        || sealed.drive != engine.drive
        || sealed.epoch != epoch
        || sealed.recipient != recipient
    {
        return Err(EngineError::SealedOutboxMismatch(format!(
            "{obligation}: sealed bytes do not name the obligated delivery"
        )));
    }
    let current = engine
        .log
        .state_of(transition_id)
        .and_then(|state| state.encryption_key_of(&recipient).copied());
    if current.is_some_and(|key| key == sealed.encryption_key) {
        Ok(Reused::Use(bytes))
    } else {
        Ok(Reused::Mint)
    }
}

/// Mint a fresh rotation delivery for the obligation and commit the
/// sealed fact, so retries resend byte-identical bytes. Returns `None`
/// — obligation stays pending — when the epoch has no state, the
/// recipient is not a member with a registered key, or the keyring
/// lacks any secret through the epoch. The size check runs before the
/// commit: persisting oversize bytes would poison the obligation past
/// retry.
fn mint_fresh_rotation(
    engine: &mut Engine,
    keyring: &DriveKeyring,
    sealed_overlay: &mut BTreeMap<(u64, DeviceId), Vec<u8>>,
    epoch: u64,
    recipient: DeviceId,
    transition_id: &TransitionId,
) -> Result<Option<Vec<u8>>, EngineError> {
    let Some(bytes) = mint_fresh_rotation_bytes(engine, keyring, epoch, recipient, transition_id)?
    else {
        return Ok(None);
    };
    engine.commit_facts(&[Fact::CapabilitySealed(epoch, recipient, bytes.clone())])?;
    sealed_overlay.insert((epoch, recipient), bytes.clone());
    Ok(Some(bytes))
}

/// Mint current-framing rotation bytes for one obligation without
/// committing anything: the caller decides whether this becomes the
/// durable obligation (a replacement fact) or a first seal.
fn mint_fresh_rotation_bytes(
    engine: &mut Engine,
    keyring: &DriveKeyring,
    epoch: u64,
    recipient: DeviceId,
    transition_id: &TransitionId,
) -> Result<Option<Vec<u8>>, EngineError> {
    let Some(state) = engine.log.state_of(transition_id) else {
        return Ok(None);
    };
    let Some(transition) = engine.log.transition(transition_id) else {
        return Ok(None);
    };
    let Some(registration) = state.encryption_key_of(&recipient).copied() else {
        return Ok(None);
    };
    // Mint authority, checked before anything is sealed or committed
    // (epochs.md rule 3). The recipient enforces this at intake: a proof
    // signed outside the transition's pre-state owner set is suppressed.
    // A sender without it would append a replacement, mark it
    // transmitted, and deliver bytes the recipient discards — a durable
    // fact claiming an obligation discharged that no recipient ever
    // honours. Leave the obligation pending for an authorized signer
    // instead; the relay reaches the owner.
    let mint_authority = match transition.prev {
        Some(prev) => engine.log.owners_of(&prev),
        // Genesis establishes its own owner set; there is no earlier
        // state to consult.
        None => engine.log.owners_of(transition_id),
    };
    match mint_authority {
        Some(owners) if owners.contains(&engine.device) => {}
        // Signed, but by a device without mint authority.
        Some(_) => return Ok(None),
        None => return Err(EngineError::TransitionUnclassified(*transition_id)),
    }
    let Some(secrets) = epoch_secrets(keyring, transition) else {
        return Ok(None);
    };
    let Some(wrap) = mint_wrap(engine.drive, &state, transition, recipient, secrets.clone()) else {
        return Ok(None);
    };
    // Mint authority, distinct from delivery authority: the owner signs
    // a commitment to this exact vector, so any member may later relay
    // the sealed bytes while only an owner can have originated them.
    let proof = OwnerProof::sign(
        &engine.identity_secret,
        &engine.drive,
        &recipient,
        &transition.transition_id(),
        epoch,
        &secrets,
    );
    let sealed = seal_rotation(
        &engine.drive,
        recipient,
        &registration,
        epoch,
        &transition.canonical_bytes(),
        &wrap,
        &proof.encode(),
    )?;
    let bytes = sealed.encode();
    crate::transport::mailbox::check_outbound_size(&bytes)?;
    Ok(Some(bytes))
}
/// The epoch-secret vector a transition's grant carries: one secret per
/// epoch `1..=N`, straight from the keyring.
fn epoch_secrets(
    keyring: &DriveKeyring,
    transition: &MembershipTransition,
) -> Option<Vec<crate::keys::EpochSecret>> {
    let mut secrets = Vec::with_capacity(transition.epoch as usize);
    for past in 1..=transition.epoch {
        secrets.push(keyring.secret(past)?.clone());
    }
    Some(secrets)
}

fn mint_wrap(
    drive: DriveId,
    state: &crate::membership::MembershipState,
    transition: &MembershipTransition,
    recipient: DeviceId,
    secrets: Vec<crate::keys::EpochSecret>,
) -> Option<Vec<u8>> {
    let cap = Capability::mint(drive, recipient, state, transition, secrets).ok()?;
    Some(cap.wrap().ok()?.as_bytes().to_vec())
}

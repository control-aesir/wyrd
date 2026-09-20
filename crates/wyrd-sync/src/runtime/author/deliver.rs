use std::collections::BTreeMap;

use wyrd_format::{DeviceId, DriveId, MembershipTransition, TransitionId};

use crate::control::{
    open as open_control, seal as seal_control, CapabilityPayload, Message, SealedControl,
    TransitionPayload,
};
use crate::durable::{Fact, Rebuilt};
use crate::keys::capability::{Capability, DriveKeyring};
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
    // from this rebuild. Mid-pass commits only append Sealed and
    // Delivered facts — never new Queued pairs — so the frozen pending
    // lists stay exact, and an in-memory overlay absorbs newly sealed
    // bytes. No re-read per pair: a newcomer catch-up or a large
    // fan-out costs one log decode, not one per obligation.
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
fn control_key_for(
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
fn open_reused_sealed(
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
    sealed_bytes: &[u8],
    recipients: impl IntoIterator<Item = DeviceId>,
    delivered: impl Fn(DeviceId) -> Fact,
) -> Result<usize, EngineError> {
    let mut sent = 0usize;
    for recipient in recipients {
        let envelope = seal_for_recipient(&engine.identity_secret, recipient, sealed_bytes)?;
        mailbox.send(envelope)?;
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
        sent += send_sealed_to(engine, mailbox, &sealed_bytes, recipients, |recipient| {
            Fact::TransitionDelivered(id, recipient)
        })?;
    }
    Ok(sent)
}

/// Send all pending capability obligations. Each pair seals its own
/// recipient-specific wrap (the ECDH wrap binds one recipient, so
/// unlike transitions the sealed bytes are per-pair), minted at send
/// time from the keyring against the epoch's canonical transition —
/// the registered key comes from chain state, never from the caller —
/// so the bytes always reflect current membership.
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
        let sealed_bytes = if let Some(bytes) = reused {
            // Reused sealed bytes are verified against the obligation
            // before use: the fact's key must name the (epoch,
            // recipient) the bytes actually grant, or the send would
            // discharge one obligation while delivering another. The
            // envelope binding needs no extra check here: the
            // commit-time epoch gate pins the payload epoch to the
            // fact's key, and the pair check below pins the fact's key
            // to the obligation.
            let obligation = format!("capability epoch {epoch} for {recipient}");
            let Some(bytes) = verify_reused_sealed(
                engine,
                &rebuilt.keyring,
                bytes,
                &obligation,
                |_, message| {
                    let Message::Capability(payload) = message else {
                        return Err(EngineError::SealedOutboxMismatch(format!(
                            "{obligation}: sealed bytes carry {:?}, not a capability",
                            message.kind()
                        )));
                    };
                    if payload.device != recipient || payload.epoch != epoch {
                        return Err(EngineError::SealedOutboxMismatch(format!(
                            "{obligation}: sealed bytes grant epoch {} to {}, not the obligated pair",
                            payload.epoch, payload.device,
                        )));
                    }
                    Ok(())
                },
            )?
            else {
                // No sealing key: retain the obligation for a later
                // pass instead of failing the whole pass on every drain.
                continue;
            };
            bytes
        } else {
            let Some(state) = engine.log.state_of(&transition_id) else {
                continue;
            };
            let Some(transition) = engine.log.transition(&transition_id) else {
                continue;
            };
            let Some(wrap) = mint_wrap(
                engine.drive,
                &rebuilt.keyring,
                &state,
                transition,
                recipient,
            ) else {
                continue;
            };
            let message = Message::Capability(CapabilityPayload {
                device: recipient,
                epoch,
                wrapped: wrap,
            });
            let Some(bytes) =
                seal_fresh_for(engine, &rebuilt.keyring, epoch, &message, |sealed| {
                    Fact::CapabilitySealed(epoch, recipient, sealed)
                })?
            else {
                // No sealing key: the obligation stays pending and
                // observable via the pending projection instead of
                // failing the whole pass on every drain.
                continue;
            };
            sealed_overlay.insert((epoch, recipient), bytes.clone());
            bytes
        };
        sent += send_sealed_to(engine, mailbox, &sealed_bytes, [recipient], |delivered| {
            Fact::CapabilityDelivered(epoch, delivered)
        })?;
    }
    Ok(sent)
}

/// Mint one recipient's wrap for an epoch from the delivery
/// snapshot's keyring: `None` when the keyring lacks any secret
/// through the epoch (the pair stays pending for a later pass) or the
/// recipient is not a member of the epoch's state with a registered
/// key.
fn mint_wrap(
    drive: DriveId,
    keyring: &DriveKeyring,
    state: &crate::membership::MembershipState,
    transition: &MembershipTransition,
    recipient: DeviceId,
) -> Option<Vec<u8>> {
    let epoch = transition.epoch;
    let mut secrets = Vec::with_capacity(epoch as usize);
    for past in 1..=epoch {
        secrets.push(keyring.secret(past)?.clone());
    }
    let cap = Capability::mint(drive, recipient, state, transition, secrets).ok()?;
    Some(cap.wrap().ok()?.as_bytes().to_vec())
}

//! The fake relay: envelopes stay until Acked; every pass offers
//! each live envelope once, in arrival order, then yields. Plus the
//! member-peer's-eye sealing helper for control messages.

use std::collections::HashSet;

use wyrd_format::DeviceId;
use wyrd_sync::control::{self, Message};
use wyrd_sync::keys::{DeviceIdentitySecret, EpochSecret};
use wyrd_sync::transport::mailbox::{
    seal_for_recipient, Delivery, DeliveryId, Disposition, Mailbox, MailboxEnvelope, MailboxError,
};

/// A fake relay: envelopes stay until Acked; every pass offers each
/// live envelope once, in arrival order, then yields.
pub(crate) struct Relay {
    live: Vec<Option<(DeliveryId, MailboxEnvelope)>>,
    offered: HashSet<DeliveryId>,
    next_id: u64,
}

impl Relay {
    pub(crate) fn new() -> Self {
        Relay {
            live: Vec::new(),
            offered: HashSet::new(),
            next_id: 1,
        }
    }

    pub(crate) fn queue(&mut self, envelopes: impl IntoIterator<Item = MailboxEnvelope>) {
        for envelope in envelopes {
            let id = DeliveryId::new(self.next_id);
            self.next_id += 1;
            self.live.push(Some((id, envelope)));
        }
    }
}

impl Mailbox for Relay {
    fn send(
        &mut self,
        envelope: MailboxEnvelope,
    ) -> Result<(), wyrd_sync::transport::mailbox::MailboxError> {
        self.queue(std::iter::once(envelope));
        Ok(())
    }

    fn recv(&mut self) -> Result<Option<Delivery>, MailboxError> {
        let found = self
            .live
            .iter()
            .flatten()
            .find(|(id, _)| !self.offered.contains(id))
            .map(|(id, envelope)| (*id, envelope.clone()));
        match found {
            Some((id, envelope)) => {
                self.offered.insert(id);
                Ok(Some(Delivery::new(id, envelope)))
            }
            None => {
                // The pass is over: the next drain re-offers
                // everything still unsettled.
                self.offered.clear();
                Ok(None)
            }
        }
    }

    fn settle(
        &mut self,
        id: DeliveryId,
        disposition: Disposition,
    ) -> Result<(), wyrd_sync::transport::mailbox::MailboxError> {
        if matches!(disposition, Disposition::Ack | Disposition::Poison) {
            // The fake keeps no durable log, so poison and consumption
            // settle identically: drop the slot. A Poison left live
            // would re-offer forever, hanging the drain instead of
            // failing it.
            for slot in &mut self.live {
                if slot.as_ref().is_some_and(|(i, _)| *i == id) {
                    *slot = None;
                }
            }
            self.live.retain(Option::is_some);
        }
        Ok(())
    }
}

/// Seal one control message under an epoch's control key and wrap it
/// for the recipient's mailbox, exactly as a member peer would.
pub(crate) fn sealed_envelope(
    sender: &DeviceIdentitySecret,
    recipient: DeviceId,
    epoch_secret: &EpochSecret,
    epoch: u64,
    message: &Message,
) -> MailboxEnvelope {
    let drive = super::signing::drive();
    let key = epoch_secret.control_key(&drive, epoch);
    let sealed = control::seal(&key, &drive, epoch, message).unwrap();
    seal_for_recipient(sender, recipient, &sealed.encode()).unwrap()
}

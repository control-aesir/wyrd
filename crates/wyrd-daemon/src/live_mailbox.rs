//! Daemon-side Nostr relay mailbox.
//!
//! `wyrd-sync` deliberately exposes a synchronous handover trait. This
//! adapter owns a multi-thread Tokio runtime and a `nostr-sdk` client so the
//! composer can keep that boundary synchronous without putting async or
//! networking into the format or sync crates.

use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::sync::Arc;

use futures_util::StreamExt;
use nostr::event::FinalizeEventAsync;
use nostr_connect::client::NostrConnect;
use nostr_sdk::prelude::{Client, ClientNotification, Event, EventBuilder, Filter, Kind, Tag};
use tokio::runtime::{Builder, Runtime};
use wyrd_format::DeviceId;
use wyrd_sync::transport::{
    Delivery, DeliveryId, Disposition, Mailbox, MailboxEnvelope, MailboxError,
};

/// Private event kind used for Wyrd's sealed control-plane deliveries.
/// Relays see only the sender, recipient tag, and opaque NIP-44 ciphertext.
const CONTROL_KIND: u16 = 30_001;

#[derive(Debug)]
struct PendingDelivery {
    id: DeliveryId,
    envelope: MailboxEnvelope,
}

/// A live Nostr mailbox for one device. The relay client is intentionally
/// owned by the daemon composer; `wyrd-sync` only sees the `Mailbox` trait.
pub struct LiveMailbox {
    runtime: Runtime,
    client: Arc<Client>,
    signer: Arc<NostrConnect>,
    owner: DeviceId,
    incoming: Receiver<Box<Event>>,
    pending: Option<PendingDelivery>,
    next_delivery: u64,
}

impl LiveMailbox {
    /// Connect to the configured relays and subscribe to this device's
    /// recipient tag. The runtime remains alive for the mailbox lifetime.
    pub fn connect<I, S>(
        signer: NostrConnect,
        relays: I,
        owner: DeviceId,
    ) -> Result<Self, MailboxError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let runtime = Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|error| MailboxError::Transport(error.to_string()))?;
        let client = Arc::new(Client::default());
        let signer = Arc::new(signer);
        let relay_urls = relays
            .into_iter()
            .map(|relay| relay.as_ref().to_owned())
            .collect::<Vec<_>>();
        let owner_tag = owner.to_string();
        let client_for_setup = Arc::clone(&client);
        runtime.block_on(async move {
            for relay in relay_urls {
                client_for_setup
                    .add_relay(relay)
                    .await
                    .map_err(|error| MailboxError::Transport(error.to_string()))?;
            }
            client_for_setup.connect().await;
            client_for_setup
                .subscribe(
                    Filter::new()
                        .kind(Kind::Custom(CONTROL_KIND))
                        .custom_tag(nostr::filter::SingleLetterTag::LOWERCASE_P, owner_tag),
                )
                .await
                .map_err(|error| MailboxError::Transport(error.to_string()))?;
            Ok::<(), MailboxError>(())
        })?;

        let (sender, incoming) = mpsc::channel();
        let client_for_events = Arc::clone(&client);
        runtime.spawn(async move {
            let mut notifications = client_for_events.notifications();
            while let Some(notification) = notifications.next().await {
                if let ClientNotification::Event { event, .. } = notification {
                    if sender.send(event).is_err() {
                        break;
                    }
                }
            }
        });

        Ok(Self {
            runtime,
            client,
            signer,
            owner,
            incoming,
            pending: None,
            next_delivery: 1,
        })
    }

    fn next_event(&mut self) -> Option<Box<Event>> {
        loop {
            match self.incoming.try_recv() {
                Ok(event) if event.kind == Kind::Custom(CONTROL_KIND) => return Some(event),
                Ok(_) => continue,
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => return None,
            }
        }
    }

    fn envelope_from_event(&self, event: Box<Event>) -> Result<MailboxEnvelope, MailboxError> {
        Ok(MailboxEnvelope {
            sender: DeviceId::from_bytes(event.pubkey.to_bytes()),
            recipient: self.owner,
            ciphertext: event.content,
        })
    }
}

impl Mailbox for LiveMailbox {
    fn send(&mut self, envelope: MailboxEnvelope) -> Result<(), MailboxError> {
        let builder = EventBuilder::new(Kind::Custom(CONTROL_KIND), envelope.ciphertext)
            .tag(Tag::custom("p", [envelope.recipient.to_string()]));
        let event = self
            .runtime
            .block_on(builder.finalize_async(&*self.signer))
            .map_err(|error| MailboxError::Transport(error.to_string()))?;
        self.runtime
            .block_on(async { self.client.send_event(&event).await })
            .map(|_| ())
            .map_err(|error| MailboxError::Transport(error.to_string()))
    }

    fn recv(&mut self) -> Option<Delivery> {
        if let Some(pending) = &self.pending {
            return Some(Delivery::new(pending.id, pending.envelope.clone()));
        }
        let event = self.next_event()?;
        let envelope = self.envelope_from_event(event).ok()?;
        let id = DeliveryId::new(self.next_delivery);
        self.next_delivery = self.next_delivery.wrapping_add(1).max(1);
        self.pending = Some(PendingDelivery { id, envelope });
        self.recv()
    }

    fn settle(&mut self, id: DeliveryId, disposition: Disposition) -> Result<(), MailboxError> {
        let Some(pending) = &self.pending else {
            return Err(MailboxError::Transport("unknown delivery".into()));
        };
        if pending.id != id {
            return Err(MailboxError::Transport("delivery id mismatch".into()));
        }
        if matches!(disposition, Disposition::Ack) {
            self.pending = None;
        }
        Ok(())
    }
}

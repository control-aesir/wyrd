//! Delivery and keys: control-plane sends plus the epoch keys inbox ingest needs.

use zeroize::Zeroizing;

use crate::transport::mailbox::Mailbox;

use super::super::author;
use super::Engine;
use super::EngineError;

impl Engine {
    /// Send every undischarged transition- and capability-delivery
    /// obligation, returning the number of relay-accepted sends this call.
    /// Transitions go before capabilities; a mid-loop transport
    /// failure leaves the rest pending for the next call. See
    /// [`author::deliver_pending`].
    pub fn deliver_pending(&mut self, mailbox: &mut impl Mailbox) -> Result<usize, EngineError> {
        author::deliver_pending(self, mailbox)
    }

    /// Hold an epoch's control key for inbox ingest. Keys live with
    /// the engine (not just the inbox) so restarts and resyncs keep
    /// them; both copies are zeroizing, so replacement briefly holds
    /// old and new without either lingering past its drop.
    pub fn add_epoch_key(&mut self, epoch: u64, key: Zeroizing<[u8; 32]>) {
        self.inbox.add_epoch_key(epoch, key.clone());
        self.epoch_keys.insert(epoch, key);
    }
}

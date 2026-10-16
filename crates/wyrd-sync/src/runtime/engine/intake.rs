//! Intake: draining the mailbox into durable facts.

use crate::transport::mailbox::Mailbox;

use super::super::intake;
use super::{DrainReport, Engine, EngineError};

impl Engine {
    /// Drain every envelope currently in the mailbox, committing facts
    /// per accepted message. Stops at the first empty `recv`.
    pub fn drain(&mut self, mailbox: &mut impl Mailbox) -> Result<DrainReport, EngineError> {
        intake::drain(self, mailbox)
    }
}

//! Control-plane transport: the Nostr mailbox and the NIP-46 signer
//! session (`docs/trust.md` "Control plane", "NIP-46 remote signing";
//! tracking issue: control-plane transport wiring).
//!
//! Two independent boundaries live here, both trait-shaped rather than
//! network-implemented: the concrete relay pool and the concrete
//! `nostr-connect` session are relay/signer-client wiring for whatever
//! composes this crate (`docs/architecture.md`'s "application/daemon
//! composes sync and fuse"), so every test in this module runs against
//! an in-memory fake, never a live network. A pool honors the
//! retain-until-ack contract by holding its sync cursor on unsettled
//! deliveries. What this module *does* pin:
//! the NIP-44 sealing of Wyrd's control bytes for mailbox delivery, and
//! the request/response shape a signer session must honor.
//!
//! **Recipient discovery (open question 1, resolved for v0):** mailbox
//! envelopes address the recipient's `DeviceId` directly, the same as
//! any two-party NIP-44 conversation. Relays therefore learn "these two
//! pubkeys are exchanging opaque ciphertext" — the same traffic-analysis
//! exposure `trust.md` already documents as best-effort, out of scope for
//! the crypto layer (identical posture to vault-visible StorageId
//! fetches). No additional unlinkability mechanism (e.g. per-message
//! ephemeral routing keys) is adopted for v0; revisit only if a concrete
//! threat model demands it.

pub mod mailbox;
pub mod signer;

pub use mailbox::{Delivery, DeliveryId, Disposition, Mailbox, MailboxEnvelope, MailboxError};
pub use signer::{SignerError, SignerSession};

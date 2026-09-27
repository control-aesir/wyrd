//! Shared fixtures. Everything rides the public API path — real
//! secp256k1 keys, hand-signed membership and snapshot bodies, real
//! control-plane sealing through a fake relay mailbox, and the
//! in-memory bulk peer. No wyrd-sync test internals: the contracts
//! must hold for outside consumers.
//!
//! The fixture lives in focused submodules split along what changes
//! together — signing, the fake relay, the engine rig, sealed
//! content, and view adapters — and this module re-exports every
//! name at its original `crate::support::*` path, so contract files
//! never churn for the split.

mod relay;
mod rig;
mod sealed;
mod signing;
mod view;

pub(crate) use relay::{sealed_envelope, Relay};
pub(crate) use rig::{scratch_dir, AnnouncedRoots, Rig};
pub(crate) use sealed::{seal_flat_drive, Loaded};
pub(crate) use signing::{
    device, drive, sign_snapshot, sign_transition, signed_head, signed_snapshot, signed_transition,
    Device,
};
pub(crate) use view::{fixture_heads, mount_heads, RemoteOnlyMaterialization};

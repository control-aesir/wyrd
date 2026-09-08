//! Capability wrapping and monotonic installation.

pub(crate) mod encoding;
pub(crate) mod envelope;
mod model;
#[cfg(test)]
mod tests;

pub(crate) use model::ecdh_shared;
#[cfg(test)]
#[allow(unused_imports)]
pub(crate) use model::{capability_aad, CAPABILITY_AAD_DOMAIN};
pub use model::{
    Capability, CapabilityError, DriveKeyring, InstallError, InstallReport, WrappedCapability,
};

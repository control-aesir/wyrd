//! Wrapped capability envelope boundary.
//!
//! The implementation remains in `model` because wrapping and unwrapping
//! construct and validate the same capability type. This module preserves
//! a focused envelope ownership path without duplicating crypto logic.

#[allow(unused_imports)]
pub use super::model::WrappedCapability;
#[allow(unused_imports)]
pub(crate) use super::model::{ecdh_shared, hkdf_capability_key};

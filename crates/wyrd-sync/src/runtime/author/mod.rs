//! Local authoring and catch-up delivery: the write half of the drive.
//!
//! A member device turns a root tree it holds into a signed snapshot
//! bound to the canonical membership state, authors the manifest
//! hierarchy from representations it actually sealed (or recorded
//! mappings it holds the epoch capability for), commits everything
//! durably, and can announce the snapshot to the other members. This is
//! the producer the rest of the runtime assumed and never had: intake
//! and the live-head projection consumed snapshots, but every body under
//! test was built by a fixture.
//!
//! One concept per file: [`snapshot`] authors bodies, [`admission`]
//! admits devices, [`announce`] sends snapshot announcements, and
//! [`deliver`] discharges the transition/capability catch-up outbox.
//! Semantics follow `docs/epochs.md` ("local write"): snapshots parent
//! onto the locally live-lineage eligible heads, bind `membership` to
//! the canonical epoch-K transition, and set `epoch` to that
//! transition's epoch. Failures are fail-closed: no canonical
//! membership, a non-member author, an unavailable root tree, or a
//! signature that will not verify commits nothing.

mod admission;
mod announce;
mod deliver;
mod snapshot;

#[cfg(test)]
mod tests_admission;
#[cfg(test)]
mod tests_snapshot;

pub(super) use admission::admit_device;
pub use admission::AdmitOutcome;
pub(super) use announce::{announce, announce_pending};
pub(super) use deliver::deliver_pending;
pub(super) use snapshot::author;

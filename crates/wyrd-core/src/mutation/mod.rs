//! The mounted-mutation channel: FUSE submits, the daemon loop executes.
//!
//! Normative in `docs/write-path.md`. FUSE never authors; a committing
//! operation submits a [`MutationRequest`] and blocks, and the live loop
//! is the only engine user. The queue establishes the total order of
//! local mutations and executes them serially — admission order, with
//! held entries retried ahead of every new submission (below) — so each
//! snapshot's parents are the heads the previous mutation left.
//!
//! Deliberately unlike the want registry: a mutation is not a demand that
//! can outlive its waiter. Admission is immediate or [`MutationError::Saturated`],
//! and once admitted the request either commits or fails before the
//! caller returns — there is no path where a committing syscall fails and
//! the mutation applies later. The price is a hard liveness dependency on
//! the loop, which is a daemon-health concern bounded by the process
//! supervisor, not per-request cancellation.
//!
//! One exception keeps the waiter blocked: a mutation whose authoring
//! needs remote content holds across passes ([`MutationBatch::defer`]),
//! pinned to its evaluated head with a wall-clock deadline measured
//! from admission ([`MutationQueue::nearest_deadline`] feeds the
//! fetch budget). The hold never outlives the waiter and never
//! applies after a failure — it is a prerequisite wait, not a
//! background retry.
//!
//! The queue has its own lock (never the projection's or the store's).
//! Submitting wakes the loop's idle wait immediately; the loop drains the
//! batch, applies each request under the store write path, and completes
//! the caller only after the pass publishes — a returned success means
//! the new state is served.
//!
//! This module depends only on `wyrd-format` and std: it is the
//! `wyrd-core` mutation surface.

mod batch;
mod kind;
mod parents;
mod queue;

pub use batch::*;
pub use kind::*;
pub use parents::*;
pub use queue::*;

#[cfg(test)]
mod tests_batch;
#[cfg(test)]
mod tests_harness;
#[cfg(test)]
mod tests_parents;
#[cfg(test)]
mod tests_queue;

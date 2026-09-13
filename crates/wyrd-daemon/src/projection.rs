//! The published serving projection: one immutable, generation-tagged
//! snapshot of what presentation backends serve.
//!
//! The sync loop is the single writer: each pass either leaves the
//! published projection untouched or replaces it wholesale with a new
//! generation built from durable state. Backends clone the current
//! [`Arc`](std::sync::Arc) under a short read lock and then serve
//! lock-free from immutable data, so publication is atomic (readers
//! never observe a half-published projection) and readers never block
//! each other on view content.
//!
//! Two counters distinguish "the world changed" from "serving changed":
//! `revision` is the engine's durable commit sequence (every fact commit
//! advances it, empty passes do not), and `generation` counts
//! publications. The loop publishes exactly when the durable revision
//! has advanced past the published one (or a dirty backlog forces it) —
//! no per-report predicate, so a future commit path cannot silently skip
//! publication the way a report-counter gate could.
//!
//! This module depends only on `wyrd-format`, `wyrd-fuse`, and std: no
//! transport, no FUSE types, no Unix. That is deliberate — it is the
//! future `wyrd-core` coordination surface, kept liftable verbatim when
//! the core/daemon crate split lands.

use std::sync::{Arc, RwLock};

use wyrd_format::ObjectStore;
use wyrd_fuse::{DriveView, Materialization, ViewHead};

/// One published generation: the serving view plus the versions that
/// produced it. Immutable after construction; the loop publishes by
/// replacing the whole value, never by mutating it.
pub struct Projection<S: ObjectStore, M: Materialization> {
    /// Publication count. Bumps on every publish; readers use it to
    /// detect staleness (an older generation is a complete, merely
    /// outdated snapshot — never a torn one).
    generation: u64,
    /// The engine durable commit sequence this generation was built
    /// from. Equal revisions mean provably identical projections, so
    /// the idle loop can skip republication without recomputing heads.
    revision: u64,
    view: DriveView<S, M>,
}

impl<S: ObjectStore, M: Materialization> Projection<S, M>
where
    S::Error: std::fmt::Debug,
{
    /// Publish a generation over a shared store handle: the loop and
    /// the backends address the same bytes, each locking only for its
    /// own operation. Heads and facts are fixed at construction.
    pub fn new(
        store: Arc<RwLock<S>>,
        materialization: M,
        heads: Vec<ViewHead>,
        generation: u64,
        revision: u64,
    ) -> Self {
        Projection {
            generation,
            revision,
            view: DriveView::shared(store, materialization, heads),
        }
    }

    /// Adopt an already-built view as generation zero: the
    /// standalone-backend path passes revision zero (no sync loop owns
    /// a revision counter there); the live handoff passes the engine's
    /// current sequence so the first pass publishes only on real
    /// change. The adopted heads and facts come from the composer's
    /// synchronously refreshed view, so the baseline is exact — the
    /// loop reconciles anything committed after the split.
    pub fn initial(view: DriveView<S, M>, revision: u64) -> Self {
        Projection {
            generation: 0,
            revision,
            view,
        }
    }

    /// Publish the next generation over a replacement view: the
    /// generation bumps, the durable revision carries over. The
    /// test/simulation path — the production loop builds generations
    /// with [`new`](Self::new), advancing both counters together.
    pub fn successor(current: &Self, view: DriveView<S, M>) -> Self {
        Projection {
            generation: current.generation + 1,
            revision: current.revision,
            view,
        }
    }

    /// The publication count of this generation.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// The durable revision this generation was built from.
    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// The serving view of this generation.
    pub fn view(&self) -> &DriveView<S, M> {
        &self.view
    }
}

//! Wyrd's daemon: the composition layer the architecture reserves for
//! exactly this role (`docs/architecture.md`): it wires the `wyrd-core`
//! node to a presentation backend and owns the process around it
//! (supervision, signals, mount diagnostics).
//!
//! Two rules shape the layout. The node ([`wyrd_core::node::WyrdNode`])
//! is presentation-agnostic: mobile platforms (Android
//! SAF/DocumentsProvider, iOS file provider) cannot use FUSE, so the
//! platform surface is a pluggable backend over the same view — the
//! same five operations, platform errors instead of POSIX ones. The
//! FUSE adapter ([`fuse`]) is the first such backend, not a property
//! of the node. This crate's [`core`] module holds the host-side
//! composition tests; [`lifecycle`] owns supervision.

pub mod core;
pub mod fuse;
pub mod lifecycle;

pub use core::{
    FailureClass, LiveConfig, LiveError, LiveNode, LiveParts, LiveSummary, NodeError,
    ResourceBudgets, RuntimeMaterialization, SyncReport, WyrdNode,
};
pub use lifecycle::{Supervisor, Wake, WakeSignal};

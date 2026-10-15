//! The embedded consumer boundary: a real consumer of `wyrd-core`
//! that is not the daemon, the CLI, or a mount.
//!
//! The crate exists so the boundary is a fact about the workspace
//! rather than a claim in a document. Its dependency set is the
//! embedder's dependency set: the format, the transport, the node,
//! and the mount-free view crate — never `wyrd-daemon` (which links
//! `fuser`), never `wyrd-cli`, never the contract suite. Contract
//! 34's member-wide checks pin both the direct edges
//! (`crate_dependencies_follow_the_layered_dag`) and the transitive
//! closure (`consumer_link_graph_excludes_presentation`), so a
//! presentation edge reaching this consumer fails the suite, not a
//! review.
//!
//! The payload is one named contract,
//! [`embedded_drive_lifecycle_needs_no_fuse_and_no_daemon`]: one drive
//! through its whole embedded lifecycle — create, write, mutate
//! through the loop-driven channel, stop, reopen, observe, write
//! policy, reopen again, shut down in order — with no backend ever
//! constructed and no child process ever spawned. If a lifecycle step
//! needs a presentation surface, a daemon process, or the CLI, this
//! crate cannot express it, and that is the finding the contract is
//! designed to surface.

#[cfg(test)]
mod embedded_lifecycle;

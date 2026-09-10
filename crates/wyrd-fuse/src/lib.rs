//! Wyrd's FUSE presentation layer: the live view and time travel.
//!
//! The read-only drive view ([`view::DriveView`]) works mount-free
//! against the format layer and an abstract materialization interface.
//! Actual FUSE mounting (macFUSE on macOS, FUSE 3 on Linux) composes
//! this view with `wyrd-sync` in a daemon; the view itself never learns
//! how bytes arrive. See `docs/architecture.md`.

pub mod view;

pub use view::{
    Attr, ConflictVersion, DirEntry, DriveView, Kind, Materialization, Node, OpenFile, ViewError,
};

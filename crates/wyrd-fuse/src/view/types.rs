//! Namespace value types live in `wyrd-core` (the provider-neutral
//! namespace model) and are re-exported here so existing view and
//! backend code keeps its paths. The symlink confinement policy lives
//! there too — it is namespace policy shared by every backend that
//! materializes links, not kernel policy. What stays in this module is
//! nothing today: the kernel refusal mapping (EACCES) lives at the
//! backend's `readlink` boundary in `wyrd-daemon`.

pub use wyrd_core::view::{
    confine_symlink_target, Attr, ConfinementError, ConflictVersion, DirEntry, Kind,
    MaterializationPolicy as Materialization, Node, OpenFile, ViewError,
};

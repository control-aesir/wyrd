//! FUSE presentation backend, split by concern: [`inode`] owns the
//! inode table and open-state tracking, [`backend`] maps kernel ops
//! onto the daemon's [`DriveView`](wyrd_fuse::DriveView). Behavior
//! tests live alongside, one file per theme.
//!
//! The composed view type is re-exported for hosts: a process host
//! (like `wyrd-cli`) builds its node over the same view the backend
//! serves, through the daemon's surface — never by depending on the
//! view crate directly.

mod backend;
mod inode;

#[cfg(test)]
mod tests_backend;
#[cfg(test)]
mod tests_conflicts;
#[cfg(test)]
mod tests_errors;
#[cfg(test)]
mod tests_harness;
#[cfg(test)]
mod tests_inode;
#[cfg(test)]
mod tests_want;

pub use backend::FuseBackend;
pub use wyrd_fuse::DriveView;

//! FUSE presentation backend, split by concern: [`inode`] owns the
//! inode table and open-state tracking, [`backend`] maps kernel ops
//! onto the daemon's [`DriveView`](wyrd_fuse::DriveView). Behavior
//! tests live alongside, one file per theme.

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

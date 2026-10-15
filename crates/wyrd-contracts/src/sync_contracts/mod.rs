//! The sync-facing contracts: verified heads, the write path, queue
//! pressure, and recovery — with the cross-cutting fixtures in
//! [`harness`].

mod harness;
mod heads;
mod queue_pressure;
mod recovery;
mod write_path;

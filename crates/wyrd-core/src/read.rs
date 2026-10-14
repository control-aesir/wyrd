//! Live mount-free reads: the demand-driven open/read sequence
//! every serving backend performs, without a kernel mount.
//!
//! Writes never needed FUSE ([`WyrdNode::put_file`](crate::node::WyrdNode::put_file),
//! [`WyrdNode::remove`](crate::node::WyrdNode::remove)), and offline
//! reads never did ([`export`](crate::export)); what only the FUSE
//! backend could do is read remote-only content live — register the
//! want, block bounded while the fetch plan serves it, and surface
//! terminal verdicts fast. [`LiveReader`] is that sequence over any
//! [`NamespaceView`], with the same first-touch, repair-on-demand,
//! and reopen-demand rules the mount follows, so the two paths
//! cannot disagree on what a read means. POSIX mapping stays at the
//! presentation boundary: this module returns typed errors, never
//! errno.
//!
//! Repair queues are borrowed, never owned: quarantine and scrub
//! submission happen only when the caller wires queues that a live
//! loop drains. Without wiring, observed-invalid bytes surface as
//! their view error untouched and nothing is submitted, so a
//! miswired reader can never grow a queue no loop drains.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use wyrd_format::{ContentId, ObjectStore};

use crate::quarantine::{QuarantineQueue, VerificationFailure};
use crate::scrub::{ScrubObservation, ScrubQueue};
use crate::view::{NamespaceView, Node, OpenFile, ViewError};
use crate::want::{wait_for_materialization, WantError, WantRegistry};

/// Window per view `read`: large enough to stream, small enough
/// that one window never holds a whole drive hostage mid-wait.
const READ_WINDOW: usize = 128 * 1024;

/// Why a mount-free read failed. Non-demand failures (lookup,
/// conflicts, path errors) ride through as the view reported them;
/// demand failures name the identity and the verdict class, the way
/// the mount's errno mapping consumes them.
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    /// The view failed outside demand: lookup, conflict, path, or a
    /// post-wait read that still cannot serve.
    #[error("view failed: {0}")]
    View(#[from] ViewError),
    /// The bounded wait expired before the identity materialized.
    /// The fetch, if admitted, continues and caches for next time.
    #[error("fetch demand expired for {content:?}")]
    Timeout { content: ContentId },
    /// A settled terminal verdict (unavailable, corrupt): fail fast,
    /// never at the deadline.
    #[error("terminal verdict: {0}")]
    Terminal(ViewError),
    /// The demand was refused or the registry failed closed.
    #[error("demand failed: {0}")]
    Demand(#[from] WantError),
}

/// In-flight repairs this reader reported, keyed by content id. A
/// fresh entry means the repair the observation started may still
/// be behind a stale projection (claim cleared, bytes unlinked,
/// refetch running, served generation not yet republished), so a
/// terminal verdict waits it out instead of failing fast on the
/// stale view. Entries expire lazily on record; the set stays tiny
/// because only live repairs are ever queried.
#[derive(Debug, Default)]
struct RecentRepairs {
    seen: Mutex<HashMap<ContentId, Instant>>,
}

/// How long a reported repair keeps a later terminal verdict from
/// completing its waiter. Bounded by the wait's own deadline in
/// practice: no wait outlives the reader's timeout, so the window
/// can only delay, never hang, a genuinely terminal read.
const REPAIR_OBSERVATION_TTL: Duration = Duration::from_secs(30);

impl RecentRepairs {
    fn note(&self, content: ContentId) {
        if let Ok(mut seen) = self.seen.lock() {
            let now = Instant::now();
            seen.retain(|_, at| now.duration_since(*at) < REPAIR_OBSERVATION_TTL);
            seen.insert(content, now);
        }
    }

    fn contains(&self, content: &ContentId) -> bool {
        self.seen.lock().is_ok_and(|seen| {
            seen.get(content)
                .is_some_and(|at| Instant::now().duration_since(*at) < REPAIR_OBSERVATION_TTL)
        })
    }
}

/// The demand-driven read sequence over one view, mirroring the
/// mount: lookup, open with want registration and bounded blocking,
/// then windowed reads under the same demand. Serve from the same
/// published projection the mount serves and both paths read the
/// same bytes with the same failure classes.
///
/// A reader without wants reads served content and fails fast on
/// remote-only identities, like the mount without demand wiring. A
/// reader with wants blocks bounded; terminal verdicts still fail
/// fast, with reopen demand noted for the next pass.
pub struct LiveReader {
    wants: Option<Arc<WantRegistry>>,
    quarantine: Option<Arc<QuarantineQueue>>,
    scrub: Option<Arc<ScrubQueue>>,
    recent_rejections: RecentRepairs,
    recent_losses: RecentRepairs,
    open_timeout: Duration,
}

impl LiveReader {
    /// Read served content with fast terminal verdicts and no
    /// blocking: remote-only identities fail as their view error.
    pub fn new(open_timeout: Duration) -> Self {
        LiveReader {
            wants: None,
            quarantine: None,
            scrub: None,
            recent_rejections: RecentRepairs::default(),
            recent_losses: RecentRepairs::default(),
            open_timeout,
        }
    }

    /// Wire fetch demand: remote-only identities register a want
    /// and block bounded while the loop's fetch plan serves them.
    pub fn with_wants(mut self, wants: Arc<WantRegistry>) -> Self {
        self.wants = Some(wants);
        self
    }

    /// Wire repair queues a live loop drains: observed-invalid
    /// bytes are named to quarantine/scrub before anything else
    /// reads them again, so the current read heals in the same
    /// call when the refetch lands. Without wiring nothing is
    /// submitted and rejections surface untouched.
    pub fn with_repair(mut self, quarantine: Arc<QuarantineQueue>, scrub: Arc<ScrubQueue>) -> Self {
        self.quarantine = Some(quarantine);
        self.scrub = Some(scrub);
        self
    }

    /// Read the whole file at `path`: lookup, demand-driven open,
    /// then windowed reads to the declared size. Reads hold their
    /// open-time file, so head advancement mid-read never silently
    /// changes the bytes — the same stability the mount's open
    /// descriptors provide.
    pub fn read_file<V>(&self, view: &V, path: &str) -> Result<Vec<u8>, ReadError>
    where
        V: NamespaceView,
        V::Store: ObjectStore,
        <V::Store as ObjectStore>::Error: std::fmt::Debug,
    {
        let node = view.lookup(path).map_err(ReadError::View)?;
        let size = match &node {
            Node::File { size, .. } => *size,
            // Symlinks resolve at the presentation boundary and
            // conflicts address through version-qualified paths;
            // the view names the real failure on open.
            _ => return Err(ReadError::View(view.open_file(&node).unwrap_err())),
        };
        let file = self.open_with_demand(view, &node)?;
        let mut bytes = Vec::with_capacity(size.min(usize::MAX as u64) as usize);
        let mut offset = 0u64;
        while offset < size {
            let window = ((size - offset) as usize).min(READ_WINDOW);
            let chunk = self.read_with_demand(view, &file, offset, window)?;
            if chunk.is_empty() {
                break;
            }
            offset += chunk.len() as u64;
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }

    /// Open with the mount's demand flow: repair-on-demand entry
    /// for observed-invalid bytes, first-touch terminal fast path,
    /// then bounded blocking with terminal-aware retries.
    fn open_with_demand<V>(&self, view: &V, node: &Node) -> Result<OpenFile, ReadError>
    where
        V: NamespaceView,
        V::Store: ObjectStore,
        <V::Store as ObjectStore>::Error: std::fmt::Debug,
    {
        let first = view.open_file(node);
        // Repair-on-demand entry: observed-invalid bytes are named
        // to the loop before anything else reads them again, then
        // become `NotMaterialized` so the reader waits on the fresh
        // generation, not on doomed bytes. Without repair wiring
        // there is no loop to repair through, so the rejection
        // surfaces untouched — and nothing is submitted.
        let first = match (&self.quarantine, &self.wants, &first) {
            (
                Some(quarantine),
                Some(_),
                Err(ViewError::RejectedRepresentation { content, kind }),
            ) => {
                quarantine.submit(VerificationFailure::content_hash_mismatch(*content, *kind));
                self.recent_rejections.note(*content);
                Err(ViewError::NotMaterialized { content: *content })
            }
            _ => first,
        };
        let first = match (&self.scrub, &self.wants, &first) {
            (Some(scrub), Some(_), Err(ViewError::LostRepresentation { content, kind })) => {
                scrub.submit(ScrubObservation::missing(*content, *kind));
                self.recent_losses.note(*content);
                Err(ViewError::NotMaterialized { content: *content })
            }
            _ => first,
        };
        // A first-touch `Unavailable` with a fresh repair observation
        // is the same repair seen one observation later: the claim
        // is cleared (or clearing) and the projection lags, so the
        // identity enters the demand flow and waits it out. Without
        // a recent observation this stays the fast terminal verdict
        // it has always been.
        let first = match (&self.wants, &first) {
            (Some(_), Err(ViewError::Unavailable { content }))
                if self.recent_rejections.contains(content)
                    || self.recent_losses.contains(content) =>
            {
                Err(ViewError::NotMaterialized { content: *content })
            }
            _ => first,
        };
        let (Some(registry), Err(ViewError::NotMaterialized { content })) = (&self.wants, &first)
        else {
            return self.finish_first(first);
        };
        let content = *content;
        // Success completes; a terminal verdict completes only when
        // no repair is in flight for the identity (surfaced below,
        // with reopen demand noted so the next pass re-drives the
        // generation) — while a repair observed moments ago is still
        // behind a stale projection, so the waiter keeps polling
        // instead of failing fast on the stale view, healing in the
        // same call when the refetch lands or timing out at the
        // deadline. Corrupt notes nothing: its repair is
        // quarantine's job, not rewant's. A rejected representation
        // observed mid-wait is reported and waited through: the
        // drain clears the claim and the admitted want re-drives a
        // fresh generation, while persistent bad providers terminate
        // through strikes into a terminal Corrupt verdict, never
        // through an unbounded quarantine loop.
        let probe = || match view.open_file(node) {
            Ok(_) => true,
            Err(ViewError::Unavailable { content }) => {
                registry.note_reopen_demand(&content);
                !self.recent_rejections.contains(&content) && !self.recent_losses.contains(&content)
            }
            Err(ViewError::RejectedRepresentation { content, kind }) => {
                if let Some(quarantine) = &self.quarantine {
                    quarantine.submit(VerificationFailure::content_hash_mismatch(content, kind));
                }
                self.recent_rejections.note(content);
                false
            }
            Err(ViewError::LostRepresentation { content, kind }) => {
                if let Some(scrub) = &self.scrub {
                    scrub.submit(ScrubObservation::missing(content, kind));
                }
                self.recent_losses.note(content);
                false
            }
            Err(ViewError::Corrupt) => true,
            Err(_) => false,
        };
        match wait_for_materialization(registry, content, self.open_timeout, probe) {
            Ok(()) => self.finish_wait(view.open_file(node)),
            Err(WantError::TimedOut) => Err(ReadError::Timeout { content }),
            Err(error) => Err(ReadError::Demand(error)),
        }
    }

    /// First attempt without demand, or a non-materialized first
    /// failure with no wants wired: terminal verdicts note reopen
    /// demand (`Unavailable`) or nothing (`Corrupt`: its repair is
    /// quarantine's job, not rewant's) and fail fast — no waiter
    /// blocks on a verdict that already exists.
    fn finish_first(&self, first: Result<OpenFile, ViewError>) -> Result<OpenFile, ReadError> {
        match (&self.wants, &first) {
            (Some(registry), Err(ViewError::Unavailable { content })) => {
                registry.note_reopen_demand(content);
                Err(ReadError::Terminal(first.unwrap_err()))
            }
            (_, Err(ViewError::Corrupt)) => Err(ReadError::Terminal(first.unwrap_err())),
            _ => first.map_err(ReadError::View),
        }
    }

    /// The post-wait retry: success serves, terminal verdicts
    /// surface as terminal, anything else rides through as the
    /// view reported it.
    fn finish_wait(&self, retry: Result<OpenFile, ViewError>) -> Result<OpenFile, ReadError> {
        match retry {
            Ok(file) => Ok(file),
            Err(error @ (ViewError::Unavailable { .. } | ViewError::Corrupt)) => {
                Err(ReadError::Terminal(error))
            }
            Err(error) => Err(ReadError::View(error)),
        }
    }

    /// One windowed read under the same demand: a served file's
    /// windows succeed outright; a window that finds its bytes
    /// unserved waits them out exactly like an open.
    fn read_with_demand<V>(
        &self,
        view: &V,
        file: &OpenFile,
        offset: u64,
        len: usize,
    ) -> Result<Vec<u8>, ReadError>
    where
        V: NamespaceView,
        V::Store: ObjectStore,
        <V::Store as ObjectStore>::Error: std::fmt::Debug,
    {
        let first = view.read(file, offset, len);
        let (Some(registry), Err(ViewError::NotMaterialized { content })) = (&self.wants, &first)
        else {
            return self.finish_first_read(first);
        };
        let content = *content;
        let probe = || match view.read(file, offset, len) {
            Ok(_) => true,
            Err(ViewError::Unavailable { content }) => {
                registry.note_reopen_demand(&content);
                !self.recent_rejections.contains(&content) && !self.recent_losses.contains(&content)
            }
            Err(ViewError::RejectedRepresentation { content, kind }) => {
                if let Some(quarantine) = &self.quarantine {
                    quarantine.submit(VerificationFailure::content_hash_mismatch(content, kind));
                }
                self.recent_rejections.note(content);
                false
            }
            Err(ViewError::LostRepresentation { content, kind }) => {
                if let Some(scrub) = &self.scrub {
                    scrub.submit(ScrubObservation::missing(content, kind));
                }
                self.recent_losses.note(content);
                false
            }
            Err(ViewError::Corrupt) => true,
            Err(_) => false,
        };
        match wait_for_materialization(registry, content, self.open_timeout, probe) {
            Ok(()) => match view.read(file, offset, len) {
                Ok(bytes) => Ok(bytes),
                Err(error @ (ViewError::Unavailable { .. } | ViewError::Corrupt)) => {
                    Err(ReadError::Terminal(error))
                }
                Err(error) => Err(ReadError::View(error)),
            },
            Err(WantError::TimedOut) => Err(ReadError::Timeout { content }),
            Err(error) => Err(ReadError::Demand(error)),
        }
    }

    /// A windowed read without demand, or a served window: terminal
    /// verdicts note reopen demand (`Unavailable`) or nothing
    /// (`Corrupt`) and fail fast like the open path.
    fn finish_first_read(&self, first: Result<Vec<u8>, ViewError>) -> Result<Vec<u8>, ReadError> {
        match (&self.wants, &first) {
            (Some(registry), Err(ViewError::Unavailable { content })) => {
                registry.note_reopen_demand(content);
                Err(ReadError::Terminal(first.unwrap_err()))
            }
            (_, Err(ViewError::Corrupt)) => Err(ReadError::Terminal(first.unwrap_err())),
            _ => first.map_err(ReadError::View),
        }
    }
}

// Sibling test file under the workspace tests_* naming: #[path] is required
// because default resolution from this parent would look for tests.rs, not this name.
#[cfg(test)]
#[path = "read/tests_read.rs"]
mod tests;

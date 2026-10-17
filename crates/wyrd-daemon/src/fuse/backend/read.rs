//! Read path.

use std::sync::Arc;
use std::time::Instant;

use fuser::FileHandle;

use wyrd_core::quarantine::VerificationFailure;
use wyrd_core::scrub::ScrubObservation;

use wyrd_core::want::wait_for_materialization;
use wyrd_format::{ObjectStore, StoreFailure};
use wyrd_fuse::{Materialization, OpenFile, ViewError};

use super::super::inode::Handle;
use super::{complete_waiter_on_terminal, errno_of, slice_image, FuseBackend};

impl<S: ObjectStore, M: Materialization> FuseBackend<S, M>
where
    S::Error: std::fmt::Debug,
{
    /// Read through an open handle: the open-time capture serves the
    /// bytes, so head advancement cannot change what an open
    /// descriptor returns. A dirty writable handle serves its buffered
    /// image instead (read-your-writes); a clean one serves its pinned
    /// capture. Unknown handles are EBADF. The non-callback form of the
    /// kernel `read` op.
    ///
    /// First touch of an unmaterialized chunk registers a want and
    /// blocks bounded; the FD pins content identity, so the retried
    /// read serves the same pinned bytes once they arrive.
    pub fn read_handle(
        &self,
        fh: FileHandle,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, fuser::Errno> {
        match self.handle_of(fh)? {
            Handle::Read(handle) => self.read_via_capture(&handle.capture, offset, size),
            Handle::Write(handle) => {
                let (image, capture, failed, append, base_size) = {
                    let write = handle.lock().map_err(|_| fuser::Errno::EIO)?;
                    // A fold may hold this handle's image: park until
                    // it settles, then read the settled state —
                    // otherwise the read would serve pre-commit bytes
                    // while the overlay contract promises the overlay.
                    let write = self.wait_inflight(write)?;
                    (
                        write.image.clone(),
                        write.capture.clone(),
                        write.failed,
                        write.append,
                        write.base.size(),
                    )
                };
                if failed {
                    return Err(fuser::Errno::EIO);
                }
                if append {
                    // Read-your-writes over the logical file: the pinned
                    // capture followed by the buffered append sequence.
                    let buffer = image.unwrap_or_default();
                    return self.read_append(&capture, base_size, &buffer, offset, size);
                }
                match image {
                    Some(image) => Ok(slice_image(&image, offset, size)),
                    None => self.read_via_capture(&capture, offset, size),
                }
            }
        }
    }

    /// Read a window of an append handle's logical file: the base capture
    /// followed by the buffered append sequence. Only the requested base
    /// range is read from the store, so a large base is not materialized
    /// for a small read.
    fn read_append(
        &self,
        capture: &OpenFile,
        base_size: u64,
        buffer: &[u8],
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, fuser::Errno> {
        let total = base_size.saturating_add(buffer.len() as u64);
        if size == 0 || offset >= total {
            return Ok(Vec::new());
        }
        let end = offset.saturating_add(size as u64).min(total);
        let mut out = Vec::with_capacity((end - offset) as usize);
        if offset < base_size {
            let base_end = end.min(base_size);
            let base = self.read_via_capture(
                capture,
                offset,
                u32::try_from(base_end - offset).unwrap_or(u32::MAX),
            )?;
            out.extend_from_slice(&base);
        }
        if end > base_size {
            let start = offset.saturating_sub(base_size) as usize;
            let stop = (end - base_size) as usize;
            out.extend_from_slice(&buffer[start..stop]);
        }
        Ok(out)
    }

    /// Read a pinned capture through the current projection, with the
    /// demand path for not-yet-local content.
    pub(super) fn read_via_capture(
        &self,
        file: &OpenFile,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, fuser::Errno> {
        let attempt = |this: &Self| {
            Result::<Vec<u8>, (ViewError, fuser::Errno)>::Ok({
                let projection = this.projection().map_err(|error| {
                    (
                        ViewError::Store(StoreFailure::Transient, "projection lock".into()),
                        error,
                    )
                })?;
                projection
                    .view()
                    .read(file, offset, size as usize)
                    .map_err(|error| (error.clone(), errno_of(&error)))?
            })
        };
        self.with_demand(|| attempt(self), |attempted| attempted.map_err(|e| e.1))
    }

    /// Run `attempt`; when it fails on a not-materialized identity and
    /// demand is wired, register the want and block bounded on it, then
    /// retry once. A terminally unavailable identity completes the
    /// waiter immediately — unless a rejection was observed for it
    /// moments ago, in which case the repair is still in flight
    /// behind a stale projection (claim cleared, bytes unlinked,
    /// refetch running, served generation not yet republished) and
    /// the waiter waits it out instead of failing fast on the stale
    /// view. `Unavailable(generation)` is otherwise a verdict, not
    /// a maybe, so the bounded `EIO` lands now instead of at the
    /// deadline — while the reopen note it leaves makes the identity
    /// re-demandable on the next pass instead of permanently
    /// terminal. A rejected representation (verification-failed
    /// bytes) is reported to the loop's quarantine drain and then
    /// demanded like any other not-local content: the current reader
    /// is the waiter repair-on-demand requires, so the wait below
    /// heals in the same read when the refetch lands. A lost
    /// representation (claimed-but-absent bytes) is reported to
    /// the loop's scrub drain and demanded the same way: the
    /// current reader is the detector the background walk has not
    /// yet been, so the wait below heals in the same read when
    /// the refetch lands. Anything else
    /// (or no demand wiring) keeps the instant-errno behavior. This
    /// is the only place FUSE expresses demand — the engine stays
    /// the single synchronization authority.
    pub(super) fn with_demand<T>(
        &self,
        attempt: impl Fn() -> Result<T, (ViewError, fuser::Errno)>,
        map: impl Fn(Result<T, (ViewError, fuser::Errno)>) -> Result<T, fuser::Errno>,
    ) -> Result<T, fuser::Errno> {
        let first = attempt();
        // Repair-on-demand entry: observed-invalid bytes are named
        // to the loop before anything else reads them again. The
        // error then becomes `NotMaterialized` for the flow below so
        // the reader waits on the fresh generation, not on doomed
        // bytes. Without demand wiring there is no loop to repair
        // through, so the rejection surfaces as EIO untouched — and
        // nothing is submitted, so a miswired queue can never grow
        // without a drain.
        let first = match (&self.quarantine, &self.wants, &first) {
            (
                Some(quarantine),
                Some(_),
                Err((ViewError::RejectedRepresentation { content, kind }, errno)),
            ) => {
                quarantine.submit(VerificationFailure::content_hash_mismatch(*content, *kind));
                self.recent_rejections.note(*content, Instant::now());
                Err((ViewError::NotMaterialized { content: *content }, *errno))
            }
            _ => first,
        };
        // Repair-on-demand entry for loss: observed-absent bytes are
        // named to the scrub drain before anything else reads them
        // again. The error then becomes `NotMaterialized` for the
        // flow below so the reader waits on the fresh fetch, not on
        // a stale `Available`. Without demand wiring there is no
        // loop to repair through, so the loss surfaces as EIO
        // untouched — and nothing is submitted, so a miswired queue
        // can never grow without a drain.
        let first = match (&self.scrub, &self.wants, &first) {
            (
                Some(scrub),
                Some(_),
                Err((ViewError::LostRepresentation { content, kind }, errno)),
            ) => {
                scrub.submit(ScrubObservation::missing(*content, *kind));
                self.recent_losses.note(*content, Instant::now());
                Err((ViewError::NotMaterialized { content: *content }, *errno))
            }
            _ => first,
        };
        // A first-touch `Unavailable` with a fresh rejection is the
        // same repair seen one observation later: the claim is
        // cleared (or clearing) and the projection lags, so the
        // identity enters the demand flow and waits it out like a
        // rejected first read. Without a recent rejection this stays
        // the fast terminal EIO it has always been.
        let first = match (&self.quarantine, &self.wants, &first) {
            (Some(_), Some(_), Err((ViewError::Unavailable { content }, errno)))
                if self.recent_rejections.contains(content, Instant::now()) =>
            {
                Err((ViewError::NotMaterialized { content: *content }, *errno))
            }
            _ => first,
        };
        // A first-touch `Unavailable` with a fresh loss observation
        // is the same repair seen one observation later: the stale
        // claim is cleared (or clearing) and the projection still
        // says `Available`, so the identity enters the demand flow
        // and waits out the in-flight refetch like a lost first
        // read. Without a recent loss this stays the fast
        // terminal EIO it has always been.
        let first = match (&self.scrub, &self.wants, &first) {
            (Some(_), Some(_), Err((ViewError::Unavailable { content }, errno)))
                if self.recent_losses.contains(content, Instant::now()) =>
            {
                Err((ViewError::NotMaterialized { content: *content }, *errno))
            }
            _ => first,
        };
        if let (Some(registry), Err((ViewError::NotMaterialized { content }, _errno))) =
            (&self.wants, &first)
        {
            let wants = Arc::clone(registry);
            let quarantine = self.quarantine.clone();
            let scrub = self.scrub.clone();
            // Success completes; terminal verdicts complete with
            // themselves (the final retry below surfaces them as
            // EIO) and note reopen demand, so a reader blocked
            // across the verdict still reopens the generation for
            // its retry — unless a rejection was observed for the
            // identity moments ago, in which case the repair is
            // still in flight behind a stale projection and the
            // waiter waits it out instead of failing fast on the
            // stale view (see `complete_waiter_on_terminal`).
            // Corrupt notes nothing: its repair is quarantine's job,
            // not rewant's — and a rejected representation observed
            // mid-wait is reported and waited through: the drain
            // clears the claim and the admitted want re-drives a
            // fresh generation, while persistent bad providers
            // terminate through strikes into a terminal Corrupt
            // verdict, never through an unbounded quarantine loop.
            // Any other failure keeps waiting: the fetch may still
            // land before the deadline.
            let retry = || match attempt() {
                Ok(_) => true,
                Err((ViewError::Unavailable { content }, _)) => {
                    wants.note_reopen_demand(&content);
                    complete_waiter_on_terminal(
                        self.recent_rejections.contains(&content, Instant::now())
                            || self.recent_losses.contains(&content, Instant::now()),
                    )
                }
                Err((ViewError::RejectedRepresentation { content, kind }, _)) => {
                    if let Some(quarantine) = &quarantine {
                        quarantine
                            .submit(VerificationFailure::content_hash_mismatch(content, kind));
                    }
                    self.recent_rejections.note(content, Instant::now());
                    false
                }
                Err((ViewError::LostRepresentation { content, kind }, _)) => {
                    if let Some(scrub) = &scrub {
                        scrub.submit(ScrubObservation::missing(content, kind));
                    }
                    self.recent_losses.note(content, Instant::now());
                    false
                }
                Err((ViewError::Corrupt, _)) => true,
                // `Corrupt` stays unconditional: the variant carries
                // no identity to key recency against, and most of
                // what lands here is structural damage no repair can
                // fix — delaying it on any-recent global state would
                // trade a fail-fast for unrelated in-flight repairs.
                // A terminal-corrupt verdict behind a lagging
                // projection still completes here; the noted reopen
                // demand and the intact policy re-drive the next
                // waiter.
                Err(_) => false,
            };
            match wait_for_materialization(&wants, *content, self.open_timeout, retry) {
                Ok(()) => {
                    return map(attempt());
                }
                Err(_) => {
                    // Deadline expired or registry refused: the
                    // POSIX surface is EIO either way. The fetch, if
                    // admitted, continues and caches for next time.
                    return Err(fuser::Errno::EIO);
                }
            }
        }
        if let (Some(registry), Err((ViewError::Unavailable { content }, _))) =
            (&self.wants, &first)
        {
            // Terminal verdict on first touch: note reopen demand for
            // the next pass's generation sweep and fail fast. No
            // waiter blocks on a verdict that already exists, and no
            // register/release cycle is owed — the note alone is the
            // demand. Returns the boundary EIO, never a wait.
            registry.note_reopen_demand(content);
            return map(first);
        }
        map(first)
    }

    /// Resolve `path` in the current projection and re-open it as a
    /// fresh capture. Used after a commit to re-pin the handle on the
    /// newly authored bytes.
    pub(super) fn capture_for(&self, path: &str) -> Result<OpenFile, fuser::Errno> {
        let projection = self.projection()?;
        let node = projection
            .view()
            .lookup(path)
            .map_err(|error| errno_of(&error))?;
        projection
            .view()
            .open(&node)
            .map_err(|error| errno_of(&error))
    }
}

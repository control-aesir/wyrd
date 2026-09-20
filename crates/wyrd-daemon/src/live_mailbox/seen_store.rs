//! Durable dedupe log for the live mailbox: one line per acked wrap
//! id, appended (and fsynced) at every ack, rebuilt as a bounded set
//! on open. See the crash-guarantee discussion on the struct.

use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};

use super::{BoundedIds, MAX_RECORD_LEN, MAX_SEEN_ENTRIES};
use nostr::event::EventId;
use wyrd_sync::transport::MailboxError;

/// Durable dedupe log: one line per acked wrap id, appended (and
/// fsynced) at every `Ack`; rebuilt as a bounded set on open. Opening
/// fails closed — only a missing file starts empty, while an
/// unreadable, non-UTF-8, or corrupt ledger refuses startup, because
/// silently replaying acknowledged wraps is the worse failure. A torn
/// final line (crash mid-append, no trailing newline) is the one benign
/// case: that ack never synced, so the tail is truncated away and the
/// delivery comes back for re-acknowledgement. Throughput is fsync-bound
/// by design (one sync per ack); batching is a future optimization that
/// must not weaken the crash guarantee. Retention is FIFO-bounded at
/// `MAX_SEEN_ENTRIES`: evicted ids stay on disk until the next
/// compaction, and the file is rewritten to one line per retained id
/// once appends pass the bound again — disk stays under twice the
/// bound, restart load under one bound, regardless of lifetime history.
#[derive(Debug)]
pub(super) struct SeenStore {
    pub(super) path: PathBuf,
    pub(super) seen: BoundedIds,
    pub(super) file: std::fs::File,
    /// Lines appended since the last compaction (including lines for
    /// since-evicted ids): the rewrite trigger.
    pub(super) appended: usize,
    /// False after a compaction whose rename succeeded but whose handle
    /// reopen failed: the on-disk file is complete, but appending
    /// through the old handle would write to the renamed-away inode.
    /// `ensure_handle` repairs this on the next mutating call instead.
    pub(super) handle_ok: bool,
    /// fsync every record and rewrite (the crash guarantee) vs plain
    /// writes. Always true in production; tests opt out per mailbox via
    /// `set_ephemeral` so flood gates measure logic, not macOS sync
    /// latency. The guarantee itself is covered by a dedicated
    /// real-fsync test.
    pub(super) durable: bool,
}

impl SeenStore {
    pub(super) fn open(path: &Path) -> Result<Self, MailboxError> {
        // Streaming load: pre-bound logs from older versions can be far
        // larger than the retention cap (the old code was append-only),
        // so startup must never hold the whole file — memory stays at
        // one capped line plus the bounded set while bytes stream once.
        // Time is linear in file size; memory is not.
        let read = match std::fs::File::open(path) {
            Ok(file) => Some(file),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(MailboxError::Transport(format!("dedupe log: {error}")));
            }
        };
        let mut seen = BoundedIds::new(MAX_SEEN_ENTRIES);
        let mut total: u64 = 0;
        let mut torn: u64 = 0;
        if let Some(file) = read {
            total = file
                .metadata()
                .map_err(|error| MailboxError::Transport(format!("dedupe log: {error}")))?
                .len();
            let mut reader = std::io::BufReader::new(file);
            let mut buf = Vec::new();
            loop {
                buf.clear();
                // take() caps the allocation first: even a hostile
                // multi-megabyte unterminated line yields at most
                // MAX_RECORD_LEN + 1 bytes here.
                let chunk = reader
                    .by_ref()
                    .take(MAX_RECORD_LEN as u64 + 1)
                    .read_until(b'\n', &mut buf)
                    .map_err(|error| MailboxError::Transport(format!("dedupe log: {error}")))?;
                if chunk == 0 {
                    break;
                }
                if !buf.ends_with(b"\n") {
                    if buf.len() > MAX_RECORD_LEN {
                        // Longer than any valid line without a newline:
                        // not a torn append but corruption. Fail closed
                        // (acks replay) rather than truncating blindly.
                        return Err(MailboxError::Transport(
                            "dedupe log: overlong corrupt line".into(),
                        ));
                    }
                    // Trailing segment without a newline is a torn
                    // append, not a record: its ack never synced, so
                    // redelivery is safe and the tail truncates below.
                    torn = buf.len() as u64;
                    break;
                }
                let line = std::str::from_utf8(&buf[..buf.len() - 1])
                    .map_err(|_| MailboxError::Transport("dedupe log: not valid UTF-8".into()))?;
                let id = EventId::from_hex(line)
                    .map_err(|_| MailboxError::Transport("dedupe log: corrupt entry".into()))?;
                seen.insert(id);
            }
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|error| MailboxError::Transport(format!("dedupe log: {error}")))?;
        if torn > 0 {
            file.set_len(total - torn)
                .map_err(|error| MailboxError::Transport(format!("dedupe log: {error}")))?;
        }
        let store = Self {
            path: path.to_owned(),
            seen,
            file,
            appended: 0,
            handle_ok: true,
            durable: true,
        };
        // No migration path by policy: pre-alpha, no deployed ledgers
        // exist, and the format never changed — the bound applies from
        // the first write. An oversized file (operator-planted) still
        // loads bounded (eviction during load) and compacts back down
        // on subsequent appends.
        Ok(store)
    }

    pub(super) fn contains(&self, id: &EventId) -> bool {
        self.seen.contains(id)
    }

    /// Persist an acknowledgement durably before the caller may forget the
    /// delivery. A failed append keeps the delivery offered (the caller
    /// keeps it queued), so a disk failure cannot drop mail on the floor.
    /// Re-recording an id is a no-op: the first record already synced,
    /// and the set keeps it unique without growing the file.
    pub(super) fn record(&mut self, id: &EventId) -> Result<(), MailboxError> {
        if self.seen.contains(id) {
            return Ok(());
        }
        self.ensure_handle()?;
        self.file
            .write_all(format!("{id}\n").as_bytes())
            .and_then(|()| self.file.flush())
            .and_then(|()| {
                if self.durable {
                    self.file.sync_data()
                } else {
                    Ok(())
                }
            })
            .map_err(|error| MailboxError::Transport(format!("dedupe log: {error}")))?;
        self.seen.insert(*id);
        self.appended += 1;
        if self.appended >= MAX_SEEN_ENTRIES {
            self.compact()?;
        }
        Ok(())
    }

    /// Rewrite the log to exactly the retained set: temp file, fsync,
    /// atomic rename, dir fsync. A crash leaves either the old or the
    /// new complete file — never a half-rewritten log — and a torn tail
    /// from a crash mid-rewrite truncates away on the next open. If the
    /// rename succeeds but reopening the append handle fails, the store
    /// is poisoned for writes (not reads) and the next mutating call
    /// repairs the handle: the data is safe, only the handle is stale.
    pub(super) fn compact(&mut self) -> Result<(), MailboxError> {
        let tmp_path = self.path.with_extension("tmp");
        {
            let mut tmp = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp_path)
                .map_err(|error| MailboxError::Transport(format!("dedupe log: {error}")))?;
            for id in &self.seen.order {
                tmp.write_all(format!("{id}\n").as_bytes())
                    .map_err(|error| MailboxError::Transport(format!("dedupe log: {error}")))?;
            }
            tmp.flush()
                .and_then(|()| if self.durable { tmp.sync_all() } else { Ok(()) })
                .map_err(|error| MailboxError::Transport(format!("dedupe log: {error}")))?;
        }
        std::fs::rename(&tmp_path, &self.path)
            .map_err(|error| MailboxError::Transport(format!("dedupe log: {error}")))?;
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            Ok(file) => self.file = file,
            Err(error) => {
                self.handle_ok = false;
                return Err(MailboxError::Transport(format!("dedupe log: {error}")));
            }
        }
        if self.durable {
            if let Some(parent) = self.path.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::File::open(parent)
                        .and_then(|dir| dir.sync_all())
                        .map_err(|error| MailboxError::Transport(format!("dedupe log: {error}")))?;
                }
            }
        }
        self.appended = 0;
        Ok(())
    }

    /// Repair a handle poisoned by a failed post-rename reopen, so a
    /// later retry repairs instead of writing through a stale handle
    /// into the renamed-away inode. No-op while healthy; failure keeps
    /// the delivery held for a later retry.
    pub(super) fn ensure_handle(&mut self) -> Result<(), MailboxError> {
        if self.handle_ok {
            return Ok(());
        }
        self.file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|error| MailboxError::Transport(format!("dedupe log: {error}")))?;
        self.handle_ok = true;
        Ok(())
    }
}

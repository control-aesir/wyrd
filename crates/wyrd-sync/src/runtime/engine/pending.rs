//! The held-message queue: arrival-ordered deferred control messages plus the dependency index.

use wyrd_format::TransitionId;

use crate::control::{ControlMessageId, Message};

use super::{DeferredWait, PendingEntry, PendingQueue};

impl PendingQueue {
    /// Number of held entries (the queue bound counts these).
    pub(in crate::runtime) fn len(&self) -> usize {
        self.by_seq.len()
    }

    /// Hold an entry, in arrival order: a new id takes the next
    /// sequence slot; a known id is replaced in place and keeps its
    /// slot, with its dependency bucket refreshed.
    pub(in crate::runtime) fn insert(
        &mut self,
        id: ControlMessageId,
        message: Message,
        wait: DeferredWait,
    ) {
        if let Some(seq) = self.by_id.get(&id).copied() {
            if let Some(entry) = self.by_seq.get_mut(&seq) {
                let old = entry.wait;
                entry.message = message;
                entry.wait = wait;
                if old != wait {
                    self.unindex(&id, old);
                    self.index(id, wait);
                }
                return;
            }
            // Unreachable: the maps move together, so a known id
            // always has its slot. Drop the dangling pointer and
            // reinsert fresh rather than strand the entry.
            self.by_id.remove(&id);
        }
        // Test-only counter shape, mirrored from the relay fake:
        // exhausting u64 is unreachable, but wrapping would silently
        // violate the order contract, so fail loudly instead.
        let seq = self.next_seq;
        self.next_seq = self
            .next_seq
            .checked_add(1)
            .expect("pending sequence space exhausted");
        self.by_seq.insert(seq, PendingEntry { id, message, wait });
        self.by_id.insert(id, seq);
        self.index(id, wait);
    }

    /// Take a held entry by id (a duplicate delivery resolving it),
    /// with the dependency it was held under.
    pub(in crate::runtime) fn remove(&mut self, id: &ControlMessageId) -> Option<PendingEntry> {
        let seq = self.by_id.remove(id)?;
        // Unreachable-None: the maps move together. The id is already
        // forgotten above, so treat a disagreement as absent.
        let entry = self.by_seq.remove(&seq)?;
        self.unindex(id, entry.wait);
        Some(entry)
    }

    /// Take a held entry by arrival sequence (flush visiting its wake
    /// set). Missing sequences are skipped by the caller.
    pub(in crate::runtime) fn remove_seq(&mut self, seq: u64) -> Option<PendingEntry> {
        let entry = self.by_seq.remove(&seq)?;
        self.by_id.remove(&entry.id);
        self.unindex(&entry.id, entry.wait);
        Some(entry)
    }

    /// Reinsert a just-removed entry at its original slot (flush
    /// re-drive and error paths): arrival order never shifts under a
    /// commit that does not consume the entry.
    pub(in crate::runtime) fn restore(&mut self, seq: u64, entry: PendingEntry) {
        debug_assert!(
            !self.by_id.contains_key(&entry.id),
            "restore follows remove: the id must be absent"
        );
        let (id, wait) = (entry.id, entry.wait);
        self.by_seq.insert(seq, entry);
        self.by_id.insert(id, seq);
        self.index(id, wait);
    }

    /// Arrival sequences the commit of `committed` unblocks, in
    /// arrival order: the exact unseen bucket plus every
    /// status-blocked entry. Visiting only these keeps flush work
    /// proportional to the woken set, never the parked queue. `None`
    /// (the undecodable-trigger fallback) wakes everything rather
    /// than stranding entries.
    pub(in crate::runtime) fn wake_seqs(&self, committed: Option<TransitionId>) -> Vec<u64> {
        let Some(target) = committed else {
            return self.by_seq.keys().copied().collect();
        };
        let mut seqs = Vec::new();
        if let Some(waiters) = self.unseen.get(&target) {
            seqs.extend(waiters.iter().filter_map(|id| self.by_id.get(id).copied()));
        }
        seqs.extend(
            self.status_blocked
                .iter()
                .filter_map(|id| self.by_id.get(id).copied()),
        );
        seqs.sort_unstable();
        seqs
    }

    /// Every held dependency in arrival order (test seam: pins the
    /// index selection without driving the queue).
    #[cfg(test)]
    pub(in crate::runtime) fn waits_in_order(&self) -> Vec<DeferredWait> {
        self.by_seq.values().map(|entry| entry.wait).collect()
    }

    fn index(&mut self, id: ControlMessageId, wait: DeferredWait) {
        match wait {
            DeferredWait::Unseen(dependency) => {
                self.unseen.entry(dependency).or_default().insert(id);
            }
            DeferredWait::StatusBlocked(_) => {
                self.status_blocked.insert(id);
            }
        }
    }

    fn unindex(&mut self, id: &ControlMessageId, wait: DeferredWait) {
        match wait {
            DeferredWait::Unseen(dependency) => {
                if let Some(waiters) = self.unseen.get_mut(&dependency) {
                    waiters.remove(id);
                    if waiters.is_empty() {
                        self.unseen.remove(&dependency);
                    }
                }
            }
            DeferredWait::StatusBlocked(_) => {
                self.status_blocked.remove(id);
            }
        }
    }
}

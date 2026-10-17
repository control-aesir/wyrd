use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use wyrd_format::ContentId;

/// Most distinct parent paths whose session-local create tokens are retained.
/// Once full, new parent observations fail closed until an invalidation
/// removes entries.
pub const DEFAULT_MAX_PARENT_TOKENS: usize = 4096;

/// The base identity a writable handle opened against, and the identity
/// the loop compares against the current head at commit. A commit is
/// accepted only if the path still carries exactly this identity;
/// anything else — a content change, a kind change, or removal — is
/// [`MutationError::Stale`], never a silent merge.
///
/// The tuple is deliberately the full file identity (size, exec, ordered
/// chunk ids) rather than a single content id: `docs/write-path.md` names
/// kind, size, exec, and content as the comparison, and the format layer
/// does not yet expose a canonical file-node id. A cheaper id is future
/// work; it must not weaken the comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileIdentity {
    size: u64,
    executable: bool,
    chunks: Vec<ContentId>,
}

impl FileIdentity {
    /// The identity of a regular file as the view presented it.
    pub fn new(size: u64, executable: bool, chunks: Vec<ContentId>) -> Self {
        FileIdentity {
            size,
            executable,
            chunks,
        }
    }

    /// The declared byte size.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Whether the exec bit is set.
    pub fn executable(&self) -> bool {
        self.executable
    }

    /// The ordered chunk ids.
    pub fn chunks(&self) -> &[ContentId] {
        &self.chunks
    }

    /// Retained chunk-list bytes: what this identity pins in memory
    /// while a writable handle holds it as its commit base. Counted
    /// alongside the handle's read capture by the open-handle byte
    /// budget.
    pub fn capture_bytes(&self) -> usize {
        self.chunks.len() * std::mem::size_of::<ContentId>()
    }
}

/// Opaque, session-local identity of a parent directory observed by a
/// presentation caller.
///
/// A token remains stable while the directory's descendants and siblings
/// change. The live loop rotates it when the directory itself is replaced or
/// removed, or when the eligible head set changes. A queued create carrying
/// an older token is rejected with [`MutationError::StaleParent`]. Tokens
/// are meaningful only within their owning mutation queue and process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ParentToken(pub(super) u64);

// Parent state is part of the mutation precondition, so poisoning fails
// closed here instead of recovering a possibly inconsistent token table.
#[derive(Debug, Default)]
struct ParentState {
    next: u64,
    tokens: HashMap<String, ParentToken>,
    blocked: HashSet<String>,
    block_all: bool,
}

#[derive(Debug)]
pub(super) struct ParentRegistry {
    state: Mutex<ParentState>,
    limit: usize,
}

impl Default for ParentRegistry {
    fn default() -> Self {
        Self::with_limit(DEFAULT_MAX_PARENT_TOKENS)
    }
}

fn is_blocked(blocked: &HashSet<String>, path: &str) -> bool {
    if blocked.contains(path) {
        return true;
    }
    let mut ancestor = path;
    while let Some((parent, _)) = ancestor.rsplit_once('/') {
        ancestor = parent;
        if blocked.contains(ancestor) {
            return true;
        }
    }
    false
}

impl ParentRegistry {
    pub(super) fn with_limit(limit: usize) -> Self {
        Self {
            state: Mutex::new(ParentState::default()),
            limit,
        }
    }

    pub(super) fn capture(&self, path: &str) -> Option<ParentToken> {
        let mut state = self.state.lock().ok()?;
        if state.block_all || is_blocked(&state.blocked, path) {
            return None;
        }
        if let Some(token) = state.tokens.get(path) {
            return Some(*token);
        }
        if state.tokens.len() >= self.limit {
            return None;
        }
        let next = state.next.checked_add(1)?;
        let token = ParentToken(next);
        state.next = next;
        state.tokens.insert(path.to_string(), token);
        Some(token)
    }

    pub(super) fn validate(&self, path: &str, token: ParentToken) -> bool {
        self.state
            .lock()
            .ok()
            .is_some_and(|state| !state.block_all && state.tokens.get(path) == Some(&token))
    }

    pub(super) fn invalidate_subtree(&self, path: &str) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if path.is_empty() {
            state.tokens.clear();
            state.blocked.clear();
            state.block_all = true;
            return;
        }
        let prefix = format!("{path}/");
        state
            .tokens
            .retain(|candidate, _| candidate != path && !candidate.starts_with(&prefix));
        state.blocked.insert(path.to_string());
    }

    pub(super) fn invalidate_all(&self) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        state.tokens.clear();
        state.blocked.clear();
        state.block_all = true;
    }

    pub(super) fn publish(&self) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        state.blocked.clear();
        state.block_all = false;
    }
}

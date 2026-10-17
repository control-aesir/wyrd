use super::{MutationBatch, MutationKind, MutationQueue};
use std::sync::atomic::AtomicBool;
use std::time::Duration;

pub(super) fn mkdir(path: &str) -> MutationKind {
    MutationKind::Mkdir {
        path: path.to_string(),
    }
}

/// Block until a request is queued, then take it as a batch. The
/// guard completes on drop, so tests must finish it explicitly.
pub(super) fn take_batch_blocking(queue: &MutationQueue) -> MutationBatch<'_> {
    let stop = AtomicBool::new(false);
    queue.wait_for_work(&stop, Duration::from_secs(5));
    let batch = queue.take_batch();
    assert!(
        !batch.is_empty(),
        "wait_for_work returned without a request"
    );
    batch
}

use crate::support::{signed_transition, Rig};
use wyrd_daemon::core::RuntimeMaterialization;
use wyrd_daemon::fuse::FuseBackend;
use wyrd_format::{Change, ObjectStore};
use wyrd_fuse::DriveView;

/// Compose a serving backend from the node's live parts: contracts
/// take the composer role production gives `main.rs` — the backend is
/// built from the parts, never handed out by the node.
pub(super) fn serving_backend<S: ObjectStore>(
    parts: wyrd_daemon::core::LiveParts<DriveView<S, RuntimeMaterialization>>,
) -> FuseBackend<S, RuntimeMaterialization>
where
    S::Error: std::fmt::Debug,
{
    FuseBackend::shared_with_wants(
        parts.projection,
        parts.wants,
        parts.mutations,
        parts.open_timeout,
        &parts.budgets,
    )
}

/// The rig's epoch-3 child transition, signed by the owner: the
/// dependency the deferred announcements wait for.
pub(super) fn epoch3_child(rig: &Rig) -> wyrd_format::MembershipTransition {
    signed_transition(
        3,
        Some(rig.admit_id),
        vec![],
        vec![Change::Rotate],
        &[rig.owner.id, rig.recipient.id],
        &[rig.owner.id],
        &rig.owner,
    )
}

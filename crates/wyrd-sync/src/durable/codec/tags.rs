// --- record tags -----------------------------------------------------------

pub(super) const COMMIT_VERSION: u8 = 0x00;
pub(crate) const TAG_TRANSITION: u8 = 0x01;
pub(super) const TAG_CAPABILITY: u8 = 0x02;
pub(super) const TAG_ANNOUNCEMENT: u8 = 0x03;
pub(super) const TAG_MANIFEST: u8 = 0x04;
pub(super) const TAG_LOCAL_OBJECT: u8 = 0x05;
pub(super) const TAG_MATERIALIZATION: u8 = 0x06;
pub(super) const TAG_CONTROL_MESSAGE: u8 = 0x07;
pub(super) const TAG_OBJECT_REMOVED: u8 = 0x08;
/// Crate-visible for the raw-commit test seam: the planted-forgery tests
/// encode records no typed `Fact` can carry.
pub(crate) const TAG_SNAPSHOT_BODY: u8 = 0x09;
/// One announcement obligation: snapshot id (32) ‖ recipient (32).
pub(super) const TAG_ANNOUNCEMENT_QUEUED: u8 = 0x0A;
/// Sealed announcement bytes: snapshot id (32) ‖ sealed control bytes.
/// Crate-visible for the raw-commit test seam.
pub(crate) const TAG_ANNOUNCEMENT_SEALED: u8 = 0x0B;
/// One discharged obligation: snapshot id (32) ‖ recipient (32).
pub(super) const TAG_ANNOUNCEMENT_DELIVERED: u8 = 0x0C;
/// One transition-delivery obligation: transition id (32) ‖ recipient (32).
pub(crate) const TAG_TRANSITION_QUEUED: u8 = 0x0D;
/// Sealed transition bytes: transition id (32) ‖ sealed control bytes.
pub(crate) const TAG_TRANSITION_SEALED: u8 = 0x0E;
/// One discharged transition obligation: transition id (32) ‖ recipient (32).
pub(super) const TAG_TRANSITION_DELIVERED: u8 = 0x0F;
/// One capability-delivery obligation: epoch u64 LE (8) ‖ recipient (32).
pub(crate) const TAG_CAPABILITY_QUEUED: u8 = 0x10;
/// Sealed capability bytes: epoch u64 LE (8) ‖ recipient (32) ‖ sealed
/// control bytes.
pub(crate) const TAG_CAPABILITY_SEALED: u8 = 0x11;
/// One discharged capability obligation: epoch u64 LE (8) ‖ recipient (32).
pub(super) const TAG_CAPABILITY_DELIVERED: u8 = 0x12;
/// `0x16`, not `0x13`: that byte is `TAG_BOOTSTRAP_PENDING`, and a tag
/// collision silently decodes as the wrong fact kind.
pub(crate) const TAG_CAPABILITY_SEALED_REPLACED: u8 = 0x16;
/// Pending invitation material: raw wrapped-capability bytes (non-empty).
pub(crate) const TAG_BOOTSTRAP_PENDING: u8 = 0x13;
/// One namespace-carry obligation: head SnapshotId (32).
pub(super) const TAG_CARRY_QUEUED: u8 = 0x14;
/// One discharged carry obligation: head SnapshotId (32).
pub(super) const TAG_CARRY_DONE: u8 = 0x15;
/// One route-specific announcement reseal: snapshot (32) ‖ route length
/// u32 LE ‖ route ‖ sealed announcement envelope. Tag 0x17: 0x16 is
/// the capability-sealed-replaced record, and the tag space is
/// append-only.
pub(super) const TAG_ANNOUNCEMENT_ROUTE_SEALED: u8 = 0x17;
/// A stated reconciliation view: u32 LE transition count ‖ 32 bytes
/// each ‖ u32 LE snapshot count ‖ 32 bytes each ‖ u32 LE capability
/// count ‖ (device 32 ‖ epoch u64 LE) each. Tag 0x18: 0x17 is the
/// route-sealed record, and the tag space is append-only.
pub(crate) const TAG_RECONCILIATION_VIEW: u8 = 0x18;
/// A received reconciliation request: requester DeviceId (32) ‖ the
/// stated-view body above. Tag 0x19: the tag space is append-only.
/// Same per-section ceiling as the stated view — one evidence layout
/// across the wire statement, the stated record, and this record.
/// Crate-visible for the tag-boundary pin below.
pub(crate) const TAG_RECONCILIATION_REQUEST: u8 = 0x19;
/// A retired transition obligation: transition id (32) ‖ recipient
/// DeviceId (32) ‖ authenticated statement digest (32). Tag 0x1A:
/// the tag space is append-only. Fixed 96 bytes — a retirement names
/// the obligation, whom it is retired for, and exactly which
/// statement proved it, nothing else.
pub(crate) const TAG_TRANSITION_RECONCILED: u8 = 0x1A;
/// A retired capability obligation: epoch u64 LE (8) ‖ recipient
/// DeviceId (32) ‖ authenticated statement digest (32). Tag 0x1B,
/// fixed 72 bytes, same shape and same scope note as above.
pub(crate) const TAG_CAPABILITY_RECONCILED: u8 = 0x1B;
/// The endpoint identity one discharged announcement was sent
/// against: snapshot (32) ‖ recipient DeviceId (32) ‖ endpoint id
/// (32). Tag 0x1C: the tag space is append-only. Fixed 96 bytes —
/// a redelivery record names the obligation, whom it went to, and
/// exactly which serving endpoint carried it, nothing else.
/// Crate-visible for the tag-boundary pin below.
pub(crate) const TAG_ANNOUNCEMENT_DELIVERED_ROUTE: u8 = 0x1C;
/// A retired announcement obligation: snapshot id (32) ‖ recipient
/// DeviceId (32) ‖ authenticated statement digest (32). Tag 0x1D:
/// the tag space is append-only. Fixed 96 bytes — a retirement names
/// the obligation, whom it is retired for, and exactly which
/// statement proved it, nothing else. The announcement-class half of
/// reconciliation: the late-joiner retirement the 21c scope boundary
/// deferred.
/// Crate-visible for the tag-boundary pin below.
pub(crate) const TAG_ANNOUNCEMENT_RECONCILED: u8 = 0x1D;
/// Record tags this version understands. Unknown tags are skipped on
/// decode for forward compatibility.
pub(crate) const KNOWN_TAGS: [u8; 29] = [
    TAG_TRANSITION,
    TAG_CAPABILITY,
    TAG_ANNOUNCEMENT,
    TAG_MANIFEST,
    TAG_LOCAL_OBJECT,
    TAG_MATERIALIZATION,
    TAG_CONTROL_MESSAGE,
    TAG_OBJECT_REMOVED,
    TAG_SNAPSHOT_BODY,
    TAG_ANNOUNCEMENT_QUEUED,
    TAG_ANNOUNCEMENT_SEALED,
    TAG_ANNOUNCEMENT_DELIVERED,
    TAG_TRANSITION_QUEUED,
    TAG_TRANSITION_SEALED,
    TAG_TRANSITION_DELIVERED,
    TAG_CAPABILITY_QUEUED,
    TAG_CAPABILITY_SEALED,
    TAG_CAPABILITY_DELIVERED,
    TAG_CAPABILITY_SEALED_REPLACED,
    TAG_BOOTSTRAP_PENDING,
    TAG_CARRY_QUEUED,
    TAG_CARRY_DONE,
    TAG_ANNOUNCEMENT_ROUTE_SEALED,
    TAG_RECONCILIATION_VIEW,
    TAG_RECONCILIATION_REQUEST,
    TAG_TRANSITION_RECONCILED,
    TAG_CAPABILITY_RECONCILED,
    TAG_ANNOUNCEMENT_DELIVERED_ROUTE,
    TAG_ANNOUNCEMENT_RECONCILED,
];

/// Resource limits: a corrupt local file must not cause unbounded
/// allocation. Commits hold small canonical facts; anything beyond
/// these bounds is damage, not data.
pub(crate) const MAX_COMMIT_BYTES: u64 = 64 * 1024 * 1024;
/// Visible crate-wide (not just load) because the admission refusal
/// names this ceiling in its structured error variant.
pub(crate) const MAX_RECORDS_PER_COMMIT: usize = 65_536;
pub(super) const MAX_RECORD_BYTES: usize = 64 * 1024 * 1024;

/// Domain tag for the commit-chain hash: integrity and ordering of the
/// durable log itself, not confidentiality.
pub(super) const COMMIT_HASH_DOMAIN: &[u8] = b"wyrd durable commit v1";
// The chain genesis: commit 1 links from all-zero bytes.

/// AAD domain for the store key envelope (keystore-shaped, own domain so
/// a wrapped store key can never open as a root or device secret).
pub(crate) const STORE_KEY_AAD: &[u8] = b"wyrd store key v1";
/// AAD domain for sealed capabilities at rest. The store key is fresh
/// random per store, so no cross-context confusion is possible; the
/// distinct domain states the intent anyway.
pub(super) const CAPABILITY_STORE_AAD: &[u8] = b"wyrd capability store v1";

/// Commit header length: version (1) + sequence (8) + previous hash (32).
/// The records section hashed into the trailer starts right after it.
pub(super) const HEADER_LEN: usize = 41;

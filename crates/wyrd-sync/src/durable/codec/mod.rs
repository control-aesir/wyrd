//! Commit envelope and fact records: tags, limits, hashing, encoding,
//! decoding, and the capability/manifest record codecs. The commit
//! format and CURRENT protocol are byte-for-byte stable; unknown record
//! tags are skipped for forward compatibility.
//!
//! v0 development note: fact *payloads* are not yet migration-stable —
//! the manifest record gained its transport column (object-model.md
//! decision 26) by changing the layout in place. A store whose manifest
//! facts predate the change fails its rebuild loudly (an unparsable
//! record poisons the commit file, so `open`/`resync` refuse it), which
//! is the deliberate pre-alpha contract: fail closed on old formats,
//! no silent interpretation, no migration until v1 freezes the format.

mod facts;
mod framing;
mod tags;

pub(crate) use facts::{decode_reconciliation_evidence, encode_reconciliation_view_canonical};
pub(super) use facts::{encode_fact, DecodedFact};
pub(super) use framing::decode_commit_file;
pub(crate) use framing::encode_commit;
pub(super) use tags::{MAX_COMMIT_BYTES, STORE_KEY_AAD};
// The per-commit record ceiling, named by the admission capacity
// refusal (child 2): the only non-load reader of a load constant.
pub(crate) use tags::MAX_RECORDS_PER_COMMIT;
// Raw-commit test seam (planted-forgery tests): test-only re-exports.
#[cfg(test)]
pub(crate) use tags::{TAG_ANNOUNCEMENT_SEALED, TAG_SNAPSHOT_BODY};
// Test-only surface: the durable suite addresses these through `codec::`.
// Cfg-gated so the lib build keeps exactly the durable-visible surface above.
#[cfg(test)]
pub(super) use facts::encode_reconciliation_view;
#[cfg(test)]
pub(super) use tags::{
    KNOWN_TAGS, TAG_ANNOUNCEMENT_DELIVERED_ROUTE, TAG_ANNOUNCEMENT_RECONCILED,
    TAG_CAPABILITY_RECONCILED, TAG_CAPABILITY_SEALED_REPLACED, TAG_RECONCILIATION_REQUEST,
    TAG_RECONCILIATION_VIEW, TAG_TRANSITION, TAG_TRANSITION_RECONCILED,
};
// The extracted test file keeps `use super::*`: this shim preserves
// its namespace so the golden-answer tests stay byte-identical.
#[cfg(test)]
pub(super) use crate::durable::{Fact, SealedCapabilityFactId};
#[cfg(test)]
pub(super) use crate::runtime::ManifestRecord;
#[cfg(test)]
pub(super) use facts::decode_record;
#[cfg(test)]
pub(super) use tags::{
    TAG_BOOTSTRAP_PENDING, TAG_CAPABILITY_QUEUED, TAG_CAPABILITY_SEALED, TAG_TRANSITION_QUEUED,
    TAG_TRANSITION_SEALED,
};
#[cfg(test)]
pub(super) use wyrd_format::{
    BaoRoot, ContentId, DeviceId, DriveId, MembershipTransition, ObjectKind, StorageId,
    TransitionId,
};

// Sibling test file under the workspace tests_* naming: #[path] is required
// because default resolution from this parent would look for tests.rs, not this name.
#[cfg(test)]
#[path = "tests_codec.rs"]
mod tests;

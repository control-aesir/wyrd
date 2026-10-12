//! Disclosure classification: the machine-checked half of the
//! observation × trust-position matrix (`docs/trust.md`, section
//! "Observation × trust-position matrix").
//!
//! Every observation struct in the diagnostics surface carries an
//! inventory mapping each of its fields to exactly one matrix row.
//! The inventories live beside their structs as `disclosure_map`
//! methods; each destructures its struct exhaustively, so adding a
//! field without extending the map fails the build, and the
//! conformance tests pin the row each field maps to. That is the
//! OD-18-4 default-deny pressure in compile-error form: no field
//! reaches a restricted position unclassified, because the
//! vault-side test (`vault_inventory_is_all_observable`, in
//! `wyrd-core`) rejects any hidden-row mapping on the vault
//! projection.
//!
//! Two scoping rules, stated so future inventories stay uniform:
//!
//! - Opaque identity and membership types (`DeviceId`,
//!   `SnapshotId`, `TransitionId`, `ContentId`, `KnownState`)
//!   carry no inventory of their own. They are classified at the
//!   parent field that holds them: a field naming a peer maps to
//!   H8, a field naming snapshot content or authorship maps to
//!   H5/H6, whatever the Rust type.
//! - Data-carrying enums with no per-variant payload surface
//!   (`DurabilityLevel`) need no row map: their exhaustive
//!   `match` sites already fail compilation on a new variant,
//!   which is the `HeadClasses` precedent in stronger form.
//!
//! Derived observations are classified by what they disclose, not
//! by their Rust type (matrix clause 3): a count that discloses
//! membership or content activity maps to the hidden row it
//! discloses, with the counts-grain reasoning in the field's doc.

/// One row of the observation × trust-position matrix. H-rows are
/// the hidden list, O-rows the observable list, H10 the escrow
/// row; the numbering matches the matrix so a mapping reads
/// without a lookup table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisclosureRow {
    /// Plaintext.
    H1,
    /// Paths.
    H2,
    /// Tree structure.
    H3,
    /// Manifest contents.
    H4,
    /// Snapshot contents and authorship.
    H5,
    /// ContentIds.
    H6,
    /// Drive identity.
    H7,
    /// Membership: who, epoch boundaries.
    H8,
    /// Control traffic: mailbox, gift wraps, announcements.
    H9,
    /// Escrow records (cleartext DriveId and epoch framing).
    H10,
    /// Opaque blob identifiers (transport hashes).
    O1,
    /// Object kinds (cleartext kind byte).
    O2,
    /// Ciphertext sizes (no padding in v0).
    O3,
    /// Counts (blobs, bytes, messages).
    O4,
    /// Timing (import, fetch, delivery).
    O5,
    /// Request patterns (who asked which hash when).
    O6,
    /// Transport identity (iroh node ids, chosen-visible pubkeys).
    O7,
    /// Correlation heuristics (co-fetching, size matching).
    O8,
}

impl DisclosureRow {
    /// True for the hidden half (H1–H10): no vault-position
    /// projection may map a field here.
    pub fn is_hidden(self) -> bool {
        !matches!(
            self,
            DisclosureRow::O1
                | DisclosureRow::O2
                | DisclosureRow::O3
                | DisclosureRow::O4
                | DisclosureRow::O5
                | DisclosureRow::O6
                | DisclosureRow::O7
                | DisclosureRow::O8
        )
    }
}

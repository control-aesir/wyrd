# Release-read v1 (frozen public-read subset)

The frozen read profile every distribution item builds on: fetch a
release snapshot by id, fetch its blobs by id, verify. Nothing else.
Frozen means the byte layouts, signing domains, and KDF contexts named
here do not move — old clients read release drives while the rest of
the protocol evolves around them. The freeze pins live in
`wyrd-sync/src/public_read.rs` (`public_announcement_encoding_is_frozen`,
`release_key_derivations_are_frozen`,
`release_metadata_encoding_is_fixed_length_and_versioned`); a change to
any frozen byte fails the suite, never ships silently.

## What a release drive is

An explicitly public distribution surface: a genesis-only drive whose
randomly generated epoch-1 secret is **published** as release metadata.
Content confidentiality for that drive is waived deliberately, per
drive, irreversibly. This is not a weaker security mode for ordinary
drives — private-drive trust semantics (`trust.md`, `epochs.md`) are
unchanged, and no private drive may reuse a release secret.

Consequences, accepted up front:

- Maintainer authorship is public: snapshots verify against the pinned
  maintainer npub, so operating a release drive discloses who publishes
  it.
- The drive never leaves epoch 1 and never grows a membership past
  genesis: there is nothing to admit anyone to, so there are no reader
  admissions, no capabilities, and no membership writes.

## The reader input

Two things, both public: the release metadata (`PublicRelease`:
`version ‖ drive ‖ maintainer ‖ genesis ‖ epoch-1 secret`, 129 bytes)
and signed-but-unsealed snapshot announcements (the ordinary
`SnapshotAnnouncement` encoding, published in the clear — members keep
receiving announcements through the sealed control-plane envelopes; the
public posting is an additional cleartext publication of the same
signed statement, never a claim that announcements are never sealed). The reader
holds no identity, no mailbox, no membership log, and no capability —
by construction the module imports none of those surfaces.

## The authorship rule

`author == maintainer && membership == genesis && epoch == 1`, then the
maintainer's announcement signature, the snapshot id, the body's scope,
and the body's own signature — in that order, so scope violations
report as scope violations even when the signature would also fail.
Every violation fails closed (`NotMaintainer`, `NotGenesis`,
`WrongEpoch`, ...); there is no fallback to membership replay,
capability installation, or a more permissive mode. Public readability
is not public mutability: anyone may fetch, only the maintainer authors.

## What verification does not prove

A valid signature proves the pinned maintainer signed the announcement.
It does not prove the snapshot is the latest release, that its contents
are benign, or that the release metadata arrived from a trusted source.
Freshness, benign-ness, and metadata provenance belong to the signed
release manifest, not to this reader.

## Negotiation floor

Release-read v1 is a subset of what peers already speak, so a node
implementing capability negotiation can express it — no negotiation
exists yet, and the subset does not depend on one. When negotiation
lands, this profile is its floor: a newer node reads release drives
through v1, and negotiation never offers less. The profile reuses the
existing construction
byte-for-byte (`wyrd announcement v1`, `wyrd snapshot v1`,
`wyrd manifest key v1`, `wyrd object key v1`, seal envelopes,
transport-root addressing), so the floor is a pinned subset of what
peers already speak — never a parallel protocol.

Publisher duty: ship sealed bytes, never re-seal. A manifest entry's
`storage_id` names one exact sealed representation — a well-meaning
re-seal by another seeder mints a fresh nonce, so the bytes no longer
match the entry and fail the identity check. Replicas distribute the
publisher's bytes bit-for-bit.

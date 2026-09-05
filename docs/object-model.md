# Object Model — v0 Format Spec

Normative. `wyrd-format` implements this contract; everything else consumes
it. Nothing in the format layer may depend on networking, async, or FUSE.

Decisions are recorded at the bottom. The crypto/control-plane design that
sits on top of this format is normative in `trust.md` and `epochs.md`.

---

## Concept stack

```
Chunk → File → Tree → Snapshot → Snapshot DAG
```

Wyrd snapshots describe a **logical drive**. Individual devices materialize
arbitrary subsets of that drive locally. A snapshot answers *what the drive
contains*; possession of objects answers *what this device has*.

Three distinct concerns, never collapsed:
- **Knowledge** — what a device knows about the drive (history, structure, metadata)
- **Residency** — what a device locally holds (object bytes)
- **Policy** — what a device decides to hold (pins, cache caps)

## Identity (two identities, enforced by types)

| Identity | Definition | Used by | Seen by |
|---|---|---|---|
| **DriveId** | random 256-bit, minted once per drive | namespaces everything: manifests, announcements, signatures | drive members; harmless if leaked |
| **ContentId** | `BLAKE3-derive_key("wyrd content v1/<kind>", plaintext)` | Merkle trees, snapshots, local dedup | drive members only |
| **StorageId** | `BLAKE3-derive_key("wyrd storage v1", ciphertext)` | object placement, fetch addresses | everyone, including vaults |

Device identity is **not** a Wyrd invention: a device is a Nostr secp256k1
public key, and snapshots carry BIP-340 Schnorr signatures — but
never Nostr event formats. The full Nostr identity boundary is defined in
`trust.md`; the rule in one line: *Nostr answers "who", Wyrd answers "what
can you decrypt".*

`ContentId` and `StorageId` are **distinct Rust types** over the same 32
bytes — the compiler, not caller discipline, prevents
`storage.get(&content_id)` accidents. `SnapshotId` is likewise its own type
(a snapshot's ContentId, typed as a DAG node).

Consequences and boundaries:
- Content identity is deterministic: identical content always yields the
  identical ContentId — this is what makes local dedup, history, and tree
  structure work, and it makes Content IDs an **equality oracle to members**.
  That is the security boundary: *members* get plaintext equality; *vaults*
  do not.
- Vault claim, stated precisely: **vaults cannot determine plaintext
  equality from object representation.** Fresh random nonces make ciphertext
  equality meaningless. (Vaults still see sizes, counts, and timing —
  traffic analysis is out of scope for the crypto layer.)
- Convergent encryption was considered and **rejected**: it would hand the
  vault the equality oracle.

## Cryptographic binding

Encryption is not just hiding: every ciphertext is AEAD-authenticated
against its **format version, object kind, and Content ID** (the AAD), so a
mismatched manifest mapping fails verification immediately, not after a
plaintext hash surprise. Decryption success alone is never sufficient — the
plaintext must also hash to the expected Content ID. Full construction in
`trust.md`.

## Canonical encoding

Every object is a typed envelope; identity is defined over exactly these
bytes:

```
offset  size  field
0       4     magic      = "wyrd"
4       1     version    = 0x00 (v0)
5       1     kind       = 0x00 chunk | 0x01 tree | 0x02 snapshot
6       ..    payload    (kind-specific, canonical)
```

Canonical rules (apply to every payload):
- integers are little-endian, fixed-width
- vectors are self-delimiting: `u32` little-endian element count, followed
  by exactly that many canonical elements (counts are not optional)
- no optional fields in v0; a field is present or the format has a new version
- tree entries are sorted by path component bytes (bytewise, case-sensitive)
- serialization is specified byte-for-byte; serde types (if any) must emit
  exactly this layout and round-trip it
- signatures are computed over a **signing preimage** — the dedicated
  self-delimiting encoding of the signed fields declared in `trust.md` —
  never "the envelope minus the signature"

Changing the encoding means a new `version` byte and new derived-key context
strings. Old objects never change meaning.

## Chunks

Files are split into chunks so large files stream, memory stays bounded, and
dedup is byte-range aware.

**Chunking contract (format-level decision):** content-defined chunking,
FastCDC-style.

| Parameter | Value (v0) |
|---|---|
| min chunk size | 16 KiB |
| target chunk size | 64 KiB |
| max chunk size | 256 KiB |
| empty file | zero chunks (represented by an empty chunk list) |
| max object size | 256 KiB (the max chunk) |

Parameters are tunable during v0 development and **frozen at v1** — changing
them changes every ContentId. Before freezing, benchmark against the real
workloads: large media (the many-small-chunks-per-movie cost shows up as
manifest size and object count), large directory trees, and repositories of
small files. Note the deliberate separation: **Wyrd chunks are logical
storage/dedup units; iroh-blobs' Bao chunking is transport verification.**
They must stay distinct abstractions.

## Files and Trees

A snapshot's tree maps paths to content. Wyrd is a **content drive**, not a
full filesystem snapshot:

**Entry fields (v0):**

| Field | Type | Notes |
|---|---|---|
| path components | UTF-8 | see path rules |
| kind | enum | `file`, `dir`, `symlink` |
| size | u64 | bytes; for `file` |
| executable | bool | files only |
| symlink target | UTF-8 | symlinks only |
| content | list of ContentIds (file) / subtree reference (dir) | |

**Explicitly not represented in v0** (and therefore not preserved across
snapshots): mtimes, atimes, ctimes, uid/gid, permissions beyond the exec bit,
xattrs, ACLs, resource forks, Finder metadata, hard links. This list is a
feature, not an omission: it keeps snapshot identity a function of content.
(Hard links are the one candidate for later reconsideration if Wyrd's
filesystem face grows.)

**Path rules:**
- `/`-separated, case-sensitive, UTF-8, no Unicode normalization is applied
  or enforced
- components must be non-empty; `.` and `..` are not valid components
- duplicate names within a tree are impossible (canonical sorted encoding)

Directories are content-addressed trees: a dir node hashes to the ContentId
of its canonical encoding. An empty directory is a valid, representable tree.

**Canonical payload encoding (dir nodes):**

```
u32 LE                  entry count
entries, sorted bytewise by component:
  u8                    kind (0 = file, 1 = dir, 2 = symlink)
  u32 LE + bytes        component (UTF-8)
  file:     u64 LE      size
            u8          executable (0 | 1)
            u32 LE + ContentIds   chunk ids (32 bytes each)
  dir:      ContentId   subtree reference (the child dir node)
  symlink:  u32 LE + bytes        target (UTF-8, unvalidated)
```

Decoders must reject non-canonical payloads: unsorted or duplicate
components, unknown kind bytes, trailing bytes, components violating the
path rules, or exec bytes other than 0/1.

Two scope boundaries a reader must know:
- **Size-vs-chunk consistency is the reader's job.** A file entry's
  declared size is not cross-validated against its chunk list at decode
  time (the format layer has no store access). A corrupted or malicious
  tree can therefore carry an inconsistent entry; the sync/FUSE layers
  must verify against stored objects before trusting sizes. The format
  guarantees only that the *encoding* is canonical.
- **Flat directories are the intended v0 answer**, not sharded/HAMT
  trees. A huge flat directory is one object, fully materialized on
  decode; the encoding's `u32` entry count is its hard ceiling. This is
  a deliberate v0 simplification and the one frozen scalability ceiling
  in the format; revisit only with evidence from real workloads.

## Manifests (the bridge between identity worlds)

Manifests are **core objects, not metadata**. They are what makes the
encrypted physical representation navigable: sealed (encrypted to the drive)
documents containing trees and the **content→storage mapping** for the
objects a snapshot references. Only drive members can read them; vaults
store them opaquely.

Design decisions:
- **Hierarchical, per-subtree manifests.** A device materializing
  `Music/Artist A/Album 7` must not download a whole-drive manifest. Root
  manifest → subtree manifests → file entries, mirroring the tree structure,
  so **materialization happens at tree granularity**.
- **Manifests are capabilities.** Cross-device dedup is a protocol over them:
  a member that learns from another member's manifest "content C is already
  uploaded as storage S" fetches S instead of uploading its own encryption of
  C. The vault never learns C. Mappings record their **encryption epoch**
  inside the authenticated manifest entry, but they are **untrusted
  optimization hints**: a mapping is acted on only after the referenced
  representation passes the two verification checks (AEAD tag over the
  bound AAD, plaintext hashing to the ContentId) — never on blind trust —
  and only by a device holding the capability for that mapping's epoch;
  otherwise the device re-encrypts under its current epoch and publishes a
  new mapping (rule in `trust.md`).
- Manifests are versioned envelopes like every other object; their partition
  encoding is the open detail (below).

## Snapshots and the DAG

Snapshots form a DAG, not a linear log:

```
Snapshot {
    parents:    Vec<SnapshotId>   // ordered, may be empty
    tree:       ContentId of root tree
    author:     Nostr public key (the DeviceId)
    membership: hash of the MembershipTransition whose state authorizes it
    epoch:      u64 — must equal the referenced transition's epoch
    flags:      u8 — bit 0 = recovery snapshot (epochs.md); all other bits reserved zero
    timestamp:  u64 (ms, HLC-ordered, display/tiebreak only)
    signature:  BIP-340 signature over
                "wyrd snapshot v1" || DriveId || signing preimage (trust.md)
}
```

- **Published snapshots are immutable and never rewritten.** (This — not
  linearity — is the append-only invariant.)
- **Authorization is two predicates, not a boolean** (normative definitions
  in `epochs.md`): *historical validity* (genuine signature, canonical
  committed membership state, author a member) vs *current eligibility*
  (live lineage, at the peer's known epoch, DAG head). Consumers must model
  classification as a typed state — REJECTED, PENDING, VOIDED, ELIGIBLE,
  canonical history, SUPERSEDED, STRANDED — where only REJECTED means
  "invalid"; the others are valid historical objects that cannot advance
  canonical state.

**Canonical payload encoding (snapshots):**

```
parents:     u32 LE count + SnapshotIds (ordered, may be empty)
tree:        ContentId (32 bytes)
author:      DeviceId (Nostr x-only pubkey, 32 bytes)
membership:  TransitionId (32 bytes)
epoch:       u64 LE
flags:       u8 (bit 0 = recovery; all other bits reserved 0)
timestamp:   u64 LE ms
signature:   64 bytes (BIP-340 over the drive-bound signing message)
```

Decoders reject truncation, trailing bytes, and nonzero reserved flag
bits. Signature validity and `epoch == membership.epoch` are authorization
concerns (`epochs.md`), not decode checks — the transition body is not
part of the snapshot.
- **Heads** are snapshots with no descendants. The set of heads is the drive's
  true state.
- **"Current" is a policy, not a fact:** a single head renders as the live
  view; multiple heads mean the drive is *conflicted* (below). FUSE must
  never assume one head is "the drive" — multi-head presentation is defined
  policy, decided before FUSE implementation.
- `author` is meaningful only because snapshots are **signed** with the
  author's Nostr identity key, bound to the DriveId; peers reject
  unverifiable snapshots (`trust.md`). Signatures ride inside the Wyrd
  envelope — snapshots are never Nostr events.
- `epoch` and `membership` tie each snapshot to the exact membership state
  that authorizes it: an epoch number says *when*, the membership reference
  says **which authorization state**. Snapshots bound to superseded or
  voided membership states remain valid history but can never advance
  canonical state (`epochs.md`).

## Conflicts

- **DAG conflict ≠ path conflict.** Multiple heads is a DAG-level conflict;
  it does not imply any path differs. Conversely, two heads can carry the
  identical bytes at a path. The live view computes path-level differences
  between heads; DAG-level conflict alone does not force a per-path
  presentation.
- Path-level conflicts surface as the conflicted path presented with both
  versions (naming scheme is a UI policy, not format).
- Resolution = publishing a new snapshot whose parents are all heads.
- The `(timestamp, author)` tiebreak orders versions for display only. It
  never decides content.

## Object store

`ObjectStore` (in `crates/wyrd-format/src/store.rs`) is the storage seam for
the **plaintext world**, addressed by `ContentId`. The two operations carry
different trust levels:

- `insert(data) -> ContentId` — local writes; the store computes identity.
- `insert_verified(expected, data)` — network imports; the store **rejects**
  any data whose derived identity differs from the expected one. Verification
  is the store's job, not the caller's discipline.

Contract: objects are immutable; `insert` of identical content is a no-op;
a stored object always hashes back to its address (the scrub invariant).
Ciphertext stores addressed by `StorageId` are a sync-layer concern (they
will ride on iroh-blobs' verified streaming rather than duplicating it).

## Remaining open questions

1. ~~**Membership/epoch state machine**~~ — resolved: normative in
   `docs/epochs.md`; snapshots bind to a membership transition.
2. Manifest partition encoding details (sharding, chunked transfer of large
   manifests).
3. Live-view conflict naming (e.g. by author id / snapshot timestamp).
4. Gossip message framing for snapshot announcements.
5. Chunk-size parameters (benchmark before the v1 freeze).

## Decision record

| # | Decision | Rationale |
|---|---|---|
| 1 | Snapshot DAG over linear log | concurrency is normal, not exceptional; heads model makes "current" a policy |
| 2 | Canonical byte-level encoding with typed envelope | encoding changes must not silently change identity |
| 3 | Domain-separated hashing (derive_key contexts) | object kinds cannot collide; addressing is a format property, not caller discipline |
| 4 | Content drive: content + minimal entry fields; metadata list explicit | Wyrd is a content drive; snapshot identity stays a function of content |
| 5 | FastCDC, 16/64/256 KiB, frozen at v1 | range-stable dedup for edited files and large media; benchmark before freezing |
| 6 | Two identities: ContentId (plaintext) + StorageId (ciphertext), distinct types | stable logical identity + zero-trust vaults; Rust enforces the boundary |
| 7 | Heads + resolution-by-new-snapshot; DAG conflict distinguished from path conflict | conflicts are forks in history, not errors |
| 8 | Hierarchical per-subtree encrypted manifests; tree-granularity materialization | partial-drive devices must not fetch whole-drive metadata; manifests are the content→storage bridge |
| 9 | AEAD binding over (version, kind, ContentId) | a wrong manifest mapping fails immediately at the AEAD tag, not late at hash-check |
| 10 | Snapshots signed by the author's Nostr identity key, bound to DriveId | `author` is authorization, not decoration; a snapshot is only valid within its drive |
| 11 | Verification inside the store (`insert_verified`) | the API must be able to enforce the documented contract |
| 12 | Nostr identity boundary: DeviceId = Nostr pubkey, Schnorr signatures, no Nostr event formats, encrypted control plane, immutable device identity | deletes an entire bespoke identity subsystem; Nostr answers "who", Wyrd answers "what can you decrypt" |
| 13 | Membership epochs: snapshots carry `epoch` **and commit to a membership transition**; keys derive from fresh random epoch secrets; rotation never re-encrypts history | revocation without rewriting immutable objects; a snapshot commits to the exact authorization state, not a claim; possession of epoch N yields nothing about N+1 |
| 14 | Membership = append-only owner-signed transition chain, authorized by the **pre-transition** owner set, resulting state derived from `prev` + `changes`; superseded/stranded forks never advance state; adoption forbidden without an owner-signed recovery snapshot | deterministic authorization everywhere; owner-set changes and last-owner removal stay expressible; a removed device's writes fail closed |
| 15 | Manifest mappings record their encryption epoch; cross-epoch reuse only with a matching capability; mappings are **untrusted hints** — acted on only after authenticated decryption | re-encryption under a new epoch yields a new StorageId for the same ContentId; a mapping is useful only if the recipient can decrypt the referenced representation, and a false hint must never corrupt state |
| 16 | Snapshots carry a `flags` byte (bit 0 = recovery snapshot) | recovery is a distinct, auditable, authenticated operation — not inferable from shape; v0 keeps it a fixed-width field, no optionality |
| 17 | `Change` canonical encoding: tag bytes 0x00 Admit, 0x01 Remove, 0x02 Rotate, 0x03 SetOwners (counted `u32` vector); a membership transition's canonical serialization is its **signing preimage ‖ signature** (no envelope kind — sealed documents, not CAS objects); `TransitionId` is its own type, distinct from `ContentId` | byte-exact BIP-340 needs one declared field order (trust.md); transitions travel sealed to the drive, so envelope framing would add nothing; the type system keeps sealed documents out of the content world |

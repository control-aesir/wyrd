# Object Model — v0 Format Spec

Normative. `wyrd-format` implements this contract; everything else consumes
it. Nothing in the format layer may depend on networking, async, or FUSE.

Decisions are recorded at the bottom. The crypto/control-plane design that
sits on top of this format is drafted separately in `trust.md` (not yet
normative).

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
public key, and snapshots carry Nostr-compatible Schnorr signatures — but
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
- no optional fields in v0; a field is present or the format has a new version
- tree entries are sorted by path component bytes (bytewise, case-sensitive)
- serialization is specified byte-for-byte; serde types (if any) must emit
  exactly this layout and round-trip it

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
  C. The vault never learns C.
- Manifests are versioned envelopes like every other object; their partition
  encoding is the open detail (below).

## Snapshots and the DAG

Snapshots form a DAG, not a linear log:

```
Snapshot {
    parents:   Vec<SnapshotId>   // ordered, may be empty
    tree:      ContentId of root tree
    author:    Nostr public key (the DeviceId)
    epoch:     u64 — the membership epoch the author claims (see trust.md)
    timestamp: u64 (ms, HLC-ordered, display/tiebreak only)
    signature: Schnorr signature over
               "wyrd snapshot v1" || DriveId || canonical bytes (sans signature)
}
```

- **Published snapshots are immutable and never rewritten.** (This — not
  linearity — is the append-only invariant.)
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
- `epoch` ties each snapshot to the membership epoch it claims: snapshots
  signed by a removed device remain valid historical forks but cannot
  advance state past the revocation boundary (`trust.md`, bounded-fork
  semantics).

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

1. **Membership/epoch state machine** — drafted in `docs/epochs.md`; its
   review (with `trust.md`) is the final gate for `wyrd-sync`.
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
| 13 | Membership epochs: snapshots carry `epoch`; keys derive from epoch secrets; rotation never re-encrypts history | revocation without rewriting immutable objects; bounded-fork semantics for post-removal snapshots |
| 14 | Membership = append-only owner-signed transition chain; stale forks never advance state; adoption forbidden without an owner-signed recovery snapshot | deterministic authorization everywhere; a removed device's writes fail closed |

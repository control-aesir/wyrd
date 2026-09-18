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
| **TransitionId** | `BLAKE3-derive_key("wyrd transition id v1", signing preimage ‖ signature)` | membership log, snapshot authorization | drive members only |

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
5       1     kind       = 0x00 chunk | 0x01 tree | 0x02 snapshot | 0x03 manifest
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
- components must not contain `/` or null bytes (names reach FUSE and host
  filesystems, where NUL truncates or panics)
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
  decode; the encoding's `u32` entry count is its hard ceiling at the
  format layer, while the sync layer applies tighter structured ceilings
  pre-transport (`Limits::V0` in `crates/wyrd-sync/src/ingest.rs`,
  decision 23). This is
  a deliberate v0 simplification and the one frozen scalability ceiling
  in the format; revisit only with evidence from real workloads.

## Manifests (the bridge between identity worlds)

Manifests are **core objects, not metadata**. They are what makes the
encrypted physical representation navigable: sealed (encrypted to the drive)
documents containing trees and the **content→storage mapping** for the
objects a snapshot references. Only drive members can read them; vaults
store them opaquely. Ownership splits along the plaintext line: schema and
canonical plaintext encoding belong to `wyrd-format` (a manifest's
ContentId is derived over its canonical plaintext like every other object),
while manifest encryption, StorageId addressing, and capability semantics
belong to `wyrd-sync` (see `trust.md` for the authorization contract).

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
- **Tree/manifest closure correspondence.** A snapshot body names a root
  tree, and that tree's files reference chunks while its directories
  reference subtrees. The manifest hierarchy is a second declaration of the
  same content. Tree nodes are **structural**: the root is `snapshot.tree`
  and each subtree is the `tree` of a `ChildManifest`. Authoring self-maps
  every tree node with a `Tree`-kind `ManifestEntry` (sealed like any other
  object), which is what makes the closure fetchable; such an entry must
  name a structurally reachable tree and declare its exact plaintext size.
  The invariant: every reachable file chunk has a manifest entry of kind
  `Chunk`, every directory subtree has a child manifest and vice versa, and
  no manifest entry names an object unreachable from the tree. The tree's
  declared file size is not compared to its chunk list (size-vs-chunk
  consistency is the reader's job, below); a chunk representation's size is
  enforced by `seal`'s two checks when it is fetched. Verified by
  `wyrd_sync::closure::verify_snapshot_manifest` (decision 27).
- **Enforcement.** Tree entries are structural, so the fetch plan always
  wants them and a receiver can assemble the full tree closure. The verifier
  runs as an authoring self-check and as the daemon's head gate: a
  classified head is installed only when its closure is complete locally and
  corresponds, so a validly signed body whose manifest describes other
  content never mounts (decision 27).

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
    timestamp:  u64 (ms; the authoring path keeps it strictly increasing
                over the local DAG; display/tiebreak only)
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

Two implementations: `MemoryObjectStore` (test and bench scaffolding) and
`FsObjectStore` (`crates/wyrd-format/src/fs_store.rs`), the crash-safe
directory store — `<dir>/objects/<kind>/<fanout>/<hex>`, temp+fsync+rename
writes, stale-temp sweep on open, verify-on-read scrub.

## Remaining open questions

1. ~~**Membership/epoch state machine**~~ — resolved: normative in
   `docs/epochs.md`; snapshots bind to a membership transition.
2. Manifest partition encoding details (sharding, chunked transfer of large
   manifests).
3. Live-view conflict naming (e.g. by author id / snapshot timestamp).
4. Gossip (iroh-gossip) framing for snapshot announcements (announcement encoding pinned in `wyrd-sync/src/control/`).
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
| 18 | Set roots (`members_root`/`owners_root`) and BIP-340 challenges are domain-separated BLAKE3 `derive_key` with pinned contexts: `wyrd member set v1` / `wyrd owner set v1` over `u32` LE count + ascending 32-byte pubkeys (duplicates removed); challenges `wyrd membership challenge v1` / `wyrd snapshot challenge v1` over the signing message | every derived constant must agree byte-for-byte across implementations (the TransitionId lesson, decision 17); all hashing stays BLAKE3 |
| 19 | `Admit` carries `{ device: DeviceId, encryption_key: [u8; 32] }` — the encryption key is the device-local capability-ECDH target, never the identity key | the NIP-46 boundary stays signing-only; "who am I" and "how are secrets delivered to me" are different keys with different risk profiles |
| 20 | Manifest entry layout: fixed 82 bytes `content_id (32) ‖ kind (1) ‖ version (1) ‖ storage_id (32) ‖ encryption_epoch u64 LE ‖ plaintext size u64 LE`; entries sorted by `(content_id, kind, version)`, decoders reject unsorted vectors | one logical object may map several representations (epochs, versions) without ambiguity; size rides along because vaults already see ciphertext size — it buys allocation without a round trip and costs no privacy |
| 21 | Subtree linkage by `(child tree ContentId, child manifest ContentId, sealed child manifest StorageId)` (96-byte records): the full identity pair, since the manifest ContentId is the AAD the child seal opens under; no names in manifests; all subtree manifests of a snapshot seal under that snapshot's manifest key | names stay in trees; the parent manifest is sealed, so vaults see only unlinkable StorageId fetches; revocation granularity stays snapshots (trust.md) while per-entry epochs let dedup survive rotation |
| 22 | `EncryptedObject` envelope `version (1) ‖ kind (1) ‖ nonce (24) ‖ ciphertext`; `StorageId` is derived over the sealed bytes; `ObjectKind::Manifest = 0x03` gives sealed manifests a kind byte (plaintext keeps a member-only ContentId; the sealed form is StorageId-addressed, no `ManifestId`) | equal plaintexts sealed twice stay unlinkable (fresh nonces); the kind byte keeps the AAD binding uniform across content and manifests without a new identity type |
| 23 | Sync-layer ingest limits (`Limits::V0`): 64 MiB object ceiling pre-decode, structural count ceilings post-decode (64 parents/changes/resolves, 1M tree entries and manifest children, 750K manifest mappings calibrated to fit the byte ceiling, 1024-byte names, 65K chunks per file, 256 KiB chunks, 16 owners); format maxima stay generous | attacker-controlled bytes meet bounded allocation everywhere: the total-bytes gate fires before decode, counts validate after decode over pre-allocation-bounded decoders |
| 24 | Bootstrap invitations under their own framing, never an epoch control key: `version ‖ drive ‖ ephemeral pk ‖ recipient ‖ encryption key ‖ inviter ‖ nonce ‖ ciphertext` (ECDH to the invitee key, owner signature over the payload inside); sealed control kinds carry no invitation tag | sealing an invitation under the key it delivers is a hard bootstrap cycle; delivery (ECDH) and authorship (owner signature) stay separate checks |
| 25 | Manifest ownership split: schema and canonical plaintext encoding in `wyrd-format`; manifest encryption, storage addressing, and capability semantics in `wyrd-sync` | the format owns the manifest's byte-level identity (ContentId over canonical plaintext); everything key- or capability-shaped stays in sync — the earlier "manifests live in `wyrd-sync`" wording contradicted the code and invited moving the type the wrong way |
| 26 | Manifest mappings carry their **transport root** (`BaoRoot`): `ManifestEntry` grows to fixed 114 bytes and `ChildManifest` links to fixed 128 bytes (the raw BLAKE3/Bao root of the referenced sealed representation, appended to decisions 20/21); the type is distinct from `ContentId`/`StorageId` with no conversions; sync-layer announcements carry the snapshot body's root plus the root manifest's `(ContentId, root)`, author-signed end-to-end; the v0 entry ceiling recalibrates 750K→580K so ceilings stay encodable within the 64 MiB object gate | Wyrd ids are keyed, kinded hashes while verified streaming addresses blobs by raw BLAKE3, so the mapping must travel with the data; a wrong root only fails a transfer (AEAD + content check remain the sole authority on arrival), so this is the manifest's untrusted-hint pattern one column over, not a new trust relationship. The envelope cannot carry its own root (self-reference), so each level names its children and its parent names it |
| 27 | Announcement outbox as durable facts: `AnnouncementQueued (snapshot, recipient)` (0x0A, 64 bytes), `AnnouncementSealed (snapshot, sealed bytes)` (0x0B), `AnnouncementDelivered (snapshot, recipient)` (0x0C); pending derives as queued-minus-delivered, first seal wins | sender-side retry needs durable per-recipient progress or a partial send strands peers; byte-identical retries collapse in the existing control-message dedupe instead of recording a route-update duplicate per attempt; append-only like every fact (delivered markers accumulate with the dedupe set) |
| 27 | **Tree/manifest closure correspondence** is an explicit invariant: tree nodes are structural (`snapshot.tree`, `ChildManifest::tree`); authoring self-maps each with a `Tree` entry (always fetched; must match a reachable tree and its size); manifest entries cover exactly the reachable chunks; every directory subtree has a child manifest and vice versa; no unreachable mapping is admitted. The tree's declared file size is not part of the invariant; chunk representation sizes are enforced by `seal`'s checks at fetch. Verifier: `wyrd_sync::closure::verify_snapshot_manifest`, run as an authoring self-check **and** as the daemon's receiving-side head gate (`verify_head_closure`): a head is installed only when its closure is complete locally and corresponds | A valid author can sign a body over tree T1 and publish a valid snapshot-bound manifest describing T2, producing an authenticated but broken replica. Fetchability and the gate close that case without a format change: tree nodes ride existing manifest-entry machinery |

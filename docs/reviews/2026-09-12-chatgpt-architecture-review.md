Yes. I reviewed the supplied `repomix-output.xml` as a whole, including the five crates, the runtime engine, persistence layer, cryptographic/key code, FUSE surface, mailbox implementation, tests, and the normative architecture/trust/epoch documents.

My overall conclusion is:

> **The core cryptographic and state-machine architecture is unusually disciplined and substantially better than I would expect from a pre-alpha decentralized filesystem. However, I would not yet consider the daemon/network boundary security-ready. The biggest problems are not primitive crypto mistakes; they are resource-exhaustion and trust-boundary issues in the live mailbox, plus a few semantic gaps between the snapshot/tree/manifest layers.**

The good news is that the dangerous issues are fairly localized.



---

# 1. Executive assessment

| Area                           | Assessment                                                                         |
| ------------------------------ | ---------------------------------------------------------------------------------- |
| Overall architecture           | **Strong**                                                                         |
| Identity separation            | **Excellent**                                                                      |
| Content/Storage ID separation  | **Excellent**                                                                      |
| Object encryption construction | **Strong**                                                                         |
| Capability model               | **Strong**                                                                         |
| Membership state machine       | **Strong**                                                                         |
| Snapshot authorization         | **Strong**                                                                         |
| Conflict semantics             | **Strong**                                                                         |
| Durable commit/replay          | **Strong**                                                                         |
| Canonical encoding             | **Strong, with some API hardening needed**                                         |
| Network mailbox security       | **Needs work**                                                                     |
| Resource-exhaustion resistance | **Needs work**                                                                     |
| FUSE security                  | **One significant issue**                                                          |
| Manifest semantic integrity    | **Incomplete**                                                                     |
| Large-history scalability      | **Needs architectural work**                                                       |
| Recovery implementation        | **Documentation/code status mismatch**                                             |
| Test strategy                  | **Very good for the implemented core; incomplete for live network/security abuse** |

I found **no obvious cryptographic primitive misuse** such as home-grown curve arithmetic, unauthenticated encryption, nonce reuse in the Wyrd AEAD construction, missing DriveId binding, or a capability recipient-confusion vulnerability.

That is a major positive.

The most important problems are instead:

1. **Unbounded mailbox retry state**
2. **Unbounded mailbox payload size**
3. **Unbounded durable poison/dedupe growth**
4. **Untrusted symlinks can escape the FUSE namespace**
5. **Manifest ↔ snapshot-tree correspondence is not actually verified**
6. **Runtime/authoring scalability degrades with accumulated history**
7. **The documented recovery state is ahead of the actual implementation**

I would fix the first four **before exposing Wyrd to hostile peers**.

---

# 2. The architecture is fundamentally sound

The crate boundaries are excellent.

`wyrd-format` remains a pure plaintext/content-addressing layer; `wyrd-sync` owns cryptographic state and synchronization; `wyrd-fuse` remains unaware of networking; and `wyrd-daemon` composes the two.

That separation is exactly the right direction for Wyrd.

The architecture document explicitly preserves the downward dependency structure and keeps FUSE ignorant of iroh/networking. 

The most important architectural decision is also correct:

```text
DriveId
    ↓
membership / epochs
    ↓
capabilities
    ↓
ContentId
    ↓
StorageId
    ↓
transport address
```

rather than trying to make one identifier answer all of those questions.

Likewise, keeping:

```text
DeviceId             = identity/signing
DeviceEncryptionKey  = capability delivery
DriveRootKey         = custody/recovery
EpochSecret          = actual content authority
```

is very good security architecture.

The trust document explicitly makes that separation and says Wyrd owns the state-machine/key-hierarchy semantics while delegating cryptographic primitives to audited libraries. 

### I would preserve this architecture.

I would **not** respond to the findings below by collapsing layers or moving crypto into `wyrd-format`.

---

# 3. P1 — Live mailbox has an unbounded retry queue

### Severity: **High**

This is the most concrete implementation vulnerability I found.

`LiveMailbox` stores unacknowledged messages in:

```rust
unacked: VecDeque<Held>
```

and `Disposition::Retry` deliberately leaves them there.

The important path is:

`live_mailbox.rs:704-733`

and:

`live_mailbox.rs:736-750`

A message which the engine cannot currently process gets retried.

In particular, `wyrd-sync/src/runtime/intake.rs` returns `Skipped` for:

```rust
Err(ControlError::UnknownEpoch(_))
```

and `Deferred` for messages waiting for membership history.

Both eventually become:

```rust
Disposition::Retry
```

But `LiveMailbox::settle()` does not remove those deliveries.

Therefore:

```text
unique message
    ↓
recv()
    ↓
unacked.push_back()
    ↓
engine says Retry
    ↓
still in unacked
```

There is **no bound on the number of unique retryable messages**.

The engine's `MAX_PENDING_MESSAGES` does not save you, because that bounds `Engine.pending`, not `LiveMailbox.unacked`.

The architecture comments actually make the intended mailbox behavior clear: the incoming channel is bounded and the relay should provide the durable backlog. 

### Attack

An attacker can send thousands/millions of syntactically valid gift wraps containing:

* a valid outer NIP-59 structure,
* valid NIP-44 encryption to the victim,
* but a Wyrd message whose epoch is unknown or whose membership dependency is unresolved.

Each one can remain in `unacked`.

This is a straightforward memory-exhaustion attack.

### Recommendation

You need an explicit distinction between:

```text
delivery currently being processed
```

and:

```text
relay-held retryable message
```

I would strongly prefer that the mailbox **not become the durable backlog**.

For example:

```text
relay
  │
  ├── bounded in-memory notification channel
  │
  └── durable relay history
```

A retry should mean:

> "I have not consumed this relay event."

not:

> "I will keep an unbounded copy of this event in RAM."

At minimum, put a hard bound on retry-held deliveries and stop draining once it is reached.

Better still, introduce an explicit mailbox state such as:

```rust
RetryLater
```

which causes the concrete mailbox to forget the in-memory copy while retaining the relay-side event.

This deserves a regression test with something like:

```text
MAX_RETRY + 1000 unique unknown-epoch messages
```

and an assertion that resident memory/state remains bounded.

---

# 4. P1 — Mailbox plaintext/ciphertext has no size bound

### Severity: **High**

This is related but distinct.

The mailbox documentation says:

> "Payload bounds are not enforced here; the engine's ingest limits ... reject oversized control payloads."

That is not sufficient.

`open_from_sender()` decrypts the NIP-44 payload before `ControlInbox::ingest()` sees it.

Then `SealedControl::decode()` does:

```rust
ciphertext: bytes[66..].to_vec()
```

So an attacker can send a huge valid NIP-44 message to the victim.

The sequence is:

```text
attacker
  ↓
valid NIP-59 gift wrap
  ↓
valid NIP-44 encryption to victim
  ↓
decrypt entire payload
  ↓
allocate potentially huge Vec
  ↓
only then discover it isn't valid Wyrd control
```

The bounded `INCOMING_CAPACITY = 1024` doesn't solve this because it bounds **events**, not event size.

The current mailbox design explicitly says the engine's ingest limits are supposed to handle this, but the limit is too late in the pipeline. 

### Recommendation

Introduce a mailbox-level maximum before expensive processing.

For example:

```rust
const MAX_MAILBOX_CIPHERTEXT_BYTES: usize = ...;
```

and reject oversized NIP-59/NIP-44 payloads before decrypting them.

You should have:

```text
relay event size limit
        ↓
NIP-59 validation
        ↓
NIP-44 ciphertext size limit
        ↓
decrypt
        ↓
Wyrd envelope size limit
        ↓
decode
        ↓
semantic limits
```

Not:

```text
decrypt arbitrary data
        ↓
then enforce limits
```

I would also put the Wyrd-level check directly into `ControlInbox::ingest()` before `SealedControl::decode()`.

That gives you defense in depth.

---

# 5. P1 — Poison messages cause unbounded durable dedupe growth

### Severity: **High**

This is subtler and important.

`SeenStore` is intentionally append-only:

```text
one EventId per line
```

and every `Ack` is persisted.

That is good for legitimate deliveries.

But the engine also `Ack`s terminal poison.

`intake.rs` explicitly says malformed terminal messages are consumed with `Ack`.

So an attacker can create:

```text
valid NIP-59
valid NIP-44
valid Wyrd envelope framing
invalid Wyrd semantic payload
```

The daemon:

1. receives it,
2. hands it to the engine,
3. engine says `Discarded`,
4. mailbox turns that into `Ack`,
5. `SeenStore::record()` writes the event ID forever.

The result is:

```text
attacker sends N unique poison messages
        ↓
N lines on disk
        ↓
N EventIds in HashSet
```

with **no compaction and no bound**.

The mailbox documentation explicitly says the seen log is append-only and never compacted in v0. 

This makes the relay mailbox a persistent local storage exhaustion target.

### Recommendation

Do **not** treat terminal poison and successfully processed Wyrd messages identically for durable dedupe.

I would change the semantic model to distinguish:

```text
AckConsumed
AckPoison
Retry
```

or equivalent.

For legitimate Wyrd messages:

```text
persist ControlMessageId / delivery identity
```

For terminal garbage:

```text
ack relay delivery
do not permanently retain its identity
```

If replaying poison is considered too expensive, use a **bounded negative cache**, not an infinite ledger.

Also consider whether the durable mailbox dedupe should actually be keyed by the Wyrd `ControlMessageId` rather than NIP-59 wrapper `EventId`. The former is already defined as the hash of the sealed Wyrd message.

That would align the durable semantic identity with the protocol identity.

---

# 6. P1 — Untrusted symlinks can escape the FUSE namespace

### Severity: **High if members are not fully trusted**

This is the most important filesystem-security issue.

`Tree` explicitly permits arbitrary symlink targets.

`tree.rs` says:

> symlink targets are resolved by the consumer, never by the format.

And `wyrd-fuse` returns the target verbatim.

`wyrd-daemon/src/fuse.rs:636-651` does exactly that:

```rust
reply.data(target.as_bytes())
```

There is no confinement policy.

So a malicious drive member can author:

```text
documents/
    secret -> /etc/passwd
```

or:

```text
secret -> /home/user/.ssh
```

or other host paths.

When mounted as a normal filesystem, the host kernel can interpret an absolute symlink in the host namespace.

That creates a very different trust boundary from ordinary Wyrd content.

Your trust model says members are allowed to author snapshots, while vaults are untrusted. 

That means you cannot implicitly assume every mounted tree is benign.

### Recommendation

You need to decide explicitly:

### Option A — Wyrd symlinks are confined

Only allow relative targets and reject:

```text
/
/absolute/path
..
```

or otherwise normalize and confine them to the mount root.

### Option B — symlinks are inert

Expose them but do not permit kernel traversal outside the Wyrd namespace.

### Option C — trusted-drive mode

Allow POSIX symlinks only when the user explicitly mounts the drive as trusted.

For a decentralized filesystem, I strongly prefer **A or B**.

At minimum I would make this a documented security invariant:

> A path obtained by traversing a Wyrd symlink must never resolve outside the Wyrd mount namespace.

That should get an integration test involving an actual FUSE mount, not just a `readlink()` unit test.

---

# 7. P2 — Manifest ↔ snapshot tree binding is incomplete

### Severity: **Medium/High**

This is the biggest semantic integrity gap in the content model.

`fetch.rs` explicitly admits:

> "What fetch does not check is that the manifest's entries describe the snapshot's tree."

The code verifies:

```text
manifest.snapshot == snapshot
manifest ContentId
AEAD
StorageId
transport root
```

but not:

```text
manifest ↔ snapshot.tree
```

The fetch planner then uses manifest entries to decide which objects to fetch.

So a malicious member can construct:

```text
Snapshot S
    tree = T1
```

but provide a valid manifest:

```text
Manifest S
    entries = objects belonging to T2
```

Both can be cryptographically valid.

The result isn't necessarily confidentiality loss, but it can produce:

```text
valid snapshot
+
valid manifest
+
valid encrypted objects
=
unreadable/broken replica
```

because the FUSE tree asks for one set of ContentIds while the manifest advertises another.

The code comments currently rely on this being "author-attested." 

I don't think that is strong enough for Wyrd's stated invariants.

### Recommendation

Build a verifier that establishes:

```text
Snapshot.tree
   ↓
Tree closure
   ↓
every referenced content object
   ↓
Manifest hierarchy
   ↓
exactly corresponding mappings
```

For each snapshot:

* every tree file chunk must appear in the manifest hierarchy;
* every manifest object should correspond to an object reachable from the tree;
* file sizes should agree;
* kinds should agree;
* child manifest references should correspond to child tree IDs;
* no unrelated mappings should be necessary for the snapshot.

You don't necessarily have to require a one-to-one representation mapping because cross-epoch representations complicate that, but the **logical ContentId set** should correspond.

This is a good place for a dedicated:

```rust
verify_snapshot_manifest(snapshot, tree, manifests, ...)
```

security boundary.

---

# 8. P2 — Authoring can stack-overflow on deep tree hierarchies

`ManifestAuthor::walk()` is recursive:

`runtime/author.rs:187`

and recursively calls itself at:

`runtime/author.rs:210`

The membership classifier has already gone to great lengths to eliminate recursion and has a 10,000-deep test.

The authoring tree walk has not received the same treatment.

This is especially relevant because:

* Wyrd trees are content-addressed,
* a tree can be imported from another member,
* tree depth is not itself globally bounded by the `check_tree()` limits.

A malicious or pathological local tree can therefore cause authoring to overflow the process stack.

### Recommendation

Make manifest construction iterative, or impose an explicit maximum tree depth.

Given the architecture you've already adopted, I'd prefer an explicit heap-based DFS:

```text
Vec<WalkFrame>
```

rather than recursion.

This would also make post-order child-manifest construction clearer.

---

# 9. P2 — Large-history scalability is currently the biggest architectural performance concern

This isn't a correctness bug, but it will become one operationally.

The runtime is intentionally append-only.

That means historical manifests accumulate.

Then:

```rust
RuntimeState::reconcile()
```

walks **all recorded manifests** and their entries.

And authoring:

```rust
runtime.recorded_mappings(&chunk)
```

scans all manifest records looking for that content ID.

So authoring a large snapshot eventually trends toward:

```text
number of chunks × historical manifest entries
```

in the worst case.

For Wyrd's intended use case — large music/movie collections and many snapshots — this is something I'd address before v1.

The manifest model itself is good: manifests are hierarchical and per-subtree, which is exactly the right shape. 

The problem is the **runtime indexes**.

### Recommendation

Maintain derived indexes such as:

```rust
ContentId
    -> Vec<Representation>
```

and:

```rust
SnapshotId
    -> RootManifest
```

and perhaps:

```rust
ManifestId
    -> Child manifests
```

incrementally.

Then:

```rust
recorded_mappings(content)
```

becomes approximately:

```text
O(number of representations)
```

instead of:

```text
O(all historical manifest entries)
```

Similarly, reconciliation should consume incremental deltas rather than re-walking the entire historical manifest universe every pass.

This is particularly important because GC is explicitly post-v1. The runtime therefore cannot assume old history will disappear. The roadmap itself says append-only history persists indefinitely in v0. 

---

# 10. P2 — FUSE directory lookup is unnecessarily expensive

Tree entries are canonically sorted.

Yet `resolve_one()` does:

```rust
tree.entries()
    .iter()
    .find(...)
```

That's linear lookup.

For a directory containing 1,000,000 entries, one lookup can therefore scan a million entries.

The same issue becomes worse in `readdir_union()`, where each name is resolved against each tree.

Because canonical ordering is already an invariant, this should be a binary search.

### Recommendation

Expose something like:

```rust
Tree::find(name: &Component) -> Option<&Entry>
```

implemented using:

```rust
binary_search_by(...)
```

Then use it everywhere.

This is a simple optimization that follows directly from the format contract rather than adding an index.

---

# 11. P2 — Vault durability is not quite as strong as the object store

`FsObjectStore` has the right crash protocol:

```text
write temp
fsync temp
rename
fsync directory
```

The vault uses:

```rust
file.sync_all()
rename()
```

but does not fsync the containing directory afterward.

`serving.rs:63-78`

So the ciphertext itself may be durable while its directory entry isn't guaranteed durable across a power failure.

That doesn't cause plaintext corruption, but it violates the otherwise very strong durability story.

### Recommendation

Make Vault use the same primitive as `FsObjectStore`:

```text
temp
fsync
rename
fsync directory
```

I'd actually factor this into a small private filesystem durability utility rather than maintaining two subtly different crash protocols.

---

# 12. P2 — `Manifest::canonical_bytes()` relies on debug assertions

`Manifest::canonical_bytes()` contains:

```rust
debug_assert!(entries sorted)
debug_assert!(children sorted)
```

but then encodes the object anyway.

This means a release build can construct a noncanonical manifest.

The decoder correctly rejects it, so this isn't a remote forgery vulnerability.

But it creates an undesirable API:

```rust
let invalid_manifest = Manifest { ... };
let bytes = invalid_manifest.canonical_bytes();
```

which succeeds in release and produces bytes that Wyrd itself later refuses.

### Recommendation

Either:

```rust
pub fn canonical_bytes(&self) -> Result<Vec<u8>, ManifestError>
```

or make construction itself guarantee canonicality.

Given your philosophy that canonical encoding is a security boundary, I prefer:

```rust
Manifest::from_parts(...)
```

to be the invariant-preserving constructor and make the raw struct fields less freely constructible.

The same general consideration applies to other public format structs.

---

# 13. P2 — Some semantic invariants are enforced too late

The code has an excellent layered structure:

```text
decode
 ↓
structural validation
 ↓
cryptographic validation
 ↓
state-machine validation
```

But some content invariants only get checked when the filesystem reads data.

For example, a `Tree::File` carries:

```text
declared size
chunk list
```

but `Tree::decode()` cannot validate that the chunk sizes actually sum to the declared size.

`wyrd-fuse::read()` eventually does.

That is defensible because the chunks may not be available yet.

However, once the author has all local objects available, the authoring path could perform stronger validation before signing a snapshot.

Right now `author.rs` validates the tree structurally but does not appear to establish complete file-size/chunk closure.

### Recommendation

Have two explicit predicates:

```text
TreeStructuralValidity
TreeContentValidity
```

The former is cheap and transport-safe.

The latter requires object resolution and can be performed:

* before local authoring;
* before serving a fully materialized snapshot;
* optionally during background scrub.

That gives the system a clearer semantic integrity model.

---

# 14. P2 — Announcement/manifest processing deliberately permits a large amount of work before snapshot authorization completes

The fetch plan processes:

1. snapshot bodies,
2. root manifests,
3. child manifests,
4. objects.

But root manifest fetching can occur independently of successful snapshot-body authorization.

That is useful for progressive synchronization, but it means an authorized member can cause a peer to ingest quite a lot of manifest metadata before the snapshot itself becomes part of the authorized DAG.

The architecture already acknowledges this distinction.

This isn't a direct security bypass because the manifest is still:

* encrypted,
* ContentId-bound,
* snapshot-bound,
* size-limited.

But it is an **amplification surface**.

I'd make this explicit in the threat model:

> Manifest metadata is authenticated evidence but is not authoritative until its associated snapshot is historically authorized.

Then make sure all expensive downstream operations remain bounded until that point.

---

# 15. Cryptographic review — this part is strong

I want to emphasize that I did **not** find a reason to redesign the cryptographic architecture.

## Identity

The two-key device model is excellent.

`DeviceIdentitySecret` and `DeviceEncryptionSecret` are distinct types and both are zeroized on drop.

That prevents a whole class of accidental key-role substitution.



## Capability wrapping

The capability construction is well designed:

```text
ephemeral ECDH
    ↓
HKDF-SHA256
    ↓
XChaCha20-Poly1305
```

with:

```text
DriveId
DeviceId
DeviceEncryptionKey
TransitionId
epoch
```

bound into AAD.

The additional plaintext/header duplication is also a good defensive measure.

The trust document's T9/T12 construction matches the implementation. 

## Epoch keys

The important property holds:

```text
root != epoch derivation
```

Epoch secrets are fresh random values and are escrowed under the root rather than derived from it.

That preserves revocation semantics.

## Object encryption

The two-check model is particularly good:

```text
AEAD verifies expected ContentId
+
plaintext hashes to expected ContentId
```

The code explicitly implements both.

That means a malicious manifest cannot substitute a different plaintext merely by manipulating its mapping.

## Drive binding

Membership signatures and snapshot signatures are DriveId-bound.

That's exactly what you want to prevent cross-drive replay.

## NIP-44 / NIP-59 layering

The separation is conceptually sound:

```text
Wyrd control encryption
        ↓
NIP-44 transport encryption
        ↓
NIP-59 relay mailbox
```

NIP-59 hides the sender from relays while retaining recipient routing.

The trust document clearly records that tradeoff. 

---

# 16. Membership state machine — strong

This is probably the strongest part of the code.

The design correctly separates:

```text
historically valid
canonical
contested
voided
stranded
eligible
```

rather than collapsing everything into `valid/invalid`.

The classifier also correctly avoids recursive ancestry traversal and explicitly tests a 10,000-deep chain.

That is exactly the sort of adversarial thinking I want to see in a decentralized protocol.

The resolution semantics are also unusually careful:

```text
resolution must explicitly name exactly the voided siblings
```

rather than allowing an arbitrary "winner" declaration.

I would keep this architecture essentially unchanged.

---

# 17. Durable persistence — very good

The durable store is one of the better parts of the code.

The sequence:

```text
commit file
    ↓
fsync
    ↓
rename
    ↓
fsync directory
    ↓
CURRENT
    ↓
fsync
    ↓
rename CURRENT
    ↓
fsync directory
```

combined with the hash chain is strong.

The single-writer lock is also the correct solution for this architecture.

The replay model is good too:

```text
transitions
    ↓
capabilities
    ↓
runtime facts
```

rather than trying to interpret arbitrary cross-type commit order.

The durable layer explicitly treats capabilities as `AuthorizedCapability` and re-validates them on rebuild. 

That is exactly the right defense against local persistence corruption.

---

# 18. FUSE architecture — good except for symlinks and scaling

The open-file behavior is particularly good.

You correctly capture the opened file's immutable content identity so:

```text
head advances
    ↓
existing FD
    ↓
still reads the old snapshot
```

That is the right filesystem semantic.

Likewise, conflicts are surfaced rather than silently merged.

I would keep that.

The major changes I'd make are:

```text
1. confine symlinks
2. binary-search tree entries
3. bound pathological path depth
4. consider bounded readdir allocations
```

---

# 19. Mailbox architecture needs a redesign before live deployment

This is the part I'd spend the next security pass on.

The conceptual design is good.

The concrete state machine is not yet robust enough under hostile traffic.

You currently have three independent resource domains:

```text
incoming channel
engine.pending
mailbox.unacked
```

Only the first two are bounded.

That is the architectural mistake.

I would instead establish one explicit invariant:

> **At no point can remote traffic cause unbounded memory growth in the daemon.**

Then derive the mailbox implementation from that.

Something like:

```text
                    ┌──────────────┐
relay ─────────────►│ bounded      │
                    │ notification │
                    │ queue        │
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │ Wyrd intake  │
                    └──────┬───────┘
                           │
              ┌────────────┴────────────┐
              │                         │
          processable              retryable
              │                         │
              ▼                         ▼
         durable fact             relay retains
                                      event
```

The mailbox should not become a second durable queue.

---

# 20. Important documentation/status inconsistency

This deserves attention because it affects security review confidence.

`ROADMAP.md` says:

> Phase 3: Recovery — shipped

and describes root reconstruction, escrow retrieval and historical restoration as landed.

But the actual source contains only the escrow primitives and bootstrap handling; there is no complete guardian/Shamir recovery implementation.

The trust document explicitly still describes recovery as **post-v0 / reserved design**. 

This is not merely cosmetic.

Someone reading the roadmap could reasonably conclude:

```text
"Root loss recovery is operational."
```

when the code does not support that.

### Recommendation

Make the roadmap match reality.

I'd change the status to something like:

```text
Recovery foundations — shipped
    - root escrow format
    - per-epoch escrow
    - custody primitives

Recovery workflow — not shipped
    - guardian selection
    - Shamir reconstruction
    - share rotation
    - historical epoch restoration
    - recovery snapshot creation
```

This is especially important for security documentation.

---

# 21. Another important status issue: the network is not actually end-to-end yet

The current `wyrd` mount still passes:

```rust
None::<&mut wyrd_sync::bulk::IrohBulkSource>
```

to the live loop.

So the system currently has:

```text
NIP-59 control plane
        +
local FUSE
        +
fetch-on-open machinery
```

but not:

```text
real peer object retrieval
```

The architecture document correctly acknowledges this. 

That's actually good — **the code isn't pretending to have a security property it doesn't have**.

But it means I would not call the network security model complete yet.

The forthcoming serving router is where the following need to be made concrete:

```text
requester identity
       ↓
drive membership
       ↓
allowed StorageId retrieval
       ↓
ciphertext-only response
       ↓
transport verification
```

The trust model explicitly says that StorageId serving is an availability/enumeration boundary and that a member who can name a StorageId can request it. 

That is a reasonable v0 decision.

It just needs to be enforced by the actual router.

---

# 22. Testing assessment

The testing strategy is **very good for the protocol core**.

Particularly good:

* property testing of membership state;
* conformance suites;
* 10,000-deep ancestry;
* malformed decoder tests;
* crash-stage persistence testing;
* corrupted object tests;
* capability replay tests;
* transport root fallback tests;
* FUSE descriptor stability;
* mailbox reconnect tests;
* queue pressure tests;
* production KDF smoke tests.

The roadmap explicitly records the hardening work as complete. 

But there is a blind spot:

### The tests are strongest around *correctness under adversarial bytes*, not *resource exhaustion under adversarial traffic*.

I would add:

```text
mailbox:
    huge outer ciphertext
    huge inner plaintext
    1M retryable messages
    1M terminal poison messages
    retry queue saturation
    durable seen-log saturation

FUSE:
    absolute symlink
    symlink escaping via relative traversal
    deep directory tree
    1M-entry directory
    pathological merged directories

runtime:
    millions of manifest entries
    thousands of historical snapshots
    repeated reconcile cost
    repeated authoring cost
```

Those tests should measure **boundedness**, not merely successful termination.

---

# 23. Security properties I would explicitly promote to first-class invariants

I think Wyrd is mature enough now that these should become named contracts, not just comments.

### S1 — Remote memory boundedness

> No remote peer can cause unbounded daemon memory growth.

### S2 — Remote disk boundedness

> No remote peer can cause unbounded durable local state growth without an explicit retention policy.

This one is particularly relevant to the mailbox seen-log.

### S3 — Symlink confinement

> A Wyrd pathname can never resolve outside the Wyrd mount namespace.

### S4 — Snapshot closure

> Every authorized snapshot's manifest closure corresponds exactly to its tree closure.

### S5 — Transport authenticity

> A transport address is never trusted as an identity; received bytes must independently verify against the logical identity.

You already implement this extremely well.

### S6 — Capability monotonicity

> Observing/replaying old capability material can never reduce or roll back key knowledge.

Already strong.

### S7 — Revocation boundary

> Possession of epoch N never implies possession of N+1.

Already strong.

### S8 — Durable publication atomicity

> No serving layer can observe a durable fact that has not reached its corresponding ciphertext residency.

Also already largely strong.

---

# 24. Suggested priority order

If this were my codebase, I would do the work in this order:

## P1 — Before hostile network testing

### 1. Fix mailbox resource bounds

All three together:

```text
unbounded retry queue
unbounded payload
unbounded poison ledger
```

This is the most important item.

### 2. Fix symlink confinement

Do not expose arbitrary host-resolving symlinks to an untrusted decentralized namespace.

### 3. Add adversarial mailbox tests

Especially:

```text
100k unknown-epoch messages
100k poison messages
oversized NIP-44 payload
```

and assert bounded state.

---

## P2 — Before calling the snapshot protocol complete

### 4. Verify manifest/tree closure

This should become an explicit security contract.

### 5. Make author tree walking iterative

### 6. Add efficient runtime indexes

Especially:

```text
ContentId → representations
```

---

## P2 — Hardening

### 7. fsync Vault directory

### 8. Remove release-only canonicality loopholes

### 9. Binary-search tree entries

### 10. Add pathological-depth/size tests

---

## Documentation

### 11. Fix recovery status

### 12. Clearly distinguish:

```text
implemented
tested
wired
end-to-end
```

throughout the roadmap.

---

# 25. What I would *not* change

I would explicitly **not** embark on a crypto redesign.

I think these decisions are correct:

* BIP-340 identity;
* separate identity/encryption device keys;
* random epoch secrets;
* root as custody rather than derivation;
* capability ECDH;
* XChaCha20-Poly1305;
* DriveId binding;
* ContentId/StorageId type separation;
* snapshot-bound membership;
* historical validity vs current eligibility;
* explicit conflict preservation;
* NIP-59 mailbox;
* NIP-44 transport encryption;
* ciphertext-only vaults;
* author-attested transport routes;
* verified streaming transport roots.

Those are the parts I'd protect from unnecessary churn.

The trust architecture is coherent. 

---

# 26. Final verdict

### **Architecture: 8.5/10**

The underlying architecture is strong and, importantly, internally coherent.

The type separation and security-boundary discipline are particularly good.

### **Cryptography: 9/10**

I don't see a compelling crypto redesign. The construction correctly delegates primitives and concentrates Wyrd-specific security in the state machines.

### **State machine: 9/10**

This is probably the strongest part of the system. The distinction between validity, canonicality, conflicts, voiding, and eligibility is exactly what a decentralized append-only system needs.

### **Persistence: 8.5/10**

Very solid crash/replay model. Vault durability just needs to be brought up to the same standard.

### **Network security: 5.5/10**

The protocol design is good, but the concrete mailbox currently has serious resource-exhaustion surfaces. The actual iroh serving authorization still needs to be implemented and audited.

### **Filesystem security: 7/10**

The immutable/open-FD semantics are good. Arbitrary symlink targets are the significant exception.

### **Scalability: 6.5/10**

Fine for the current prototype, but the historical-manifest scanning model will become painful for the kind of large, long-lived library Wyrd is intended to handle.

---

## Bottom line

**I would continue with the current architecture. I would not redesign Wyrd.**

But I would put a temporary security gate in front of the next live-network phase:

```text
                         CURRENT
                            │
              ┌─────────────┴─────────────┐
              │                           │
       protocol core                 live network
              │                           │
          ✅ strong                  ⚠️ security gate
                                          │
                    ┌─────────────────────┼─────────────────────┐
                    │                     │                     │
             mailbox bounds       symlink confinement    manifest closure
                    │
                    ▼
                fix first
```

The interesting thing about this review is that **the biggest risks aren't in the cryptographic design at all**. They're exactly at the points where an elegant state-machine protocol meets hostile, unbounded real-world inputs.

That is a good place to be at the pre-alpha stage: the core is worth preserving, and the remaining security work is concrete enough to attack directly.

# Principal Rust Architecture Review — Wyrd

## Executive assessment

**Overall: strong protocol/core design, but not yet ready to call the architecture “hardened.”**

The most encouraging part is that the **cryptographic and authorization boundaries are substantially better than the average pre-alpha distributed-storage project**. The code consistently distinguishes `ContentId`, `StorageId`, `SnapshotId`, `DeviceId`, `TransitionId`, and `DeviceEncryptionKey`; AEAD is delegated to audited crates; network imports use `insert_verified`; membership is treated as a deterministic state machine; and the snapshot DAG correctly distinguishes historical validity from current eligibility.

The test suite is also unusually serious for this stage: I count roughly **387 `#[test]` cases plus seven proptest/fuzz-oriented suites** in the packed source, including crash-injection and membership conformance tests.

However, I found several issues that I would address **before building more user-facing functionality**:

### Highest-priority findings

1. **🔴 Deferred mailbox messages can be permanently discarded when the pending queue reaches 1024.**
2. **🔴 The `Mailbox` API cannot actually express the ack/retry contract that `Engine` relies on.**
3. **🔴 Iroh bulk fetching defeats its own memory ceiling by downloading the entire blob before checking the limit.**
4. **🔴 Long-lived identity, encryption, and epoch secrets are held in non-zeroizing types.**
5. **🔴 FUSE currently treats every changed directory subtree as a path conflict, contradicting the normative “DAG conflict ≠ path conflict” rule.**
6. **🟠 `DriveView::set_heads(Vec<Snapshot>)` accepts unverified snapshots, so the most important view invariant is conventionally enforced rather than type-enforced.**
7. **🟠 Capability validation does not actually bind the capability to the transition named by the capability.**
8. **🟠 The sync engine repeatedly rebuilds the entire durable state from disk instead of maintaining one authoritative in-memory runtime state.**
9. **🟠 `canonical_bytes()` on `Manifest` can emit non-canonical bytes in release builds because canonicality is only `debug_assert!`ed.**
10. **🟠 The format/architecture documentation has a genuine boundary contradiction around where manifests belong.**

I would characterize Wyrd as **architecturally promising and cryptographically disciplined, but with several boundary contracts that are currently comments rather than enforced invariants.**

---

# 1. Critical issues

## C1 — Pending-message overflow permanently loses legitimate messages

**`crates/wyrd-sync/src/runtime/intake.rs:64-78`**

This is the clearest correctness bug I found.

When a message cannot yet be authorized, it is placed in `pending`. Once the queue reaches `MAX_PENDING_MESSAGES`, the code instead commits the message ID:

```text
Action::Defer if engine.pending.len() >= MAX_PENDING_MESSAGES =>
    vec![Fact::ControlMessage(*id)]
```

That means the message becomes permanently "seen".

The surrounding documentation explicitly says the opposite: the sender can supposedly redeliver the message once legitimate pending messages drain. But on redelivery, `ControlInbox::ingest()` returns `Duplicate`; there is no pending message anymore, so the message is discarded.

The implementation and documentation therefore disagree.  

### Why this matters

This is an availability attack:

1. Attacker sends 1024 messages whose authorization depends on unknown/future membership.
2. They fill `pending`.
3. A legitimate capability or snapshot announcement arrives.
4. It is over the limit.
5. Its ID is durably marked seen.
6. The legitimate message can never be processed.

That is particularly bad because the queue limit was introduced specifically as an anti-DoS mechanism.

### Fix

Do **not** solve overflow by converting "deferred" into "durably consumed".

The protocol needs an explicit disposition:

```rust
enum Delivery {
    Ack,
    Retry,
    Drop,
}
```

or something equivalent.

A deferred message must remain retryable without being indistinguishable from a permanently rejected message.

---

## C2 — `Mailbox` has no acknowledgement/retry semantics

**`crates/wyrd-sync/src/transport/mailbox.rs:103-114`**

This is the architectural problem underlying C1.

The trait is:

```rust
fn send(...)
fn recv(&mut self) -> Option<MailboxEnvelope>
```

`recv()` **takes** the envelope.

But the engine's documented semantics explicitly depend on a relay retaining messages for redelivery after:

* unknown epoch,
* unavailable membership state,
* deferred announcements,
* transient transport problems,
* crash before durable commit.

The engine documentation even says that crash recovery depends on "the relay retaining unacked deliveries". Yet there is no `ack`, `nack`, lease, receipt, cursor, or transaction boundary in the interface. 

### This needs to be resolved before the real relay pool

I would make the transport contract something like:

```rust
trait Mailbox {
    type Delivery;

    fn recv(&mut self) -> Result<Option<Self::Delivery>, MailboxError>;
}

trait Delivery {
    fn envelope(&self) -> &MailboxEnvelope;
    fn ack(self) -> Result<(), MailboxError>;
    fn retry(self) -> Result<(), MailboxError>;
}
```

Or, if the actual relay naturally gives you a cursor:

```rust
recv() -> Delivery {
    id,
    envelope,
    receipt,
}
```

with explicit commit/ack semantics.

**Do not build the websocket relay pool around the current `recv()` abstraction.** It will force transport semantics into undocumented adapter behavior.

---

## C3 — Iroh bulk transport violates its advertised memory ceiling

**`crates/wyrd-sync/src/bulk.rs:173-191`**

The implementation does:

```text
get_blob(...).bytes().await?
...
if bytes.len() > max { ... }
```

So the complete remote blob is materialized before the `max` check.

The comments acknowledge this explicitly: the iroh implementation enforces the limit **after transfer**. 

The architectural contract says the opposite: the caller supplies a pre-decode ceiling and an oversized representation should fail rather than being handed to the engine.

This matters because Wyrd treats bulk peers as untrusted.

A hostile peer can potentially respond with a very large blob and force the daemon to allocate it before Wyrd says:

> "this is over the 64 MiB limit."

### Fix

The transport layer needs a **streaming bounded receive**:

1. obtain advertised blob length if available;
2. reject before allocation if it exceeds the ceiling;
3. otherwise stream into a bounded buffer;
4. abort as soon as the bound is crossed;
5. only return the bytes after transport verification completes.

The important distinction is:

> **"verified before use" does not require "unbounded before rejection."**

This should be fixed before calling the iroh bulk implementation production-grade.

---

## C4 — Long-lived secret material isn't consistently zeroized

**`crates/wyrd-sync/src/runtime/engine.rs:148-158`**

The `Engine` stores:

```rust
identity_secret: SecretKey,
encryption_secret: SecretKey,
epoch_keys: BTreeMap<u64, [u8; 32]>,
```

The project has clearly thought about zeroization—the root key and epoch secret types use `ZeroizeOnDrop`, and even the ephemeral scalar has a documented upstream limitation. 

But the actual engine's long-lived secrets are plain values.

This is especially notable because the code's own `aead::open()` returns a plain `Vec<u8>` rather than `Zeroizing<Vec<u8>>`. 

### Security impact

A crash dump, allocator reuse, debugger attachment, or memory forensic capture can potentially retain:

* the device's Nostr identity secret;
* its capability encryption secret;
* every retained epoch control key.

The root/epoch abstractions demonstrate that the project already considers this a security invariant.

### Fix

Introduce explicit secret wrappers:

```rust
type SecretBytes = Zeroizing<[u8; 32]>;
```

or dedicated newtypes:

```rust
#[derive(ZeroizeOnDrop)]
struct DeviceIdentitySecret(...);

#[derive(ZeroizeOnDrop)]
struct DeviceEncryptionSecret(...);

#[derive(ZeroizeOnDrop)]
struct ControlKey(...);
```

Then make the engine and inbox use those types.

For capability plaintext specifically, make the AEAD open path return `Zeroizing<Vec<u8>>` where the plaintext is secret.

---

# 2. Major issues

## M1 — FUSE violates the documented distinction between DAG conflicts and path conflicts

This is a substantive semantic issue.

The normative documentation says:

> multiple heads do not imply that any particular path conflicts.

It explicitly says **"DAG conflict ≠ path conflict."** 

But `DriveView::merge()` compares `Node` values directly:

```text
if present.len() == resolutions.len()
    && present.iter().all(|(_, node)| node == first)
```

A directory node contains:

```text
Node::Dir { subtree: ContentId }
```

so if:

```text
HEAD A: /Music -> subtree A
HEAD B: /Music -> subtree B
```

then `/Music` is declared a conflict—even if the only difference is `/Music/song.mp3`.

The code explicitly documents this conservative behavior.  

### Why that's wrong

Suppose:

```text
HEAD A
  /dir/file-a
  /dir/common

HEAD B
  /dir/file-b
  /dir/common
```

The correct semantic result is:

```text
/dir              directory, not conflict
/dir/common       identical
/dir/file-a       only A
/dir/file-b       only B
```

The current algorithm produces:

```text
/dir -> Conflict
```

and only then recursively exposes a union.

That's not the same abstraction.

### Fix

Merge directory nodes structurally rather than by subtree identity.

Conceptually:

```rust
Dir + Dir => merge_directory_contents(...)
File + File => compare file identity
Symlink + Symlink => compare target
anything else => conflict
```

The subtree IDs should be used as an optimization:

```rust
if subtree_a == subtree_b {
    return identical_dir;
}
```

but **not as the definition of a path conflict**.

This is important enough that I would fix it before calling the FUSE view's conflict semantics correct.

---

## M2 — Conflict nodes are visible but not actually resolvable/readable

The `Node::Conflict` representation is good:

```text
Conflict {
    versions: Vec<ConflictVersion>
}
```

and the versions retain their `SnapshotId`. 

But `open()` rejects a conflict outright:

```text
Node::Conflict => Err(ViewError::Conflict)
```

and `readdir()` presents a union under the original names. 

So the user can see:

```text
foo
```

is conflicted, but cannot directly access:

```text
foo from snapshot A
foo from snapshot B
```

The documentation says conflicted paths should expose both versions. 

This is acknowledged as an open UI policy, so I wouldn't call it a protocol defect. But it is a **major FUSE/product correctness gap**.

### Recommendation

Define the conflict presentation before the kernel adapter:

```text
foo/
  .wyrd/
    <snapshot A>
    <snapshot B>
```

or some similarly explicit namespace.

Do not let FUSE invent this policy.

---

## M3 — `DriveView` accepts arbitrary, unverified snapshots

**`crates/wyrd-fuse/src/view.rs:132-155`**

`DriveView` accepts:

```rust
heads: Vec<Snapshot>
```

and `set_heads()` accepts another raw `Vec<Snapshot>`.

There is no type distinction between:

```text
untrusted Snapshot
```

and:

```text
signature-verified, authorization-classified live head
```

The sync layer does have exactly the sort of wrapper you need:

```text
AuthorizedSnapshot
```

which verifies the BIP-340 signature before wrapping the body. 

The daemon subsequently exposes `refresh_live_heads()` from the classified engine. 

So the *actual current composition path* is mostly sound.

The problem is that the API doesn't enforce it.

### Better boundary

Something like:

```rust
pub struct ViewHead {
    snapshot: AuthorizedSnapshot,
}
```

in the appropriate boundary crate would make:

```text
verified snapshot
       ↓
live-head policy
       ↓
filesystem view
```

a real type boundary.

This is exactly the sort of invariant Wyrd's architecture is trying to enforce.

---

## M4 — Capability validation doesn't bind the capability to its transition

**`crates/wyrd-sync/src/keys/capability/model.rs:115-155`**

`Capability::mint()` takes:

```rust
state: &MembershipState,
transition: TransitionId,
epoch: u64,
```

but never establishes that `state` is actually the state produced by `transition`.

`validate_against()` only checks:

* device is a member;
* encryption key matches the registered key. 

That means the API can construct a capability whose:

```text
state = transition A
transition field = transition B
```

provided the device/encryption key happens to be compatible.

### Why this matters

The trust contract says the capability is bound to the transition and epoch. 

Currently, that binding is partly enforced by the caller (`intake` looks up `capability.transition`) rather than by the capability model.

It doesn't appear to give an immediate privilege escalation because the actual epoch secrets are still what determine access. But it weakens the provenance guarantee and creates future audit/security risk.

### Fix

Make the authoritative transition state inseparable:

```rust
Capability::mint(
    drive,
    authorized_transition: &AuthorizedTransition,
    device,
    secrets,
)
```

or have `MembershipState` carry its own `TransitionId`.

Then:

```rust
transition == state.transition_id()
epoch == state.epoch
```

becomes structurally enforced.

---

## M5 — Runtime repeatedly reconstructs itself from disk

**`crates/wyrd-sync/src/runtime/engine.rs:287-304`**

`Engine` already owns:

* membership log;
* inbox;
* pending state;
* durable store.

Yet:

```rust
pub fn runtime_state(&self) -> Result<RuntimeState, EngineError> {
    Ok(self.store.rebuild(self.device)?.runtime)
}
```

and `live_heads()` also performs a complete rebuild.

The fetch planner goes further and rebuilds the store state every convergence pass.

This means the durable log is effectively being used as the engine's read model, even while the engine maintains an in-memory model.

### Performance consequences

For a large drive/history:

```text
every refresh
    ↓
read all commits
    ↓
decrypt/replay all facts
    ↓
reconstruct runtime
    ↓
reconstruct DAG
    ↓
classify
```

That's excellent as a **recovery mechanism**, but poor as the normal steady-state path.

### Recommended architecture

Have:

```text
Engine
 ├── authoritative in-memory state
 └── DurableStore
       ↑
       └── recovery/rebuild only
```

Then expose snapshots/clones of the in-memory state.

Use rebuild on:

* startup;
* explicit integrity verification;
* corruption recovery;
* tests.

Not on every presentation refresh.

---

## M6 — Manifest canonical encoding isn't actually self-protecting

**`crates/wyrd-format/src/manifest.rs:257-280`**

The documentation says the encoding is canonical, but:

```rust
debug_assert!(entries are sorted);
debug_assert!(children are sorted);
```

and then it emits the bytes anyway.

In release:

```rust
Manifest {
    entries: unsorted_vec,
    ...
}
```

can produce bytes that the decoder itself will reject.

The fields are also public, so callers can construct such values freely. 

### Better design

One of:

1. `Manifest::new()` sorts/validates and fields become private.
2. `canonical_bytes()` returns `Result<Vec<u8>, ManifestError>`.
3. Store canonical data in `BTreeMap/BTreeSet`.
4. Keep the current representation but rename it `encode_assuming_canonical()`.

For a protocol core, I prefer **validated construction + private fields**.

A method called `canonical_bytes()` should not be capable of producing non-canonical bytes.

---

## M7 — `u32` length casts are unchecked across the format

There are numerous constructions like:

```rust
self.entries.len() as u32
self.parents.len() as u32
blob.len() as u32
self.changes.len() as u32
```

The format deliberately uses `u32` counts, but the encoders do not reject values exceeding `u32::MAX`.

This is not remotely reachable with today's normal limits, so I would **not** call it a practical exploit.

But for a canonical wire format, this is the wrong invariant:

```text
Rust collection length
       ↓ unchecked cast
wire length
```

It should be:

```rust
u32::try_from(len).map_err(...)
```

This becomes especially important if future limits change.

---

## M8 — `DriveView` path lookup is O(N) per path component

`resolve_one()` does:

```text
tree.entries().iter().find(...)
```

rather than binary-searching the canonical sorted entries. 

But Wyrd explicitly canonicalizes tree entries bytewise.

That gives you a free optimization:

```rust
binary_search_by(...)
```

or a helper:

```rust
Tree::get(name)
```

with the lookup logic encapsulated in `wyrd-format`.

For a directory with 100k entries, this is the difference between roughly:

```text
O(100k)
```

and:

```text
O(log 100k)
```

per component.

This is an obvious optimization and also makes the tree abstraction cleaner.

---

## M9 — Open FDs aren't snapshot-stable

The FUSE adapter returns:

```text
FileHandle(0)
```

for every file, and `read()` completely ignores the handle. It re-resolves the inode's **path** against the current view.  

If the live head advances:

```text
open("/foo")   -> version A
head changes
read(fd)       -> version B
```

That is surprising POSIX behavior and becomes particularly problematic for a Time-Machine-like immutable snapshot system.

### Fix

On `open()` capture an immutable `OpenFile`:

```text
file handle -> snapshot identity + chunk list + size
```

and have `read()` use the captured object rather than re-resolving the path.

This also makes the semantic model much cleaner:

> a file descriptor represents the object that was opened, not whatever happens to occupy that path later.

---

## M10 — FUSE lock poisoning causes panics

There are numerous:

```rust
self.inodes.read().expect("inode lock")
self.inodes.write().expect("inode lock")
self.directories.read().expect("directory lock")
```

inside kernel callbacks. 

A poisoned lock should not normally happen, but filesystem code should be particularly reluctant to panic.

The correct failure mode is:

```text
lock poisoned
    ↓
EIO
```

rather than process termination.

I would make the lock accessors return a controlled filesystem error.

---

# 3. Architectural/documentation issues

## A1 — Manifest ownership is internally contradictory

`AGENTS.md` says:

> "`wyrd-format` is the plaintext world: keys, ciphertext, and manifests live in `wyrd-sync`." 

But:

* `wyrd-format/src/manifest.rs` defines the plaintext manifest structure;
* `wyrd-format` README explicitly says manifests do not belong there;
* `object-model.md` calls manifests **core objects**;
* the manifest's canonical encoding is part of the object model.

At the same time, the implementation sensibly keeps **manifest sealing and cryptography** in `wyrd-sync`. 

I think the implementation is actually closer to the better architecture:

```text
wyrd-format
    Manifest schema
    canonical encoding
    ContentId semantics

wyrd-sync
    manifest encryption
    StorageId representation
    transport
    authorization/materialization
```

So I would **change the documentation rather than move the manifest type**.

The rule should say something like:

> Manifest schema and canonical plaintext representation belong to `wyrd-format`; manifest encryption, storage addressing, and capability semantics belong to `wyrd-sync`.

Otherwise future contributors will "fix" the code in the wrong direction.

---

## A2 — T16 is correctly respected for the mailbox, but the current API must not become the final transport API

This part is actually good.

The repository explicitly says the real relay pool and NIP-46 session are outside the current `wyrd-sync` boundary. 

The mailbox implementation also explicitly says:

> No live relay client lives here.



That is the right decision.

**But C2 means the trait is not yet expressive enough for the eventual transport.**

So I would *not* implement the relay pool by simply adding:

```rust
struct RelayPool;
impl Mailbox for RelayPool { ... }
```

to the existing contract.

First fix the delivery semantics.

---

# 4. Security review

## AEAD design — strong

This is one of the best parts of the repository.

The construction correctly binds:

```text
version
kind
ContentId
```

into AAD, while `StorageId` is derived from the encrypted representation. The implementation uses XChaCha20-Poly1305 from the library rather than implementing cryptography itself. 

The verification path also performs both:

1. AEAD authentication;
2. plaintext → expected `ContentId`.

That is exactly the defense needed against malicious manifest mappings.

The tests explicitly cover wrong key, wrong storage ID, wrong size, etc. 

**Assessment: PASS.**

---

## ContentId / StorageId separation — strong

The type distinction is excellent:

```text
ContentId
StorageId
SnapshotId
DriveId
DeviceId
TransitionId
DeviceEncryptionKey
```

and the documentation is very clear about the two identity worlds. 

One caveat: `from_bytes()` is public for all these types. That means:

> the type system prevents accidental *mixing*, but not accidental *forging*.

That's acceptable for parsing untrusted wire data, but it means the API should continue to make "verified" wrappers meaningful.

---

## Nostr identity boundary — strong

The implementation correctly treats Nostr as:

```text
identity + signing
```

rather than making Wyrd objects into Nostr events.

The NIP-46 contract is also nicely constrained to a closed domain enum rather than arbitrary strings. 

**Assessment: PASS.**

---

## Epoch key derivation — strong

The epoch secret is separate from the root and is generated independently. The root only wraps escrow records rather than deriving epoch secrets directly.

That matches the stated T4/T8/T13 model.

**Assessment: PASS.**

The main problem is **memory lifecycle**, not cryptographic derivation.

---

## Manifest trust model — strong

The project gets an important distributed-systems point right:

> manifests are optimization hints, not authority.

The fetch path doesn't trust:

```text
ContentId -> StorageId
```

until the encrypted object passes the complete verification path.

That's exactly what a zero-trust storage design needs. 

**Assessment: PASS.**

---

# 5. Durable store

This area is surprisingly good.

The implementation has:

* exclusive store locking;
* temp file writes;
* file fsync;
* rename;
* directory fsync;
* chained commit hashes;
* `CURRENT`;
* crash injection points;
* replay verification.

The store explicitly acquires the lock before reading/writing state. 

The crash testing is particularly valuable.

### One architectural caveat

`CURRENT` is an integrity anchor, not an anti-rollback mechanism.

An attacker who can modify the durable store can potentially replace `CURRENT` with an older valid state and make the store replay an older prefix.

That is probably acceptable because **local storage isn't currently modeled as malicious**, but the threat model should say so explicitly.

If protection against local rollback is ever required, you'll need an external monotonic anchor—OS secure storage, hardware monotonic counter, remote witness, etc.

---

# 6. Membership and authorization

## Strongest subsystem in the project

The membership code is probably the most architecturally mature part.

Good decisions include:

* predecessor-based validation;
* pre-transition owner authority;
* derived member/owner roots;
* explicit contested/voided/orphaned states;
* deterministic ordering;
* explicit recovery semantics;
* property testing of arrival-order invariance.

The classification engine explicitly computes historical validity separately from current eligibility, matching the normative contract. 

The tests also intentionally exercise permutations of arrival order. 

**Assessment: very good.**

### Performance concern

The classification machinery repeatedly traverses the full observed graph.

For small histories, that's fine.

For a drive with hundreds of thousands/millions of snapshots and a long membership history, you eventually want:

```text
incremental membership classification
incremental snapshot classification
cached transition states
cached descendant/head indexes
```

I would **not optimize this yet**, however. First establish workload evidence.

---

# 7. FUSE / presentation layer

The separation is fundamentally right:

```text
wyrd-format
      ↑
wyrd-fuse
      ↑
wyrd-daemon
      ↑
wyrd-sync
```

`wyrd-fuse` has no sync/networking dependency and only knows about `ObjectStore`, `Snapshot`, trees, and the abstract `Materialization` interface. That's exactly the right layering. 

The daemon is also correctly positioned as composition rather than part of the format model. 

### But the FUSE implementation is still a prototype

The following are not ready:

* snapshot-stable file handles;
* proper conflict version access;
* block-and-fetch behavior;
* time travel;
* robust inode semantics;
* possibly platform-specific semantics.

The README itself correctly describes much of this as planned rather than complete. 

That is fine for pre-alpha; I would not interpret those as roadmap failures.

---

# 8. Code quality

## Positive

The code is generally:

* strongly typed;
* explicit;
* well documented;
* conservative about cryptographic validation;
* fairly idiomatic Rust;
* low on clever abstraction;
* good about keeping security-sensitive state access visible.

The comments are unusually useful because they explain **why**, not merely what.

The decomposition:

```text
runtime/
  engine
  intake
  plan
  fetch
```

is directionally good.

---

## What I'd change

### 1. Too much invariant documentation instead of invariant types

There are several places where the code says:

> callers must...

when the architecture would benefit from making that impossible.

Examples:

```text
Manifest sortedness
DriveView heads are verified
Capability transition binding
Mailbox acknowledgement
```

The project's philosophy is already heavily type-oriented, so I would push that further.

### 2. Avoid `debug_assert!` for protocol invariants

If violating the condition makes the generated bytes invalid, it isn't a debugging aid.

It's an error condition.

### 3. Reduce `String`-based error propagation

There are places where store errors become:

```rust
ViewError::Store(format!("{error:?}"))
```

That is convenient but loses structured error information.

For the presentation boundary that's tolerable, but I'd preserve structured causes where practical.

### 4. Introduce small domain wrappers around secrets

The project already does this for `DriveRootKey` and `EpochSecret`. Extend that discipline to the engine.

---

# 9. Testing assessment

**Very strong for protocol correctness.**

The repository has approximately:

* **387 unit tests**
* multiple property-test suites
* saved proptest regression cases
* fuzz/property-oriented decoding tests
* membership conformance tests
* durable crash-injection tests
* restart/replay tests
* multi-device convergence tests
* malformed-input tests

That is excellent.

The durable tests in particular are much better than superficial smoke tests.

### Missing testing layer

What is missing is **cross-crate integration testing**.

I would add a small set of tests that instantiate:

```text
wyrd-format
    ↓
wyrd-sync
    ↓
wyrd-fuse
    ↓
wyrd-daemon
```

and specifically prove the architectural contracts.

Examples:

```text
unverified Snapshot cannot become a live FUSE head
ContentId never appears in a vault transport record
malformed manifest cannot become materialized content
changed descendant does not create a directory path conflict
open FD remains stable after head advancement
deferred message survives queue pressure
bulk source never allocates beyond its configured limit
```

Those tests are more valuable now than another 100 unit tests for individual encoders.

---

# 10. Minor issues

### m1 — `ObjectStore::get()` doesn't carry `ObjectKind`

The store knows kind at insertion but retrieves solely by `ContentId`.

That is safe because the domain-separated identity makes cross-kind collisions computationally infeasible, and the FS implementation probes all kinds.

Still, a typed API such as:

```rust
get(kind, id)
```

could eliminate unnecessary probing and make intent clearer.

Not urgent.

---

### m2 — `FsObjectStore` explicitly trusts its directory

The documentation openly states that symlink/foreign-entry attacks aren't defended against.

That's acceptable if the store directory is trusted, but the threat model should make this explicit.

---

### m3 — FUSE inode semantics are minimal

`nlink = 1`, synthetic timestamps, fixed ownership, etc. are all acceptable for the prototype, but expect compatibility issues with applications that assume normal filesystem metadata.

---

### m4 — `iroh-gossip` is currently a dependency without corresponding production implementation

The dependency set is deliberately pinned together, which is good, but unused dependencies increase build and audit surface.

This can remain while the gossip framing is under active development; otherwise defer it until needed.

---

### m5 — Some API comments are now stale

There are several "not yet implemented", "later issue", and "skeleton" comments that don't perfectly match the increasingly substantial implementation.

The repository explicitly says stale docs are worse than missing docs. 

I'd do a documentation consistency pass after the architectural fixes.

---

# 11. What is already architecturally excellent

There is a lot here I would **not change**.

### Keep

**Content/Storage identity separation**

This is foundational and correctly represented in Rust types.

**Immutable CAS semantics**

`insert()` deduplicates and `insert_verified()` verifies before accepting network data. The object store contract is exactly what you want. 

**Snapshot-as-DAG model**

The repository correctly avoids mutable "current file" state. Snapshots remain immutable history. 

**Historical validity vs current eligibility**

This is an excellent distributed-systems decision. Don't collapse those concepts.

**Two device keys**

The distinction:

```text
Nostr identity key → signing
device encryption key → capability delivery
```

is very good.

**AEAD + ContentId double verification**

Keep this exactly.

**Untrusted manifest model**

Also keep this.

**Durable commit protocol**

The crash model and replay chain are mature enough that I would preserve the overall design.

**FUSE as presentation, not synchronization**

Absolutely keep this.

---

# 12. Recommended priority order

I would **not** follow the roadmap by simply adding the next feature. I'd do this hardening sequence first:

### Phase 0 — Fix protocol-boundary correctness

**1. Redesign mailbox delivery semantics**

Fix:

* ack/retry;
* deferred delivery;
* crash/redelivery;
* poison suppression;
* queue overflow.

This is the most important architectural item.

**2. Fix bounded bulk transfer**

Make the iroh path genuinely bounded before allocation.

**3. Zeroize all long-lived secret material**

Engine, inbox, capability plaintext, etc.

**4. Bind capabilities structurally to transitions**

Remove the ability to construct inconsistent `(state, transition, epoch)` tuples.

---

### Phase 1 — Fix view semantics

**5. Fix directory conflict merging**

Use subtree identity as an optimization, not as path-conflict semantics.

**6. Define conflict version presentation**

Do this before implementing the real FUSE UX.

**7. Make open file handles immutable**

A handle should capture the exact snapshot/object it opened.

**8. Replace `expect()` in FUSE callbacks**

Return `EIO`.

---

### Phase 2 — Make invariants real

**9. Make canonical encoders infallible by construction or fallible explicitly**

Especially `Manifest`.

**10. Replace unchecked `as u32` conversions**

Use checked conversion.

**11. Strengthen verified-head typing**

Don't let raw `Snapshot` cross into the presentation layer where an authorized/live-head type is appropriate.

---

### Phase 3 — Performance

**12. Stop rebuilding durable state for every read model**

Make the engine's in-memory state authoritative during normal operation.

**13. Binary-search tree entries**

Very cheap win.

**14. Add runtime benchmarks**

Especially:

* 10k / 100k / 1M tree entries;
* 10k / 100k snapshots;
* large hierarchical manifests;
* large pending queues;
* long chunk lists;
* repeated `runtime_state()` calls.

---

# Final verdict

I'd give the current architecture roughly:

| Area                       | Assessment                                                   |
| -------------------------- | ------------------------------------------------------------ |
| Core object model          | **Excellent**                                                |
| Type separation            | **Excellent**                                                |
| Cryptographic construction | **Very strong**                                              |
| Membership state machine   | **Very strong**                                              |
| Durable persistence        | **Strong**                                                   |
| Zero-trust model           | **Strong conceptually**                                      |
| Sync runtime               | **Good, but boundary semantics need hardening**              |
| FUSE model                 | **Correct direction, several semantic bugs**                 |
| Daemon composition         | **Good**                                                     |
| Testing                    | **Excellent for this maturity level**                        |
| Performance architecture   | **Adequate for pre-alpha, needs restructuring before scale** |
| Documentation consistency  | **Needs cleanup**                                            |

The important distinction is that I **don't see a fundamental flaw in Wyrd's core thesis**. The separation between immutable logical history and encrypted physical storage is sound, and the cryptographic binding model is considerably more disciplined than the average P2P storage prototype.

The current danger is different:

> **Several of the strongest architectural guarantees exist in comments and caller discipline where they should exist in APIs and state-machine boundaries.**

The mailbox delivery contract is the biggest example. The FUSE head boundary and capability transition binding are two others.

If you fix those boundary issues before adding the real relay pool / full FUSE / mobile surfaces, I think the architecture becomes substantially more robust rather than merely accumulating implementation on top of the current prototype.

One final note: I attempted to run a workspace `cargo check`, but the review environment does not have `cargo` installed, so this review is **source-level rather than compiler/test-execution verified**. The findings above are based on the complete packed source available in the uploaded repository snapshot, not on assumptions about unseen files.

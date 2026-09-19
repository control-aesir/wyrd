I reviewed the supplied repository snapshot as a release review, starting with `AGENTS.md`, then the architecture and normative documents, and then the implementation and contract suite. I treated `trust.md` and `epochs.md` as contracts rather than suggestions.

## Verdict

# **NO-GO for v0.1.0-alpha**

There are **six blockers** I would require before shipping this as an externally usable alpha:

1. **Unbounded live-mailbox memory**
2. **Mailbox payload size is enforced too late**
3. **The durable mailbox seen-log is an attacker-controlled unbounded disk/memory sink**
4. **The required durable announcement outbox does not exist**
5. **`refresh_live_heads()` violates the documented all-or-nothing projection rule**
6. **FUSE/session failure can leave the live daemon running, while admitted mutation callers can be stranded**

There are also several should-fix issues, including the unresolved NIP-46 trust boundary, incomplete admission/bootstrap synchronization, real-relay interoperability, and release documentation drift.

The cryptographic/state-machine core is considerably better hardened than the remaining release surface. The blockers are mostly **resource exhaustion, durability/liveness, and composition-boundary failures**, not broken BIP-340/AEAD/capability primitives.

---

# 1. Blockers

## B1 — `LiveMailbox.unacked` is unbounded

**Severity: blocker**

### Code

`crates/wyrd-daemon/src/live_mailbox.rs:288`:

```rust
unacked: VecDeque<Held>,
```

and `recv()` accepts every previously unseen valid gift wrap:

`crates/wyrd-daemon/src/live_mailbox.rs:704-733`.

There is no maximum on the number of held deliveries. `INCOMING_CAPACITY = 1024` only limits the Tokio notification channel; it does **not** bound `unacked`. The current implementation explicitly moves every accepted wrap into that deque. 

`settle()` only removes the entry for `Ack`; `Retry` deliberately leaves it there:

`crates/wyrd-daemon/src/live_mailbox.rs:736-758`.

### Attack

An attacker can publish arbitrarily many syntactically valid NIP-59 wraps addressed to the device.

They do not need to be valid Wyrd control messages. They only need to get through the NIP-59 wrapper boundary. The mailbox hands them to the engine, where messages can become `Deferred`/`Skipped`/otherwise held.

Each becomes:

```text
relay event
    → Event in notification queue
    → Held
    → unacked VecDeque
```

and remains there.

The engine's new `MAX_PENDING_MESSAGES = 1024` does **not** solve this. The mailbox is upstream of that bound. 

### Consequence

A public relay-facing attacker can turn mailbox traffic into unbounded daemon heap consumption.

This is especially inappropriate for Wyrd because the trust model intentionally permits asynchronous/offline operation: the mailbox is an externally exposed persistence boundary.

### Required fix

Give `unacked` an explicit bound and define what happens at saturation.

The existing engine pattern is the right model:

> **do not Ack; leave the message available in relay history; shed it locally.**

Then add a regression test that injects `MAX + N` unique valid wraps whose inner Wyrd payload remains deferred and proves mailbox memory/state remains bounded.

---

## B2 — Mailbox payload size is checked after full decryption/allocation

**Severity: blocker**

The live mailbox module explicitly says payload bounds are delegated to the engine:

`live_mailbox.rs:41-46`.

But the actual boundary is:

`crates/wyrd-sync/src/transport/mailbox.rs:108-121`.

`open_from_sender()` performs:

```rust
nip44::decrypt_to_bytes(...)
```

before `ControlInbox::ingest()` sees the payload. 

Likewise, the live NIP-59 mailbox has:

```rust
const INCOMING_CAPACITY: usize = 1024;
```

which bounds **event count**, not event byte size.

### Why this matters

A hostile peer can provide a very large but cryptographically valid NIP-44 ciphertext.

The current sequence is approximately:

```text
large relay event
    ↓
large Event retained
    ↓
NIP-59 unwrap
    ↓
NIP-44 decrypt / allocate plaintext
    ↓
copy into Wyrd envelope
    ↓
ControlInbox length checks
```

The security limit is therefore downstream of the expensive operation.

The current bulk path gets this right: iroh first obtains a verified size and rejects oversize before buffering. The mailbox does not have an equivalent early gate. 

### Required fix

Introduce a mailbox-layer ceiling before expensive decryption/copying:

```text
relay/event ceiling
    ↓
NIP-44 ciphertext ceiling
    ↓
decrypted Wyrd-envelope ceiling
    ↓
semantic ControlInbox limits
```

The limit needs to be tested at the live mailbox boundary, not only in `ControlInbox`.

---

## B3 — `mailbox.seen` is an unbounded attacker-controlled disk and heap sink

**Severity: blocker**

`SeenStore` is explicitly:

`crates/wyrd-daemon/src/live_mailbox.rs:168-184`.

It maintains:

```rust
seen: HashSet<EventId>
file: std::fs::File
```

and the documentation explicitly says the file is never compacted:

`live_mailbox.rs:168-179`.

Every acknowledged delivery calls:

`live_mailbox.rs:233-241`

which appends the wrapper ID and performs `sync_data()`.

The engine's intake treats terminal malformed/invalid messages as discard-and-ack. Therefore an attacker can manufacture **unique, validly wrapped but semantically useless messages** and cause permanent dedupe entries. The earlier review embedded in the repository identifies exactly this path. 

### Consequences

One attacker-controlled message causes permanent:

* one disk record;
* one `HashSet<EventId>` entry;
* one synchronous filesystem durability operation.

And on restart, `SeenStore::open()` reads the entire log into memory:

`live_mailbox.rs:187-221`.

So the problem is both:

```text
runtime heap growth
+
persistent disk growth
+
restart-time heap spike
```

This is not merely a future compaction concern because the input is remotely controllable.

### Required fix

Separate:

1. **durable acknowledgement of a valid Wyrd delivery**, and
2. **discarding terminal garbage/poison**.

Possible approaches:

* bounded negative cache for poison;
* don't durably retain wrapper IDs for messages rejected before Wyrd semantic acceptance;
* durable dedupe keyed to the Wyrd `ControlMessageId` where appropriate;
* bounded/compacted acknowledgement storage.

At minimum, the protocol needs an explicit **retention bound**.

---

## B4 — The durable announcement outbox required by `write-path.md` is absent

**Severity: blocker**

This is the clearest documentation/implementation contradiction.

The normative write path says the announcement obligation is created **atomically with the durable commit** and survives a crash. The obligation is then discharged later. 

The document is explicit:

> step 3 = durable commit + announcement obligation

and:

> a restart reconciles un-discharged obligations.

But the implementation has only an imperative announcement operation.

`crates/wyrd-sync/src/runtime/author.rs:455-525` constructs and immediately sends the announcement to the mailbox. 

There is no durable outbox fact/store corresponding to that obligation.

The repository's own status documentation admits this remains open: `feat(sync): durable announcement outbox and retry contract`. 

The contract test also does **not** prove crash recovery of an outbox. It manually retries:

`crates/wyrd-contracts/src/sync_contracts.rs:455-475`.

### Failure sequence

Today:

```text
author snapshot
    ↓
durable local commit
    ↓
process dies before announce_snapshot()
    ↓
snapshot exists locally
BUT
no durable obligation says "announce this"
```

On restart there is nothing to retry.

This violates the explicit durability contract.

### Required fix

Make the announcement obligation part of the durable commit transaction:

```text
prepare snapshot
prepare manifests
durably commit snapshot + obligation
publish local view
serve
discharge outbox entry
```

Then add a crash/restart contract:

```text
commit
→ crash before announcement
→ restart
→ same snapshot discovered in outbox
→ announcement sent
→ no re-authoring
```

Until that exists, I would not claim the mounted write path satisfies its normative durability semantics.

---

## B5 — `refresh_live_heads()` can silently replace a valid head set with a partial set

**Severity: blocker**

This is a subtle but important contradiction.

The contract says:

> refresh is all-or-nothing, never a partial head set, never a clear.

`crates/wyrd-contracts/src/sync_contracts.rs:240-248`. 

But production code does this:

`crates/wyrd-daemon/src/core.rs:190-ish` / current `refresh_live_heads()`:

```rust
let heads = self.engine.live_heads()?;

let verified = heads
    .into_iter()
    .filter(|head| {
        verify_head_closure(...).is_ok()
    })
    .collect::<Vec<_>>();

self.view.set_heads(view_heads(verified));
```

The current implementation is visible in the repository's projection path. 

That means:

```text
eligible heads = [A, B]
A closure valid
B closure corrupt/missing

refresh
→ [A]
→ install [A]
```

instead of:

```text
refresh
→ closure failure
→ keep previous installed [A, B]
→ surface error
```

Worse, if all heads fail closure, the current code can install an empty head set.

### Why this is security-relevant

The design explicitly says a damaged durable store must **not silently manufacture a different namespace**.

A corrupted or incomplete head can therefore cause the mounted view to silently regress from:

```text
A + B
```

to:

```text
A
```

rather than surfacing the damaged state.

That is exactly what the all-or-nothing projection contract was intended to prevent.

### Required fix

Change the semantics to:

```rust
for every eligible head:
    verify closure
    if any verification fails:
        return Err(...)
```

Only call `set_heads()` after **all** heads pass.

Then add the missing contract:

> one valid + one closure-damaged eligible head → projection fails → previously installed heads remain untouched.

The existing `failed_projection_leaves_installed_heads_untouched` test only damages `CURRENT`, causing `engine.runtime_state()` itself to fail. It does not exercise this per-head partial-filter path. 

---

## B6 — FUSE session failure is observed but does not supervise the daemon loop

**Severity: blocker**

The CLI starts the FUSE session on a separate thread:

`crates/wyrd-daemon/src/main.rs:502-510`.

Then immediately runs:

`main.rs:512-521`:

```text
FUSE thread
    ↓
session.run()

main thread
    ↓
live.run_loop(...)
```

The code explicitly acknowledges the problem:

> a dead event loop leaves a record even while the live loop below is still blocked — the main thread only learns the outcome at join time.



That is backwards for process supervision.

### Failure sequence

If `session.run()` terminates unexpectedly:

```text
FUSE session dies
    ↓
error logged
    ↓
SHUTDOWN remains false
    ↓
live.run_loop() continues
    ↓
daemon continues syncing/serving
    ↓
main thread never joins because it is still inside run_loop
```

So the process can continue without its primary presentation surface.

### There is a second liveness problem

`MutationQueue::submit()` intentionally blocks:

`crates/wyrd-daemon/src/mutation.rs:350-370`.

The reply is completed by the live loop. 

The queue's `MutationBatch` correctly prevents a taken batch from stranding callers, but there is **no shutdown/drop path that drains requests still sitting in `MutationQueue::pending`**.

So if the live loop exits through its error cap, admitted FUSE callers can remain blocked on `Reply::wait()`.

The loop explicitly has a terminal error path:

`core.rs:1110-1118`:

```rust
if consecutive > config.max_consecutive_errors {
    return Err(error);
}
```

The test suite even proves that this path exists. 

### Required fix

Have one lifecycle supervisor own both:

```text
FUSE session
live loop
serving endpoint
mailbox
mutation queue
```

and make termination propagate in both directions.

At minimum:

* FUSE session error → set shutdown;
* live-loop terminal error → set shutdown;
* queue shutdown → complete all pending replies with `MutationError::Engine`/`Shutdown`;
* join FUSE before process exit;
* no admitted syscall can wait forever after daemon shutdown.

This deserves a dedicated lifecycle contract.

---

# 2. Should-fix findings

## S1 — NIP-46 trust contract and current CLI disagree

**Severity: should-fix**

`trust.md` says the daemon must never receive the nsec when NIP-46 is used; the remote signer exposes scoped signing operations. 

The current CLI explicitly reconstructs a `nostr::SecretKey` from the identity and feeds it into the live mailbox:

`crates/wyrd-daemon/src/main.rs:459-469`. 

The engine itself also retains a `DeviceIdentitySecret`.

The important distinction is that **NIP-46 is documented as optional**, so I am not treating local-key operation itself as a release blocker. The problem is that the trust contract currently reads more strongly than the implementation.

The code comment says NIP-46 is a separate tracked issue.

### Recommendation

Either:

* explicitly define **local-key mode** as an alpha trust mode and amend `trust.md`, or
* finish the NIP-46 signer boundary before claiming the current daemon architecture satisfies the trust contract.

Do not leave the normative text and actual custody model ambiguous.

---

## S2 — Fresh-member synchronization is incomplete

**Severity: should-fix**

The bootstrap invitation contains:

```text
drive
inviter
invitee
encryption_key
genesis
capability
```

but not current heads or snapshot announcements. `BootstrapInvitation` is defined in `crates/wyrd-sync/src/control/bootstrap.rs`. 

The normal snapshot announcement path sends to:

```rust
members_of(&body.membership)
```

in `author.rs:513-524`. 

Therefore a device admitted at epoch N does not automatically receive snapshot announcements for snapshots whose membership reference predates its admission.

More fundamentally, I do not see a production snapshot-history discovery exchange in the supplied runtime.

The documented new-device flow guarantees capability delivery, but the bootstrap object itself doesn't establish a current snapshot/head discovery mechanism.

### Consequence

A newly admitted device can possess the keys necessary to read history without necessarily having the identifiers necessary to discover that history.

This needs an explicit protocol path, probably either:

* bootstrap current-head state;
* peer snapshot inventory/exchange;
* or a post-admission authoritative head announcement.

This is a **real functionality gap**, but I am keeping it below blocker because the current CLI does not yet expose a complete membership-management workflow.

---

## S3 — Actual external Nostr relay interoperability is not established

**Severity: should-fix**

The live mailbox has substantial in-process testing, but the tests use `MiniRelay`.

The repository itself identifies external relay interoperability as still open. 

The protocol relies on fairly specific behavior:

* NIP-59 gift wraps;
* relay replay;
* duplicate EVENT/MESSAGE delivery behavior;
* subscriptions after reconnect;
* random gift-wrap timestamps;
* no cursor;
* dedupe across replay.

Those assumptions need at least one real relay interoperability test before calling the live mailbox production-shaped.

---

## S4 — Vendored `fuser` cannot be signed off from this review artifact

**Severity: should-fix / release-process blocker if macOS binaries are shipping**

The root manifest says:

`Cargo.toml:22-30`

that Wyrd carries a vendored `fuser 0.18.0` with a deliberate macOS `libfuse3` build-script divergence.

However, `vendor/fuser/` is absent from the supplied Repomix artifact.

Therefore I cannot verify:

* the actual `build.rs`;
* whether the divergence is limited to the documented branch;
* whether upstream 0.18.0 was copied faithfully;
* whether the macOS probing logic is correct;
* whether the vendored source contains unintended changes.

I would **not call this a code defect based on the supplied material**. It is a release-audit gap.

For a macOS release, inspect and diff the entire vendored crate against the pinned upstream source before signing the binary.

---

## S5 — `Cargo.lock` cannot be audited from the supplied artifact

**Severity: should-fix release-process item**

`AGENTS.md`/root manifest deliberately pin the iroh set:

```text
iroh        = 1.1.0
iroh-blobs  = 0.103.0
iroh-gossip = 0.101.0
bao-tree    = 0.16.1
```

and the root explicitly says they must move as a set.

The manifest is clear. 

But Repomix explicitly excludes `*.lock`, so I cannot verify the actual resolved `Cargo.lock`.

Thus:

* manifest pinning: **clean**
* lockfile resolution: **not verified**

Do not interpret this as a discovered dependency mismatch.

---

# 3. Considerations

## C1 — `SeenStore` also has poor restart scaling

Even after solving the security problem above, `SeenStore::open()` reads the entire file:

`live_mailbox.rs:187-221`.

Since the current format is:

```text
one event ID
one line
forever
```

restart cost is O(total historical acknowledgements), with the whole file temporarily represented as a `Vec<u8>` plus UTF-8 `&str` plus `HashSet`.

The current design is acceptable only if a bounded/compacted retention scheme replaces it.

---

## C2 — `settled: HashSet<DeliveryId>` grows for the entire mailbox lifetime

`LiveMailbox` keeps a separate `settled` set, and `settle()` inserts every acknowledged delivery ID:

`live_mailbox.rs:739-755`.

Because IDs are monotonically allocated, this does not need to be an unbounded set.

A cleaner design is:

```text
next_delivery
+
outstanding IDs
```

where any previously minted ID not outstanding is known to have settled.

Not a release blocker, but unnecessary long-lived memory.

---

## C3 — Production `expect()` remains at synchronization boundaries

Examples:

* `live_mailbox.rs:422` — mailbox channel mutex;
* `live_mailbox.rs:646` — channel swap;
* `serving.rs:175`, `184`, `414` — serving mirror mutex.

The mutation queue deliberately handles poisoning correctly:

`mutation.rs:410-417`. 

The FUSE-facing code also has explicit error mapping to EIO.

The remaining `expect()` calls therefore stand out. A poisoned synchronization mutex is a local invariant failure, not ordinary input, so this is not automatically exploitable. But the stated release philosophy is fail-closed rather than process-panic.

I would convert production lock poisoning to explicit error propagation where feasible.

---

## C4 — Flat-directory lookup remains linear

`wyrd-fuse/src/view/drive.rs` resolves a component by iterating the decoded tree entries.

That matches the deliberately chosen flat-directory v0 format, which explicitly accepts fully materialized flat directories. `object-model.md` documents this tradeoff.

So this is **not a correctness finding**.

It becomes relevant at the upper v0 tree limits because lookup/readdir repeatedly pays decode + linear search costs.

This is a known architectural v0 tradeoff rather than a blocker.

---

# 4. Normative contract review

## `object-model.md`

### Found implemented/tested

The important format invariants are well represented:

* ContentId/ObjectKind separation;
* canonical tree ordering;
* duplicate component rejection;
* invalid path components;
* canonical exec byte;
* bounded decoder allocation;
* ContentId verification;
* snapshot canonical encoding;
* immutable snapshot model;
* explicit epoch/membership binding;
* manifest canonicality;
* transport-root separation.

The tree decoder, for example, caps its initial vector allocation rather than trusting a hostile `u32` count:

`wyrd-format/src/tree.rs:266-270`.

Chunk-count byte length is checked before extracting the IDs:

`tree.rs:309-315`.

That is exactly the sort of defensive parsing I wanted to see.

---

# 5. `trust.md` / cryptographic review

The core cryptographic construction is one of the cleaner portions of the code.

### Clean

* BIP-340 delegated to `secp256k1`;
* no hand-written curve arithmetic;
* AEAD centralized in `keys/aead.rs`;
* XChaCha20-Poly1305;
* explicit AAD;
* zeroizing secret wrappers;
* separate identity/encryption secret types;
* DriveRootKey absent from ordinary capabilities;
* epoch secrets independently random;
* capabilities AAD-bound to drive/device/encryption key/transition/epoch;
* monotonic capability installation;
* capability recipient mismatch tests;
* capability replay tests;
* superseded encryption-key tests.

`keys/aead.rs:1-52` is particularly straightforward: one seal/open implementation and zeroizing plaintext output.

The identity wrappers use `ZeroizeOnDrop` and redact `Debug`:

`keys/device.rs:19-38`.

I found no evidence in the supplied code of Wyrd implementing its own cryptographic primitive.

### KDF feature

The root uses Cargo resolver 2, and the insecure KDF is only enabled through dev-dependencies in the daemon/contracts crates.

The production dependency declarations do **not** enable it by default.

So I do **not** find evidence that `insecure-fast-kdf` leaks into an ordinary release dependency graph.

Caveat: commands such as test/all-target builds intentionally enable the feature. That is appropriate for test speed, but the release pipeline should build the actual release artifact with production/default features and preferably assert the feature graph.

---

# 6. Epoch/membership state machine

This area looks substantially covered.

The conformance suite exercises:

* genesis;
* duplicate genesis;
* predecessor validation;
* epoch gaps;
* author-before-transition authority;
* removal;
* terminal zero-owner state;
* owner constraints;
* rotate;
* conflict detection;
* resolution;
* contradictory resolution;
* orphaning;
* arrival-order independence.

Snapshot authorization tests also cover:

* bad signature;
* wrong drive;
* invalid author key;
* unknown membership;
* orphaned membership;
* contested membership;
* superseded heads;
* stranded heads;
* recovery;
* recovery-authority checks;
* unknown parents;
* multi-head behavior.

That is an unusually good state-machine test surface for an alpha.

I did **not** find a current cryptographic authorization bypass in this area.

---

# 7. Fetch/read path

The fetch architecture is substantially sound.

The iroh bulk path correctly does:

```text
connect
→ get_verified_size
→ reject if > max
→ bounded stream
→ verify transport
→ hand bytes to engine
```

`wyrd-sync/src/bulk.rs:313-338`.

The stream accumulator additionally checks every leaf against remaining budget:

`bulk.rs:363-384`.

That is the correct hash/size-before-allocation discipline.

The fetch-on-open design also has:

* explicit want registry;
* bounded waits;
* EIO on expiry;
* RemoteOnly/Fetching/Unavailable/Corrupt distinctions.

I found no new concrete fetch-allocation bug in this review.

---

# 8. Write path

The mounted write implementation is largely aligned with `write-path.md`.

Verified in code/tests:

* whole-file logical image;
* bounded per-handle image;
* aggregate budget;
* dirty-handle count;
* `ENOSPC`;
* `EFBIG`;
* `O_APPEND`;
* `O_TRUNC`;
* `O_SYNC`;
* stale handle → EIO;
* no snapshot for clean flush;
* descriptor stability;
* release best-effort semantics;
* serialized mutation queue;
* no network wait while holding the view/store lock.

The budget implementation is particularly well bounded: `session.rs:111-132` refuses handle/aggregate/dirty-handle excess and keeps accounting unchanged on refusal.

I therefore **do not** find the earlier feared write-buffer budget hole in the current code.

The remaining write-path blocker is the missing durable announcement obligation, not local snapshot construction.

---

# 9. Mount attack surface

### Clean

I checked the important pieces:

* `.` and `..` rejected by format components;
* NUL rejected;
* path depth bounded;
* absolute/escaping symlink targets confined;
* symlinks are never followed by Wyrd's tree resolver;
* escaping symlink returns EACCES;
* synthetic ownership is explicit;
* modes are synthesized according to the v0 contract;
* internal errors generally map to EIO;
* inode numbers are retired rather than reused across kind changes;
* open descriptors capture their content;
* `statfs` uses nonzero bounded synthetic capacity.

The symlink boundary is particularly clear at `wyrd-daemon/src/fuse.rs:2214-2223`.

I did not find a current `..`/absolute-target escape in the mounted surface.

---

# 10. Dependency architecture

The dependency arrows are correct in the supplied manifests:

```text
wyrd-format
    ↑
wyrd-sync
    ↑
wyrd-daemon
    ↑
FUSE presentation
```

and:

```text
wyrd-fuse
    → wyrd-format
```

with no iroh dependency in `wyrd-fuse`.

The root also explicitly denies unsafe code by default and makes the verified-head capability boundary an explicit exception.

I found no architecture violation where iroh leaked into `wyrd-format` or `wyrd-fuse`.

---

# 11. Test-gap assessment by crate

## `wyrd-format`

**Most important remaining untested behavior:** hostile/persistent filesystem-store failure sequences beyond the existing injected directory-fsync tests.

The current suite is already strong around:

* reopen;
* corruption;
* verified insertion;
* directory fsync failure;
* concurrent insertion;
* stale temp cleanup.

So this is not a blocker.

## `wyrd-sync`

**Most important remaining gap:** real external transport interoperability and crash/restart semantics of the future announcement obligation.

The state machines themselves have the strongest coverage in the repository.

## `wyrd-fuse`

**Most important remaining gap:** actual kernel-level mount behavior.

The mount-free view is well tested, but the boundary between the Rust backend and real FUSE/macFUSE behavior is inherently difficult to establish from unit tests.

## `wyrd-daemon`

**Most important gap:** lifecycle failure tests.

Specifically:

```text
FUSE session dies
live loop is still running
mutation caller is blocked
live loop reaches terminal error
daemon shutdown
```

There is currently no contract proving all of those actors terminate without stranded callers.

## `wyrd-contracts`

**Most important gap:** resource-exhaustion and lifecycle contracts.

The suite has 16 named cross-crate contracts and good architectural coverage, but the three mailbox resource issues and the FUSE/live-loop lifecycle issue are exactly the sort of properties that should become named contracts before release.

---

# 12. Documentation contradictions

There is also straightforward release-documentation drift.

`README.md:66` says Wyrd is already a **read-write FUSE mount**, while `README.md:137` still says:

> "there is no mountable drive yet."

That is plainly stale. `README.md:94-97` and `168-169` also describe the read-write mount as implemented.

`ROADMAP.md:51-68` says Phase 2 shipped and the write path landed, but `ROADMAP.md:120-137` still lists write support as upcoming.

This isn't a security defect, but it matters for an alpha because users and release automation will otherwise get contradictory statements about what is actually supported.

---

# What I specifically found clean

I checked these rather than assuming them:

* **ContentId vs StorageId separation** — clean.
* **Canonical tree parsing** — clean.
* **Canonical snapshot parsing/signing inputs** — clean.
* **BIP-340 delegated to audited dependency** — clean.
* **AEAD centralized/AAD-bound** — clean.
* **Epoch secrets independently generated** — clean.
* **Capability recipient/drive/transition binding** — clean.
* **Monotonic capability installation** — clean.
* **Membership conflict semantics** — substantially covered.
* **Snapshot historical-vs-current authorization distinction** — substantially covered.
* **Stale/superseded/stranded head classification** — substantially covered.
* **Manifest/tree closure verifier itself** — present and meaningfully tested.
* **Transport-root verification and bounded iroh fetches** — clean.
* **Object-store corruption detection** — clean.
* **Object-store post-rename durability reconciliation** — clean.
* **FUSE path grammar/depth** — clean.
* **Symlink confinement** — clean.
* **Synthetic ownership/modes** — aligned with v0 design.
* **FUSE open-handle stability** — explicitly contract-tested.
* **Write budgets and errno mapping** — well covered.
* **Mutation ordering** — explicit and tested.
* **Poisoned mutation queue lock recovery** — clean.
* **Normal production dependency direction** — clean.
* **`insecure-fast-kdf` absent from ordinary production dependencies** — clean, with the release-build caveat above.
* **No evidence of GC or mutable snapshot rewriting** — consistent with the append-only design.

---

# Required pre-alpha exit list

I would make the release gate:

### Must fix

* [ ] **Bound `LiveMailbox.unacked`**
* [ ] **Bound mailbox event/ciphertext/decrypted payload before expensive allocation**
* [ ] **Put a bounded retention policy around mailbox dedupe**
* [ ] **Implement durable announcement outbox**
* [ ] **Make live-head closure verification all-or-nothing**
* [ ] **Make FUSE/session/live-loop lifecycle supervised and terminate mutation waiters on shutdown**

### Strongly recommended before announcement

* [ ] Resolve the NIP-46/local-nsec normative contradiction.
* [ ] Demonstrate fresh-device admission → membership state → current-head discovery → historical synchronization.
* [ ] Run at least one real external Nostr relay interoperability test.
* [ ] Audit the vendored `fuser` tree against upstream 0.18.0.
* [ ] Verify the actual `Cargo.lock` against the manifest pins.
* [ ] Add explicit mailbox resource-exhaustion contracts.
* [ ] Add daemon lifecycle contracts.
* [ ] Clean stale README/ROADMAP claims.

## Final release decision

**NO-GO.**

The blockers are not theoretical architectural nitpicks. Three are remotely triggerable resource-exhaustion paths, one breaks a stated crash-durability guarantee, one can silently alter the mounted namespace after corruption, and one leaves the daemon lifecycle unsupervised.

The good news, from a release-engineering perspective, is that I **would not reopen the cryptographic/state-machine architecture based on this review**. The highest-value work now is to finish the boundaries around the already-solid core: **bounded mailbox → durable outbox → atomic projection → supervised lifecycle**.


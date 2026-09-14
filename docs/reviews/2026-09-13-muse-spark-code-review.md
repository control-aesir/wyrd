# Wyrd full codebase review — 2026-09-13 (Muse Spark)

Reviewer: Muse Spark (`muse-spark-1.3-contributor-free`), via OpenCode agent.
Scope: repository root `/Users/thomas/workspace/control/wyrd`, all five crates
(`wyrd-format`, `wyrd-sync`, `wyrd-fuse`, `wyrd-daemon`, `wyrd-contracts`),
`docs/` normative contracts, workspace lints/build/test/clippy as observable
from this machine. Prior reviews in `docs/reviews/` were read first; findings
below re-verify them against current code rather than repeating them blindly.
Where a prior P1 is fixed, that is stated explicitly.

Short version: the protocol core remains the strongest part of this codebase
and should not be redesigned. One prior P1 (symlink confinement) has been
fixed well. Four prior P1/P2 classes are still open in current code
(mailbox retry/size/ledger bounds, manifest-tree closure, recursive authoring,
vault dir-fsync), plus one new drift worth fixing promptly (resolved iroh
1.1.0 vs the documented 1.0.3 set). Nothing below suggests a crypto
redesign; almost everything is at the boundary where a clean state machine
meets unbounded real-world input, plus maintainability pressure from three
files over 2,200 lines.

## 1. Overall assessment

| Area | Verdict |
|---|---|
| Architecture / crate boundaries | Strong, compliant (one drift, see 4.1) |
| Cryptography (constructions, key hierarchy) | Strong, no redesign warranted |
| Membership / authorization state machines | Strongest part of the system |
| Durable commit / replay | Strong |
| FUSE view semantics | Good, one prior P1 now fixed |
| Live mailbox / network boundary | Needs work before hostile exposure (unchanged) |
| Manifest snapshot-tree binding | Incomplete (unchanged, explicitly documented in code) |
| Scalability (large history / large dirs) | Needs index work before v1-scale libraries |
| Tests for protocol correctness | Very good |
| Tests for adversarial resource use | Incomplete |
| Code quality / docs | Excellent, best-in-class comments for pre-alpha |
| Maintainability (file sizes, duplication) | Shows early strain in 3 files |

Test evidence from this machine: `cargo test -p wyrd-format -p wyrd-fuse`
gives 119 + 30 passing; `cargo test -p wyrd-format -p wyrd-sync -p wyrd-fuse`
gives 385 passing in `wyrd-sync` alone, 0 failures throughout, plus doctests
passing. `cargo clippy -p wyrd-format -p wyrd-sync -p wyrd-fuse --all-targets`
is clean. `wyrd-daemon` and `wyrd-contracts` could not be built here because
the system `fuse` library is missing (`fuser` build script fails on
`pkg-config --libs --cflags fuse`), so daemon/contracts clippy and tests are
explicitly unverified in this review, not claimed clean.

## 2. Potential bugs and edge cases

Ordered by severity. All paths verified by reading current source.

### P1a. `LiveMailbox.unacked` is still unbounded (still open)

- `crates/wyrd-daemon/src/live_mailbox.rs:288` declares
  `unacked: VecDeque<Held>`.
- `crates/wyrd-daemon/src/live_mailbox.rs:704-733` (`recv`) pushes every
  new, non-duplicate, well-formed wrap into `unacked` with no length check.
- `crates/wyrd-daemon/src/live_mailbox.rs:736-758` (`settle`) removes on
  `Ack` only; `Retry` deliberately leaves the entry held, and `recv`
  round-robins held entries.
- `INCOMING_CAPACITY = 1024` at `live_mailbox.rs:109` bounds the Tokio
  notification channel, not `unacked`.

The engine side did gain a bound (`MAX_PENDING_MESSAGES = 1024` in
`crates/wyrd-sync/src/runtime/engine.rs:183`, with shed-without-consume
semantics in `crates/wyrd-sync/src/runtime/intake.rs:18-44`), but that
bounds `Engine.pending`, not mailbox `unacked`. An attacker sending many
unique syntactically-valid wraps whose Wyrd payloads are `Skipped`
(unknown epoch) or `Deferred` keeps every one of them in daemon memory.
The module docs acknowledge the surrounding tradeoff
(`live_mailbox.rs:41-46`) but do not bound this deque.

Recommendation: bound `unacked` explicitly and define the overflow
semantic (shed held mail back to relay history without acking it, mirroring
the engine's `RelayHeld` shedding), plus a regression test with
`MAX + N` unique unknown-epoch wraps asserting bounded memory/state.

### P1b. Mailbox payload size is still enforced too late (still open)

- `live_mailbox.rs:41-46` states payload bounds are not enforced in the
  mailbox and deferred to engine ingest limits.
- `crates/wyrd-sync/src/transport/mailbox.rs:108-121` (`open_from_sender`)
  NIP-44-decrypts the full outer ciphertext before
  `ControlInbox::ingest` ever sees it; `SealedControl::decode` then
  copies the inner ciphertext into a `Vec`.
- `INCOMING_CAPACITY` bounds event count, not event byte size.

A huge but validly-encrypted NIP-44 message therefore allocates and
decrypts before any Wyrd length check fires. Add a mailbox-level
ciphertext/plaintext ceiling before decrypt/decode (relay event size,
then NIP-44 size, then Wyrd envelope size, then semantic limits), and a
test with one oversized outer ciphertext asserting early rejection
without unbounded allocation.

### P1c. Durable seen-log grows without bound on poison (still open)

- `live_mailbox.rs:168-184` documents the seen log as append-only and
  never compacted in v0; `SeenStore::record` at `live_mailbox.rs:233-241`
  appends plus `sync_data` per ack.
- `crates/wyrd-sync/src/runtime/intake.rs:90-119` maps unopenable outer
  seals and undecodable payloads under a held key to `Outcome::Discarded`,
  and `drain` at `intake.rs:80-83` settles those as `Ack`.

Every unique poison wrap therefore costs one permanent line on disk and
one permanent in-memory `HashSet` entry. Distinguish durable consume of
a processed Wyrd message from relay-level discard of terminal garbage
(e.g. ack-without-retain, or a bounded negative cache), and consider
whether durable dedupe should key on Wyrd `ControlMessageId`
(`crates/wyrd-sync/src/control/mod.rs:99-114`) rather than the NIP-59
wrapper `EventId`. At minimum, name the retention policy: "unbounded
growth, compaction tracked" is currently documentation, not a policy.

### P2a. Manifest-tree correspondence is still explicitly unchecked (still open, documented)

`crates/wyrd-sync/src/runtime/fetch.rs:40-52` states the gap plainly:
fetch verifies same-snapshot binding, ContentId, AEAD, StorageId, and
transport root, but "does *not* check ... that the manifest's entries
describe the snapshot's tree". `DriveView` (`crates/wyrd-fuse/src/view/drive.rs:11-16`)
serves trees without seeing manifests by design, so no consumer today
holds both sides. The comment says the cross-check "lands with the
daemon that composes sync and fuse", but no such verifier was found in
this review. A malicious member can therefore serve a cryptographically
valid snapshot plus a valid manifest for a different tree, yielding a
valid-but-unreadable replica (availability/integrity, not
confidentiality loss).

Recommendation: add `verify_snapshot_manifest(snapshot, tree, manifests)`
as a named security boundary; check logical ContentId-set correspondence
(exact representation correspondence is not required given cross-epoch
representations), file sizes, kinds, and child-manifest/tree linkage.

### P2b. `ManifestAuthor::walk` is still recursive (still open)

`crates/wyrd-sync/src/runtime/author.rs:187` recurses at line 210 per
directory level. The membership chain walk (`crates/wyrd-sync/src/membership/chain.rs:271-316`)
and the classifier were deliberately made iterative, and the FUSE
`resolve_one` path documents why recursion is avoided there
(`crates/wyrd-fuse/src/view/drive.rs:299-303`). Imported tree depth is
not globally bounded by ingest limits in a way that protects the local
authoring stack. Convert to an explicit heap `Vec<WalkFrame>` DFS or
impose and enforce a maximum tree depth at authoring time.

Note the contrast that makes this actionable rather than theoretical:
`wyrd-format` mutation recursion (`crates/wyrd-format/src/mutation.rs:254-296`)
is bounded by `MAX_PATH_DEPTH = 256` (`mutation.rs:35`), but authoring
walks content-addressed trees of arbitrary depth, not caller-supplied
paths.

### P2c. Vault import still skips the directory fsync (still open)

`crates/wyrd-sync/src/serving.rs:114-139` does file `sync_all` then
`rename`, with no containing-directory fsync. The two sibling crash
protocols both fsync the directory: `FsObjectStore::atomic_write`
(`crates/wyrd-format/src/fs_store.rs:157-174`) and
`DurableStore::atomic_write` (`crates/wyrd-sync/src/durable/store.rs:79-87`).
The ciphertext is durable while its directory entry may not be across
power loss. Factor one shared private durability helper rather than
keeping three subtly different crash protocols.

### P2d. Release builds can encode non-canonical manifests/snapshots (still open)

- `crates/wyrd-format/src/manifest.rs:176-188`: sortedness is
  `debug_assert` only; release encodes anyway.
- `crates/wyrd-format/src/snapshot.rs:87-90`: `Snapshot::new` reserved-flag
  hygiene is `debug_assert` only.

Decoders correctly reject the output, so this is not a forgery path, but
it is a footgun API: `canonical_bytes()` can produce bytes Wyrd itself
refuses. Prefer `Manifest::from_parts(...) -> Result<_, _>` as the
invariant-preserving constructor, or return `Result` from
`canonical_bytes()`. The workaround in `seal.rs:181` (which calls
`manifest.canonical_bytes()` before sealing) then cannot seal garbage.

### P2e. `u32` length casts in encoders can truncate (new, low practical severity)

- `crates/wyrd-format/src/tree.rs:191` (`entries.len() as u32`),
  `tree.rs:200` (`name.len() as u32`), `tree.rs:210`,
  `crates/wyrd-format/src/manifest.rs:192-197`,
  `crates/wyrd-format/src/snapshot.rs:117`.

Decode paths bound counts via `Limits::V0` and pre-allocation caps, but
encode paths cast `usize` to `u32` without checking. Reaching truncation
requires gigabytes of entries in one object (practically unreachable
today, and ingest limits would reject the result on decode), but the
correct pattern is a checked conversion or debug assertion at the cast.
Cheap to fix, removes a latent corrupt-encoding path from local
authoring.

### P3a. FUSE read path has no path-depth bound (new)

`wyrd-format` rejects paths deeper than 256 components
(`mutation.rs:223-241`), but the serving path
`crates/wyrd-fuse/src/view/drive.rs:436-446` accepts arbitrary depth.
`resolve_one` is iterative so there is no stack risk, yet each level
costs a store lock plus tree decode (`drive.rs:356-362`). A pathological
FUSE-supplied path is therefore a CPU/IO amplification input. Bound it
(the same 256 is the obvious shared constant) or document why serving
intentionally accepts deeper paths than mutation can author.

There are also two `parse_path` implementations with different semantics
(`mutation.rs:223` strict with depth bound vs `drive.rs:436` leading-slash
tolerant without one). Unify them or name the difference; two path
grammars is how traversal bugs start.

### P3b. Inconsistent lock-poison policy between view and daemon (new)

`DriveView::store_read/store_write` (`drive.rs:66-78`) maps a poisoned
`RwLock` to `ViewError::Store` (fail closed). Daemon code in the same
trust domain panics instead: `live_mailbox.rs:422`
(`.expect("mailbox channel lock")`), `serving.rs:136`
(`.expect("vault mirror lock")`), `live_mailbox.rs:716-719`
(`.expect("delivery id space exhausted")`). Poison means "a thread
panicked mid-critical-section"; serving threads should fail the
operation, not the process. The `u64` delivery-id exhaustion expect is
practically unreachable, but returning `MailboxError::Transport` costs
nothing and removes a panic from review scope.

### P3c. `fuser` build dependency makes contracts untestable without system FUSE (new/operational)

`crates/wyrd-contracts/Cargo.toml:11` depends on `wyrd-daemon`, which
depends on `fuser`, and contracts dev-depends on `fuser` directly. On a
machine without `fuse.pc` (this Mac), neither daemon nor contracts builds,
so the architectural contract suite cannot run. If `devenv` is supposed
to provide `fuse`, verify it; otherwise consider gating the actual mount
code behind a feature so `wyrd-contracts` and the daemon's
presentation-agnostic core remain testable everywhere. At minimum,
document the system prerequisite next to the `cargo nextest run`
instruction in `AGENTS.md`.

## 3. Code quality (style, readability, maintainability)

This is a genuinely well-written codebase. Module docs state the invariant,
the decided property, and the non-goal before the code; error enums are
specific (`IngestError`, `SealError`, `CapabilityError`, `BudgetError`,
`WantError`, `ConfinementError`); `thiserror` is used consistently; no
`anyhow` leakage into libraries was observed; `unsafe_code = "deny"` at the
workspace with explicit, commented `#[allow(unsafe_code)]` exceptions
(`crates/wyrd-daemon/src/core.rs:51-52`,
`crates/wyrd-daemon/src/main.rs:250`,
`crates/wyrd-fuse/src/view/head.rs:6-17`) matches the documented policy and
is greppable. Comments describe how code is used, not line-by-line what it
does, per repo convention.

Maintainability pressures, all fixable without redesign:

- Three files exceed 2,200 lines and own too many concerns:
  `crates/wyrd-daemon/src/core.rs` (2,849), `crates/wyrd-daemon/src/fuse.rs`
  (2,809), `crates/wyrd-sync/src/runtime/engine.rs` (2,243). The next
  splits suggest themselves: `core.rs` (live loop vs handle/session
  management), `fuse.rs` (read backend vs write backend vs tests),
  `engine.rs` (intake vs authoring vs bootstrap vs reporting already exist
  as modules; move more methods out of the inherent impl).
- The `.expect("bounds checked")` idiom after explicit `need()` checks
  (`manifest.rs:152-157`, `tree.rs:240`, `seal.rs:91`) is sound but noisy;
  a `read_u32le`/`read_array::<N>` helper returning `Result` would remove
  dozens of expects from audit scope.
- `merge.rs:14-41` clones every `Node` (including chunk-id vectors) to
  compare them. Fine today; for conflicted large directories consider
  comparing by reference or by subtree id before cloning.
- `Snapshot::new` takes seven arguments with an `#[allow(clippy::too_many_arguments)]`
  (`snapshot.rs:77`). A builder or params struct would read better and
  remove the allow.
- Test modules are large but disciplined; production/test separation via
  `#[cfg(test)]` and `test_util` modules is consistent.

## 4. Architecture guideline compliance (`docs/...`)

Compliant with two exceptions.

What complies:

- `wyrd-format` depends only on `blake3`, `fastcdc`, `hex`, `thiserror`
  (`crates/wyrd-format/Cargo.toml:7-11`): no networking, async, or FUSE.
  Plaintext/ciphertext split is respected; `ContentId`/`StorageId` are
  distinct types (`identity.rs:71-100`), `SnapshotId`/`TransitionId`
  likewise.
- `wyrd-fuse` depends only on `wyrd-format` + `thiserror`
  (`crates/wyrd-fuse/Cargo.toml:7-9`): no iroh knowledge. The mount-free
  view plus daemon FUSE adapter matches `architecture.md`'s composer
  model, and `projection.rs:1-23` explicitly keeps the core liftable for
  mobile surfaces.
- `wyrd-contracts` is a workspace leaf depending on everything and
  depended on by nothing: correct.
- Snapshot/membership/epoch semantics observed in code match
  `object-model.md`, `trust.md`, and `epochs.md`: drive-bound signatures,
  `epoch == membership.epoch` checked by the authorization engine rather
  than decode (`snapshot.rs:19-21`), deterministic BIP-340 nonces,
  fresh random epoch secrets with escrow (not derivation), monotonic
  capability install (`keys/capability/model.rs:19-22`), unknown-epoch
  vs poison distinction in intake.
- Canonical-encoding rules, `Limits::V0` calibration
  (`ingest.rs:67-92`), and the transport-root column (decision 26) are
  consistently applied from format through bulk through fetch.

### 4.1. Exception 1 — resolved iroh set has drifted from the pinned set

`Cargo.toml:60-63` pins the validated set as iroh 1.0.3 /
iroh-blobs 0.103.0 / iroh-gossip 0.101.0 with "change all three together
and test". `Cargo.lock` in this checkout resolves `iroh` to 1.1.0
(observed in build output as `iroh v1.1.0`, `iroh-relay v1.1.0`). Caret
semantics allowed the drift. Either re-pin exact versions (and the
`bao-tree`/`bytes`/`n0-future` companions noted at `Cargo.toml:64-69`) or
update the documented set and re-validate; a silently drifted transport
set defeats the "validated as a set" rule.

### 4.2. Exception 2 — `envelope.rs` docs omit the manifest kind

`crates/wyrd-format/src/envelope.rs:10` and the kind table document only
`0x00 chunk | 0x01 tree | 0x02 snapshot`, while `identity.rs:48-68`
defines `Manifest = 0x03` and `fs_store.rs:77-82` stores it. The code
accepts `0x03` via `ObjectKind::from_byte`; the envelope doc is stale.
One-line doc fix; while there, state whether sealed manifests ever ride
the typed envelope or are always `EncryptedObject` + `StorageId`
(decision 22), since today's reader can infer either.

### 4.3. Roadmap vs normative docs (unchanged from prior review)

`ROADMAP.md:65-74` marks "Phase 3: Recovery Completion — shipped"
(root recovery, historical restoration, recovery snapshot creation),
while `trust.md` still reserves recovery as post-v0 and the code contains
escrow primitives plus bootstrap handling rather than guardian/Shamir
reconstruction. Rename the roadmap item to "Recovery foundations —
shipped" with the workflow items explicitly unshipped, as the prior
review recommended. Security docs must not imply root-loss recovery is
operational.

## 5. Test coverage observations

Counts from this machine: `wyrd-format` 119 passed, `wyrd-fuse` 30
passed, `wyrd-sync` 385 passed, 0 failed; doctests pass. Daemon and
contracts tests could not run here (missing system FUSE; see 2.P3c), so
their coverage is assessed by inspection, not execution.

Strong areas (keep): membership conformance suites per `epochs.md`,
authorization conformance, property tests (`membership/properties.rs`,
`authorization/properties.rs`), fuzz decoders (`sync/src/fuzz.rs`),
durable crash-stage injection (`durable/store.rs:21-41`), capability
replay/monotonicity tests, transport-root fallback tests, FUSE
descriptor-stability tests, mailbox reconnect tests, queue-pressure tests
(`intake::tests::pending_holds_are_bounded`,
`overflowed_hold_survives_queue_pressure`), write-budget and want-registry
saturation tests.

Gaps (all measurable boundedness/closure properties, not happy paths):

1. Mailbox adversarial bounds: oversized outer ciphertext, 100k
   unknown-epoch wraps, 100k poison wraps — assert bounded `unacked`,
   bounded allocation pre-ingest, bounded seen-log.
2. Authoring depth: 10k-deep tree through `ManifestAuthor::walk`
   (membership already has the analogous depth test; authoring does not).
3. Directory scale: 1M-entry lookup latency and merged-`readdir` cost;
   asserts the binary-search fix from 7.2.
4. Manifest-tree closure: valid snapshot + valid-but-mismatched manifest
   must not yield a servable replica.
5. Symlink escape at the mount boundary: absolute + `..`-escape targets
   through the real `readlink` path (`daemon/src/fuse.rs:1752,2055`),
   not just `confine_symlink_target` unit tests.
6. Vault crash test: power loss between file `sync_all` and directory
   fsync must not lose the publication (fails today by construction).
7. `u32`-cast and `parse_path` divergence tests if 2.P2e/2.P3a are fixed.

## 6. Clippy warnings and suggestions

- `cargo clippy -p wyrd-format -p wyrd-sync -p wyrd-fuse --all-targets`:
  clean on this machine (no warnings emitted).
- `wyrd-daemon` / `wyrd-contracts` clippy: not runnable here (system
  `fuse` missing; `fuser` build script exits 101). Do not interpret the
  clean result above as workspace-clean. Run
  `cargo clippy --workspace --all-targets` inside `devenv shell` (or
  wherever `fuse.pc` exists) before merging review-driven fixes.
- Existing `#[allow(clippy::...)]` occurrences are narrow and justified
  (`Snapshot::new` arity, `enum_variant_names` in classify, Dead-code
  `CrashStage` outside `cfg(test)` with a comment explaining the single
  entry point). No blanket allows observed.
- Suggested future lints (not enabled today, no action required now):
  `clippy::checked_conversions` would have caught 2.P2e at the cast
  sites; `clippy::len_without_is_empty`/`clippy::too_many_arguments`
  already fire where useful.

## 7. Performance considerations

No benchmarks were run; all complexity claims are from code reading.

1. `recorded_mappings` is `O(all recorded manifest entries)` per chunk
   (`runtime/mod.rs:369-376`), called per chunk during authoring
   (`author.rs:268`). `reconcile` (`runtime/mod.rs:439-...)` re-walks all
   manifests and entries per pass. Both are correct for append-only v0
   but trend toward chunks-times-history. Maintain incremental indexes
   (`ContentId -> representations`, `SnapshotId -> root manifest`)
   before large long-lived libraries land. GC does not exist by design,
   so history never shrinks to hide this.
2. `resolve_one` is linear per component (`drive.rs:316-319`) over
   canonically sorted entries; `put_node` has the same linear find
   (`mutation.rs:275`). Expose `Tree::find(name) -> Option<&Entry>` via
   `binary_search_by` on the already-guaranteed sort order and use it on
   both paths. `readdir_union` multiplies the cost across heads.
3. `chunk::split` (`chunk.rs:35-46`) copies every chunk into a fresh
   `Vec` and `insert_chunks` stores again: roughly 2x transient memory
   per file plus hashing. Fine under `Limits::V0`, but large-file ingest
   should stream chunks rather than materializing the whole split.
4. `SeenStore::record` fsyncs per ack by design (`live_mailbox.rs:233-241`).
   Correct for low-rate control traffic; do not reuse this pattern for
   any high-rate path. Batching is noted as future work in the file.
5. `WantRegistry` waiters poll every 50ms (`want.rs:55`); mutation idle
   wait slices at 250ms (`mutation.rs:100`). Both are deliberate
   condvar-free designs; keep them off any hot path and revisit only
   with wakeup-loss analysis in hand.
6. `MAX_WRITE_BUFFER_BYTES = 64 MiB` per handle, 256 MiB aggregate, 64
   dirty handles (`session.rs:28-32`) are independent of `Limits::V0`
   yet interact at commit (whole-file rewrite model per `write-path.md`).
   The layering is documented correctly in `session.rs:15-18`; keep the
   two limit systems cross-referenced when either changes.

## 8. Specific improvements (file:line)

1. `crates/wyrd-sync/src/serving.rs:114-139` — add directory fsync after
   rename in `Vault::import` (reuse `fsync_dir` from `fs_store.rs:69` or
   `durable/store.rs:72`; ideally extract one shared helper).
2. `crates/wyrd-format/src/manifest.rs:176-188` — replace `debug_assert`
   sortedness with a fallible constructor or `Result`-returning
   `canonical_bytes`.
3. `crates/wyrd-format/src/snapshot.rs:87-90` — same for reserved-flag
   hygiene in `Snapshot::new`.
4. `crates/wyrd-sync/src/runtime/author.rs:187-254` — make `walk`
   iterative (heap `Vec<WalkFrame>`) or enforce a documented max tree
   depth with a dedicated error.
5. `crates/wyrd-fuse/src/view/drive.rs:316-319` and
   `crates/wyrd-format/src/mutation.rs:275` — binary search over sorted
   entries via a shared `Tree::find`.
6. `crates/wyrd-sync/src/runtime/mod.rs:369-376` — index
   `ContentId -> Vec<ManifestEntry>` incrementally; stop scanning all
   manifests per chunk.
7. `crates/wyrd-daemon/src/live_mailbox.rs:288,704-758` — bound `unacked`
   with relay-retained shedding; add the `MAX + N` regression test.
8. `crates/wyrd-daemon/src/live_mailbox.rs:41-46`,
   `crates/wyrd-sync/src/transport/mailbox.rs:108-121` — enforce
   outer-ciphertext and inner-plaintext ceilings before decrypt/decode.
9. `crates/wyrd-daemon/src/live_mailbox.rs:168-184,233-241` — bound the
   poison ledger (ack-without-retain or bounded negative cache; consider
   keying durable dedupe on `ControlMessageId`).
10. `crates/wyrd-sync/src/runtime/fetch.rs:40-52` — implement the
    snapshot-manifest closure verifier where sync and fuse compose.
11. `crates/wyrd-fuse/src/view/drive.rs:436-446` — bound serving path
    depth (share `MAX_PATH_DEPTH` from `mutation.rs:35`) and unify the
    two `parse_path` implementations.
12. `crates/wyrd-daemon/src/live_mailbox.rs:716-719`,
    `live_mailbox.rs:422`, `crates/wyrd-sync/src/serving.rs:136` —
    return errors instead of `.expect()` on poison/exhaustion paths.
13. `Cargo.toml:60-69`, `Cargo.lock` (iroh 1.1.0) — re-pin or re-validate
    the iroh set as a set; consider exact version pins so caret drift
    cannot silently invalidate the "validated set" claim.
14. `crates/wyrd-format/src/envelope.rs:10,48-49` — document kind `0x03`
    manifest and its relation to `EncryptedObject`.
15. `ROADMAP.md:65-74` — rename Phase 3 to foundations-shipped, workflow
    unshipped.
16. `AGENTS.md` commands section — document the system `fuse.pc`
    prerequisite (or feature-gate the mount code) so
    `cargo clippy --workspace` / `cargo nextest run` reproduce outside
    `devenv shell`.
17. `crates/wyrd-format/src/tree.rs:191,200`,
    `manifest.rs:192-197`, `snapshot.rs:117` — checked `u32`
    conversions at encode sites (enables `checked_conversions` later).
18. `crates/wyrd-daemon/src/core.rs` (2,849 lines),
    `crates/wyrd-daemon/src/fuse.rs` (2,809),
    `crates/wyrd-sync/src/runtime/engine.rs` (2,243) — split along the
    seams named in section 3.

## 9. What changed since the 2026-09-12 review (verification)

- Fixed and well done: symlink confinement. `confine_symlink_target`
  (`crates/wyrd-fuse/src/view/types.rs:138-157`) with `Absolute` /
  `EscapesRoot` errors, enforced at the daemon `readlink` boundary
  (`crates/wyrd-daemon/src/fuse.rs:2055`, documented at `fuse.rs:28-34`),
  plus unit tests (`view/tests.rs:580-619`). No trusted-drive opt-out in
  v0 is the right default.
- Partially mitigated: engine pending is now bounded with
  relay-retained shedding (`engine.rs:177-183`, `intake.rs:18-44`), but
  the mailbox `unacked` deque is not — P1a above is the remainder.
- Still open as written: P1b, P1c, manifest-tree closure, recursive
  `walk`, vault dir-fsync, `debug_assert` canonicality, roadmap recovery
  wording.
- New in this review: iroh lockfile drift, `u32` casts, serving
  path-depth bound, poison-policy inconsistency, contracts/fuser
  testability, file-size/duplication maintainability items.

## 10. Verdict

Architecture 8.5/10, crypto 9/10, state machines 9/10, persistence 8.5/10,
filesystem 8/10 (up from 7: symlink confinement landed), network boundary
5.5/10 (unchanged: the design is sound, the mailbox bounds are not),
scalability 6.5/10 (unchanged). Continue with the current architecture;
do not redesign. Gate hostile-network exposure on P1a-P1c plus the
mount-boundary regression tests, and take P2a (manifest closure) before
calling the snapshot protocol complete.

## 11. Cross-check against ngit issues (2026-09-13, 50 open + 1 closed)

Every finding above was looked up in the issue tracker. Most are already
tracked; four are not. No new issues were filed from this review.

### Tracked — direct match (open)

| Review finding | Issue |
|---|---|
| P2c vault dir-fsync (`serving.rs:114-139`) | `fix(sync): fsync the vault directory after publication`, bug P2 — nostr:nevent1qqsrlvt5900c44c8m9m05qgzjupl6cwk63ljw25lrpn6066ptgsxh2cpz9mhxue69uhkwunpwdczuap49eehgzk94pn |
| P2b recursive `ManifestAuthor::walk` (`author.rs:187`) | `fix(sync): make manifest authoring traversal stack-safe`, bug P2 — nostr:nevent1qqsxc5u26l4297t02za42fx8awxmee584kf54mrs4886hgt87p5v8hcpz9mhxue69uhkwunpwdczuap49eehgem53zz |
| P2a manifest-tree closure (`fetch.rs:40-52`) | `fix(sync): verify snapshot and manifest closure correspondence`, bug P2 — nostr:nevent1qqszmhz0l97jsafuyx7lazkv8lfpjg6852wcqdxunxxamhasehk5v5cpz9mhxue69uhkwunpwdczuap49eehg6rwdx4 |
| Roadmap recovery wording (`ROADMAP.md:65-74`) | `docs(roadmap): distinguish recovery foundations from recovery workflow`, chore P3 — nostr:nevent1qqs8y0jj4r3f7ad8wgzejnrmhr2ja0jq0w84vywgsggdq6yahp53w0spz9mhxue69uhkwunpwdczuap49eehgrq5s6a |
| P2d `Manifest::canonical_bytes` debug-only (`manifest.rs:176-188`) | `fix(format): make Manifest canonical encoding infallible by construction`, P2 — nostr:nevent1qqsfcjffum56ch5wmqdcx32sumkplx3z4aahwslmtppm5v2age5zf3cpz9mhxue69uhkwunpwdczuap49eehgvve0cy |
| P2d `Snapshot::new` debug-only (`snapshot.rs:87-90`) | `fix(format): fallible Snapshot construction for reserved flags`, P2 — nostr:nevent1qqsqrs7x6u788hx27vl0t8zasmeu8rzvdgrxk2xfxwvkv0mxz7t5m4cpz9mhxue69uhkwunpwdczuap49eehgcerekh |
| P2e `u32` casts in encoders | `fix(format): checked u32 length conversions across encoders`, P2 — nostr:nevent1qqsye7z8xy5jykzkfrzwnpr5kc6h90lh3xg2e837axgeqgvtq5ffpkqpz9mhxue69uhkwunpwdczuap49eehgr057l8 |
| Linear `resolve_one` (`drive.rs:316-319`) | `perf(fuse): binary-search canonical tree entries in path resolution`, P3 — nostr:nevent1qqsx6h0h9ztknvcyc6e76d5sgzymlednsp4vey4tmnqjl573qnpexzgpz9mhxue69uhkwunpwdczuap49eehgglwlpu |
| `recorded_mappings` / reconcile scaling (`runtime/mod.rs:369-376`) | `perf(sync): index deferred messages by dependency`, P2 — nostr:nevent1qqswfwgmqwa5mxaqa7hv6hl9m0drjzsejggrwxz2daan2s6r9muk58gpz9mhxue69uhkwunpwdczuap49eehgx6eln6 — plus `perf(sync): cache or incrementally advance the live-head projection`, P3 — nostr:nevent1qqsv5z8jrudzpuv8n4f367lrjp4xjvh6zlkszd4gen7d4ccyggs9cmspz9mhxue69uhkwunpwdczuap49eehgu4lj9x — plus `test(sync): add runtime property and scale coverage`, P3 — nostr:nevent1qqs84ag9eauuujjv5mld7a55kv05wxgfwlasnfhradfdqmfsz7ppznspz9mhxue69uhkwunpwdczuap49eehg93mpql |
| Duplicate `parse_path` / mutation traversal (`mutation.rs:223` vs `drive.rs:436`) | `perf(format): centralize mutation path traversal and bottom-up rebuild`, P4 — nostr:nevent1qqsvdcgpfvdkwvku0et0969mg45zwvzvszm73jfgfuectngrm0saycqpz9mhxue69uhkwunpwdczuap49eehgsn4x3e (covers the mutation.rs side; the serving-side depth bound in P3a is not mentioned there) |
| Poison-policy `.expect()` sites (sync side) | `refactor(sync): replace cross-call .expect() with typed errors`, P3 — nostr:nevent1qqs88eerqhfeeplddt8lrawuu2gucevducjfjdgta6zcaxg6ajaq6qqpz9mhxue69uhkwunpwdczuap49eehgr5efl3 (covers `plan.rs:49` / `intake.rs`; the daemon-side expects in P3b are not in scope there) |
| P1a/P1b/P1c mailbox bounds | Covered by `feat(daemon): add runtime resource limits and backpressure`, P2 — nostr:nevent1qqstrwjc4g4e9hsp2v4jspule4h9w4ujqdkysdt7umlh3txgk7s9k3qpz9mhxue69uhkwunpwdczuap49eehgdzy80r — whose comment explicitly names all three hazards (unbounded `unacked`, pre-ingest decrypt allocation, poison ledger growth) with 100k-delivery bounded-state acceptance tests. Tracked as one umbrella issue plus comment, not three separate issues. Related: `docs(sync): document control transport dedupe semantics`, P4 — nostr:nevent1qqsz0uk767zzggv7s08nhtykfrc8eqazmtwswwzmzm4u8fl4uv4rs8spz9mhxue69uhkwunpwdczuap49eehgj8l6aj, and `test(daemon): add production soak and crash-boundary coverage`, P2 — nostr:nevent1qqsg90w0hl364m2s5xs6enpslfcfajxjthghel7sn65a8z69qze7cvspz9mhxue69uhkwunpwdczuap49eehg4jzv2r. |
| Kind-byte `0x03` docs (object-model table) | `docs: object-model canonical encoding table omits Manifest 0x03`, P4 — nostr:nevent1qqs08pdjw2c7dlgwst2d87jje39k759zmkgcsv0n58fufh37gramgkcpz9mhxue69uhkwunpwdczuap49eehgvtju5m (covers the object-model table; the stale `envelope.rs:10` doc noted in 4.2 is the same one-row class of fix) |

### Tracked — fixed, no open issue (verified in code)

Symlink confinement (prior P1): `confine_symlink_target`
(`wyrd-fuse/src/view/types.rs:138-157`), enforced at the daemon
`readlink` boundary (`wyrd-daemon/src/fuse.rs:2055`), unit-tested
(`view/tests.rs:580-619`). No open issue mentions symlinks; nothing to
file.

### Not tracked — gaps worth filing (none filed by this review)

1. iroh version-set drift (4.1): `Cargo.toml:60-63` pins iroh 1.0.3 /
   blobs 0.103.0 / gossip 0.101.0 while `Cargo.lock` resolves iroh
   1.1.0. The open `chore: drop or defer the unused iroh-gossip
   dependency` (P4 —
   nostr:nevent1qqsqgvv76k54x2ngxg5papmkm72n80hq0vstat80gk9jrtkdtru7qrcpz9mhxue69uhkwunpwdczuap49eehgf6swmm)
   touches version-set discipline but not this drift. Suggest a
   re-pin-or-revalidate issue.
2. Serving path-depth bound (P3a): `drive.rs:436-446` accepts unbounded
   depth while `mutation.rs:35` caps authoring at 256. Not mentioned in
   the centralize-traversal issue.
3. Daemon-side `.expect()` on poison/exhaustion paths (P3b):
   `live_mailbox.rs:422`, `serving.rs:136`, `live_mailbox.rs:716-719`.
   The typed-errors issue is sync-runtime scoped.
4. `fuser` system dependency blocks daemon/contracts builds and tests
   outside an environment providing `fuse.pc` (P3c): document the
   prerequisite or feature-gate the mount code. No open issue found.

*Model: Muse Spark (`muse-spark`) — full codebase review, 2026-09-13.*

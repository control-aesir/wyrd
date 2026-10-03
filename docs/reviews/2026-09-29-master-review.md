# Wyrd master review - 2026-09-29

Reviewer: OpenCode agent (model: `opencode-go/longcat-2.5-preview-free`)

Review scope: `master` at `7295a81`, all seven workspace crates, the contract
suite, and the normative documents in `docs/`. Special attention to security,
crypto, and general bugs. Cross-referenced against the open ngit issue set.

## Verdict

**No critical vulnerabilities found.** The cryptographic foundations are sound:
domain-separated key derivation, AEAD everywhere with correct AAD binding,
monotonic capability install, deterministic BIP-340 with full key validation,
and the scrub invariant (stored bytes hash back to their address) is correctly
implemented. The membership state machine follows `epochs.md` faithfully.

> **Read this with the validation pass at the bottom of this file.** The
> counts below are the original model's and do not reconcile with its own
> findings list or crate table. One High and two of the seven Mediums do not
> survive checking, and two of the proposed fixes are actively unsafe. The
> findings text is preserved verbatim; the validation section records what
> holds.

The findings below are **1 high**, **7 medium**, and **22 low** severity. The
high-severity finding is a spec deviation in the write path. The medium
findings include a missing input validation on a cryptographic boundary, two
panic-on-invalid-input paths, and several test-hygiene issues. Most low
findings are performance concerns (O(n^2) walks, per-comparison allocations)
or 32-bit platform edge cases.

No new critical or high-severity security vulnerabilities were discovered beyond
what is already tracked in ngit.

---

## High-severity findings

### H1 - `AppendFile` uses wrong size limit constant

- **File**: `crates/wyrd-core/src/live.rs:1356`
- **Severity**: High (spec deviation)
- **Description**: The `AppendFile` mutation checks `total >
  MAX_WRITE_BUFFER_BYTES` (64 MiB), which is the per-handle write buffer
  limit, not the file size limit. `CommitFile` has no such check and relies
  on protocol ingest limits. This means a file larger than 64 MiB cannot be
  appended to through the mount, even if the protocol allows it. The check
  is also redundant with the protocol ingest limits that `Entry::file` and
  `author_snapshot` already enforce.
- **Spec**: `docs/write-path.md` says file size should be limited by protocol
  ingest limits (`Limits::V0`), not by `MAX_WRITE_BUFFER_BYTES`.
- **Fix**: Remove the `MAX_WRITE_BUFFER_BYTES` check from `AppendFile` and
  rely on protocol ingest limits, matching `CommitFile`'s behavior. Or use
  the correct protocol limit constant.
- **Tracked**: No matching ngit issue found.

---

## Medium-severity findings

### M1 - `Capability::new` does not validate `device` as a curve point

- **File**: `crates/wyrd-sync/src/keys/capability/model.rs:96-125`
- **Severity**: Medium (security)
- **Description**: `Capability::new` validates `encryption_key` as a curve
  point but does NOT validate `device` or `transition` as valid x-only
  pubkeys. A malformed device ID propagates into the keyring and AAD. While
  `DeviceId` is a 32-byte array, not all 32-byte arrays are valid secp256k1
  public keys. This is a missing validation on a cryptographic boundary.
- **Spec**: `trust.md` T14 implies device IDs are secp256k1 x-only pubkeys.
- **Fix**: Add `XOnlyPublicKey::from_slice(device.as_bytes()).is_err()`
  check alongside the encryption_key validation.
- **Tracked**: No matching ngit issue found.

### M2 - `PublicKey::from_byte_array` may panic on invalid input

- **File**: `crates/wyrd-core/src/mailbox/mod.rs:1433`
- **Severity**: Medium (panic on invalid input)
- **Description**: `send` calls
  `PublicKey::from_byte_array(*envelope.recipient.as_bytes())` without
  handling the `Result`. In nostr 0.45.5, this returns `Result<PublicKey,
  Error>`. If the recipient bytes are not a valid secp256k1 public key, this
  will panic. While `DeviceId` is a 32-byte array, not all 32-byte arrays
  are valid public keys.
- **Fix**: Handle the `Result` with `?` and map the error to
  `MailboxError::InvalidKey` or `MailboxError::Transport`.
- **Tracked**: Related to `chore(daemon): propagate lock poisoning instead
  of expect on live paths` (ngit issue with 1 comment).

### M3 - `establish_drainer` uses `expect` on channel readiness

- **File**: `crates/wyrd-core/src/mailbox/mod.rs:1083`
- **Severity**: Medium (panic path)
- **Description**: `ready_rx.await.expect("drainer task outlived its spawn")`
  will panic if the drainer task dies before sending readiness. A panic in
  the drainer task (e.g., from a bug in `drain_notifications`) would cause
  this `expect` to fire, crashing the entire mailbox.
- **Fix**: Return an error instead of panicking, allowing the caller to
  handle the failure gracefully.
- **Tracked**: Related to `chore(daemon): propagate lock poisoning instead
  of expect on live paths` (ngit issue with 1 comment).

### M4 - `set_size_at` submits mutation for non-existent path

- **File**: `crates/wyrd-daemon/src/fuse/backend.rs:1765-1795`
- **Severity**: Medium (correctness)
- **Description**: When `attr_at` fails (e.g., the path doesn't exist),
  `current` is set to `u64::MAX`. If `size != u64::MAX`, the code proceeds
  to submit a `SetAttrs` mutation that will fail with `NotFound`. This is a
  wasted submission and a confusing error path.
- **Fix**: Return the error from `attr_at` directly instead of using
  `unwrap_or(u64::MAX)`.
- **Tracked**: No matching ngit issue found.

### M5 - Deterministic BIP-340 nonces in test signing fixtures

- **File**: `crates/wyrd-contracts/src/support/signing.rs:69,77`
- **Severity**: Medium (test-only, but a dangerous pattern to normalize)
- **Description**: `sign_transition` and `sign_snapshot` use
  `sign_schnorr_no_aux_rand`, which produces deterministic nonces. In
  production, deterministic nonces for Schnorr signatures are a known
  vulnerability: nonce reuse across different messages leaks the private
  key. While this is test-only code with fixed keys, it establishes a
  pattern that could be copy-pasted into production code.
- **Fix**: Use `sign_schnorr` with a `rand::OsRng` auxiliary randomness
  source, or add a comment explicitly warning that this pattern must never
  be used in production.
- **Tracked**: No matching ngit issue found.

### M6 - Temp dir resource leak in `export_rejects_conflict_version_composed_escape`

- **File**: `crates/wyrd-fuse/src/view/tests.rs:713-737`
- **Severity**: Medium (test hygiene)
- **Description**: The test creates a temp dir and removes it at the end.
  If any assertion between those lines fails, the temp dir leaks. In a CI
  environment with many test runs, this can accumulate.
- **Fix**: Use a guard struct with `Drop` that removes the dir, or use the
  `tempfile` crate's `TempDir` which cleans up automatically.
- **Tracked**: No matching ngit issue found.

### M7 - Phase-two worker never joined in concurrency contract

- **File**: `crates/wyrd-contracts/src/fuse_contracts.rs:386-398`
- **Severity**: Medium (test reliability)
- **Description**: The phase-two publish worker is spawned but intentionally
  never joined. If the worker panics, the panic is silently swallowed and
  the test hangs until `recv_timeout` fires after 60 seconds, misreporting
  the failure as a deadlock rather than a panic.
- **Fix**: Have the worker send a `Result` on a channel before exiting, and
  check it after the loop. Or use `std::thread::scope`.
- **Tracked**: No matching ngit issue found.

---

## Low-severity findings

### Performance

| # | File:Line | Description |
|---|-----------|-------------|
| L1 | `wyrd-format/src/manifest.rs:136-142` | `sort_key` allocates a `Vec<u8>` per comparison during `sort_by_key`. |
| L2 | `wyrd-format/src/mutation.rs:440-465` | `resolve_entry` clones the entire tree at each path level. |
| L3 | `wyrd-format/src/mutation.rs:283,327,360,407,488` | Mutation helpers clone the entire tree at each recursion level. |
| L4 | `wyrd-sync/src/membership/chain.rs:499-563` | `classify_remaining` inheritance walk is O(n^2) worst case. |
| L5 | `wyrd-sync/src/membership/chain.rs:387-484` | `handle_conflict` iterates all grandchildren of all contenders. |
| L6 | `wyrd-sync/src/membership/mod.rs:365-379` | `is_retired` walks the entire canonical chain on every call. |
| L7 | `wyrd-core/src/mailbox/mod.rs:1502` | `settle` uses O(n) linear search for delivery lookup. |
| L8 | `wyrd-sync/src/durable/codec.rs:469` | `Vec::with_capacity(count.min(1024))` may cause reallocations for large commits. |
| L9 | `wyrd-sync/src/control/message.rs:318` | `Vec::with_capacity(n.min(1 << 20))` may cause reallocations for large capabilities. |

### Robustness

| # | File:Line | Description |
|---|-----------|-------------|
| L10 | `wyrd-format/src/identity.rs:200-202` | `u32_le` uses `.expect()` which could panic on overflow. |
| L11 | `wyrd-format/src/fs_store.rs:283-310` | `atomic_write` loop relies on `open()` being the only temp remover. |
| L12 | `wyrd-format/src/fs_store.rs:332-336` | `insert` reads entire file into memory for validation. |
| L13 | `wyrd-sync/src/bulk.rs:200-207` | `candidate_share` division could panic on u32 overflow (currently safe). |
| L14 | `wyrd-sync/src/keys/capability/model.rs:352` | Overflow error message is misleading (says "malformed" not "overflow"). |
| L15 | `wyrd-sync/src/serving.rs:869-899` | `ServingEndpoint::shutdown` doesn't explicitly await the drain task. |

### 32-bit platform edge cases

| # | File:Line | Description |
|---|-----------|-------------|
| L16 | `wyrd-daemon/src/fuse/backend.rs:2124` | `offset as usize` could truncate on 32-bit. |
| L17 | `wyrd-daemon/src/fuse/backend.rs:1282,1314` | `image[offset as usize..end]` could panic on 32-bit. |
| L18 | `wyrd-daemon/src/fuse/backend.rs:889-891` | `buffer[start..stop]` could panic on 32-bit. |

### Code quality

| # | File:Line | Description |
|---|-----------|-------------|
| L19 | `wyrd-fuse/src/view/drive.rs:374,386,404` | Store errors formatted with `Debug` may expose internal details. |
| L20 | `wyrd-contracts/src/layer_contracts.rs:420-458` | `check_core_nostr_scope` passes vacuously if source tree missing. |
| L21 | `wyrd-contracts/src/support/relay.rs:89-100` | `sealed_envelope` uses `.unwrap()` on fallible operations. |
| L22 | `wyrd-fuse/src/view/drive.rs:45-62` | Duplicate head conversion logic in `DriveView` constructors. |

---

## Positive observations

1. **Checked arithmetic everywhere**: All bounds checking uses `checked_add`
   and `checked_mul`, preventing integer overflow.
2. **Canonical encoding enforcement**: Decoders reject unsorted entries,
   duplicate components, trailing bytes, and invalid path components.
3. **Scrub invariant**: `FsObjectStore::get` verifies that stored bytes hash
   back to their ContentId, failing closed on corruption.
4. **Domain-separated hashing**: All identity derivations use BLAKE3
   `derive_key` with distinct context strings.
5. **Type-safe identities**: `ContentId`, `StorageId`, `SnapshotId`,
   `DriveId`, `DeviceId`, `TransitionId`, and `DeviceEncryptionKey` are
   distinct types, preventing accidental mixing.
6. **Crash-safe durability**: The `Durability` layer correctly implements
   temp+fsync+rename+dir-fsync, with pending-directory recovery.
7. **No unsafe code** in `wyrd-format`; the `VerifiedSnapshot` trait in
   `wyrd-fuse` is the only `unsafe` impl and is thoroughly documented.
8. **Comprehensive tests**: Every module has thorough unit tests covering
   round-trips, error cases, and edge cases.
9. **Credential file handling** in `wyrd-cli` is solid: `O_NOFOLLOW`,
   ownership checks, permission checks, bounded reads, zeroization.
10. **Resource limits** are well-enforced in the FUSE backend: open handle
    caps, write buffer limits, dirty handle limits, all with proper error
    mapping.

---

## Cross-reference with ngit issues

### Already tracked (no new issue needed)

| Ngit issue | Related finding |
|---|---|
| `chore(daemon): propagate lock poisoning instead of expect on live paths` | M2, M3 |
| `chore(tests): identify the intermittent nextest leaky verdict` | M6, M7 (test hygiene) |
| `perf(format): avoid allocation in ManifestEntry::sort_key` | L1 |
| `perf(sync): avoid repeated runtime rebuilds during plan execution` | L4, L5, L6 |
| `perf(fuse): index entries during readdir_union if large-directory or multi-head scans materialize` | L2, L3 |
| `perf(membership): batch the log analysis behind authoritative lookups if capability volume grows` | L6 |
| `perf(daemon): reuse durable live-head state during local writes` | L7 |
| `perf(fuse): binary-search canonical tree entries in path resolution` | L2, L3 |
| `perf(format): centralize mutation path traversal and bottom-up rebuild` | L2, L3 |
| `docs: stale API comment consistency pass` | L19, L22 |
| `chore(daemon): native macOS File Provider backend alongside FUSE` | L16, L17, L18 (32-bit edge cases) |

### New findings not tracked in ngit

| Finding | Suggested issue |
|---|---|
| H1: `AppendFile` wrong size limit | `bug(core): AppendFile uses MAX_WRITE_BUFFER_BYTES instead of protocol ingest limit` |
| M1: `Capability::new` missing device validation | `harden(sync): validate device ID as curve point in Capability::new` |
| M4: `set_size_at` submits mutation for non-existent path | `bug(daemon): set_size_at submits mutation for non-existent path` |
| M5: Deterministic BIP-340 in test fixtures | `chore(tests): use OsRng for BIP-340 test signing` |
| L10: `u32_le` panic on overflow | `harden(format): return Result from canonical_bytes on overflow` |
| L13: `candidate_share` division overflow | `harden(sync): use u64 for candidate_share division` |
| L14: Misleading overflow error message | `chore(sync): distinguish overflow from malformed in capability decode` |
| L15: `ServingEndpoint::shutdown` doesn't await drain | `harden(sync): await drain task in ServingEndpoint::shutdown` |
| L20: `check_core_nostr_scope` false negative | `harden(contracts): fail layer check when source tree missing` |
| L21: `sealed_envelope` uses `.unwrap()` | `chore(contracts): propagate errors in sealed_envelope` |

---

## Crate-by-crate summary

| Crate | Critical | High | Medium | Low | Assessment |
|---|---|---|---|---|---|
| `wyrd-format` | 0 | 0 | 0 | 5 | Production-ready. Strong canonical encoding, checked arithmetic, scrub invariant. |
| `wyrd-sync` | 0 | 0 | 1 | 6 | Solid crypto hygiene. Missing device ID validation is the most actionable finding. |
| `wyrd-core` | 0 | 1 | 2 | 4 | Good structure. AppendFile spec deviation and two panic paths need attention. |
| `wyrd-daemon` | 0 | 0 | 1 | 4 | Well-protected against overflow. One correctness bug in `set_size_at`. |
| `wyrd-cli` | 0 | 0 | 0 | 0 | Excellent. Credential handling is solid. |
| `wyrd-fuse` | 0 | 0 | 1 | 3 | Clean, well-structured. Test hygiene issues only. |
| `wyrd-contracts` | 0 | 0 | 2 | 3 | Comprehensive. Test reliability and hygiene issues. |

---

## Validation

This review was performed by reading all source files in all seven crates
and cross-referencing against the normative documents in `docs/`. No code
was modified. The findings are based on static analysis only; no dynamic
testing was performed as part of this review.

The most recent prior review (`2026-09-24-full-security-functionality-review.md`)
found 2 high-severity findings (mailbox byte bound, announcement gating).
Those findings are tracked in ngit and appear to still be open. This review
did not re-confirm or deny those findings, as they are already tracked.

---

# Validation of this review - 2026-09-29

**Reviewer of this validation: `space-bunny-free` (model id
`opencode-go/space-bunny-free`), an LLM agent run interactively by Zander.**

The findings above were produced by a separate model review of `master` at
`7295a81` and are preserved verbatim. This section records an independent
check of every one of them, run the same day against the source tree, the
normative docs, the vendored `nostr`/`secp256k1` crate sources, and all 75
open ngit issues.

Method difference worth stating: the original pass was static reading only
(see its Validation section). This one read each cited region, checked the
cited external APIs against their actual signatures, and checked the
cross-reference table against the real issue set. `master` has since moved to
`ae52ea7`; those two commits touch `identity.rs`, `manifest.rs`, `store.rs`,
`envelope.rs`, and `ingest.rs`, so the line numbers cited in the findings are
exact at `7295a81` and drift by up to +12 lines at HEAD.

## Verdict on the review: 5/10

Detection quality ~6, severity and fix quality ~3, bookkeeping ~3.

What is genuinely good: the line citations are near-perfect. Every one checked
landed on the code it described, which is rare and is what made the rest of
this validation possible. The area selection is coherent, the crypto
foundations verdict is correct, and several findings are real and worth
filing (M1, M3, M4, L1, L4, L6, L12, L20).

What caps it: the only High finding and two of the seven Mediums are wrong at
the root. M2 asserts a `Result`-returning signature for a function that
returns a bare value, and prescribes `?` on it. M5's premise misstates how
BIP-340 nonces work, and its fix contradicts the normative `trust.md` T10
decision, while the same document's Verdict praises deterministic BIP-340.
H1's fix would silently truncate large files. None of these are close calls.

## Per-finding verdicts

| Finding | Verdict |
|---|---|
| H1 | Code fact correct. Premise, severity, and fix are wrong. Re-scope before filing. |
| M1 | Correct. Real gap, no security impact. Low, not Medium. Same class as M2. |
| M2 | Wrong. Describes an API that does not exist. |
| M3 | Correct as code, with a documented invariant directly above it. Low. |
| M4 | Correct. The caller sees the same errno either way. Low, not Medium. |
| M5 | Wrong, and the fix violates a normative spec decision. Reject. |
| M6 | Correct. Info-level; the claimed cost is one directory per failed run. |
| M7 | Half right. The proposed fix is what the code already does. Info-level. |
| L1, L4, L6, L12, L20 | Correct and useful. |
| L2, L3, L5, L7 | Right shape, wrong description of the cost (detail below). |
| L8, L9, L10, L11, L13, L14, L19, L22 | Correct reading of the code, but each restates a deliberate documented decision rather than a defect. |
| L15 | Wrong. Contradicted by the code it cites. |
| L16, L17, L18 | Unreachable. The invariants the code relies on make them impossible. |

## H1 - the one High finding does not survive

The code fact is right: `live.rs:1356` does compare the post-append total
against `MAX_WRITE_BUFFER_BYTES`. Everything built on it is wrong.

1. **It is not a spec deviation.** `write-path.md:624-629` says the local
   budgets are "independent of the **protocol ingest limits**
   (`Limits::V0`)", which "still bound every committed object" — the two are
   meant to coexist, not substitute. `write-path.md:803` lists
   `MAX_WRITE_BUFFER_BYTES + 1 → ENOSPC` as a required resource test. The same
   bound guards the truncate arm (`live.rs:1477`) and the FUSE handle arm
   (`backend.rs:1994`), and `tests_handles.rs:570,613` pin it. Append is the
   consistent case, not the odd one out.
2. **The claimed redundancy does not exist.** `Entry::file`
   (`tree.rs:98-112`) validates the component name only. No size, no chunk
   count, nothing about limits.
3. **The proposed fix causes data loss.** `read_current_file_prefix` clamps
   its read: `let len = size.min(max_len)` (`live.rs:1755`). Delete the guard
   and an append to a 100 MiB file reads the first 64 MiB, appends to it, and
   commits the result as the file's new content. Silent truncation of the
   tail, with a fresh snapshot and a new file identity over it.

The residual is real but smaller than stated: appending cannot grow a file
past the per-handle write budget even where the protocol would allow it. That
is a design limitation worth an issue, and the fix is a bounded-memory append
implementation, not a deleted check.

## M2 - asserts an API that does not exist

nostr 0.45.5 declares
`pub const fn from_byte_array(bytes: [u8; Self::LEN]) -> Self`
(`nostr-0.45.5/src/key/public_key.rs:106-108`). It returns `Self`, not
`Result`; it performs no validation and cannot panic. The finding's three
claims (returns a `Result`, the unhandled `Result` will panic, handle it with
`?`) are all consequences of the same misreading, and the suggested fix would
not compile. The code at `mailbox/mod.rs:1433` could not hold a `Result`; it
is passed straight to `GiftWrapBuilder::new` at 1446.

The real, much smaller finding underneath: `send` does no curve-point check on
the recipient before building a gift wrap around a garbage `DeviceId`. That is
the same gap as M1, and the review filed it twice under two different
severities and two different framings ("security" and "panic on invalid
input"). File it once.

## M5 - wrong premise, and the fix contradicts the spec

- The stated vulnerability is a misstatement of the mechanism.
  `sign_schnorr_no_aux_rand` derives the nonce per BIP-340 from the key and
  the message, so two different messages never share a nonce. The key leak
  requires signing the *same* message twice, which yields the same signature
  and leaks nothing.
- Deterministic nonces are **normative here**, not a hazard:
  `trust.md:618` ("Signatures use **canonical BIP-340 nonces** (no auxiliary
  randomness)") and decision T10 at `trust.md:846` ("deterministic nonces
  make ids stable"). Switching the fixtures to `sign_schnorr` with `OsRng`
  aux contradicts the contract, and copied into a signing path it would change
  every derived id.
- The priority is inverted. The same call is in six production paths
  (`control/mod.rs:261`, `bootstrap.rs:221`,
  `authorization/predicates.rs:21`, `transport/signer.rs:100,154`,
  `membership/validate.rs:27`). The review flagged the test fixture and none
  of them, then praised the pattern in its own Verdict.

## L16, L17, L18 - unreachable on 32-bit

L17 and L18 are unreachable because of the write-budget invariant.
`budget.reserve` caps the handle image at `MAX_WRITE_BUFFER_BYTES` *before*
the slice is taken (`backend.rs:1275,1293`), so `offset` and `end` can never
exceed 64 MiB and `offset as usize` cannot truncate on a 32-bit target. In
`read_append`, `start` and `stop` are derived from `end - base_size` against a
buffer bounded by the same cap (`backend.rs:877,889-891`), so the range is
always in bounds. The slices cannot panic and the casts cannot wrap.

L16 is unreachable for a different reason, and this is a correction to my own
first pass. In `readdir` the `offset` is the cookie the backend itself handed
out on the previous reply, `(index + 1) as u64` (`backend.rs:2124,2127`), so
it is bounded by the length of the union listing, which the tree entry
ceilings bound far below `usize::MAX` on any target. A hostile client cannot
widen it; it can only ever pass back a cookie it was given. Filing a 32-bit
issue for it would be filing a non-bug.

L15 is wrong for a different reason: the join it says is missing is two lines
below its own citation. `shutdown` awaits `router.shutdown()`, drops the
sender, and calls `runtime.shutdown_timeout(...)` (`serving.rs:881,896-897`),
which is the join. The comment at 860-868 documents exactly this, including
why a panicked handler task must not skip it.

## Findings that restate a decision rather than report a defect

Not wrong, but nothing to act on without a decision to revisit:

- **L10** restates the documented infallible-encoder policy
  (`identity.rs:206-212`): lengths are bounded at construction, so `u32_le`
  asserts instead of propagating, to keep `encode` infallible. The proposed
  issue ("return `Result` from `canonical_bytes` on overflow") would undo a
  deliberate design choice.
- **L9** restates the anti-allocation rule stated in the comment directly above
  it (`message.rs:310-311`): decoders must not trust a declared length for
  pre-allocation. The two identical instances at `bootstrap.rs:298` and
  `rotation.rs:328` were missed, which is the better thing to have reported.
- **L11** restates the loop's termination invariant, documented at
  `fs_store.rs:275-278`.
- **L15** is in this group only in that it is already handled; see above.
- **L8**, **L13**, **L14** are accurate readings of small things. L13 is
  described wrong: `Duration / u32` panics only on a zero divisor, not on
  overflow; the real edge is the `total - index` subtraction. L14 is a
  self-inconsistent plaintext reported as `Malformed`, next to a
  `HeaderMismatch` variant for disagreements with the envelope header, which
  is a defensible split; calling it an overflow issue is not.
- **L19**, **L22** are style observations. Note that L19's `Debug` strings are
  carried inside `ViewError::Store`, which `errno_of` collapses to an errno, so
  they do not reach the FUSE client.

Cost descriptions that are wrong in a way that matters for the perf issues they
were filed against:

- **L2**: `resolve_entry` clones the tree once (`mutation.rs:448`) and then
  *replaces* `current` with `load_tree` at each step. The per-level cost is a
  store read plus a decode, not a clone.
- **L3**: clones the entry vector once per level, which is inherent to the
  bottom-up rebuild the tracked `perf(format)` issue already targets.
- **L5**: right shape, but the hot spot is the `others` `HashSet` rebuilt
  inside the grandchild loop (`chain.rs:413-417`), not the iteration itself.
- **L7**: accurate, and bounded: `unacked` is capped by
  `MAX_UNACKED_DELIVERIES` (1024), so it is a bounded scan, not unbounded
  linear search.

## Document integrity errors

1. **The crate-by-crate table does not reconcile with the findings.** Its low
   column sums to 25 against the 22 listed, and six of seven rows
   mis-attribute: wyrd-format claims 5 lows and has 6 (L1, L2, L3, L10, L11,
   L12); wyrd-sync claims 6 and has 8; wyrd-core claims 4 and has 1 (L7);
   wyrd-daemon claims 4 and has 3; wyrd-fuse claims 3 and has 2;
   wyrd-contracts claims 3 and has 2. The headline "1 high, 7 medium, 22 low"
   is the correct one.
2. **Positive observation 7 is false.** `VerifiedSnapshot` has four `unsafe
   impl`s, not one: `wyrd-fuse/view/head.rs:84`, `wyrd-fuse/view/tests.rs:93`,
   `wyrd-daemon/fuse/tests_harness.rs:28`, `wyrd-contracts/support/view.rs:26`.
   There is also unsafe libc in `wyrd-daemon/fuse/backend.rs:94` and
   `wyrd-cli/main.rs:209,447,450`. The "no unsafe in wyrd-format" half is
   correct.
3. **Positive observation 1 overstates.** The bounds-checking policy also
   relies on `saturating_add` and `usize::try_from(..).unwrap_or(usize::MAX)`
   in the paths that matter (`live.rs:1788`, `backend.rs:1290-1297`), not only
   on `checked_add`/`checked_mul`.
4. **Several "already tracked" cross-references point at the wrong issue.**
   L4/L5 are mapped to "avoid repeated runtime rebuilds during plan
   execution", which is about the tokio runtime and has nothing to do with a
   membership-log walk (L6's real home, the membership batching issue, is also
   listed). L2/L3 are mapped to two *fuse* issues while living in
   `wyrd-format`; the correct one is also listed. L7 is mapped to a daemon
   live-head issue. L19/L22 are mapped to a stale-comment issue, which matches
   neither, and since no replacement is proposed they are effectively dropped.
   M6 is mapped to the nextest-leaky issue when the real temp-dir issue is
   "chore(tests): make daemon scratch dirs unique under parallel cargo test".
   The four "no matching ngit issue found" claims (H1, M1, M4, M5) are
   correct, checked against all 75 open issues. M2/M3's cited issue has 0
   comments, not 1.
5. **The prior-review claim is wrong twice.** `2026-09-24-full-security-functionality-review.md`
   has seven high findings (H1-H7), not two. And neither the mailbox byte bound
   nor announcement gating has an open ngit issue, so "tracked in ngit and
   appear to still be open" is false. This costs nothing: the mailbox byte
   bound is in fact fixed in code (`MAX_MAILBOX_RELAY_EVENT_BYTES` and the
   `MAX_MAILBOX_RELAY_WIRE_BYTES` SDK backstop, `mailbox/mod.rs:243-284,686-690`,
   with the inner gates in `wyrd-sync/src/transport/mailbox.rs:77,93`).

## Recommended disposition

Six issues filed on 2026-09-29 as Rowan, each created bare and triaged after
with one `issue label` call per category (type, priority, release):

| Finding | Issue | Labels |
|---|---|---|
| M1 + M2 | `harden(sync): validate device IDs as curve points where they are parsed` (`nostr:nevent1qqs857qucehn206t5lc2ksyg3var5cr047lg2sp977gpudclta3dn4gpz9mhxue69uhkwunpwdczuap49eehge5xkfs`) | enhancement, P4, v0.2.0-alpha |
| M3 | `harden(core): return an error when the mailbox drainer fails to start` (`nostr:nevent1qqsz9ldrldemkdgra60kr6d7lpvnvalzvmpnfk8ydwrkphp67ys8qaspz9mhxue69uhkwunpwdczuap49eehgh3lrn3`) | chore, P4, v0.2.0-alpha |
| M4 | `bug(daemon): set_size_at submits a mutation for a path it could not stat` (`nostr:nevent1qqsvlwqw72d7kwyqnt5xlvulvjn9ts2cyhsrnajc7x7d7rulasa7smqpz9mhxue69uhkwunpwdczuap49eehg4vtvqh`) | bug, P4, v0.2.0-alpha |
| H1, re-scoped | `enhance(core): support O_APPEND to a file larger than the per-handle write budget` (`nostr:nevent1qqsxv4sc8h4rwp2lrgl34c2d93xmdc2jh02rqq5y8dv5rhygafn9nagpz9mhxue69uhkwunpwdczuap49eehgcx89tc`) | enhancement, P4, v0.2.0-alpha |
| L12 | `perf(format): avoid the whole-object revalidation read on a no-op insert` (`nostr:nevent1qqsrvaekqjr6tpp3426lsm2mjc0ehrnx8z3gcmls7wccqg24rd5kz7gpz9mhxue69uhkwunpwdczuap49eehgd9hdgt`) | enhancement, P4, v0.2.0-alpha |
| L20 | `bug(contracts): the layer 34 nostr-scope check passes when the source tree is missing` (`nostr:nevent1qqsp00l807c86ccuf8gq6snzl4am45ns2hzaffu2nrqughnmjfevy9cpz9mhxue69uhkwunpwdczuap49eehgqg7pe8`) | bug, P3, v0.2.0-alpha |

Each body carries the corrected analysis, so the review's original severity
does not travel with the issue. The append issue states explicitly that the
existing bound is load-bearing and must not be deleted.

Deliberately not filed:

- **L1** is already tracked by `perf(format): avoid allocation in
  ManifestEntry::sort_key`.
- **L4 and L6** fall under `perf(membership): batch the log analysis behind
  authoritative lookups if capability volume grows`, which already owns the
  cost of `chain::analyse` and the chain walks. Filing them separately would
  fragment one trigger condition across three issues. L4's specific
  inheritance-walk shape is worth adding to that issue as a comment when
  someone next touches it.
- **L16** is unreachable, per the correction above.
- **M2 and M5** as written, per the sections above.
- **L2, L3, L5, L7** are already covered by the `perf(format)` traversal and
  `perf(daemon)` live-head issues they were mapped to.
- **L8, L9, L10, L11, L13, L14, L19, L22** restate deliberate decisions. L10,
  L11, and L15 are recorded here as not findings. If a later reader finds any
  of them filed as an issue, this section is the correction.


# Error conventions

How fallible code reports failure across the workspace. Established by the
daemon and sync `.expect()` refactors; copy this pattern for the next
crate instead of inventing one.

## The rule

Non-test code returns typed errors. `.expect()` and `.unwrap()` appear
only in `#[cfg(test)]` modules, test helpers (`test_util`, `properties`,
`conformance`, `fuzz`), examples, and benches — never on a runtime path.

## The shape

One `thiserror` enum per module boundary (`EngineError`, `DaemonError`,
`MailboxError`, `VaultError`, `ManifestError`, ...). All three crates
already carry `thiserror` as a workspace dependency.

- Variants carry the failing identity: ids, counts, ceilings — enough to
  diagnose without a debugger (`Oversize { bytes, max }`,
  `ChunkUnavailable(ContentId)`, `MissingEpochKey(u64)`).
- Propagate with `#[from]` / `#[source]`; convert at the boundary where
  context is added, not earlier.
- `String` payloads only at genuinely foreign boundaries (relay
  transport text, object-store backends). Prefer a typed variant
  everywhere else.

## Fail closed, then restore

Authorization and classification failures are errors that abort the
operation before any durable mutation (`epochs.md` recovery). On an
error path, restore the in-memory invariants first and report second:
the intake precedent restores the pending queue and resynchronizes
volatile state to the durable baseline before returning, so a redelivery
converges instead of wedging.

## Raise vs count

Fatal commit, record, and settlement failures are raised. Per-item
failures that must not wedge a batch are counted in a report, never
raised: one hostile envelope cannot stop the drain (`DrainReport`
precedent), and a missing or corrupt bulk object just leaves its plan
item unfulfilled for the next pass.

## Checklist for new fallible code

1. New failure mode → new variant on the module's error enum, carrying
   the failing identity.
2. Crossing into another module → `#[from]` conversion at the boundary.
3. Auth/classification involved → fail closed before durable mutation;
   restore in-memory state on the way out.
4. Batch processing → decide raise (fatal) vs count (per-item), and say
   which in the enum's doc comment.
5. Test-only failure injection → `cfg(test)` guard, thread-local, reset
   on drop; never reachable from release paths.

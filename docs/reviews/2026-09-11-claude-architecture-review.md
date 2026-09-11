# Wyrd Architecture & Code Review

I've completed a deep review of the codebase (all 4 crates, ~27K lines, cross-referenced against `AGENTS.md`, `architecture.md`, `object-model.md`, `trust.md`, and `epochs.md`). Here's the full report. I've hit my tool budget for this turn, so I'm delivering findings now rather than pushing further into `wyrd-sync/src/durable/*` internals and `wyrd-daemon`'s remaining test files, which I'd flag as the natural next pass.

## Executive summary

This is an unusually disciplined pre-alpha codebase. Every "hard rule" in `AGENTS.md` that I could check against the actual dependency graph and code checked out cleanly: `wyrd-format` has zero networking/async/FUSE dependencies, there is **zero `unsafe` code** anywhere in the four crates, no custom cryptographic primitives exist (every AEAD/ECDH/HKDF/Schnorr/Argon2id operation funnels through one audited-crate wrapper per primitive), and the crate dependency graph exactly matches the documented layering (`wyrd-fuse` never sees `iroh`; `wyrd-daemon` is the sole composer). I found no violations that break a core guarantee (immutability, zero-trust vaults, revocation exactness). I did find two genuine **Major** spec/robustness gaps, a handful of **Minor** issues, and a large amount of genuinely excellent engineering worth calling out specifically.

---

## Critical Issues

**None found.** I specifically checked every hard rule in `AGENTS.md` against the code (crate dependency purity, content-ID/vault separation, append-only immutability, Nostr identity boundary, "no custom crypto primitives," iroh version pinning) and found no violations that would break a stated core guarantee.

---

## Major Issues

### 1. Genesis membership transitions with non-empty `resolves` are silently accepted

`epochs.md` states as a pinned rule: *"Transitions with a non-empty `resolves` where no conflict exists at `prev` are invalid."* This is correctly enforced in `membership/chain.rs::walk()` for the normal case (a transition extending an established canonical tip) — but it is **not** checked for the genesis transition itself. In `validate_link()`, the genesis branch (`t.prev == None`) returns `Link::Valid` based only on `derive_next` + `check_genesis_shape`, never inspecting `t.resolves`. Since there's no "conflict at prev" possible before epoch 1 exists, a genesis transition should always require `resolves.is_empty()`, but nothing enforces that — a genesis transition carrying garbage `resolves` entries (even duplicates) is accepted as fully valid and can become canonical.

I traced the practical impact and believe it's low — the genesis's own `resolves` field is never read by any downstream logic (conflict resolution only inspects a *child's* `resolves` against its *parent* contenders), so this doesn't appear to enable a privilege-escalation or authorization bypass. It's a genuine, concrete deviation from the written contract that a conformance test would have caught (there is no test for "genesis with non-empty resolves is rejected" in `membership/conformance/genesis.rs`).

**Fix:** add a `!t.prev.is_some() && !t.resolves.is_empty()` check (e.g., in `check_intrinsic` or the genesis branch of `validate_link`) yielding a new `InvalidReason` variant.

### 2. `Daemon::new()` panics instead of propagating a `Result`

In `wyrd-daemon/src/core.rs`, `Daemon::new()` calls `engine.runtime_state().expect("engine runtime state must be readable during composition")`. `runtime_state()` calls `self.store.rebuild(self.device)?` — a real, fallible disk-read/replay operation (confirmed by tracing into `Engine::open`). Elsewhere in the exact same file, the identical operation is handled correctly: `refresh_materialization()` propagates the same call's failure via `?` as an `EngineError`. This is an inconsistency in the crate's otherwise very consistent "propagate as `Result`" discipline, and it means a legitimately possible durable-store read failure at daemon startup (corrupted log, disk I/O error) crashes the process instead of surfacing a recoverable error to whatever composes the daemon.

**Fix:** make `Daemon::new()` return `Result<Self, EngineError>`.

---

## Minor Issues

1. **`Snapshot::new()` only `debug_assert`s reserved-flag zero-ness.** In release builds, a caller can construct and sign a `Snapshot` with garbage reserved flag bits; this only fails later when a peer decodes it (`decode()` correctly rejects it). Consider a fallible constructor instead of relying solely on `debug_assert`.
2. **`ManifestEntry::sort_key()` allocates a `Vec<u8>`** for the content-ID comparison on every call (used inside sortedness checks). Comparing `content_id.as_bytes()` (`&[u8; 32]`) directly would avoid the allocation. Cosmetic at v0 scale.
3. **A few cross-call invariants use `.expect()` instead of a typed error** — e.g. `runtime/plan.rs`'s `runtime.announcement(snapshot).expect("pending bodies derive from announcements")` and `runtime/intake.rs`'s `.status(...).expect("membership observed")`. Both are safe today given the surrounding single-threaded logic, but a future refactor could silently violate the assumption and turn a recoverable state into a panic rather than an `EngineError` variant.
4. **`iroh-gossip` is declared as a workspace dependency but never imported anywhere.** Not a bug (gossip framing is an explicitly open decision per `object-model.md` open question 4), but worth a tracking note so it doesn't look like dead weight to a future `cargo machete` pass.
5. **Ephemeral ECDH scalar zeroization has an honestly-documented gap:** `secp256k1::SecretKey` (0.30) doesn't implement `Zeroize`, so the FFI-held copy of one-time ephemeral private keys isn't scrubbed on drop — only the crate's own seed-byte sibling is. This is disclosed candidly in `keys/ephemeral.rs` rather than hidden, but it's a real (small) residual exposure window worth tracking against an upstream fix.
6. **`FsObjectStore::atomic_write`'s retry loop has no bounded retry count**, relying on the argument "only `open()` removes temps and `open()` calls are finite." True in practice, but a max-retry ceiling would make the liveness guarantee airtight rather than assumption-based.
7. **No `#![forbid(unsafe_code)]`** (or workspace lint) pins the current zero-`unsafe` property anywhere. Cheap insurance for a codebase clearly already committed to this bar.
8. **`object-model.md`'s "Canonical encoding" table only lists 3 kind bytes** (chunk/tree/snapshot), even though the code and decision record 22 correctly define `Manifest = 0x03`. Doc-only nit; the code is correct.

---

## Positive Findings

This codebase is genuinely strong. Highlights, each backed by something I directly traced in the code:

- **Type-enforced identity separation** — `ContentId`/`StorageId`/`SnapshotId`/`TransitionId`/`DeviceId`/`DeviceEncryptionKey` are all distinct newtypes over the same 32 bytes; there is no code path that can accidentally mix them.
- **Zero `unsafe` code** anywhere across all four crates.
- **Remarkably uniform defensive-decoding idiom**, repeated verbatim from `wyrd-format::tree` through `wyrd-sync::control::bootstrap` and `keys::capability`: `checked_add`/`checked_mul` before every length computation, capped pre-allocation before trusting attacker-supplied counts, and `.expect("bounds checked")` appearing only ever immediately after an equivalent explicit bounds check.
- **The membership state machine is a faithful, testable transcription of `epochs.md`** — conflict detection/resolution matching, the terminal zero-owner rule, and the remove+re-admit-same-transition rejection all match the spec's pinned semantics, including field order in signing preimages matching `trust.md`'s literal notation.
- **The snapshot classification engine (`authorization/classify.rs`) implements the mutually-recursive `in_live_lineage` predicate as a monotone fixed-point iteration, not recursion** — with an explicit 10,000-deep-chain test proving it doesn't stack-overflow on adversarial depth. The same iterative discipline shows up again in `wyrd-fuse::view::resolve_one`. This is a detail most implementations miss entirely.
- **The "decryption success alone is never sufficient" invariant from `trust.md` is implemented exactly as specified in `seal.rs`**, with a dedicated test that hand-crafts a tag-valid-but-content-mismatched envelope to prove the second (hash) check is load-bearing, not decorative.
- **Every pinned BLAKE3 domain-separation context string** across `trust.md`/`epochs.md`/`object-model.md` (20+ constants) is present in the code, correctly scoped, and cross-tested for non-collision.
- **Secret hygiene**: `EpochSecret`, `DriveRootKey`, and ephemeral scalars all use `Zeroizing`/`ZeroizeOnDrop` and redact `Debug` output.
- **Capability installation is genuinely monotonic and re-validates against live membership state** rather than trusting the wrapped envelope alone, closing the "capability envelope alone proves nothing about authorization" gap the code's own comments call out.
- **The durable commit log is a real hash-chained, crash-safe append log** with a precisely stated failure-mode table, and re-validates capabilities/snapshot-bodies on every rebuild rather than trusting prior validation.
- **`Limits::V0` exactly matches `object-model.md` decision 23**, and ships a self-consistency test that mechanically verifies the count ceilings are actually reachable within the byte ceiling.
- **iroh/iroh-blobs are genuinely wired end-to-end**, not stubbed — `bulk.rs` has a real integration test fetching Bao-verified bytes over a live loopback QUIC connection.
- **Test culture maps almost 1:1 onto `epochs.md`'s own "Conformance tests" checklist** rather than generic smoke tests.

---

## Expected Incompleteness (not defects)

Consistent with `architecture.md`'s own stated status, I found **no implementation** anywhere in the tree of: supervised-task backoff, event-subscription drainers, filesystem-watcher lag contracts, or self-write echo-suppression (all named in `AGENTS.md`'s review focus #5). There is also no `wyrd-daemon` binary entry point (only `lib.rs`, `core.rs`, `fuse.rs` exist) and no live fetch-state-machine driver moving objects through `RemoteOnly → Fetching → Available`. These are exactly the items `architecture.md` names as still-open ("relay pool / signer-client wiring, the daemon binary entry point, and the live fetch-on-open loop are still open") — worth confirming with the team that this matches their own tracking, but it's honest pre-alpha scope, not a hidden gap.

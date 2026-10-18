# Wyrd Adversarial Codebase Quality Review

Reviewer: OpenCode agent (model: `beam-free`, model id `opencode-go/beam-free`)
Tree reviewed: `master` @ `c78502d15e863de517c1e0a18182668ba173cf9f`
(2026-10-18). Working tree: `devenv.lock` modified (4 insertions, 4 deletions);
one untracked prior review file (`docs/reviews/2026-10-18-beam-free-architecture-review.md`);
no source files modified. This review creates only this file.

## 1. Baseline and scope

Crates inspected: all nine workspace members, with emphasis on
`wyrd-core` (`node`, `live/apply`, `mutation`, `mailbox`, `vault`, `status`),
`wyrd-sync` (`runtime/engine`, `durable/codec`, `keys/keystore`),
`wyrd-format` (`fs_store`, `mutation`, `store`), `wyrd-cli` (`credentials`,
`commands/mount`, `commands/sync`, `drive_config`), `wyrd-contracts`
(`upgrade_contracts`, `node_contracts`, `layer_contracts`), and `wyrd-embed`.

Checks actually run:
- `cargo fmt --all -- --check` — clean.
- `cargo clippy --workspace --all-targets -- -D warnings` — clean.
- `cargo nextest run -p wyrd-contracts` (default profile) — 135 passed,
  5 skipped (2 blocked upgrade tests, 3 slow/live-relay tests).
- Targeted source inspection of the modules named in each finding.

Documented conventions used as evidence: `docs/error-conventions.md`,
`docs/architecture.md`, `AGENTS.md`, `.cargo/config.toml`, and
`crates/wyrd-contracts/src/layer_contracts.rs`.

## 2. Overall assessment

The codebase is unusually well defended at its declared boundaries:
the crate DAG, the single `AuthorizedSnapshot` mint site, and the
transitive closure of `wyrd-fuse` are machine-checked by
`layer_contracts.rs`; clippy and fmt are clean; the contract suite
passes. The risk is not in the shipped boundary checks but in the
gaps between declared and enforced behavior: two upgrade invariants are
`#[ignore]`d with `todo!()` bodies, several production error paths
still use `.expect()` on invariants that are not compiler-enforced,
and a translator from `EngineError` to `MutationError` uses a
catch-all that silently downgrades any future variant to opaque `EIO`.
These are small, fixable, and worth fixing before the format freeze.

## 3. Ranked findings

### F1 — `authoring_error` catch-all hides new engine failures (C3)
- Location: `crates/wyrd-core/src/live/apply.rs:31` (`authoring_error`).
- Problem: the match maps `EngineError::Store`, `Ingest`, `Vault`,
  `Durable`, and `ObjectStore` explicitly, then falls through
  `_ => MutationError::Engine`. `EngineError` has dozens of variants
  (`crates/wyrd-sync/src/runtime/engine/mod.rs:162`); any new one
  silently becomes opaque `EIO` instead of being classified.
- Example: a new `EngineError::NeedContent`-adjacent authoring failure
  added during fetch work would be reported to a waiter as `Engine`
  (EIO) with no discriminating errno, and no compiler error would fire.
- Why not already prevented: the match is deliberately non-exhaustive;
  there is no test enumerating `EngineError` variants against
  `authoring_error`.
- Smallest fix: make the match exhaustive — either list the remaining
  variants explicitly mapping to `MutationError::Engine`, or add a
  `#[cfg(test)]` exhaustiveness test that fails to compile on a new
  variant until the mapping is revisited.
- Guardrail: a unit test asserting `authoring_error` output for every
  `EngineError` variant.

### F2 — Durable commit decoder panics on slice conversion (C1/C3)
- Location: `crates/wyrd-sync/src/durable/codec/framing.rs:85,97,109,126`
  (`.expect("take")` / `.expect("trailer bounds")`).
- Problem: `decode_commit_file` is the corruption boundary for the
  durable log. Length checks guard these conversions today, but the
  `.expect()` calls make the panic the failure mode if any invariant
  drifts; a future refactor that changes `take` or `pos` arithmetic
  turns a malformed commit into a process abort instead of
  `DurableError::CorruptCommit`.
- Example: a truncated or reordered commit file should yield
  `CorruptCommit(seq)` and let the store refuse the file; today a
  latent off-by-one in `pos` handling aborts the daemon.
- Why not already prevented: the conversion sites are not exercised by
  a proptest over arbitrary bytes; existing tests name specific
  malformations.
- Smallest fix: replace each `.expect(...)` with
  `.ok_or_else(&corrupt)?` / `try_into().map_err(|_| corrupt())?`.
- Guardrail: a proptest feeding random bytes to `decode_commit_file`
  asserting no panic and a `CorruptCommit`/`Corrupt` result.

### F3 — `WyrdNode::new` leaves the view headless (C3)
- Location: `crates/wyrd-core/src/node.rs:95-108` (`WyrdNode::new`),
  callers in `crates/wyrd-cli/src/commands/mount.rs:80-81`,
  `crates/wyrd-cli/src/commands/sync.rs:1235-1236`,
  `crates/wyrd-embed/src/embedded_lifecycle.rs:93-95`.
- Problem: construction stores an empty head set (`Vec::new()`) and
  requires a separate `refresh_live_heads()` before the view serves
  durable heads. Every production caller remembers this step, but the
  API permits reading an empty drive between construction and refresh.
- Example: an embedder that calls `WyrdNode::new` then reads
  `view().lookup(...)` before `refresh_live_heads()` observes an
  empty namespace and can treat the drive as new/empty.
- Why not already prevented: the two-step is documented as intentional
  (classification lives in `refresh_live_heads`), but nothing in the
  type system marks a freshly constructed node as unrefreshed.
- Smallest fix: either make `new` install live heads (propagating
  `NodeError`) or add a distinct `WyrdNode::open`/`unrefreshed`
  constructor so the unrefreshed state is explicit at call sites.
- Guardrail: a contract test asserting a node serves its authored
  head immediately after `WyrdNode::new` without an explicit refresh.

### F4 — Mailbox runtime access is an unchecked ordering invariant (C3)
- Location: `crates/wyrd-core/src/mailbox/mod.rs:714-720` (`rt()`).
- Problem: `rt()` uses `.expect("mailbox runtime is present until
  shutdown")`. Correctness depends on shutdown ordering (loop returns
  before mailbox shutdown), which is a convention, not a type-level
  guarantee. A reordered teardown path panics instead of yielding
  `MailboxError`.
- Example: a future host that calls `mailbox.shutdown()` then retries
  a send (or drains after shutdown) aborts the process rather than
  reporting `Transport`/`Shutdown`.
- Why not already prevented: the only enforcement is the doc comment on
  `rt()` and the daemon's teardown order.
- Smallest fix: make `rt()` return `Result<&Runtime, MailboxError>` and
  propagate, or add a `Shutdown` variant to `MailboxError`.
- Guardrail: a test exercising mailbox use after `shutdown()`.

### F5 — `insecure-fast-kdf` is an additive footgun (C2/C4)
- Location: `crates/wyrd-sync/Cargo.toml:43-45`,
  `crates/wyrd-sync/src/keys/keystore.rs:51-95`.
- Problem: the weak profile is gated by `cfg(any(test, feature = ...))`
  and the feature is additive. `cargo build/test --all-features` (or any
  downstream that enables it) compiles the weak KDF into binaries; the
  production table is only exercised when the feature is absent. The
  doc warns against `--all-features`, but nothing rejects it.
- Example: a CI or release script invoking
  `cargo test --workspace --all-features` silently stops exercising
  `KDF_M_COST_KIB`/`KDF_T_COST`/`KDF_P_COST`.
- Why not already prevented: `kdf_parameters_are_pinned` and
  `prod_kdf_params_round_trip` run only under the feature-absent
  configuration; there is no compile-time guard.
- Smallest fix: add a `compile_error!` when
  `insecure-fast-kdf` is enabled outside `cfg(test)`, or a CI step
  that runs `cargo test -p wyrd-sync` without the feature and asserts
  the production table.
- Guardrail: the existing keystore pinning tests run in the default
  (feature-absent) configuration.

### F6 — Two upgrade invariants are declared but unproven (C2)
- Location: `crates/wyrd-contracts/src/upgrade_contracts.rs:324-335`
  (`upgrade_replays_previous_fact_payload_versions`, `#[ignore]`)
  and `crates/wyrd-contracts/src/upgrade_contracts.rs:610-620`
  (`upgrade_full_version_matrix_synchronizes`, `#[ignore]`).
- Problem: both tests carry `todo!()` bodies and are ignored, so
  fact-payload version replay and the mixed-version matrix are
  aspirational. A regression in version handling or capability
  negotiation would not fail the suite.
- Example: a change to `ControlMessage` decoding that drops version
  information would pass today because the replay clause is not
  executed.
- Why not already prevented: the tests are intentionally blocked on
  unimplemented payload versioning and capability negotiation; the
  `todo!()` only fires if someone runs them with `--ignored`.
- Smallest fix: keep the blockers, but split the currently-provable
  clauses (wire version byte, single-version gate) into separate
  non-ignored tests so the suite fails on regressions of shipped
  behavior; leave the blocked clauses ignored with their `todo!()`.
- Guardrail: the existing non-ignored upgrade tests continue to pass.

### F7 — Test fakes panic on real paths (C2)
- Location: `crates/wyrd-core/src/live/tests_prereq.rs` (`FileView`,
  `unimplemented!("tests build the view shared")` for `open`,
  `store_handle`, `store_read`, `store_write`) and
  `crates/wyrd-core/src/export/tests_export.rs` (`FakeView`,
  `unimplemented!` on the same methods).
- Problem: these fakes compile against `NamespaceView` but panic if a
  refactor routes a read or store access through them. Tests that use
  them therefore cannot distinguish "the path is not exercised" from
  "the path works."
- Example: a change that makes export touch `store_read` would still
  compile, then panic in tests, and could be mistaken for an unrelated
  failure; conversely, a test that never reaches the store cannot
  detect a store-access regression.
- Why not already prevented: the unimplemented methods are confined to
  test modules, so clippy/CI do not flag them.
- Smallest fix: implement the missing methods on the fakes (delegating
  to an inner store) or remove the capabilities the fake does not
  support from its trait surface.
- Guardrail: a smoke test that drives each fake through `open`,
  `store_read`, and `store_write`.

### F8 — Local check aliases are non-transitive (C3)
- Location: `.cargo/config.toml` (`fast-sync`, `fast-core`,
  `fast-daemon`, `fast-cli`, `fast-all`).
- Problem: each alias selects only its named crate. `fast-sync` does
  not run `wyrd-core`, `wyrd-daemon`, or `wyrd-cli`, which depend on
  `wyrd-sync`, so a `wyrd-sync` change can break downstream crates
  while the local lane stays green. The PR gate (`cargo nextest run`)
  covers the whole workspace, but the fast lane is the feedback
  developers actually use.
- Example: a signature change in `wyrd-sync` that compiles in
  `wyrd-sync` but breaks `wyrd-core` is not caught by
  `cargo fast-sync`.
- Why not already prevented: the aliases are documented as per-crate
  shortcuts, not reverse-dependency closures; there is no
  `fast-affected` variant.
- Smallest fix: add an alias that runs the reverse closure
  (`wyrd-sync` plus `wyrd-core`, `wyrd-daemon`, `wyrd-cli`,
  `wyrd-contracts`, `wyrd-embed`) or document the required
  follow-up command in the alias help.
- Guardrail: none beyond the full PR gate.

### F9 — Production panic on object path parent (C4)
- Location: `crates/wyrd-format/src/fs_store.rs:554`
  (`path.parent().expect("object paths have parents")`).
- Problem: the insert path panics if `path` has no parent instead of
  returning `FsStoreError`. The invariant holds for internally
  constructed paths, but it is not compiler-enforced.
- Example: a future store backend or test helper constructing an
  object path without a parent would abort instead of failing the
  insert.
- Why not already prevented: `FsStoreError` has no variant for this
  case, and the path is built internally.
- Smallest fix: replace the expect with
  `path.parent().ok_or(FsStoreError::io(...))` or a dedicated
  `FsStoreError::InvalidPath` variant.
- Guardrail: a unit test inserting through a path with no parent.

## 4. Test-effectiveness table

| Invariant / behavior | Relevant test | What it proves | What it fails to prove |
|---|---|---|---|
| Durable log rejects malformed commits | `decode_commit_file` callers in `wyrd-sync` tests | Structural rejection for named malformations | No panic on arbitrary bytes; conversion-site invariants are assumed, not exercised |
| Production KDF parameters are pinned | `kdf_parameters_are_pinned`, `prod_kdf_params_round_trip` (`keys::keystore`) | Pinned table and round trip when feature absent | Does not run when `insecure-fast-kdf` is enabled; gating regressions can hide |
| Live heads install only after refresh | mount/sync/embed call sites + `heads` contracts | Correct behavior when refresh is called | Does not prove a freshly constructed node is unusable/empty; the two-step is caller discipline |
| Engine-to-mutation error classification | `authoring_error` call sites in `live/apply.rs` | Named variants map to expected errno | New `EngineError` variants fall through to opaque `Engine` without a compile error |
| Upgrade payload version replay | `upgrade_replays_previous_fact_payload_versions` (ignored) | Nothing today | The entire clause is unexecuted; version-replay regressions pass |
| Mixed-version synchronization | `upgrade_full_version_matrix_synchronizes` (ignored) | Nothing today | Capability negotiation / oldest-mutual selection is unimplemented and untested |

## 5. Feature / configuration / CI coverage summary

- `wyrd-sync` feature `insecure-fast-kdf` (additive, default off)
  weakens Argon2id to 8 MiB / 1 pass. Enabled only in
  `[dev-dependencies]` of `wyrd-core`, `wyrd-daemon`, `wyrd-embed`,
  `wyrd-contracts`, and `wyrd-cli`; production `wyrd-cli` does not
  enable it. Production builds use the pinned 64 MiB / t=3 table.
- `unsafe_code = "deny"` workspace-wide; the only `unsafe` surfaces are
  the documented capability crossings (`VerifiedSnapshot`,
  `from_verified_unchecked`, signal handler, `geteuid`, umask test
  helpers).
- PR gate: `cargo nextest run` (default profile) plus
  `cargo test --workspace --doc`; slow/live-relay tests are
  `--profile slow` and excluded from the default gate.
- Local lanes: `fast-*` aliases are per-crate and non-transitive
  (F8).
- Two upgrade tests remain `#[ignore]` with `todo!()` bodies (F6).

## 6. Improvement plan

Immediate (correctness / release risk):
1. F2 — remove `.expect()` from `decode_commit_file` conversion sites.
2. F1 — make `authoring_error` exhaustive or add an exhaustiveness guard.
3. F5 — add a compile-time or CI guard for `insecure-fast-kdf` outside tests.

Small independent refactors:
4. F4 — make mailbox `rt()` fallible.
5. F9 — replace the `fs_store` path-parent expect with a typed error.
6. F7 — implement the missing methods on test fakes.

Longer-term structural:
7. F3 — collapse or explicitly mark the `WyrdNode::new` → refresh
   two-step.
8. F6 — split provable upgrade clauses out of the ignored tests.
9. F8 — add a transitive local check alias.

## 7. Review limitations

- No mutation of source files was made; findings are based on static
  inspection plus the checks listed in §1.
- The 100k+ line `wyrd-sync` runtime was sampled, not line-audited;
  findings there are limited to the codec and keystore surfaces
  inspected.
- No performance measurements, fuzzing results, or live-relay runs
  were performed; slow-profile and interop tests were not executed.
- `devenv.lock` changes are unrelated to this review and were not
  analyzed.
- Findings are structural; they do not assert the presence of a
  demonstrated runtime bug beyond the specific panic sites named.

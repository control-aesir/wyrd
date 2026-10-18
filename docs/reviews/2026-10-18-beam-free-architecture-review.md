# Wyrd Adversarial Architecture Review

Reviewer: OpenCode agent (model: `beam-free`, model id `opencode-go/beam-free`)
Tree reviewed: `master` @ `c78502d15e863de517c1e0a18182668ba173cf9f`
(2026-10-18). Working tree: `devenv.lock` modified (4 insertions, 4 deletions);
no source files modified. This review creates only this file.

## 1. Executive assessment

The implemented architecture is substantially the one described by `docs/architecture.md`:
a downward-only crate DAG enforced by `wyrd-contracts/src/layer_contracts.rs`, a
single verification crossing from `wyrd-sync` into `wyrd-namespace`, an append-only
fact log with hash-chained commits, and a presentation-agnostic node composed of
`WyrdNode`/`LiveNode`. The enforcement is unusually concrete: contract 34 checks
every member's production dependency set, the transitive closure of `wyrd-fuse`,
and the exact count of `from_verified_unchecked` mint sites.

The main gap is not a broken boundary in the shipped code but a set of **declared-but-unproven
contracts**: two upgrade invariants are `#[ignore]`d with `todo!()` bodies, and
capability negotiation/version advertisement is not implemented, so the mixed-version
matrix and payload replay are aspirational. A second, smaller gap is **initialization
coupling**: `WyrdNode::new` leaves the view headless and requires a separate
`refresh_live_heads()` call, so a node's read surface is not a pure function of its
engine state at construction. Both are risks rather than demonstrated defects.

## 2. Baseline

### 2.1 Crates and responsibilities

| Crate | Responsibility | Key modules |
|---|---|---|
| `wyrd-format` | CAS identities, chunking, Merkle trees, snapshot DAG, `ObjectStore` | `identity`, `store`, `fs_store`, `snapshot`, `membership`, `mutation` |
| `wyrd-sync` | Transport, encrypted manifests, membership state machine, runtime engine, durable store | `runtime/engine`, `durable`, `membership`, `keys`, `serving`, `bulk` |
| `wyrd-namespace` | Provider-neutral value types, `Head`, `NamespaceView`, verified-head token | `view` |
| `wyrd-fuse` | Mount-free drive view | `view/*` |
| `wyrd-core` | Embeddable node, mutation queue, live loop, mailbox, budgets | `node`, `live`, `mutation`, `mailbox`, `view` |
| `wyrd-daemon` | Composition library, FUSE backend | `core`, `fuse` |
| `wyrd-cli` | Process host, commands, credentials, update | `commands/*`, `credentials`, `live` |
| `wyrd-embed` | Embedded lifecycle contract | `embedded_lifecycle` |
| `wyrd-contracts` | Cross-crate contract suite | `layer_contracts`, `*_contracts` |

### 2.2 Dependency direction

Downward only, machine-enforced by `layer_contracts.rs`: `wyrd-format` has no
workspace deps; `wyrd-sync` depends on format+namespace; `wyrd-core` depends on
format+namespace+sync; `wyrd-fuse` depends on format+namespace; `wyrd-daemon`
composes core+sync+fuse; `wyrd-cli` depends on daemon+core+sync+format.
`wyrd-contracts` is a leaf. `wyrd-embed` depends on format+sync+core+fuse and
never daemon/cli/contracts.

### 2.3 Important call paths

- `Engine::create`/`open_keystore` → `WyrdNode::new(engine, store)` →
  `refresh_live_heads()` (manual) → `into_live()` → `LiveNode::run_loop`.
- Write: `WyrdNode::put_file` → `engine.begin_write` → mutate store →
  `engine.author_pending_write` → `install_authored_head`.
- Read: FUSE/backend → `NamespaceView::lookup/open_file/read` over published
  `Arc` generation.
- Fetch: backend want → `WantRegistry` → live loop → `engine.execute_plan` →
  `store_write` → `refresh_materialization`.

### 2.4 Documents inspected

`architecture.md`, `object-model.md`, `trust.md`, `epochs.md`,
`sync-and-peers.md`, `write-path.md`, `fetch-on-open.md`, `crash-consistency.md`,
`resource-limits.md`, `storage-growth.md`, `upgrade-contract.md`, `mobile.md`,
`error-conventions.md`. Plus `AGENTS.md` and prior review
`docs/reviews/2026-10-03-space-bunny-v0.2-release-review.md`.

### 2.5 Areas not reviewed

Slow-profile live-relay tests, Lima/microVM e2e, Nix packaging, vendor fuser,
the `update` self-update module, and most of `wyrd-cli` command implementations.
No tests were run for this review beyond reading contract definitions.

## 3. Core boundaries

### A. Protocol/core independence

Protocol semantics live in `wyrd-format` (no async/network/FUSE) and
`wyrd-sync` (transport). `wyrd-fuse` links no transport (contract 34 transitive
check). `wyrd-namespace` performs no cryptography. Hidden assumptions: process
lifetime for the live loop, filesystem durability semantics for `FsObjectStore`,
and a single writer per store directory (advisory `LOCK`). These are documented
in `crash-consistency.md` and `fs_store.rs`.

### B. Crate responsibilities

Coherent. The main mixed concern is `wyrd-cli` depending directly on
`wyrd-sync`/`wyrd-core` for offline commands, bypassing `wyrd-daemon`
composition. This is permitted by policy and needed for offline administration,
but it means the CLI is a second composition root.

### C. Ownership of truth

- Drive membership: `MembershipLog` rebuilt from durable facts (`DurableStore`).
- Live heads: `Engine::live_heads()` classification over rebuilt snapshot bodies.
- Serving bytes: published `Arc` generation in `LiveNode`.
- Materialization policy: `RuntimeMaterialization` rebuilt from `RuntimeState`.
- Terminal fetch state: in-memory `fetch_terminal` only.

Single owner per durable fact; derived state is rebuilt, never persisted.

### D. State machines

Membership transition chain, epoch secrets, snapshot authorization, fetch
terminality, mutation queue. Transitions are atomic at commit level (single
batch per membership half). Crash windows are explicitly enumerated in
`crash-consistency.md`.

### E. Durability/concurrency

Commit protocol in `durable/mod.rs`: temp+fsync+rename+dir fsync, CURRENT
advance. Advisory lock. Store clones share `Arc<Durability>`. No locks held
across network waits in the documented design.

### F. Resource ownership

`ResourceBudgets` gathers node-side bounds; sync-engine bounds remain constants.
`retained_bytes_quota` defaults to `None` (unbounded). Bounds are compositional
within a live session but `wyrd-cli` runs defaults with no tuning flags.

### G. Identity/security

ContentId/StorageId/SnapshotId distinct types. Root custody, fresh epoch secrets,
NIP-44 control plane, AEAD AAD binding. Verification crossing count pinned.

## 4. Findings

### F-1 — Upgrade payload replay is unimplemented (A2)
- Intended: upgrade contract invariant 2 (payload half) proves previous fact
  payloads replay under current records.
- Evidence: `crates/wyrd-contracts/src/upgrade_contracts.rs:329-334`:
  `#[ignore = "blocked on fact-payload versioning (v0.9.0)"]` and
  `todo!("replay v0 fact payloads into current records once payloads are
  versioned")`.
- Scenario: a future release ships fact-payload versioning; without replay
  evidence, an upgrade can silently drop or misinterpret historical facts.
- Consequence: evolution/correctness risk; upgrade safety unproven.
- Correction: implement fact-payload versioning and un-ignore the test.
- Guard: the ignored test itself, once activated.

### F-2 — Mixed-version matrix blocked on capability negotiation (A2)
- Intended: upgrade invariant 5 proves mixed-version peers synchronize.
- Evidence: `crates/wyrd-contracts/src/upgrade_contracts.rs:614-619`
  (`#[ignore = "blocked on capability negotiation"]`, `todo!`).
- Scenario: two peers on different alpha versions meet; oldest-mutual selection
  does not exist, so there is one version gate.
- Consequence: pre-v1 mixed-version sync is undefined; acceptable only while
  every alpha may break compatibility.
- Correction: advertise capabilities and implement oldest-mutual selection before
  any compatibility promise.
- Guard: un-ignore `upgrade_full_version_matrix_synchronizes`.

### F-3 — `WyrdNode::new` leaves the view headless (A3)
- Intended: a composed node's read surface reflects engine state.
- Evidence: `crates/wyrd-core/src/node.rs:87-95` passes `Vec::new()` as heads to
  `V::open`; every caller (e.g. `crates/wyrd-embed/src/embedded_lifecycle.rs:93,153,213`)
  must call `refresh_live_heads()` separately.
- Scenario: an embedder forgets the refresh and serves an empty drive despite
  a populated engine.
- Consequence: initialization-coupling risk; not a current defect because all
  in-tree callers refresh.
- Correction: either install `engine.live_heads()` during `new`, or document the
  two-step invariant as a type-level precondition.
- Guard: a contract asserting `WyrdNode::new` followed by `view().lookup` sees
  authored heads without an explicit refresh.

### F-4 — Terminal fetch state is process-memory only (A3)
- Intended: terminal verdicts are run-scoped diagnostics.
- Evidence: `fetch_terminal` is an in-memory `BTreeMap` in `Engine`
  (`crates/wyrd-sync/src/runtime/engine/terminal.rs`); `terminal_snapshot()`
  clones it; `WyrdNode::new` captures it but a restart loses it.
- Scenario: a device restarts mid-backoff; terminal verdicts reset and fetch
  work resumes, which is the documented behavior, but any consumer assuming
  durable terminality would be wrong.
- Consequence: status/observability semantics are run-scoped; document clearly.
- Correction: none needed if run-scoped is intended; add an explicit doc note if
  not.
- Guard: `crash-consistency.md` terminal section.

### F-5 — `wyrd-cli` is a second composition root (A3)
- Intended: CLI programs over the daemon's public surface.
- Evidence: `crates/wyrd-cli/Cargo.toml` depends on `wyrd-sync` and
  `wyrd-core` directly; `crates/wyrd-cli/src/main.rs` imports `Engine` and
  `WyrdNode`.
- Scenario: offline commands construct engines directly, duplicating composition
  logic outside `wyrd-daemon`.
- Consequence: change amplification when node composition changes.
- Correction: route all engine construction through `wyrd-daemon` helpers where
  feasible; keep direct deps only for genuinely offline reads.
- Guard: layer contract already pins the allowed edges; add a contract that CLI
  does not construct `LiveNode` outside `mount`.

### F-6 — Default retained-bytes quota is unbounded (A4)
- Intended: append-only store growth is bounded only when configured.
- Evidence: `crates/wyrd-core/src/budgets.rs` `DEFAULT_RETAINED_BYTES_QUOTA = None`;
  field doc states unconfigured deployments are unlimited.
- Scenario: an unconfigured device grows without refusal.
- Consequence: operational, not correctness; documented default.
- Correction: none required; consider a non-default documented recommended value.
- Guard: `storage-growth.md`.

### F-7 — `FsObjectStore` verified cache is mtime+length keyed (A4)
- Intended: bitrot detection via full re-derive when stamp is stale.
- Evidence: `crates/wyrd-format/src/fs_store.rs` `VerifiedStamp { len, modified }`;
  doc notes bitrot leaving length and mtime untouched is invisible to the stamp.
- Scenario: storage corruption preserving size and mtime; `get` retires the stamp
  only when it observes corruption.
- Consequence: a narrow detection window; full re-derive still catches it when
  the stamp is absent.
- Correction: none; document the residual window.
- Guard: existing scrub tests.

## 5. Invariant-ownership table

| Invariant | Owner | Enforcement | Durable evidence | Recovery | Tests |
|---|---|---|---|---|---|
| Object identity matches bytes | `FsObjectStore` | `insert_verified`, verify-on-read | object files | re-derive | scrub tests |
| Commit visibility iff seq ≤ CURRENT | `DurableStore` | CURRENT marker | commit files + CURRENT | replay 1..=CURRENT | crash matrix |
| Heads are verified | `wyrd-sync` authorization | `AuthorizedSnapshot::authorize` | snapshot bodies | re-verify on read | layer contract |
| Membership authorization | `MembershipLog` | transition validation | transition facts | replay | conformance suite |
| Live heads classification | `Engine` | `eligible_head_bodies` | snapshot bodies + log | rebuild | heads contracts |
| Materialization policy | `Engine`/`RuntimeMaterialization` | status overlay | runtime facts | rebuild | policy contracts |
| Resource bounds | `ResourceBudgets`/registries | admission checks | none (runtime) | reset on restart | budget tests |

## 6. Future-evolution assessment

- Desktop: FUSE adapter is one backend over `NamespaceView`; boundary holds.
- History/conflict resolution: merge/recover APIs exist in `Engine`; DAG
  classification supports heads.
- Mobile: no `wyrd-mobile` crate yet; docs are a design plan. `DriveView`
  stayed in `wyrd-fuse`; providers program against `NamespaceView`, so the
  boundary is preserved but the mobile adapter does not exist.
- Vault/recovery: root custody and epoch secrets implemented; multiple owners
  and Shamir deferred.
- Security freeze: content verification and store-level `insert_verified`
  implemented.
- Stable release: blocked on upgrade payload versioning and capability
  negotiation (F-1, F-2).

## 7. Remediation sequence

Release blockers (before any compatibility promise):
1. Implement fact-payload versioning; activate upgrade invariant 2.
2. Implement capability advertisement + oldest-mutual selection; activate
   invariant 5.

Later work:
3. Decide whether `WyrdNode::new` should install heads or codify the refresh step.
4. Document terminal-state run-scoping and unbounded default quota.
5. Add a contract preventing CLI from constructing `LiveNode` outside mount.

## 8. Coverage limitations

This review did not run the test suite, slow profile, or e2e harnesses. It did not
inspect `wyrd-cli` command implementations beyond `main.rs`, the update module,
Nix packaging, or vendor fuser. Findings are based on code and document inspection
only.

# Changelog

All notable changes to Wyrd are documented here, following [Keep a
Changelog](https://keepachangelog.com/en/1.1.0/). `ngit release publish`
extracts release notes from the level-two section matching the release
version, so each release renames `[Unreleased]` below to its version.

## Compatibility first

The number that decides whether two builds interoperate is the **on-disk
format version**, not the app version. Every envelope carries it
(`wyrd_format::envelope::VERSION`, currently `0x00` = v0); a build rejects
envelopes it does not understand. Newer formats arrive as additive
representations alongside the old ones — or, when a genuine break is
unavoidable, as a snapshot-producing migration — never as in-place rewrites:
old representations stay readable for at least one full release window (see
`docs/upgrade-contract.md` for the full upgrade rules). Until 1.0, assume **every**
alpha can change the format, the trust protocol, and the CLI: drives created
by one alpha may not open under the next, and the release notes for each
version say exactly what changed.

## [Unreleased]

### Changed

- CI `rust` and `nix` jobs run in parallel (the `needs: rust` ordering
  is dropped): wall time is the slower job, not the sum. Wasted nix
  compute when `rust` fails fast is accepted.
- Local quarantine with re-want (peer-repair Part 1, second child;
  OD-12-1 A remove, OD-12-2 A re-want-on-next-waiter, SD-1 A
  client-plane-only): a read that observes verification-rejected
  bytes names the representation to the loop's drain, which emits
  the diagnostic, discards the bytes (new narrow
  `DiscardRejectedRepresentation` operation — verify-then-unlink,
  never a general store `remove`), clears the possession claim via
  the sole `ObjectRemoved` writer, and leaves the `Cached` policy
  and the waiting reader to re-demand a fresh generation. New
  `ViewError::RejectedRepresentation` verdict (identity + kind);
  structural corruption keeps its unrepairable shape. No durable
  quarantine state; the vault is untouched.

### Added

- Explicit convergence-over-delivery invariants (docs only, no behavior
  change): `docs/architecture.md` gains transport-is-never-evidence
  and identity-layering invariants pointing at the DG-3 forget
  contract and `docs/crash-consistency.md`; `docs/sync-and-peers.md`
  states recovery attaches to the semantic class (transitions and
  capabilities are state-essential, announcements and content objects
  recover independently); `docs/resource-limits.md` states locally
  authoritative does not mean locally unbounded.
- Reconciliation view fact kind (`0x18`) and replay arm
  (`21a-reconciliation-fact`): the recipient's per-class durable
  evidence (committed transitions, held snapshots, installed
  capability epochs) commits as a stated view and replays verbatim;
  derivation ignores stated views, torn commits leave the previous
  view, and retirement on an in-memory-only view is refused. A
  statement claiming more than the base facts hold is dropped at
  load with a warning — the claim fails closed while the store stays
  open. Recorded in `docs/upgrade-contract.md`; no wire behavior yet
  (21b/21c wire the statement and the retire condition).
- Restart-equivalence relation (DG-5): `docs/crash-consistency.md`
  gains the normative predicate over durable externally meaningful
  state as a per-surface table — survives, rebuilt, lost-correctly,
  or excluded by name — where every row names its observable, its
  verdict, and the strongest pin available (a direct test where one
  can be written, a named derivation where it cannot). Serving
  endpoint identity is excluded by name (residency in, address out);
  the restart-loss rule for memory-only state not yet written
  (peer-repair generations) is normative now, rows land with the
  code. Pinned by nine row and crash-stage tests plus the
  whole-relation invariant
  `a_crash_loses_ephemeral_state_but_no_durable_obligation`
  (asserted across a real mid-flight reopen), the named
  suppression-loss pin, the new status row test alongside the
  pre-existing whole-status tripwire, and the want-registry
  loss test.
- Reconciliation request message and intake (`21b-reconciliation-request`):
  the recipient-originated pull statement as a new control kind
  (`ReconciliationRequest`, `0x04`: requester plus canonical evidence
  bytes, no nonce so redelivery/reseal/re-request converge by content),
  a received-request durable fact (`0x19`: requester plus evidence,
  no subset check — the sender cannot validate another device's
  holdings), and an intake arm that commits the pair on first sight
  inside the existing per-pass budget, dedupes on (requester,
  statement digest) so transport seen-log eviction is safe, suppresses
  requester≠sender disagreement and undecodable evidence memory-only,
  and sheds floods relay-held. The send-side trigger (OD-21-4: durable
  gap — parked deferrals today, unfetchable-head deferred — or
  reconnect edge, never a timer, coalesced to one request,
  volatile already-asked marker, frozen drives silent) derives the
  view live and fans it out without committing — the send path never
  authors facts, so triggers advance no sequence; the live loop feeds
  it the mailbox reconnect edge. Nothing retires yet (21c). Recorded in
  `docs/upgrade-contract.md`, `docs/object-model.md`,
  `docs/resource-limits.md`.
- Reconciliation response and retire condition
  (`21c-reconciliation-response`): the sender answers each received
  statement once per lifetime (volatile answered set, restarts
  re-answer idempotently) — retiring what the evidence covers
  (direct hold, validated-successor ancestry for transitions, exact
  install match for capabilities) by committing `TransitionReconciled`
  (`0x1A`) / `CapabilityReconciled` (`0x1B`) facts naming the
  obligation, recipient, and proving statement digest, and
  retransmitting what it does not through the existing deliver path
  (at most 32 sends per statement, no new wire kind, transitions
  past the recipient's newest evidenced install skipped). Pending
  derives as queued-minus-(delivered ∪ reconciled). Scope boundary:
  transitions and capabilities only — announcement obligations stay
  pending, pinned by test. Recorded in `docs/upgrade-contract.md`,
  `docs/object-model.md`, `docs/resource-limits.md`,
  `docs/storage-growth.md`, `docs/sync-and-peers.md`.
- Reconciliation diagnostics (`21d-reconciliation-diagnostics`):
  `sync status` gains a `reconciliation` row — statements received
  plus transitions and capabilities retired, all from committed
  facts, classes and counts only (no identities, pinned by test) —
  and `sync now` reports the open gap as two gauges
  (`reconciliation: U statements awaiting answer, S stalled`) and
  fails the run while either is open, even with a quiet outbox, so
  automation keying on exit status sees it. The stall half fires if
  and only if an evaluated statement made zero progress and its
  obligations are still owed at end of run (unresolvable
  transition, missing sealing key, a relay that accepts nothing); a scoped
  skip the pass's unscoped delivery then discharges reads zero by
  design. Recorded in `docs/cli.md`, `docs/sync-and-peers.md`.
- Normative DG-3 control-message recovery / forget contract in
  `docs/sync-and-peers.md`: retire an obligation only on durable
  evidence the recipient's state subsumes it (per-class predicates),
  recipient-originated reconciliation pull, bounded-retention
  assumption, seven normative acceptance scenarios. Qualifies the
  "relay retains every unacked envelope" sentence in
  `docs/crash-consistency.md` and records the `*Reconciled` fact-tag
  pattern in `docs/upgrade-contract.md`. Decision only; no behavior
  change. Implementation is gated on this artefact.
- Observability PR 1 (expose what is computed): `sync now` splits
  deferred holds by cause (unseen / status-blocked / shed), accumulates
  every fetch counter plus per-pass sends across all passes, and adds a
  write-path section (snapshot rate, per-source share, admission-to-commit
  latency — process-local; zero for headless runs, which submit no
  mutations); the mailbox line names saturation recoveries; `mount.log`
  dispatch lines carry the mutation-queue backlog beside the latency.
  Lifetime `WriteStats` accumulate at the mutation seam (counts only,
  never paths). `FsStoreError::Corrupt` and `IdentityMismatch` no longer
  carry the object identity (concealment is absence).
- Observability PR 2 (the four missing projections): `sync status`
  names peers as opaque handles (`peer-N`, stable for the rendering —
  never a persisted namespace), reports the durable queue depth
  (outstanding outbox pairs plus reconciliation gaps, from committed
  facts only), convergence from durable facts, and materialization as
  counts; connectivity reads `not observed` because status never
  connects. Live-head author `DeviceId`s render as handles now, not
  raw ids. `sync now` names the senders its intake actually heard, by
  full `DeviceId` — any key that mailed us, member or not. Staged
  carries count in the queue total and render on their own line, on
  no peer line. Deferral-cause attribution is pinned stable across
  redelivery and restart.
- Normative DG-1 mutation/commit boundary table in `docs/write-path.md`:
  one snapshot per commit-forcing event (folding all pending), dirty-handle
  release as a forcing event, namespace operations as folding forcing events,
  no idle-window commit in v0.3. Decision only; no behavior change and no
  format impact. Implementation is gated on this artefact.
- Local test lane: `[profile.local]` in `.config/nextest.toml` (cheap
  deterministic tests; excludes the contracts binary, the relay cover,
  floods, and the individually slowest tests measured in the P0
  baseline) plus per-area `cargo fast-*` shortcuts in
  `.cargo/config.toml`. The existing default profile is now documented
  as the PR gate; no test was added, removed, or modified.
- DG-1 pending-set coalescing: buffered writes across handles and paths
  accumulate in the daemon's handle overlays, and a commit-forcing event
  folds the whole pending set plus itself into one snapshot
  (`MutationKind::Fold`, per-member dispositions, same-path tie-break with
  forcer privilege, aborted folds restore members to pending). Same-path
  append sequences concatenate in buffering order. The debounce-save
  workload commits one snapshot per save (50 to 10 across the committed
  workload test) with byte-identical final content. No format impact:
  only when the snapshot boundary fires changes, not what a snapshot is.
- Normative DG-4 retention/refusal contract in `docs/storage-growth.md`
  with the authorization half as `docs/trust.md` T18: serving members and
  vaults may decline to retain what an authorized member authored, at the
  enforcement points the contract names (receive-path pre-admission gate;
  residency refusal after durability — announcement barrier on the
  authoring device, mirror admission and serving maps on a receiving
  peer). Eviction and unbounded-growth-as-contract are refused for v0.3.
  Decision only; neither ceiling is enforced yet, no behavior change, and
  no format impact. Enforcement, the accounting prerequisites
  (vault-seeing counter, durable refusal state, `RetainedBytes`
  decrement), and the acceptance tests are the implementation follow-up
  gated on this artefact.
- Retention constraints v0.x must preserve in
  `docs/retention-constraints.md`: retention vs residency model, the
  transition-churn adversary, refusal semantics over the DG-4 A/B bridge,
  accounting prerequisites as contract, and what v0.3-v0.4 must not
  introduce (no eviction, no pruning, no rate limiting of durable
  commits, no wire refusal signal, no quota-pressure reclamation).
  Decision only; no behavior change and no format impact. GC
  implementation stays post-v1.
- Generation-scoped terminal fetch state with waiter completion
  (`docs/peer-repair.md` Part 1, first child; OD-11-1/11-2/11-3 all
  option A): `FetchStatus::Unavailable` carries the completed
  generation; the engine tracks per-identity attempt generations fed
  by the representation-level strike ledgers and completes a
  generation when every representation is cooled on failure evidence
  (attempted generations only — never on budget backoff, absence,
  missing keys, or local refusals). The corrupt   verdict is reserved
  for all-invalid evidence. Terminal generations complete their
  waiters with bounded `EIO`, retire from want admission, reopen as a
  new generation on observed demand (sticky reopen notes — a waiter
  never blocks on an existing verdict), and publish through the
  serving projection via the revision gate. Memory-only throughout: no
  durable fact, nothing survives reopen. No format impact and no
  protocol change; quarantine, scrub, and diagnostics are the
  following children.
- Retention accounting follow-through (OD-26, `feat(cli): predictable
  retention`): `RetainedBytes::subtract` (saturating, removal paths only —
  quarantine is a decrement only where it actually removes bytes);
  `check_retained_ceiling` startup diagnosis for a quota below current
  retention; `wyrd cache policy` reports retained content (quota-enforced),
  fact log and sync vault (observational) plus an explicitly
  non-authoritative advisory ceiling when no quota is configured; and a
  committed measurement showing 100 opens of unavailable content commit
  1 fact in 1 commit file with no amplification (4 fsyncs per commit is
  derived from the commit protocol, not counted). No CLI quota flag,
  no default ceiling, no enforcement change: fetched bytes, the vault,
  and the fact log still cross no ceiling.

### Fixed

- Drive custody files are created with explicit restrictive modes on
  Unix, independent of the process umask: `store-key.wrap`, `keystore`,
  `pairing.secret`, and `LOCK` at `0o600`, the drive directory (and
  `commits/`) at no wider than `0o700`, `DRIVE` at no wider than
  `0o644`. Modes are never loosened — a replaced custody file takes
  the hardened mode — and only the leaf directory this call creates is
  restricted, except that establishing fresh drive state restricts the
  directory it is given (missing parents above the leaf keep the
  operator's modes); pre-existing files, directories, and established
  drives are otherwise untouched (inspect a pre-fix drive with `stat`,
  repair by hand).
- Disambiguate the bare invariant refs in the upgrade-contracts index
  (`crates/wyrd-contracts/src/lib.rs`) to name `docs/upgrade-contract.md`
  explicitly (comment only): `docs/architecture.md` now also carries ten
  invariants, so the bare counts were ambiguous. The orphan-ignore half
  of entry 32 additionally points at `docs/crash-consistency.md`, where
  `orphan_files_are_ignored` is pinned.
- Correct entry 28's wording in the upgrade-contracts index and its test:
  the gate-half probe forges a sealed control version and fails closed
  with `ControlError::UnknownVersion`, not a forged envelope version
  failing open (comment only).

## [0.2.0-alpha]

### Added

- Headless synchronization without a mount: `wyrd sync status` reports
  durable sync state (pending outbox obligations, known membership tip
  against held epoch secrets, live heads with classification counts,
  mailbox posture) and never connects; `wyrd sync now` runs the mount's
  sync machinery with no FUSE session, bounding the run at 32 passes
  and reporting quiet, quiet-with-unfetchable-heads, or the pass cap.
- `wyrd sync now --offline`: explicit opt-in to a relay-less local run
  (idle intake, local obligations only).
- `wyrd member list | log | status | remove | rotate | set-owner`: offline membership-log projection plus owner-gated
  authoring of removal, key rotation, and ownership change.
- `wyrd member invite` and `wyrd device pairing-request | join`: a
  file-based pairing and invitation flow for adding a device across two
  drive directories, including reader invitations.
- `wyrd member resolve <winner> --void <sibling>...`: owner-signed
  resolution of a frozen membership-conflict epoch.
- `wyrd snapshot list | heads | plan | merge`: offline snapshot-DAG
  projection and deterministic merge of conflicted live heads over an
  explicit per-path spec (`--take path=@N`, `--drop path`,
  `--default @N`), with a dry-run `plan`.
- `wyrd pin | unpin | evict | cache status|policy`: durable per-subtree
  materialization policy, two independent columns (retention POLICY vs
  LOCAL presence), offline and idempotent, never altering a snapshot.
- `wyrd export`: guaranteed offline data egress — files, directories (empty
  included), symlinks, and the executable bit as an ordinary tree,
  conflicts as `name@N` siblings, staged and renamed so a failure leaves
  no partial tree.
- Read-only **reader** membership role: admitted readers receive the same
  capabilities as members and converge past admission, but author
  nothing and have their announcements suppressed at intake.
- Post-invitation epoch keys are delivered by ECDH rotation framing
  (`ROTATION_VERSION` 0x01 → 0x02, owner-proofed), so a newcomer joins
  into the current epoch rather than the invitation's epoch.
- Durable control-plane delivery obligations: transitions and
  capabilities are queued with their authoring, sealed once for
  byte-identical retries, and marked delivered only when at least one
  **relay accepts** the write (`SendReport.accepted > 0`).
- Multi-relay supervised mailbox: repeatable `--relay`, per-relay
  health polling into `MailboxHealth`, capped-backoff
  drainer/relay recovery, one stable subscription per mailbox with
  CLOSE+REQ resubscribe transactions, and relay-sent subscription
  closures counted in `closed_subscriptions` instead of reading as an
  idle mailbox.
- Per-relay send forensics on the control-plane send path
  (`mailbox send relay outcome`, debug): accepted and non-accepted
  relays are named with the relay's own message.
- Supervised live loop: per-class failure supervision (mailbox, store,
  engine) with equal-jittered capped backoff and a separate consecutive
  cap per class, event-driven pacing woken by inbound mail, and
  composer-owned ordered teardown (session join, admission close, loop
  join, then transport under bounded deadlines).
- Runtime resource budgets (`ResourceBudgets`): want registry, want
  admission per pass, mutation queue, parent tokens,
  per-handle and aggregate write buffers, dirty handles, open handles,
  open-capture bytes. Defaults only — the binary takes no flags.
- `crates/wyrd-core` and `crates/wyrd-namespace` extracted from
  `wyrd-daemon`: the embeddable node is presentation-agnostic, and the
  namespace value model and verification-proof token are
  provider-neutral. `wyrd-fuse`'s production link graph reaches neither
  `wyrd-sync` nor any iroh crate, now machine-enforced transitively by
  contract 34.
- Per-syscall diagnostics: `tracing` events plus per-request FUSE
  request probes (opcode, latency, errno) on stderr and in
  `mount.log`, and a teardown phase line per shutdown stage.

### Changed

- **Membership transition encoding (format break).** The canonical
  transition document gained a `readers_root` field and a
  `0x04 AdmitReader` change tag. **A drive created by v0.1.0-alpha.1
  does not open under this build.** Old records are refused, not
  reinterpreted (see `docs/upgrade-contract.md`).
- Bare `wyrd sync now` without `--relay` is refused with a usage error
  instead of exiting 0 with an idle intake; pass `--offline` for the
  relay-less local run.
- Closure of the mounted write path: the daemon-owned mutation queue
  now drains admitted mutations after the live loop returns instead of
  settling them, so unmount-time commits of still-dirty handles execute
  against a still-open queue.
- The serving endpoint is member-hosted in the shipped composition
  (`WyrdNode::open_serving`), so a serving peer in v0.2 holds the
  identity, epoch keys, and live mailbox — the keyless-replica posture
  is the design target for future serving surfaces, not today's
  composer (`docs/trust.md` T17).
- Resigned identical capabilities are deduplicated at intake against the
  committed-capability projection before the per-pass fact budget is
  charged.

### Fixed

- A dirty handle torn down at unmount committed a truncated image and
  reported success. The commit now fails closed when the buffered image
  is absent, and the full-image-across-teardown case is pinned
  (`live_mount_preserves_dirty_handle_across_shutdown`).
- `establish_drainer` no longer `expect`s drainer readiness; a drainer
  that dies before signalling is a reported transport error, and the
  supervisor rebuilds (`dropped_readiness_reports_a_transport_error_not_a_panic`).
- Removal of an unreadable or non-file custody record is refused before
  the store opens.
- Capability `unwrap` no longer accepts a secret vector shorter than the
  transition's epoch.

## [0.1.0-alpha.1]

### Added

- Local drive lifecycle in the `wyrd` binary: `wyrd init` creates identity,
  root custody, and genesis membership; `wyrd mount` serves a live
  read-write projection with clean shutdown on SIGINT/SIGTERM.
- Mounted write path: daemon-owned mutation queue, namespace operations,
  and append-handle semantics behind the FUSE mount.
- Demand-driven fetch: opening non-local content registers a want and
  blocks bounded (`EIO` on expiry), with read-side chunk demand and a
  real-iroh serving endpoint answering peer fetches by transport root.
- Encrypted control plane: NIP-44 mailbox sealing with a durable
  seen-event-id dedupe log, supervised live NIP-59 relay mailbox, and
  per-pass route publication into the fetch plane.
- Typed-error convention across daemon and sync boundaries (one
  `thiserror` enum per module; fail-closed authorization with
  restore-then-report recovery), documented in
  `docs/error-conventions.md`.
- Nix flake distribution: `packages.wyrd` / `apps.wyrd` (`nix build .#wyrd`,
  `nix run .#wyrd -- --help`) built from the committed `Cargo.lock` with the
  toolchain pinned in `rust-toolchain.toml`, for `aarch64-darwin`,
  `aarch64-linux`, and `x86_64-linux`. `devenv.nix` stays the development
  environment; the flake is distribution only.
- Deterministic per-platform release archives: `packages.wyrd-dist`
  (`nix build .#wyrd-dist`) produces the `wyrd-{version}-{platform}.tar.gz`
  named in `.ngit/release.yaml`, so a main release always covers every
  application platform.
- `nix` CI gate (`.ngit/act/workflows/workflow.yml`): `nix flake check` on push to
  `master` and on `ready_for_review` for PRs touching the flake, the Rust
  workspace, or the workflow itself.
- Release manifest (`.ngit/release.yaml`): per-platform `wyrd-{version}`
  archives for ngit releases, with notes extracted from this changelog.

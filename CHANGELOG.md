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

### Added

- Frozen public-read subset, release-read v1
  (`nostr:nevent1qqsykx7wc5tv2wu2j7gsee3ml9lygp426f55tlsc43jy37gn6h8e49cpz9mhxue69uhkwunpwdczuap49eehghl83gt`):
  `wyrd-sync/src/public_read.rs` is the keyless release reader — scope
  gate (pinned maintainer, genesis membership, epoch 1), snapshot fetch
  by transport root with id-exchange fallback, manifest and object opens
  under the published epoch-1 secret, all reusing the existing
  construction byte-for-byte. Release drives are explicitly public
  distribution surfaces (per-drive, irreversible confidentiality waiver),
  never a weaker mode for ordinary drives. Byte-exact freeze vectors pin
  the announcement encoding, both signing regions, both epoch-1 key
  families, and the 129-byte release-metadata layout; every scope
  violation fails closed with no fallback to membership replay or
  capability installation. Contract: `docs/release-read.md`.

- Sync-convergence wave 2
  (`nostr:nevent1qqs050vlflle96xqhm9yke5943dwr0579k86nmf29k8u935mdrhyhxqpz9mhxue69uhkwunpwdczuap49eehgy8qvr2`):
  microvm phase 7 grows a second wave where the member converges with
  headless `sync now` and no mount up, then reads the converged state
  mount-free (`snapshot list` on both peers, diffed byte-identical by
  the host — identical live heads mean identical manifests, hence
  identical bytes by CAS), with one faulted-in wave-2 read tying the
  heads to bytes through the serve route.
- Shared drive-path semantics
  (`nostr:nevent1qqs854dvqpuuqx547p6gmyvxt25lslnrvt76l0zxxswgcayrt9cwd0qpz9mhxue69uhkwunpwdczuap49eehgpwq2qz`):
  `wyrd-contracts` contracts 42-49 run every namespace scenario twice —
  once through the core mutation channel plus `LiveReader`, once through
  `FuseBackend` — and assert identical outcome traces (create/write/read
  incl. multi-window files, rename/delete, error classes, publication
  generations, write-fold coalescing, conflict version reads, materialization classes, restart
  from custody, shutdown). Where the surfaces are documentedly different
  (plain-conflict opens, remote-only and terminal demand failures, stale
  descriptors, closed-channel submits) each side's own tag is pinned, and
  a negative control keeps the comparator from passing vacuously.
- Live mount-free reads
  (`nostr:nevent1qqs9v3gervmm9putjafptv94a0qna9xlllve4s7l4aahej5a0p95wucpz9mhxue69uhkwunpwdczuap49eehg3r8q9l`):
  `wyrd_core::read::LiveReader` is the demand-driven open/read sequence
  over any namespace view — want registration, bounded blocking,
  repair-on-demand entry, terminal fast paths with reopen demand —
  with the same rules the FUSE mount follows, so embedders read
  remote-only content without a kernel mount and both paths share
  one read semantics, proven by equivalence tests over a real
  `DriveView`.
- Embedded consumer boundary
  (`nostr:nevent1qqs9v3gervmm9putjafptv94a0qna9xlllve4s7l4aahej5a0p95wucpz9mhxue69uhkwunpwdczuap49eehg3r8q9l`):
  `crates/wyrd-embed` is the embedder-shaped consumer — a real
  consumer of `wyrd-core` that is not the daemon, the CLI, or a
  mount. Its one named contract,
  `embedded_drive_lifecycle_needs_no_fuse_and_no_daemon`, drives one
  drive through the whole embedded lifecycle (create, direct write,
  loop-driven mutation, stop, reopen from custody, namespace and
  status reads, materialization policy write, second reopen, ordered
  shutdown) with the same heads, durable facts, and durable policy
  across each restart, no want-registry or in-memory state carried
  across, and a late mutation submitter resolved with `Shutdown`
  instead of hanging. The boundary is machine-enforced, not merely
  documented: contract 34's new
  `consumer_link_graph_excludes_presentation` pins the embedder's
  production closure (no daemon, no CLI, no suite, and no
  `fuser`/`libc`/`clap` under any reached member) beside the existing
  direct-edge check, and `workspace_members_are_exact` pins the member
  set the member-wide checks run over. Contract text:
  `docs/architecture.md`, "The embedded consumer boundary".
- Relay-flap forensics
  (`nostr:nevent1qqsxtrye00qccpa6dtsx8xczyjrvn3xm8fwecf06tvt7tvd4wmev56cpz9mhxue69uhkwunpwdczuap49eehgm4t73u`):
  after two ~30s relay outages left neither guest logs nor a host load
  record, the relay guest now dumps its current-boot journal into the
  run logs on a ~60s timer (up to ~90s after a bounded or failed
  dump; a silent heartbeat beside an aging log means dumps keep
  failing — teardown destroys the VM and the relay
  carries no ssh key by design, so this is the only post-mortem
  path), and the runner logs timestamp, host loadavg, and relay TCP
  state every 5s. Pinned by a stub covering the timer, the dump path,
  and the logger's lock-fd and lifecycle wiring.
- Wrapper-only e2e gate entry
  (`nostr:nevent1qqs95k4x4s2cw4c6a95w42xasmw0vegtucj26agj2kzrahgajvwpmzgpz9mhxue69uhkwunpwdczuap49eehghvrm23`):
  each wrapper mints a random per-run token, publishes it in the run's env
  file, and hands it to its direct child; the orchestrator, the guest legs,
  and the Lima suite compare the caller-supplied token against the published
  one via `tests/e2e-guard.sh` and refuse direct execution without it. The
  microVM orchestrator additionally requires the runner's flock to be held,
  so stale tokens from dead or kept runs cannot authorize a suite, and
  binds the token to the minting wrapper's pid. `WYRD_E2E_UNWRAPPED=1`
  is the explicit bypass for deliberate debugging (an accident barrier,
  not an authorization boundary: the token is a bearer value).
- Pre-commit bash syntax gate: a wrapper sweeps `bash -n` over every
  staged shell script (`bash -n` alone parses only its first file
  argument), after a stray `done` shipped and invalidated a 40-minute
  suite run past all its evidence. Pinned by a stub that fails a
  broken fixture even behind clean files.
- Role-narrowing withdrawal driver
  (`nostr:nevent1qqsxsskuhzne6qgv4ndw6hsssmqmdhxu8kaz5mtnx4s49ny53l88f3qpz9mhxue69uhkwunpwdczuap49eehgjpqlyw`):
  an acknowledged narrowing now advances through the route-publication
  gate instead of resting there. While narrowing the live loop announces
  route-less, so the signed route-update channel drops the device from
  peers' maps (never a silent endpoint stop — in-flight fetches keep
  serving); withdrawing a live route redelivers once per pair and
  quenches under a recorded withdrawn sentinel, so re-widening
  re-addresses like any route change. Pending completes to settled
  `mirror` exactly when no own in-scope snapshot still names a route at
  a peer and serving idles; `role status` names the outstanding count,
  effective stays vault until that commit, and a stuck withdrawal
  reports pending with its reason.
- Post-upgrade convergence leg
  (`nostr:nevent1qqsr9arqyq4vjvcvtfsqrqf3r5h0wp0zju2zrf7h42uzggl950e0h8qpz9mhxue69uhkwunpwdczuap49eehg57t5zx`):
  microVM phase 8 gains an upgrade-rejoin leg pair — the owner upgrades its
  serving binary in-guest via `wyrd update` against a host-crafted
  same-checkout archive, then re-announces, and the member converges on the
  post-upgrade set (text markers plus a 1 MiB blob verified by published
  hash) with no remount and byte-identical views. The true cross-version
  extension reuses these assertions with a v0.2.0 binary; the fixture-half
  design and blockers are recorded on the issue.
- Persistent relay and replication configuration
  (`nostr:nevent1qqs8x585cx3ut5wr5m6prd0286g3c05mxlm9emqm8v236xl600ew4cqpz9mhxue69uhkwunpwdczuap49eehgk3hyj4`,
  OD-C1..C4 all option A): a drive directory's `default.toml` names its
  relays and credential paths once, and every networked subcommand resolves
  the same file — explicit `--relay` flags replace the configured list, the
  credential flags override the configured paths, and `--config` points at a
  file elsewhere. The empty-means-idle refusal judges the effective set (a
  file declaring no relays still refuses a bare `sync now`; a configured
  relay contradicts `--offline` like a flag), unknown keys are refused with
  their name, the file holds paths never secret material, and it reads
  without the store lock. `sync status` / `sync now` print a `relays from:`
  line and `cache policy` a `configuration:` section, so precedence is
  debuggable. `toml` joins `wyrd-cli`'s production edges (parse-only),
  allow-listed in the layer contract's policy.
- Validation pins for the serving-endpoint follow-ups
  (`nostr:nevent1qqsr5xjn0nfpwd2dgl4ez6fzt3hurajgdk39nj2d443df5l2utuv9ggpz9mhxue69uhkwunpwdczuap49eehgk382gu`):
  the mailbox-line/exit agreement test now pins the corroborated-communication
  exception both directions (accepted intake and accepted sends keep the honest
  degraded line while the exit completes); the supervisor's sampler-input fold
  (`note_supervisor_observation`: ticks advance every observation, the first
  observed connection latches `relay_attached` permanently) pins deterministically
  without a live relay; a fresh peer converges entirely against a substitute
  serving endpoint over the same vault (fetch-d shape, 0.8 s, no Phase-12 gate);
  and page-check drift/copy failures now print the slot's live copy and rules
  inline instead of an opaque slot id.
- Bounded candidate walk (`docs/retry-policy.md`, walk-bound item of
  `nostr:nevent1qqst96hdcjv8y9dj2e87rfesxaxn8lf07cxym2nkck7h4wtjgy3hzjqpz9mhxue69uhkwunpwdczuap49eehggnzphy`):
  each pass attempts at most the first three freshness-ordered
  providers (`FETCH_WALK_CAP`), so a long candidate tail can no
  longer spend the pass's whole dial cost up front. Fault-failing
  heads mark and sink, so consecutive passes page through a failing
  tail (dial hangs page one per pass through the K-th head's
  full-share expiry); un-attempted candidates record nothing — no
  strike, no burn — and retry next pass by republication. The
  accepted limit is a live tail pinned behind three or more
  persistently stalled transfers, which waits on the
  representation's strike/burn cooldowns. Property 8 in
  `docs/fetch-on-open.md` now states the bounded walk.
- Bounded incremental admission catch-up (`docs/resource-limits.md`,
  child 1 of `nostr:nevent1qqsqufuj24ttsndlug9usn904axmy4m2sslgs2hk3u9n592sy0hlvdspz9mhxue69uhkwunpwdczuap49eehg4rsmla`):
  admitting a device no longer commits one batch proportional to
  recorded history. The admission commits one membership batch,
  then fills the lineage-closure announcement obligations in
  batches of at most 1,024 (`ADMISSION_OBLIGATION_BATCH`), so no
  commit's size is a function of history and the 65,536-record
  ceiling can no longer refuse a valid admission for closure
  length. Each obligation is independently durable and idempotent
  per (snapshot, recipient) — the batches are the progress record,
  no checkpoint marker — and a crash between batches resumes to
  exactly the missing suffix. The per-epoch walk horizon stays by
  explicit decision (OD-16-2 A).
- Named admission capacity refusal plus invite rerun-resume (child 2
  of the same issue, same PR): an admission whose membership batch
  cannot fit the per-commit ceiling fails as
  `EngineError::AdmissionBatchOverBudget` — batch count, ceiling,
  and unqueued closure size, stating rerunning cannot help — instead
  of a generic durable failure. Rerunning `member invite` for an
  already-admitted device resumes its catch-up fill (identity-guard:
  supplied key and role verified against the recorded admission)
  and reissues its invitation, reporting `already a member; resumed
  M obligations` or `catch-up already complete; 0 obligations`;
  `AdmitOutcome` carries `obligations_queued` and `batches` for the
  fresh path.
- Device-local materialization roles (`wyrd role set|status`,
  `crates/wyrd-core/src/role.rs`): a `mirror`/`vault` posture stored
  in one `role` file beside the keystore — no fact, no snapshot,
  nothing any peer can observe. The role is a retention default, not
  an override: under `vault`, unpinned content is effectively
  retained and `cache status` reports effective numbers; `evict`
  under `vault` refuses; narrowing away from `vault` requires
  `--yes` and keeps vault-effective posture until withdrawal
  completes. Normative contract in `docs/sync-and-peers.md`
  (Materialization policy vs peer role).
- Observation × trust-position matrix (`docs/trust.md`):
  the 18 hidden/observable disclosure classes as normative rows
  over five trust positions (keyless replica, member-hosted
  composition, public relay, drive member, removed device), each
  cell carrying a verdict at guaranteed / best-effort / accepted
  exposure confidence, with vault surfaces bound to the keyless
  column on every composition and conformance clauses (data-flow
  classification, missing-and-misleading detection, derived
  observations classified by disclosure).
- ngit-workflow opencode plugin (spike: issue triage only,
  `.opencode/plugins/ngit-workflow.ts`): a typed `ngit_issue_triage` tool
  that applies exactly one type, one priority, and one `release:*`
  milestone in a single validated call, removing displaced labels in the
  same call, and verifies the end state, so agents stop re-deriving label
  ceremony. Closed label sets are enforced in code (creation-time labels
  are unrepresentable: the tool takes no creation path); pure logic is
  covered by offline deno tests in   `.opencode/plugin-tests/` (run:
  `devenv shell -- deno test --allow-read .opencode/plugin-tests/`).
- Vault-position diagnostics projection (`wyrd-core::vault`,
  `wyrd vault status`): the stopped-drive section now shows the
  keyless-replica subset (outbox/queue counts, reconciliation and
  materialization counts, backlog predicate) through a dedicated
  `VaultStatus` type with no identity-bearing field, instead of
  the member projection's tip, epochs, head authors, peer
  handles, mailbox line, and durability verdict. Pending counts
  come from the same delivered-union-reconciled set difference
  the member projection counts, tallied in the runtime state
  beside the lists so no identity crosses the boundary. The
  surface takes no relay configuration (matrix H9).
- Disclosure conformance inventory (`wyrd-sync::disclosure`,
  `disclosure_map` on every observation struct): each field of the
  member and vault projections plus their nested types maps to
  exactly one matrix row, pinned as golden literals over live
  values. Every map destructures its struct exhaustively, so an
  unmapped field fails the build (OD-18-4 default-deny in
  compile-error form; verified with E0027); a vault-all-observable
  rule rejects any hidden-row mapping on the vault projection.
- Announcement-class reconciliation for late joiners
  (`docs/sync-and-peers.md`):
  a sender answering a reconciliation statement queues the
  recipient's missing announcements (recorded announcements minus
  evidenced snapshots, installed epochs only — synthesized
  obligations, no prior queue fact needed) for the barrier-gated
  publish pass, so a device admitted epochs later learns
  superseded-epoch snapshot ids through the one reconciliation
  mechanism. The answer pass itself sends no announcements:
  discharge stays behind the serving-readiness barrier like every
  other queued obligation. Retirement commits the new
  `AnnouncementReconciled`
  fact (tag `0x1D`, fixed triple like the other classes) on direct
  statement evidence of the snapshot — no ancestry widening — and
  pending derives as queued minus (delivered ∪ reconciled) for all
  three classes. `sync status` reports announcements retired
  alongside the other classes.
- Freshness ordering in bulk fetch (`docs/retry-policy.md`,
  `crates/wyrd-sync/src/bulk.rs`): the candidate walk orders each
  attempt from a per-provider outcome memory — recently failed
  providers sink behind unmarked ones, stably, nobody dropped. Only
  dial-phase failures train the memory (transport failures mark,
  sliced-deadline expiries do not, transfer-phase failures never
  sink other representations, fulfillment clears); marks expire
  after 5 minutes and republication clears nothing. Strike
  counting and engine cooldowns unchanged.
- `wyrd update <drive> --archive <path>` (29, step 1: artifact
  contract only): resolves a local release archive under its
  canonical name (`wyrd-<version>-<os>-<arch>.tar.gz`), validates
  the name before anything is stopped, and reports the artifact
  identity (version, target, blake3, bytes) with an honestly
  unverified compatibility line — the resolve step runs no checks.
  Noncanonical names (including hash-prefixed nix store basenames)
  are usage errors naming the expected shape. No process is
  stopped, no store is opened, no lock is taken.
- `wyrd __update_verify` (29, step 3: hidden internal subcommand,
  the transaction's authoritative check): opens the store with
  this binary, replays every commit through its readers,
  authorizes the live heads, restores epoch keys, and proves
  byte-identical durable state afterwards (keystore, CURRENT,
  DRIVE, commit set — no transition emitted, no commit authored).
  Prints the U4 report and exits 0 if and only if verified;
  unknown control versions fail as invariant 10 with the byte
  named, undecodable versioned formats as invariant 2, while a
  held lock or wrong passphrase refuses with no verdict at all.
  Object payload bytes are the documented residual (no public
  store-enumeration API); the two upgrade-contract gaps ride
  every report as unverified.
- `wyrd update` runs the full transaction (29, step 4): converge
  leftovers, resolve, lock-probe quiescence (`stop the service
  first` on held), stage to `<exe>.next`, advisory preflight,
  early verification refusal before any swap, two-rename swap
  with `<exe>.prev` kept, authoritative `__update_verify` in
  the gap with a 300s bound, commit or atomic rollback, handoff
  (`start the service`) or `--restart` long-running supervision
  with signal forwarding and exit propagation. Every report —
  verified included — names the two blocked upgrade invariants;
  a post-swap rejection under `--restart` starts the restored
  binary (rollback with continuity). Credential paths forward
  to the verification child, never read by the parent. Foreign
  `os`/`arch` archives refuse with both platforms named (macOS
  cross-arch allowed per the release script's Rosetta policy).
  Every terminal outcome records `<exe>.update-verdict` (done,
  rolled-back, or refused) beside the binary, so automation that
  cannot observe stdout still reads the result; `--restart`
  explicitly transfers into long-running supervision (exit
  reports the supervised run, the verdict record and `update`
  lines report the update).
- `wyrd vault <drive> status` (22c): process posture from a
  vault-maintained sidecar (`<drive_dir>/vault.posture`, schema v1)
  beside durable state, strictly separated. The running vault
  publishes instance id, serving id, startup/ready timestamps,
  last-pass timestamp and verdict, and run counters atomically on
  every loop event; status reads them without opening the store, so
  it works while the vault holds the exclusive lock. Fresh means
  recent, stale means last-recorded (threshold: three posture
  intervals, 180s) — both report liveness unverified, and neither
  claims convergence. Durable state reuses `sync status` facts when
  stopped and reports unavailable while running; restarts mint a new
  instance before ready and never inherit. Bare `wyrd vault
  <drive>` still starts the process.

- Step-15 unknown-parent legs report per-probe section timings
  (`step15 probe <name>=<Ns>` in the leg logs): instrument-first
  evidence for the last uninstrumented e2e chunk, no probe behavior
  changed; helper grammar still pinned by
  `tests/test-probe-mark.sh`, which now also pins the step-13 and
  step-15 legs' overrides and exact mark counts.
- Step-13 crash-injection legs report per-probe section timings
  (`step13 probe <name>=<Ns>` in the leg logs, attempt counts where a
  loop retries): instrument-first evidence for the crash-budget work,
  no probe behavior changed; helper grammar still pinned by
  `tests/test-probe-mark.sh`.
- Step-9 fetch-plane legs report per-probe section timings
  (`step<PROBE_STEP> probe <name>=<Ns>` in the leg logs, with the
  recovery attempt count): instrument-first evidence for the
  revival-budget work, no probe behavior changed. A hermetic stub
  (`tests/test-probe-mark.sh`) pins the line grammar.
- `wyrd mount --interval SECS` paces the live loop's idle deadline
  (1-86400s, default 5s): producers still wake the loop
  immediately, so this only bounds how long total silence may delay
  a pass. The e2e suites pass it through from `E2E_INTERVAL`
  (validated at mount time), and the microVM runner now reports
  host-side section timings (`HOST sections: build=… boot=…
  ssh_wait=… relay_wait=…`) alongside the phase headers.

- `wyrd sync now` distinguishes quiescence from convergence (22b):
  a healthy quiet exit that still owes fetch work now reports
  `completed: quiet with N unfulfilled (...)` with the backlog and
  its causes, instead of the bare `completed: quiet` of a fully
  satisfied target. The exit code is unchanged (success, like the
  `unfetchable heads` quiet before it): automate on the unfulfilled
  count and the cause clauses, not the exit status. No loop, pass-
  cap, or backoff behavior changes — the distinction is terminal
  classification only.
- `wyrd vault` lifecycle ownership (22b): one vault or mount per
  drive, enforced by the kernel-held store lock. A second `vault`
  against a held drive exits 2 promptly, naming the drive —
  replacing the unnamed `durable commit failed` wording that said
  nothing about where. The lock dies with its process, so a crash
  leaves no stale record; a held lock proves occupancy only, never
  health. No pidfile, socket, or status file; no
  `start|stop|status` subcommands (those belong to 36-packaging).
  Proven by a refusal process test (exit 2, drive named, drive
  available after the holder exits, SIGKILL-then-replacement
  reaches ready) and a microVM leg where a fresh peer fetches
  against the immediate KILL replacement — re-announcement and
  content service each peer-observed, never read off the ready
  line. The leg caught a real defect on its first run: relay
  acceptance had discharged announcements a dead route stranded,
  so route-scoped redelivery now reopens discharged announcements
  for the current head's reachable closure under a new serving
  endpoint (same route resends nothing; out-of-scope history stays
  discharged, so one restart cannot re-announce the whole outbox
  past; transitions and capabilities stay discharged). Every send
  records the route it went out under, last route wins, so the
  repair repeats on no subsequent pass. The
  replacement serves the closure from the retained vault store, so
  a late peer recovers history, not just the head.
- `wyrd vault` foreground process (22a): the mount's live loop and
  serving surface with no presentation session — the persistent
  process that `sync now` (bounded one-shot, unchanged) is not.
  One `vault ready: serving <id>` line after the first routed pass,
  periodic `vault posture` proof-of-life, failures with the mount's
  shape; stderr always plus an appended `--log-file`, never a
  drive-resident default; SIGTERM exits 0 on a clean stop (durable-
  outbox-first: pending obligations resume on the next run, TERM
  never loses one). No
  retention promise (waits for DG-4), no liveness handle, no
  supervision — those are the 22b and packaging follow-ons. Loop
  composition, the serving install step (flush, route, barrier), and
  the transport tail now live in `wyrd-daemon`'s vault module as one
  copy shared by mount, `sync now --serve`, and vault (route-plus-
  barrier wiring pinned by a test a hand-wired barrier cannot
  satisfy; flush-before-route is the shared code order).
- MicroVM degraded-path legs (G5, tests only — no behavior change):
  crash injection (owner SIGKILL mid-burst reopens clean with
  byte-complete survivors; member SIGKILL with a pending obligation
  under partition replays and re-serves), resource exhaustion
  (filled filesystem fails closed ENOSPC, drive stays readable and
  recovers, offline export holds only byte-complete fills), and
  unknown parent (announcements converge with the owner down;
  reads of unserved bodies fail EIO bounded, never hang; heal
  converges once the owner returns; manifest-missing UnknownParent
  stays pinned at contract level). New suite phases 13-15; the whole-run
  cap moves 90 to 120 minutes with the legs' stated budgets.
  The exhaustion drive lives on a fixed-size ext4 image
  loop-mounted in-guest: filling the shared state dir fills the
  host root fs, which kills guests and the suite silently.

- Tested review helpers (`.ngit/scripts/review.sh`, exposed as `review`
  in dev shells, with a stub-based suite under `.ngit/scripts/tests/`):
  `resolve-pr` maps the
  current branch to its PR id offline-first, `pr-context` prints the PR
  view with its comment thread, and `post-comment` takes the body on
  stdin, posts exactly once as Wyrd AI Review, and verifies. Review
  agents call these instead of re-deriving ngit ceremony.

- Crash-consistency window pins (G4, tests only — no behavior
  change): cross-subsystem reopen agreement (one test per crash
  stage where the object store, vault, and fact log can disagree,
  plus the vault/object-store pair under a post-rename fsync
  failure and the poisoned-lock stays-failed consequence),
  post-corruption projection (a damaged head fails the pass with
  the previous generation still serving; normative rule stays in
  `docs/epochs.md`), and mirror-queue diagnostics (depth travels
  with the not-ready report; a rejecting queue warns at the
  default level). Inventory in `docs/crash-consistency.md`.

- Device-local durability levels (DG-2, normative in
  `docs/write-path.md`): a completed write reports which of Working,
  Committed, or Published it reached, indexed by the DG-1
  commit-forcing event that fired — Working before the first
  snapshot, Committed while an announcement obligation is queued,
  Published once the outbox is quiet. Reported as one field on the
  offline-capable `sync status` (`durability: working | committed |
  published`); no new command, no per-write surface, no format
  change. Working state stays never servable, never announceable,
  and never readable as a head.

- MicroVM step selection (`nix/microvm/run-microvm.sh --step N[,N...]`):
  run the prefix closure over suite phases 1-15 (1-5 shared core,
  6-15 microvm legs), mirroring `lima/run-alpha.sh --step`. An empty
  entry or a non-step is refused; omitting the flag means all phases.

- Owner recovery-snapshot workflow (`wyrd snapshot recover plan/run`):
  republish stranded bytes as a recovery-flagged snapshot parented
  onto the current eligible heads, without adopting the dead fork's
  lineage. Plan first (one row per source root path: ready,
  already-live, undecryptable, missing, each with its reason), then
  run with `--take`, `--all`, or `--content`. Owner-only with an
  up-front CLI pre-check; the engine re-enforces ownership at
  authoring. `snapshot list` and `snapshot heads` mark
  recovery-flagged tips. Selection is root-entry granularity over a
  single source body addressed by id — no historical browsing.

- Warn-once control-plane refusal: the first all-relay refusal of an
  outbox obligation logs at warn (kind only, never identities) so a
  never-flipping policy refusal is operator-visible under the default
  filter; repeats stay at debug. Logging only — obligations still
  pend and no Delivered fact commits on refusal.

- Headless serving composition (`sync now --serve`, OD-23-V/W/X):
  the bounded headless drain optionally binds the mount's serving
  surface (open, bulk, flush, route, barrier) so its announcements
  carry a dialable route and discharge waits on mirror readiness;
  after the drain's own verdict the endpoint serves the converged
  snapshot until SIGINT/SIGTERM and shuts down in mount order. No
  barrier without serving (route-less authoring unchanged);
  `--serve` refuses `--offline`; `docs/trust.md` names both
  shipped member-hosted shapes. Bridge until `wyrd vault` exists.
- Shed-wait attribution on `sync now` (`17-observability`, OD-17-2
  extension): pending-bound sheds carry their already-classified wait
  into `deferred_shed_unseen` / `deferred_shed_status_blocked`, and
  the shed total renders its wait detail in parentheses when the run
  shed anything (classified waits first, then the unclassified
  budget/quota remainder — a partition of `shed`, and of nothing
  else). Budget, quota, and charge-time sheds stay unclassified by
  design: the shed decision runs before classification to avoid
  spending verification.
- Observation × trust-position matrix (`17-observability`, OD-17-6,
  `docs/trust.md`): what each diagnostic surface (`sync now` run
  output, `sync status` durable surface, debug log, durable drive
  metadata, the wire) may show and must never show, composed with
  the party table. More classification never widens a surface.
- Explicit no-persistence policy for verification identities
  (`17-observability`, OD-17-1 B): per-representation verification
  identities are intentionally not persisted — deliberate
  privacy/data-minimality policy, documented in
  `docs/peer-repair.md` with the evidence hierarchy
  (`VerificationFailure` → debug log → run-report counts →
  identity-free durable metadata). The implementation distinguishes
  a single genuine rejection class, so no cause-taxonomy extension
  was warranted.
- Dial/transfer split in bulk fetch (`docs/retry-policy.md`,
  roadmap item 2): each attempt now runs the dial under its own
  allowance and size discovery plus streaming under the leftover,
  with identical timeout instants and error classes — the split
  adds measurement, not new timeout behavior. `IrohBulkSource`
  keeps cumulative `BulkFetchStats` (attempts, dial/transfer
  timeouts, fulfilled bytes, wasted bytes) and every attempt emits
  a forensics line (provider, hash, phase, dial latency, streamed
  bytes), so restart waste is measurable for the deferred resume
  decision. Cross-pass resume stays deferred behind the design
   note; no `BulkSource` trait change.

### Fixed

- ENOSPC attribution across the write path
  (`nostr:nevent1qqs2rnte3r0tqlfhmtfv56hwuxrqez6z6jrv0hc7usj40puvv0trscqpz9mhxue69uhkwunpwdczuap49eehgmle0y8`):
  every `ENOSPC` source — daemon write budget, open-capture ceiling,
  retained-bytes quota, backing-store capacity — reached the mount as
  the same errno with nothing in the logs saying which refused, so
  exhaustion runs could not tell a full disk from a daemon budget.
  Each refusal site now logs a debug line naming its `layer` (which
  resource) and `stage` (which write-path step it precedes) with the
  deciding numbers — including a `backing-store-capacity` / `commit`
  line on every commit-phase store write that maps to `StorageFull`
  (chunk inserts, tree writes, and the authoring outcome), so the disk
  path names its layer wherever the refusal lands. Errno contract
  unchanged (`ENOSPC` for all), no behavior change, no new error
  variants. Pinned by five log-capture emission tests plus two
  end-to-end wiring tests that drive commits into a write-refusing
  store, documented in `write-path.md` ("ENOSPC attribution"), and the
  exhaustion e2e leg now captures the backend target and asserts the
  failing fill names its layer.
- Review helper names the missing argument on an empty id
  (`nostr:nevent1qqsqgnnlt9akul5d0n7590y7kl2kg8gx97c5aafks8nqy8kaaq4mfncpz9mhxue69uhkwunpwdczuap49eehgae50uz`):
  `review pr-context` / `post-comment` with an unset variable printed only
  the generic usage text, which reads as an arg-parsing failure and sends
  the operator debugging quoting instead of the variable. Both now print
  `missing id (resolve it first: review resolve-pr)` before usage.
  Pinned by two stub cases in `.ngit/scripts/tests/test-review.sh`.
- Fresh-join authorship outwaiting the mutation deadline
  (`crates/wyrd-sync/src/runtime/author/snapshot.rs`,
  `crates/wyrd-core/src/live.rs`,
  `nostr:nevent1qqspxn54twzd3a206lw38vx94scw4nunjy0ahapj6yvzsxt84df0ngqpz9mhxue69uhkwunpwdczuap49eehgvsehv5`):
  the authoring walk named only its first missing chunk per evaluation,
  so a cold device discovered one miss per sync pass and a first-minute
  write routinely outwaited the 30s `max_mutation_wait` while its closure
  drained. The failed walk now collects every miss over the whole tree
  (`EngineError::ChunksUnavailable`) and `MutationError::NeedContent`
  carries the set, so one evaluation registers all of its demand and the
  retry converges over fetch rounds (paced by the per-pass admission cap)
  instead of rediscovering one miss per pass. Fail-closed semantics and
  the 30s value are unchanged: nothing authors until every named chunk
  lands. Chunks a saturated want registry refuses defer with the mutation
  instead of failing it, so a past-bound miss set still converges.
  Single-miss sites (view lookups, the merge locality pre-pass) name one.

- ngit-workflow triage tool success result referenced an undefined
  `removals` binding (every success threw ReferenceError after applying
  labels): the reported shape is now built by `triageSuccessResult` in
  `.opencode/lib/ngit-triage.ts`, pinned by the offline suite, and the
  entry only stringifies it.

### Changed

- CLI command tree hardened after the `main.rs` split
  (`nostr:nevent1qqsyfxq3flw7nx0slwkvmvpuau47a9xmfsgstk5leulu297af7fvkqgpz9mhxue69uhkwunpwdczuap49eehgfncncm`,
  follow-up): sixteen single-module helpers return to private
  visibility, the `every_src_file_is_a_declared_module` pin descends
  into `src/commands/`, `docs/cli.md` names `commands.rs`, and the new
  `tests/help_contract.rs` verifies the full `--help` tree plus error
  paths against the committed `help-contract.blake3` (46 pages) inside
  the normal cargo gate. No behavior change.
- CLI vault/member/snapshot/device families extracted from `main.rs`
  (`nostr:nevent1qqsyfxq3flw7nx0slwkvmvpuau47a9xmfsgstk5leulu297af7fvkqgpz9mhxue69uhkwunpwdczuap49eehgfncncm`,
  phase 4): `vault` with the status renderer, durable-probe helpers,
  and vault-position report, `member` with the invite/resume renderers,
  carry/invitation-file helpers, and member reports, `snapshot` with
  the merge-path guards and snapshot/recovery renderers, and `device`
  with the bounded reader, identity reports, and the shared `parse_*`
  hex helpers (moved as-is; consolidation stays a follow-up) move to
  `cli/src/commands/`, one module per family. `main.rs` (1,941 → 595
  lines) keeps the dispatcher, `CliError`, and the process host. Pure
  move with `pub(crate)` visibility: no dispatch, lifecycle,
  exit-code, ordering, or error-path change, and the full `--help`
  tree plus error paths are byte-identical before and after.
- Sync engine split by responsibility family
  (`nostr:nevent1qqszz92kdwfwxcle7fdphp5gzcugflfyhmjtdqxza5kh5cv4fzs6yzcpz9mhxue69uhkwunpwdczuap49eehg2zxjr3`):
  the 2755-line `engine/mod.rs` keeps the module doc, `EngineError`, all
  shared types, the `Engine` struct, and the observation accessors, while
  the `impl Engine` verb groups move verbatim to one submodule each
  (`membership`, `authoring`, `delivery`, `carry`, `outbox`, `intake`,
  `materialization`, `plan`, `terminal`) and `impl PendingQueue` moves to
  `pending`. Pure move: every method keeps its signature and reach —
  `pub(super)` becomes the identical `pub(in crate::runtime)` across the
  module boundary — all `engine::` paths resolve unchanged, and the full
  nextest gate passes with no behavior diff.
- CLI sync family extracted from `main.rs`
  (`nostr:nevent1qqsyfxq3flw7nx0slwkvmvpuau47a9xmfsgstk5leulu297af7fvkqgpz9mhxue69uhkwunpwdczuap49eehgfncncm`,
  phase 3): `sync` / `sync_now` with `SyncRunReport`, the pass cap and
  settle constants, the stopping-verdict helpers, and the status/now
  renderers move to `cli/src/commands/sync.rs`. `SyncRunReport` fields
  (plus `accumulate`) are `pub(crate)` for the untouched `tests_sync`
  tree. Pure move: no dispatch, lifecycle, exit-code, ordering, or
  error-path change, and the full `--help` tree plus error paths are
  byte-identical before and after.
- CLI small command families extracted from `main.rs`
  (`nostr:nevent1qqsyfxq3flw7nx0slwkvmvpuau47a9xmfsgstk5leulu297af7fvkqgpz9mhxue69uhkwunpwdczuap49eehgfncncm`,
  phase 2): `mount`, `export` (with the shared offline policy-node
  opener), `pin`/`unpin`/`evict` with their renderers, `role` with its
  renderer and role-file error mapper, and `cache` with its residency
  renderers and `RetentionAccounting` move to `cli/src/commands/`, one
  module per family. Pure move with `pub(crate)` visibility: no
  dispatch, lifecycle, exit-code, ordering, or error-path change, and
  the full `--help` tree plus error paths are byte-identical before
  and after.
- CLI argument and runtime helpers extracted from `main.rs`
  (`nostr:nevent1qqsyfxq3flw7nx0slwkvmvpuau47a9xmfsgstk5leulu297af7fvkqgpz9mhxue69uhkwunpwdczuap49eehgfncncm`,
  phase 1): the clap types (`Cli`, `Credentials`, `RelayArgs`, `Command`,
  the eight action enums) move to `cli/src/args.rs`, the credential and
  identity readers (plus `current_uid`, which only they use) to
  `cli/src/credentials.rs`, and the live-node plumbing (shutdown latch
  and installer, teardown bounds, retention cross-check, loop config,
  bulk binding, serving park/shutdown) to `cli/src/live.rs`. Pure move
  with `pub(crate)` visibility: no dispatch, exit-code, ordering, or
  error-path change, and the full `--help` tree plus error paths are
  byte-identical before and after.
- No-op inserts skip the revalidation read for verified objects
  (`nostr:nevent1qqsrvaekqjr6tpp3426lsm2mjc0ehrnx8z3gcmls7wccqg24rd5kz7gpz9mhxue69uhkwunpwdczuap49eehgd9hdgt`):
  the store keeps a bounded in-process map of length-plus-mtime stamps for
  objects it has already verified, so a repeated insert of unchanged bytes
  pays a `stat` instead of a full file read and BLAKE3 re-derive (about
  half the per-op cost at 1-16 MiB on the measured path; the remaining
  cost is hashing the caller's input, which the `insert` API needs to
  address the object). Any stamp drift falls back to the full re-derive
  that heals bitrot, and a `get` that observes corruption retires the
  stamp so the next insert heals rather than trusting it.
- Tree lookups binary-search the canonical entry order
  (`nostr:nevent1qqsx6h0h9ztknvcyc6e76d5sgzymlednsp4vey4tmnqjl573qnpexzgpz9mhxue69uhkwunpwdczuap49eehgglwlpu`):
  `Tree::get` resolves a component with `binary_search_by` over the same
  bytewise `Component` order entries are sorted by at construction, and
  the mount-free view's per-component path walk uses it in place of a
  linear `iter().find`. A lookup on an N-entry directory drops from O(N)
  to O(log N) per component; the comparator is the construction sort, so
  it can never disagree with a scan. `Tree::get` is additive; no format
  or canonicalization change.
- Manifest entry sort keys compare in place
  (`nostr:nevent1qqsyla3wxrcnnasvw7uh28cqwgcu8thuaue7kcasam9lxltk42jxjrspz9mhxue69uhkwunpwdczuap49eehgzm5sem`):
  `ManifestEntry::sort_key` borrows the 32-byte content identity instead
  of allocating a `Vec<u8>` per call, so canonicalizing a manifest and
  verifying its sortedness no longer allocate. The key order is
  untouched.
- Sync and mailbox test suites split by topic
  (`nostr:nevent1qqsgjnygyl3wqz8ujfwvwvervlet4sn6e5kn0f4kwmvps63jeeev7hcpz9mhxue69uhkwunpwdczuap49eehg9ccgw9`):
  the six oversized suites are split along their existing clusters —
  `engine/tests_delivery.rs` into delivery, stale obligations,
  registration, preframing, and crash stages (shared plant fixtures
  into `tests_harness.rs`); `plan/tests_execution.rs` into convergence
  and bounded execution; `author/tests_admission.rs` into admission,
  reissue, epoch rotation, fill, and admission failures
  (`mint_bare_chain`/`bare_tree`/`relay_catch_up` into
  `tests_harness.rs`); the fetch strike/cooldown cluster into the
  existing `tests_attempts.rs`; `durable/tests.rs` into lifecycle,
  corruption, rebuild, capability, outbox, rotation, reconciliation,
  and permissions (shared fixtures into a new `tests_harness.rs`); and
  `mailbox/tests_delivery.rs` into delivery, outage, and shutdown.
  Pure move: no test renamed, no assertion edited, and the nextest
  test-name set is identical before and after.
- Sync contracts split by theme
  (`nostr:nevent1qqsvq5j5lmgvgzy7x4ay22zmcj4hc530u09eyardhzvs2qd8sjagwdcpz9mhxue69uhkwunpwdczuap49eehgmqylse`):
  `wyrd-contracts`' 3,096-line `sync_contracts.rs` is now a
  `sync_contracts/` directory: `heads.rs` (verified-head classification
  and mounting), `write_path.rs` (publication, carry, and closure),
  `queue_pressure.rs` (deferred delivery and bulk ceilings), and
  `recovery.rs` (conflicted drives, grafting, and owner proofs), with the
  cross-cutting `serving_backend`/`epoch3_child` fixtures in
  `harness.rs`. Pure move: contract names and count unchanged, shared
  `support` rig use unchanged.
- View and backend test suites split by topic
  (`nostr:nevent1qqs9ntumnt0l5fcycq7vxct2m2947j28a4mdmxslg359llprkchdccspz9mhxue69uhkwunpwdczuap49eehg0yykgn`):
  `wyrd-fuse`'s `view/tests.rs` is now `tests_harness.rs` (fixtures only)
  plus `tests_read.rs`, `tests_merge.rs`, `tests_symlink.rs`,
  `tests_chunks.rs`, and `tests_grammar.rs`; `wyrd-daemon`'s
  `fuse/tests_backend.rs` is now `tests_readonly.rs`, `tests_budget.rs`,
  `tests_write.rs`, and `tests_handles.rs`, with the backend-level inode
  lifecycle tests appended to the existing `tests_inode.rs` and the
  cross-cluster `kind_changing_backend`/`publish` fixtures moved into
  `tests_harness.rs`. Pure move: no test renamed, no assertion edited,
  and the nextest test-name set is identical before and after.
- Signing-domain home (`crates/wyrd-format/src/signing.rs`,
  `nostr:nevent1qqs2eg9qr56egtqz8k7jvuarlkm8gjn0lgkuq3j6arsmxvkvxec46lgpz9mhxue69uhkwunpwdczuap49eehgyn7anc`):
  `SignDomain` and the membership/snapshot/owner-proof challenge
  contexts plus finalizations move from `wyrd-sync` into `wyrd-format`,
  so a minimal remote signer recomputes digests depending only on
  `wyrd-format` plus `secp256k1`/`blake3`. `wyrd-sync` re-exports every
  publicly reachable moved path, so no public spelling changes. The v2 request/response
  envelope codec stays sync-side (session framing, per the review
  amendment), as do the epoch-secret vector commitment and the
  owner-proof preimage builder (sync-side key material and `Zeroizing`
  buffers). Pinned bytes identical: no contract change. A scratch crate
  on `wyrd-format` + `blake3` recomputes all three challenges,
  including the full canonical owner-proof preimage.
- Serving surface split (`crates/wyrd-sync/src/serving/`): the 1,145-line
  `serving.rs` is now `vault.rs` (raw byte CAS, no iroh/tokio dependency),
  `mirror.rs` (bounded write-through queue, backpressure, readiness
  barrier), `endpoint.rs` (iroh router, loopback mode, bounded shutdown),
  and `source.rs` (runtime-state adapter), with `mod.rs` carrying the
  module doc and re-exports. No public path changes and no behavior
  change; the conformance tests stay in one file with explicit imports
  instead of three copies of the loopback/poison/tempdir helpers.
  `Vault` keeps the mirror attachment slot (`mirror_slot` /
  `attach_mirror`): the write-through needs an attachment point and
  removing it would change shutdown-detach semantics, so `vault.rs`
  names the mirror types without depending on the transport.
- Issue triage labels (`ROADMAP.md`, `CONTRIBUTING.md`,
  `docs/collaboration-workflow.md`, `AGENTS.md`): `release:backlog` is the
  parked state and every triaged issue carries exactly one `release:*`
  label — an absent milestone is invisible to the label-filtered queries
  release planning depends on. Project labels must never be passed at issue
  creation: creation-time labels are permanent and cannot be retracted
  through a later `ngit label` event (`--remove-label` only covers
  triage-applied labels).
- Wall-clock accounting in the e2e harnesses (`tests/alpha-common.sh`):
  every step header, every check line, and a closing summary now carry
  elapsed seconds, taken from bash's `SECONDS` builtin so no check forks
  a `date`. Three deltas, kept distinct on purpose: run-relative arrival
  on a step header, the cost of one check on its PASS line, and a step
  total so a slow phase is attributed to its own header rather than to
  whatever step follows it. Both harnesses share the helper, so Lima and
  the microVM gate report the same shape, and the summary is guarded to
  print once per shell even though the harness calls it from both `main`
  and its EXIT trap.
  The gate had no timing at all outside `stop_mount`, so no claim about
  where its minutes went could be checked against anything. First
  measurement, Lima full suite: step 6 is 133s of a 152s run and steps
  1-5 together are 19s, so the offline contract is free and the cost is
  entirely the network phase.
- E2e harness hygiene, all locally provable (`lima/run-alpha.sh`,
  `tests/alpha-common.sh`, `tests/alpha-lima.sh`, new
  `tests/step-grammar.sh` with `tests/test-step-grammar.sh`).
  `run-alpha.sh` skips the ~92MiB closure export when the guest already
  carries the exact binary, mirroring `provision.sh`'s import gate so the
  two cannot disagree into a missing import; a flapping probe falls
  through to the export. `check_no_leaks` scans each log once for all
  secrets instead of once per secret, and fails closed on an empty secret
  set or an unreadable log rather than passing vacuously. The `--step` comma-list grammar is
  one shared `step_max` function with 40 stub checks (1-6/1-15,
  malformed inputs, glob safety, base-10 canonicalization); Lima adopts
  it, and the microVM runner and host orchestrator adopt it in the entry
  below. The stub suite runs in CI (shell-tests), so that claim is
  revision-bound; the green Lima full suite (106 checks, 156s) and the two
  end-to-end refusal proofs (`--step 99`, `--step 4,,5`) are
  local-operator evidence, not attached to a revision.
- MicroVM gate batch 2: parallel builds, host phase timing, one `--step`
  grammar (`nix/microvm/run-microvm.sh`, `tests/alpha-microvm.sh`). The
  five builds (wyrd, nak, three runners) run in the background behind one
  fail-fast wait each: the first failed wait kills its siblings before dying,
  so a dead build never burns CPU through teardown, and wall time is the
  slowest build rather than the sum. The runner and the host orchestrator
  both adopt the shared `step_max` grammar, so `--step 01` canonicalizes
  to 1 everywhere and the refusals (`--step 99`, `--step 4,,5`,
  whitespace) hold with one message shape; the `step-grammar.sh` header
  no longer claims Lima-only. Host phase headers and PASS lines carry the
  same `SECONDS`-based deltas as the guest helper, closing the last
  timing blind spot the interval-knob decision needs. Build and timing
  proof needs odin (neither runs on macOS); the grammar refusals are
  proven locally below, and the stub suites still pass. Review round:
  backgrounded builds close fd 9 (run-lock discipline, stub-pinned by
  the new `tests/test-runner-fd.sh`), build logs move to
  `$STATE_DIR/build-logs` outside the phase-1 pre-clean (host leak check
  covers both dirs), stubs pin the 1-15 range (40 checks).
- CI `rust` and `nix` jobs run in parallel (the `needs: rust` ordering
  is dropped): wall time is the slower job, not the sum. Wasted nix
  compute when `rust` fails fast is accepted.
- CI's `nix` job no longer assembles the microVM runner disk images on
  every PR (bare `nix flake check` OOMed the runner building
  `microvm-store-disk.erofs`): it builds the `wyrd` and `wyrd-dist`
  checks and evaluates the whole flake with `--no-build`, proving the
  VM topology still evaluates. The runner closures build when a
  microVM run needs them (`nix/microvm/run-microvm.sh`).
- Local quarantine with re-want (peer-repair Part 1, second child;
  OD-12-1 A remove, OD-12-2 A re-want-on-next-waiter, SD-1 A
  client-plane-only): a read that observes verification-rejected
  bytes names the representation to the loop's drain, which emits
  the diagnostic, discards the bytes (new narrow
  `DiscardRejectedRepresentation` operation — verify-then-unlink,
  never a general store `remove`), clears the possession claim via
  an `ObjectRemoved` commit, and leaves the `Cached` policy
  and the waiting reader to re-demand a fresh generation. New
  `ViewError::RejectedRepresentation` verdict (identity + kind);
  structural corruption keeps its unrepairable shape. No durable
  quarantine state; the vault is untouched.
- Local scrub for out-of-band loss (peer-repair Part 1, third
  child): claimed-but-absent bytes are observed at read time (new
  `ViewError::LostRepresentation` verdict, identity + kind — a
  stale `Available` no longer reads as an unreachable peer) and by
  a bounded per-pass presence walk over locally claimed
  identities from a rotating in-memory cursor. The loop's drain
  emits the diagnostic, re-verifies presence (a concurrent heal
  keeps its claim with no redundant fetch), clears the stale
  claim via the second `ObjectRemoved` writer
  (`Engine::record_missing_objects`, resolving each cleared
  identity's retained size from its manifest entry in one batch
  pass), and leaves the intact `Cached` policy for the background
  plan to refetch with no waiter synthesized. The walk runs after
  admission (reusing its snapshot) and the drain clears ahead of
  fetching, so walk-found losses clear on the same pass they are
  observed. No bytes are unlinked, no protocol change, no new
  durable-fact kind; the vault is untouched.
- CI draft and reporter jobs persist the per-repo ngit event cache
  (`.git/nostr-cache.lmdb`) through the actions/cache steps alongside
  the global cache: fresh checkouts discarded the bulk of relay sync
  state every run, so auto-draft cold-synced past the resolution
  deadline on every new PR. Resolution deadline 180s to 480s and the
  per-call bound 120s to 300s as cold-seed cover; scan and publish
  calls are each capped at the time left on a shared per-step budget
  (60s under the 10-minute job ceiling), so a slow run can never
  stall into cancellation and skip the cache save. The reporter save
  step runs unconditionally like the draft one. A hermetic shell-test
  job (`bash .ngit/scripts/tests/run-all.sh`) pins the bound
   arithmetic. Warm runs finish in seconds.
- Local writes pay one durable rebuild instead of four
  (`nostr:nevent1qqsd2mkn4gxkplcxxvkz9gtvgphajy8tg7663xccsxgkeeq6l65679spz9mhxue69uhkwunpwdczuap49eehgscysnc`):
  `put_file`/`remove` rebuilt the durable runtime state and
  reclassified the snapshot DAG once to pick the write base, once more
  to author, and twice again in the head-projection refresh
  (`runtime_state` plus `live_heads`).
  `Engine::begin_write` now captures the eligible heads with the
  rebuilt state that classified them in a linear `PendingWrite`
  session, and `Engine::author_pending_write` reuses it instead of
  replaying; the authored snapshot installs directly as the only head
  (the path admits zero or one prior heads, and a member-authored
  snapshot under canonical membership is eligible with a closure the
  authoring just verified). Parent selection stays engine-side — the
  node only counts heads and mutates the engine-resolved base — and a
  session naming several heads fails closed
  (`EngineError::WriteConflicted`) rather than extending one side.
  Measured on a 200-snapshot drive, release build: per-write 81ms to
  63ms (about a fifth off, growing with history since each rebuild
  replays O(history) facts). No snapshot, membership, restart, or
  multi-head-resolution semantic change.


### Fixed

- `sync now` mailbox verdict requires observation-validity: a
  zero-connected sample with zero supervisor ticks no longer fails
  the run (that is the mailbox's initial state, not a measurement),
  and relay communication in either direction with no observed
  attachment exempts an "unreachable relay" diagnosis — delivered
  intake or relay-accepted sends both prove the relay talked to
  this run, so a stale zero-connected sample cannot convict.
  Attached-then-lost still fails, so a genuinely dead relay keeps
  its verdict — with one residual window: the attachment latch flips
  only on a supervisor-tick observation, so an attachment and loss
  both landing between ticks reads as never-attached. Fixes quiet headless restarts (e.g. `sync now
  --serve` re-park) exiting degraded within a second of startup,
  including runs that attached and delivered mid-run before any
  supervisor tick observed the attachment.
- Release `dist/` archives are copied under canonical names
  (`wyrd-<version>-<os>-<arch>.tar.gz`): one mapping serves the
  build copy, `--verify`, and the `--strict` gate, so the gate can
  no longer drift from what the copy step produces. Unblocks
  archive resolution by name for `wyrd update` and every `--strict`
  release cut.

### Added

- Fetch-failure diagnostics on `sync now` (peer-repair Part 1, fourth
  and last child; OD-14-1 A sync-now-only, OD-14-2 C total-always
  with conditional breakdown and unconditional deadlines, OD-14-3 A
  counts-only): the run prints one line per fired fetch class
  (`transport_errors`, `missing`, `invalid`, `unavailable_keys`,
  `local_failures`) when work is left behind, plus unconditional
  `deadlines` (budget-pressure discards) and `terminal` (identities
  holding a completed terminal generation, a live gauge read once
  at run end) lines, and `quarantine` / `scrub` lines when the run
  did   repair work. Class counters are diagnostic counts, never a
  decomposition of `unfulfilled`; the surface is client-position
  (counts by reason, never identities). `sync status` stays
  durable-only. The step-9 leg scopes `wyrd_core=debug` to its own
  mount (Lima step-6 style) for the pass-line grep; suite-wide
  debug would suppress the `wyrd`-target warn step 2 requires.
- Lima harness guards the guest share: `lima/run-alpha.sh` verifies the
  guest serves this checkout before building (the instance yaml's
  recorded path, plus a guest mount check — no guest toolchain needed)
  and refuses on a stale share instead of silently testing the wrong
  code; `--re-share` re-points the instance at the current checkout
  and restarts it.
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
- Negative contract for the reader-set format break (contract 55):
  a synthetic pre-`readers_root` transition document refuses with
  `MembershipError::Truncated` instead of reinterpreting the tail,
  and a commit carrying the short record fails load with
  `DurableError::CorruptCommit` while a fresh handle still refuses
  it identically — pinning the 0.2.0-alpha compatibility claim
  (tests only, no behavior change).

### Fixed

- Bootstrap seal binds the envelope version and the ephemeral key into
  the AEAD tag: the AAD is now `"wyrd bootstrap v1" ‖ version ‖ drive ‖
  recipient ‖ encryption key ‖ inviter ‖ ephemeral pk` (mirroring the
  rotation fix in 7060570), and the signed plaintext repeats the full
  header instead of omitting the version and the ephemeral key.
  Wire-affecting: bytes sealed by an older build no longer open, which
  is the new construction refusing the old encoding by design
  (nothing deployed, alpha).
- Bulk transport shutdown is graceful-or-abort instead of fail-on-wedge:
  the endpoint close gets a short bounded graceful attempt (5s,
  `wyrd_sync::GRACEFUL_CLOSE_DEADLINE`); on expiry the endpoint
  is aborted, a warning names the graceful-close timeout, and shutdown
  still exits 0. Shutdown success means Wyrd stopped its own work and
  released its resources — it no longer requires relay infrastructure
  to acknowledge graceful closure, which intermittently held TERM
  shutdown past the 60s bound (Lima step 6) with live relay connections
  that had no reason to drain.
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
- Refresh two stale control-plane wiring comments
  (`crates/wyrd-sync/src/control/mod.rs`, `message.rs`): relay delivery
  via `wyrd-core`'s `LiveMailbox` has landed, so they no longer read
  as pending work (comment only).
- Drop the unused `nostr-connect` workspace pin and its pre-granted
  `wyrd-daemon` allow-list entry: no member declares it, nothing
  imports it, and the pre-grant would let a future addition slide
  past the layer check silently. Re-add both with the NIP-46 session
  wiring (trust.md T16).
- Operational state directories land owner-only from creation
  (`nostr:nevent1qqsyfct79g8mzw84wf6uq6snw20sg97xsngx8gxyp8rnyt8qez49zdcpz9mhxue69uhkwunpwdczuap49eehg5u9vq7`):
  the custody fix left the `escrow/`, `vault/`, and `serve/`
  subdirectories umask-derived; they now follow the same
  creation-only contract as the custody files. The escrow write
  establishes its directory through `ensure_owner_only_dir` and writes
  the epoch sidecar through `atomic_write_mode` at `0o600` (a crash
  between temp and rename no longer strands a group-readable sidecar
  holding a wrapped epoch secret), and `Vault::open` and the serving
  endpoint's `serve/` creation harden their leaves the same way.
  Modes are chosen, not umask-derived — pinned under umask `0o000`
  and `0o077` — and opening never chmods: a pre-fix drive's loose
  directories keep their modes until repaired by hand. No durable
  bytes change.

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

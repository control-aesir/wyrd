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

### Fixed

- Drive custody files are created with explicit restrictive modes on
  Unix, independent of the process umask: `store-key.wrap`, `keystore`,
  `pairing.secret`, and `LOCK` at `0o600`, the drive directory (and
  `commits/`) at `0o700`, `DRIVE` at no wider than `0o644`. Modes are
  never loosened and never chmod'ed in place — a replaced custody file
  takes the hardened mode — and pre-existing files and established
  drives are otherwise untouched (inspect a pre-fix drive with `stat`,
  repair by hand).

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

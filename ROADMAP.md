# Roadmap

This file tracks the implementation order for Wyrd. The normative contracts
live in `docs/object-model.md`, `docs/trust.md`, `docs/epochs.md`, and
`docs/sync-and-peers.md`; this roadmap stays directional.

Milestones are capability-oriented, not issue-volume-oriented. Each milestone
names the system that must become trustworthy before the next begins. The
shape is deliberate: v0.2 through v0.3 make the substrate trustworthy,
v0.4 through v0.7 build products around that substrate, and v0.8 through
v1.0 make long-term promises about it.

| Milestone | Thesis |
| --------- | ------ |
| v0.2 | Trustworthy live synchronization |
| v0.3 | Durable operation and content recovery |
| v0.4 | Cross-platform desktop product |
| v0.5 | Human-scale history and conflict resolution |
| v0.6 | Mobile synchronization |
| v0.7 | Production vault infrastructure and disaster recovery |
| v0.8 | Protocol compatibility and security freeze |
| v0.9 | Release candidate and soak |
| v1.0 | Full Wyrd drive |

Read as transitions: v0.2, sync works; v0.3, one machine can safely operate
it; v0.4, people can use it; v0.5, people can understand its history;
v0.6, people can use it on mobile; v0.7, infrastructure can keep it alive
and recover it; v0.8, contracts become long-lived; v0.9, prove the whole
thing; v1.0, ship it.

## Triage: placing work on the map

Every issue carries exactly one `release:*` milestone. The label scheme is
`release:v0.2.0-alpha`, `release:v0.3.0-alpha`, and `release:v0.9.0-beta`
for the existing milestones, then bare `release:v0.4`, `release:v0.5`,
`release:v0.6`, `release:v0.7`, `release:v0.8`, and `release:v1.0` with no
qualifier suffix.

- Parked issues (visible future work with no commitment) carry no milestone
  label at all. A parked issue must say so in its body.

A new issue matches a milestone thesis below, or it forces a thesis
discussion first. For v0.2 specifically, the entry test is: does this alter
behavior a peer can observe over the network, or prevent locally
corrupted or invalid state from being accepted? Performance work enters v0.2
only when current behavior violates an operational bound; otherwise the
sequence is correctness, measure, optimize, prove equivalence.

Project rule, all milestones: the protocol and synchronization semantics
never depend on whether the consumer is FUSE, a desktop application, iOS,
Android, or a vault. Presentation surfaces are adapters around `wyrd-core`
and the daemon, never the architecture. Platform clients may differ in
process, lifecycle, storage, and IPC architecture, and legitimate
platform-specific abstractions (persistence capabilities, lifecycle,
resource budgets, key storage) are inputs to the core, not knowledge of
which product is calling; they must nevertheless consume the same core
synchronization and state semantics rather than reimplementing them. This
is the constraint that keeps the v0.4 through v0.7 product work from
turning the daemon into an unmaintainable universal application.

## Current Boundary

Protocol identity, wire format, authorization model, and control-plane
contracts are frozen for v0. Core implementation and local durability
semantics remain open where the product above them requires it:

- format and identity types
- canonical serialization and decoding
- membership and snapshot authorization
 - epoch keys, capabilities, bootstrap framing, and escrow records
   (local custody wrap/unwrap; the guardian root-recovery workflow is
   future work — see Phase 3)
- control-plane message set and mailbox/signing trait boundaries

Recovery comes in three distinct senses in this file. Say which one, every
time; never let "recovery" float:

- crash recovery: a local process or device survives a crash. Shipped.
- content recovery: stranded local content is grafted into current state.
  v0.3.
- root recovery: all capable devices are lost and guardians reconstruct
  control and root material. v0.7.

Phases 1 to 4 shipped their tracked scope: the runtime sync engine, the
read-only filesystem slice, crash recovery, recovery foundations, and
the hardening passes are in place and under test. The mounted write path
has landed since, and the mount serves read-write by default. The
frontier is the live network (see v0.2 below).

## Phase 1: Runtime Sync — shipped

Goal: turn protocol primitives into a crash-safe, reconnecting sync engine.

Tracked by (all applied):

- `feat(sync): runtime sync engine` (`nostr:nevent1qqsd3u6j08rq9n0u0k9tjl4jp88fqjjktrp2pnqfr0g4tl3rwh425xgpz9mhxue69uhkwunpwdczuap49eehgv5jzw2`)
- `feat(sync): durable local state and crash recovery` (`nostr:nevent1qqszjy7pcdmf7kztts3q048dr2d46zmjccjq2p5zl5tw5ndg9hgk6tcpz9mhxue69uhkwunpwdczuap49eehgp4ul4q`)
- `feat(sync): control-plane transport wiring` (`nostr:nevent1qqswa6y6lwxywrnq5gt7w6v25gq9dz37qw7pq2cz63uppl3ajwnzh7cpz9mhxue69uhkwunpwdczuap49eehgtxs4lc`)

Landed:

- durable membership, snapshot, manifest, capability, and materialization
  state — durable fact log, replay, restart reconciliation under test
- crash recovery and restart reconciliation, including torn-commit recovery
- transport identity distribution: BaoRoot announcements, author-signed
  routing columns, announcement fork gating at intake with route updates
- bulk object transport type (`IrohBulkSource`) and the fetch plan that
  consumes the announced identities

Remaining in this phase: the serving router peers dial into (real-iroh
loopback in the `wyrd` binary), NIP-46 remote signing, and bulk
backpressure under live network conditions.

## Phase 2: Minimal Filesystem Slice — shipped

Goal: prove the runtime can surface a real drive through a filesystem API.

Tracked by (applied):

- `feat(fuse): minimal read-only mount slice` (`nostr:nevent1qqs9ews64fvne43dvzszggedn789kz4ylyfj88qxzy7epvqwq3wa5fgpz9mhxue69uhkwunpwdczuap49eehgzyghwf`)

Landed:

- read-only FUSE mount via the daemon (`wyrd init`, `wyrd mount`)
- lookup, readdir, open, read, stat over the mount-free view
- remote-only fetches through the documented materialization boundary:
  fetch-on-open demand machinery (want registry, blocking open/read with a
  bounded `EIO` deadline) proven against the bulk-source contract

Remaining in this phase: nothing — the write path landed and the mount
serves read-write by default.

## Phase 3: Recovery Foundations — shipped; workflow pending

Goal: land the recovery primitives the trust contract reserves the
design for (`docs/trust.md`, Recovery). Making root recovery operational
end to end (guardians reconstructing a lost root) is explicitly NOT in
this phase.

Tracked by (applied):

- `feat(sync): recovery protocol completion` (`nostr:nevent1qqszq7ctvnagpkzwdcfyjs2u6ezqw2qrvgcqtsnawrugnz2yxarfxhspz9mhxue69uhkwunpwdczuap49eehgql62dp`)

Landed (foundations — implemented, tested, wired):

- epoch-secret escrow records (T13): wrap/unwrap implemented and
  under test, wired into bootstrap custody (epoch-1 un-escrow on
  reopen) — end to end for local custody, not for guardians
- bootstrap custody handling: create plus reopen flows
- recovery-snapshot flag and grafting rules, specified in
  `docs/epochs.md` (content grafts, never lineage); the creation
  workflow that mints one is unshipped (see below)

Explicitly NOT landed (unimplemented, untracked — file tracking
issues before implementing):

- guardian selection and membership-log guardian fields
- Shamir reconstruction flow (k-of-n share return, root rebuild,
  fresh capability / new epoch)
- share rotation (re-split, re-deliver on compromise or loss)
- historical epoch restoration
- owner recovery-snapshot creation workflow

Until those land, root loss with all capable devices gone is
unrecoverable — exactly as `docs/trust.md` states. Nothing here
should be read as operational root recovery.

## Phase 4: Hardening — shipped

Goal: make the protocol surfaces resilient under adversarial and malformed inputs.

Tracked by (all applied):

- `docs(sync): state the ingest decode-cost bound` (`nostr:nevent1qqstgq2uqm2vtf4efjc6hdah5k4cl856c08vakzn7lmewqkgtew8gscpz9mhxue69uhkwunpwdczuap49eehgf3hxu4`)
- `test(sync): capability and canonical-apply property follow-ups` (`nostr:nevent1qqsxestle2hqna4lj0794qc8shns9p4nk9r4cd0pxy8rhap28thtd4cpz9mhxue69uhkwunpwdczuap49eehg3u5ztw`)
- `test(sync): fuzz protocol decoders` (`nostr:nevent1qqs94gh4yjy66kcllmxze7dtu8n0jed3anlz0w7jpjs9rcm3gc7e2lgpz9mhxue69uhkwunpwdczuap49eehg2jard5`)

Landed: decode-cost and allocation bounds, property coverage for canonical
state transitions, and fuzzing for the envelope and decoder surfaces.

## v0.2 — Trustworthy live synchronization

Thesis: Wyrd can synchronize real drives reliably over the live network.

Ship: multi-relay mailbox operation, relay interoperability, peer repair
and history catch-up, correct closure and head gating, demand-driven
content acquisition, bounded intake and resource consumption, correct
shutdown and restart behavior, headless sync, sync status, materialization
policy, reliable FUSE read/write operation, E2E convergence tests,
adversarial and runtime property tests, operationally meaningful limits
and failure behavior.

Explicitly do not ship: the recovery grafting workflow (no operator
surface: no CLI command, no daemon entry point, no owner
recovery-snapshot creation workflow — that workflow is v0.3), mobile, File Provider,
sophisticated conflict UI, production telemetry platform, marketplace,
release distribution, major performance architecture.

Definition of done: given two or more legitimate Wyrd peers connected
through real relay infrastructure, ordinary mutations — including history
catch-up after disconnection — converge correctly, survive restart,
partition, and heal, never silently accept invalid state, and can be
operated without a mounted FUSE filesystem. History acquisition and state
convergence are separate failure domains; the definition covers both.

Known v0.2 limitations (documented, not deferred silently): stranded local
content has no sanctioned path back until the v0.3 content-recovery
workflow; the local store is cooperative, so concurrent non-cooperating
writers are outside the supported concurrency model.

Milestone decision (content recovery in v0.2): the grafting
primitives exist at the library layer only.
`Engine::author_recovery_snapshot` stays public because
`wyrd-contracts` pins the normative grafting rule (`docs/epochs.md`)
end to end from outside the crate; that pinning is contract
enforcement, not a shipped workflow. Nothing in the operator surface
(CLI, daemon, embeddable node) calls it, and the owner
recovery-snapshot creation workflow that would make grafting operable
ships in v0.3. Recovery terminology follows the canonical
definitions above (crash, content, root): this paragraph concerns
content recovery only.

## v0.3 — Durable operation and content recovery

Thesis: Wyrd is no longer merely a working sync engine; it is something an
operator can safely run on one machine. Three parts, in dependency order.

### v0.3 core: durability, recovery, observability

Device-local durability levels, mutation accumulation versus snapshot
commitment, explicit transaction and commit windows, crash semantics,
content-recovery snapshots and sanctioned grafting, durable outbox
semantics, restart-equivalence testing. This comes before editors and
mobile behavior are built on Wyrd.

Real observability, not telemetry for its own sake: sync, peer, relay,
pending work, fetch failures, materialization, queue and resource
pressure, and convergence state, with explicit privacy boundaries (a vault
is a different trust position from a client).

### v0.3 dogfood: unattended vault operation and self-hosted distribution

A single unattended vault: one operator can run a reliable persistent Wyrd
peer with persistent materialization policy, predictable retention,
resource limits, restart recovery, health and status, relay and
replication configuration, secure credential handling, and upgrade
behavior. `wyrd vault` on a server should be forgettable. This is
unattended operation, not the production vault network (see v0.7).

Distribution as dogfood of that operator system: seeder vault, Wyrd drive
releases, signed manifests, multi-source retrieval, `wyrd-get`, frozen
public-read subset. Wyrd uses Wyrd to distribute Wyrd. Distribution is a
v0.3 target for dogfooding — an optional validation track, not a v0.3 exit
criterion — and must never become the schedule driver for the core
durability and recovery work above.

### v0.3 architecture: consolidation after the semantics stabilize

The deferred splits (live loop, engine, mailbox supervision, serving,
FUSE, contracts, CLI, tests) land here, once live-network semantics are
stable enough that moves are safe. Refactors are eligible when they reduce
semantic locality cost without changing the active contract; they are not
scheduled merely because a file is large. The goal is semantic locality —
every major invariant has a discoverable home — not pretty files. Do not
split files while the semantic boundary is moving; split them after it
has stabilized.

## v0.4 — Cross-platform desktop product

Thesis: a normal person can use Wyrd as a desktop file-sync application.

A cross-platform desktop application around the core, on macOS, Linux, and
Windows: drive lifecycle (create, join, leave, device enrollment and
removal or revocation, owner and member management, drive deletion and
export where applicable), invitation and join flow, sharing and membership
UX (protocol membership is not user-facing sharing: roles, removal
consequences for materialized data, ownership transfer), sync status,
pause and resume, selective sync and materialization, storage usage,
offline status, relay status, conflict indicators, settings,
notifications, key and device management.

The test: a technically competent person installs the application and
creates and manages a drive without ever learning what the `wyrd` CLI is.

Conflict guarantee for v0.4, explicitly: conflicts cannot surprise or
destroy data. Detection, clear divergence indication, both branches
preserved, inspectable conflicts, a safe path into history, and at most
the simplest keep-both operation. Full resolution workflows belong to
v0.5; a first conflict must never silently discard either side.

FUSE stays an implementation and presentation surface where appropriate;
it is not the product contract. File-provider integrations are platform
adapters. The UI talks to the Wyrd control plane, not to FUSE.

## v0.5 — Human-scale history and conflict resolution

Thesis: the immutable snapshot model becomes a usable human workflow.

Conflict resolution is a namespace and state UI, not a sync-engine
feature: visual branch and head representation, side-by-side comparison,
text merge, binary selection, directory and rename/delete reconciliation,
keep-mine, keep-theirs, keep-both, manual merged results, historical
snapshots, restore of previous versions, arbitrary snapshot browsing, and
resolution audit. The governing principle: the UI resolves conflicts by
creating a new legitimate snapshot transition; it never mutates history.

Kept separate from v0.4 on purpose: v0.4 is usable synchronization with
conflict safety, v0.5 is usable history semantics with human resolution.

## v0.6 — Mobile synchronization

Thesis: Wyrd works as a first-class mobile storage and sync system, on iOS
and Android.

Lifecycle-aware sync, background wakeups, push gateway, battery and
resource budgets, cellular and Wi-Fi policy, selective materialization,
offline operation, local cache, upload and download queues, foreground
catch-up, conflict notifications, secure key storage, device enrollment
and removal, mobile-specific recovery.

The operational contract is wake, inspect durable state, perform bounded
work, persist, and sleep — never "keep the daemon alive forever". Mobile
provides lifecycle and resource policy around the same shared semantic
sync engine; it must not own synchronization semantics, though its process
architecture may differ. Mobile client semantics develop against ordinary
Wyrd peers; the vault-backed wake topology (phone sleeps, vault holds,
desktop converges) is exercised as a supported topology in v0.7.

## v0.7 — Production vault infrastructure and disaster recovery

Thesis: Wyrd operates as infrastructure, and infrastructure can keep a
drive alive and recover it — not merely personal-device sync.

Production vault network: multiple independently operated vaults providing
durable, policy-controlled infrastructure for drives — unattended
replication, replication and residency policy, storage and bandwidth
quotas, peer admission and removal, relay configuration, encrypted-at-rest
storage, monitoring, a backup and redundancy strategy appropriate to the
vault's retention and recovery contract (whether "backup" means another
Wyrd vault holding replicated state or an independent disaster-recovery
copy with its own retention semantics is a v0.7 design decision, not an
accident), upgrade, migration, operational alerts, and
mobile wake and background workflows as a supported operational topology.
Vaults stay ordinary protocol participants, not privileged servers.

Operational root recovery becomes a committed deliverable here, so v0.8
can audit and freeze it: guardian selection and membership state, Shamir
reconstruction, root and control-key reconstruction, fresh capability and
epoch after recovery, share rotation, historical epoch handling, recovery
after loss of all capable devices, recovery after vault or device
compromise, and end-to-end recovery drills. Without this, v0.9 would
polish an application whose disaster story is still "do not lose all
your devices" — which does not fit the v1 promise.

## v0.8 — Protocol compatibility and security freeze

Thesis: the protocol and operational model are mature enough for
long-lived promises.

Exit condition: no known consumer-facing change requires changing object
identity, serialization, authorization, membership, epoch, recovery,
conflict, storage, compatibility, or user-visible drive semantics. After
this point, changing the protocol becomes an exceptional event.

Protocol: versioned fact payloads, capability negotiation, mixed-version
policy, compatibility matrix, migration machinery, retention refusal
semantics, epoch escrow (finalizing the long-lived contract; the mechanism
foundations already landed), finalized key-rotation semantics. Security:
full threat-model review, recovery and custody review, device-compromise
and malicious-vault scenarios, relay metadata analysis, downgrade and
replay analysis, resource-exhaustion review, external audit if feasible.
Release engineering is subordinate: reproducible builds, signed releases,
update mechanism, platform packaging, migration and compatibility testing.
Coverage gates become meaningful here, once contracts are stable enough to
measure.

## v0.9 — Release candidate and soak

Thesis: no major architecture remains between this and v1. Freeze object
identity, serialization, compatibility rules, membership, epochs, conflict
and recovery semantics, client and vault roles, storage semantics, and
upgrade and migration rules. Hard rule for the milestone: no new
subsystem, no protocol redesign, no opportunistic refactor, no new
platform, no new recovery model. Only proving what exists: soak testing,
upgrade and migration testing, large drives, pathological histories,
large vaults, multi-device and partition scenarios, mobile lifecycle,
disk-full, crash injection, relay failure, malicious peers,
cross-platform runs, audit fixes, UX polish.

## v1.0 — Full Wyrd drive

Defined by user capabilities, not implementation completeness. Files:
install on Mac, Linux, Windows, iOS, and Android; create and join drives;
edit normally with automatic sync; work offline and reconcile on
reconnect; choose local materialization; recover previous versions.
Migration: existing directories import as first-class drives without
destroying or rearranging them — predictable symlinks, permissions and
ownership on Unix, Windows semantics, case collisions, Unicode
normalization, timestamps, executable bits, large files, files changing
mid-import, resumable interrupted imports, and explicitly documented
unsupported metadata. Conflicts: understand, compare, and resolve them
without understanding Merkle DAGs, preserving both sides when desired.
Devices: add, remove, revoke, and inspect status and materialization.
Vaults: configure retention, run unattended, monitor, recover, replace,
several per drive. Sharing: share drives with other people, with explicit
roles and removal consequences. Recovery: never one disk failure away
from unsupported recovery. Updates: move between releases without
understanding protocol versioning.

## Post-v1

Garbage collection stays post-v1: it needs a retention/acknowledgement
design that is separate from the core protocol boundary. The current
contract is append-only history, immutable objects, and explicit state
changes.

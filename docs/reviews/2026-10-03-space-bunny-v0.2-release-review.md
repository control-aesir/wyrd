# v0.2.0-alpha release review — "Trustworthy live synchronization"

Reviewer: OpenCode agent (model: `space-bunny-free`, model id
`opencode-go/space-bunny-free`)
Tree reviewed: `master` @ `2b6ad380f9e6a622e828b83ba8c4728d5dba363a`
(2026-10-03). 658 commits since `v0.1.0-alpha.1`; 76 commits since the
prior pass's `4c9f279`.
Host: macOS 14 / aarch64-darwin, system macFUSE present, network
available, Nix store writable.

Read-only. No source file was modified. The only file this review
creates is itself.

## How to read this document

Sections 1–8 answer the seven review tasks in order. Section 9 is the
do-not-ship argument. Section 10 lists what I ran. Section 11 lists
candidates I checked and refuted, so a later pass does not re-file
them. Section 12 lists what I could not run.

**Evidence standard.** Every finding below carries a file:line and
either a command I ran or a test I read. "Could panic", "might race",
and "a future edit could" are not findings and do not appear as such.
Anything I could not execute is marked UNVERIFIED, never PASS.

**Relationship to prior passes.** `docs/reviews/2026-10-02-space-bunny-…`
("the 10-02 pass") and `…-luna-…` reviewed `4c9f279`. All four of the
10-02 blockers and all six of Luna's blockers have been addressed in the
76 commits since. I re-verified each rather than assuming, and I record
the disposition in §9.1 so the next reviewer does not re-litigate them.

---

## 1. Verdict, up front

**Every gate I could run is green. The case for DO NOT SHIP is weak,
and I do not think it succeeds.** §9 states that plainly and explains
why the argument I was asked to make does not hold against the tree as
it stands.

Three things are true at once, and the tension between them is the
useful part of this review:

1. **The engineering is in good shape and the evidence is unusually
   honest.** 1404 tests, three clean runs, no flakes; a slow profile
   that exercises the outage and saturation legs; both previously
   ignored live-public-relay interop tests pass here, three extra
   times; both previously ignored macOS FUSE mount tests pass; the
   10-02 P0 truncation defect is fixed and I confirmed the fix by
   running the test that pins it; a systematic peer-reachable-panic
   audit found zero. `docs/resource-limits.md`,
  `docs/crash-consistency.md`, `docs/fetch-on-open.md`, and
  `docs/peer-repair.md` state their own boundaries, including the ones
   that are unflattering.

2. **The release is deliberately not cuttable.** `.ngit/release.yaml:1-8`
   is a banner that says "Do NOT cut a v0.2 release", and
  `.ngit/act/workflows/dist.yml:37` disables the only publishing job
   with `if: false`. `Cargo.toml:15` is still `0.1.0-alpha.1` and
   `CHANGELOG.md` has no `[Unreleased]` section. This is a recorded
   scope decision, not an oversight — §2.5 and §2.6 work through it.
   So "should v0.2.0-alpha ship" is, today, a question about a
   decision the project already made.

3. **A small number of specific claims are false or unproven, and they
   are cheap to fix.** One user-facing capability claim in the README
   is false (§2.3, finding D-1). The two failure-mode legs that the
   ROADMAP's limitations paragraph leans on are self-declared
  UNVERIFIED (§3.3, finding C-4). The single relay behaviour that would
   make control-plane delivery silently wrong is unmodelable and
   untested (§3.1, finding B-2). None of these is a data-loss defect.

If the intent is to cut v0.2.0-alpha anyway, my recommendation is:
land §2.1 (the changelog), fix §2.3's D-1, and either close or
explicitly carry §3.3's C-4 — then flip the two gates and cut. None of
that is a redesign.

---

# 2. Task A — what must be true for the release cut, and what is missing

## 2.1 Version and CHANGELOG

### Findings

| # | Finding | Evidence |
|---|---|---|
| A-1 | Workspace version is still `0.1.0-alpha.1` | `Cargo.toml:15`; every member inherits it |
| A-2 | `CHANGELOG.md` has **no `[Unreleased]` section**. Its only level-two heading is `## [0.1.0-alpha.1]` (`CHANGELOG.md:22`), and the header promises releases "rename `[Unreleased]` below to its version" (`CHANGELOG.md:6`). There is nowhere to put v0.2 notes. | `CHANGELOG.md:1-54` read in full; `ngit release publish` extracts from the section matching the version (`.ngit/release.yaml:14-16`) |
| A-3 | `nix build .#wyrd-dist` therefore produces an **alpha.1-named** archive: `result → /nix/store/35hkrlfv…-wyrd-0.1.0-alpha.1-macos-aarch64.tar.gz`. `release.yaml` names its assets `dist/wyrd-{version}-…`, so a `v0.2.0-alpha` tag without a version bump yields an archive no v0.2 manifest would accept. | I built it; `.ngit/release.yaml:47-67` |
| A-4 | The `## Compatibility first` header (`CHANGELOG.md:8-20`) states the general pre-1.0 rule but **does not name the one format break that actually landed** (see §2.2). An alpha.1 operator reading the v0.2 release notes would not learn that their drive will not open. | `CHANGELOG.md:8-20` vs `docs/upgrade-contract.md:158-161` |

A-1/A-2 were raised in the 10-02 pass as "Blocker 4" and filed against
`chore(release): keep v0.2 distribution disabled`. I am **not**
re-reporting them as defects — they are the deliberate gate. What I am
reporting is new: **A-3** (the archive name consequence, which no prior
review states) and **A-4** (the compatibility break is absent from the
changelog, which no prior review states).

### Missing CHANGELOG entries

Enumerated from `git log v0.1.0-alpha.1..HEAD` (658 commits, filtered
to `feat`) cross-checked against `docs/cli.md` §Subcommands. Every entry
below is a capability present in the tree and absent from
`CHANGELOG.md`. Drafted as Keep-a-Changelog bullets.

```markdown
## [Unreleased]

### Added

- Headless synchronization without a mount: `wyrd sync status` reports
  durable sync state (pending outbox obligations, known membership tip
  against held epoch secrets, live heads with classification counts,
  mailbox posture) and never connects; `wyrd sync now` runs the mount's
  sync machinery with no FUSE session, bounding the run at 32 passes
  and reporting quiet, quiet-with-unfetchable-heads, or the pass cap.
- `wyr member list | log | status | remove | rotate | set-owner`: offline membership-log projection plus owner-gated
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
  materialization policy, two independent columns (POLICY and intent vs
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
  reinterpreted. See §2.2.
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
  (`live_mount_preserves_dirty_handle_across_shutdown`). I ran it: pass.
- `establish_drainer` no longer `expect`s drainer readiness; a drainer
  that dies before signalling is a reported transport error, and the
   supervisor rebuilds (`dropped_readiness_reports_a_transport_error_not_a_panic`).
- Removal of an unreadable or non-file custody record is refused before
  the store opens.
- Capability `unwrap` no longer accepts a secret vector shorter than the
  transition's epoch.
```

## 2.2 Compatibility — does a current drive open?

**Format version: unchanged.** `wyrd_format::envelope::VERSION` is
`0x00` at `v0.1.0-alpha.1`
(`git show v0.1.0-alpha.1:crates/wyrd-format/src/envelope.rs`, line 27)
and `0x00` at HEAD (`crates/wyrd-format/src/envelope.rs:36`). Only two
commits touched that file since the tag, both documentation/freeze work.

**Object identity: unchanged.** The four `content_context()` strings and
the four envelope kind bytes are byte-identical at the tag and at HEAD
(`git show v0.1.0-alpha.1:crates/wyrd-format/src/identity.rs:41-59` vs
`crates/wyrd-format/src/identity.rs:48-66`). Commit `7f83d2b` *froze*
this contract — it documented that `ContentId` derives from the
canonical payload and not from envelope framing, and added golden-vector
and framing-invariance tests. It did not move any address.

**Durable fact log: versioned, and it moved.** `COMMIT_VERSION` is
carried in the commit envelope. Two new record tags landed since the
tag: `BootstrapPending` (`0x13`) and `CapabilitySealedReplaced`
(`0x16`), plus the whole reader-role set of transitions.

**The break.** `git --no-pager diff v0.1.0-alpha.1 HEAD --
crates/wyrd-format/src/membership.rs` shows the canonical transition
document gained a `readers_root: [u8; 32]` field between `owners_root`
and `author`, and a `0x04 AdmitReader` change tag. The preimage changed
by 32 bytes, so `TransitionId` changed for every transition. The decoder
is length-guarded (`from_canonical_bytes` uses a `need(pos, n)` closure
with `checked_add`, `crates/wyrd-format/src/membership.rs:369-375`), so
an alpha.1 transition body **fails to decode** rather than misparsing.

**What that means, precisely.** `docs/upgrade-contract.md:158-161`
states it: "The `v0.1.0-alpha.1` fixture went out with the reader-set
format break: pre-v1 alphas may break compatibility, and no legacy
transition decoder is carried for unshipped software. The next release
cuts a fresh fixture and re-enables cross-release replay."

So: **a drive from current (master) opens under current, obviously. A
drive created by v0.1.0-alpha.1 does not open under master.** Under
upgrade-contract invariant 10, a known record tag whose payload will not
parse poisons the commit file, so open and resync refuse it —
**loudly, by design**. I did not run this end to end: the fixture is gone
(`crates/wyrd-contracts/tests/fixtures/stores/` contains only `dev/`)
and `upgrade_previous_release_store_replays` is an `#[ignore]`d
`todo!()` (`crates/wyrd-contracts/src/upgrade_contracts.rs:259-262`).
The loudness of the refusal is therefore UNVERIFIED by me; the
incompatibility is documented by the project and confirmed by the diff.

**Trust-protocol changes: yes, and they are forward-only.**
`ROTATION_VERSION` moved `0x01 → 0x02` (a third blob: the owner proof).
Under invariant 10 that fails loudly as `UnknownVersion`, not a silent
reinterpretation, and the `CapabilitySealedReplaced` tag is the one
deliberate forward-compatibility exception: an old node skips `0x16` and
keeps treating the superseded bytes as the obligation
(`docs/upgrade-contract.md:102-140`). Both directions are documented;
the tag boundary is pinned by
`the_replacement_tag_is_a_clean_upgrade_boundary`.

**CLI: massively changed** — §2.1 lists ~11 new subcommands and two
removed ones (`cargo run -p wyrd-cli` did not exist at the tag; the
binary lived in `crates/wyrd-daemon/src/main.rs`, and the workspace had
5 members rather than 8). `AGENTS.md:60-64` documents
`cargo test -p wyrd-cli`, which is correct at HEAD and was meaningless at
the tag. This is worth stating in the release notes because anyone with
alpha.1 muscle memory will type the wrong thing.

**Wire (relay): unchanged** — same NIP-59 four-layer framing, rumor kind
9501, recipient `#p` tag, kind 1059 gift wrap. The only wire-adjacent
change is per-relay accounting on send.

**Verdict for §2.2.** The compatibility answer an operator needs is
"alpha.1 drives do not open; they refuse loudly; here is why." That
answer exists in `docs/upgrade-contract.md` and in **no** release-note
surface, because there are no release notes (§2.1). This is finding
A-4.

## 2.3 Doc drift in README.md and ROADMAP.md

The brief assumed README/ROADMAP describe "a much smaller product" than
the code, and that ROADMAP Phase 1 "Remaining" still lists the serving
router and NIP-46. Both halves of that premise are **out of date**, and
I checked each:

- **ROADMAP Phase 1 "Open from this phase"** (`ROADMAP.md:120-134`) now
  lists exactly two items — NIP-46 remote signing, and bulk backpressure
  under live network conditions — and marks each with a status call.
  The serving router is in the **Landed** list
  (`ROADMAP.md:106-111`). Both remaining items are accurately remaining:
  `control/nip46.rs` is wire codecs only with no session-negotiation
  implementation, and fetch is single-threaded per pass with no
  concurrency limit. **Refuted — no finding.** The 10-02 NB-2 was fixed
  by commit `962348d`.
- **README Status** (`README.md:83-106`) now names the supervised
  mailbox, multi-relay operation, cross-implementation proof, the
  serving router, the read-write mount, and the headless surface.

The real drift runs the **other** way — README overclaims.

| # | Location | False or stale statement | Proposed replacement (not applied) |
|---|---|---|---|
| D-1 | `README.md:71` | "* **Time Travel:** Historical snapshots and previous roots can be browsed using ordinary file manipulation tools." **False.** No operator surface reads back a non-head snapshot. `docs/cli.md:210-212` says so in as many words: "the unselected versions survive only inside the merge's parent heads, **which no v0 surface reads back**." `ROADMAP.md:374-377` assigns "historical snapshots, restore of previous versions, arbitrary snapshot browsing" to **v0.5**. The mount takes no snapshot selector (`mount` args: `crates/wyrd-cli/src/main.rs:88-103`); `export` takes none (`:109-116`); `DriveView` reads only its installed head vector (`crates/wyrd-fuse/src/view/drive.rs:31-35`, `:131-140`); the `@N` grammar is conflict-version selection among *current* heads, not history (`crates/wyrd-fuse/src/view/grammar.rs:1-12`, `:66-72`). | "* **Conflict Versioning:** when concurrent publishes produce multiple heads, both versions stay reachable and the mounted view and export address them as `name@N` siblings, numbered in SnapshotId byte order. Browsing arbitrary historical snapshots and restoring previous versions is **not** available in v0.2; it is v0.5 work (`ROADMAP.md`)." |
| D-2 | `README.md:133` | `crates/wyrd-fuse` described as "The drive as a filesystem: live view, **time travel**, visible conflicts." Same false claim, in the crate table. | "`crates/wyrd-fuse` \| Mount-free drive view: live projection, conflict-version lookup, visible conflicts. It links no transport — not even transitively (contract 34)." |
| D-3 | `README.md:129-137` | The Repository Layout table lists **6 crates**; the workspace has **8**. `wyrd-core` (the embeddable node) and `wyrd-namespace` (the provider-neutral value model and verification-proof token) are both missing. | Add two rows: "`crates/wyrd-namespace` \| Provider-neutral namespace model: value types, the verified-head handle, the read surface every presentation backend serves. Depends on `wyrd-format` and `thiserror` only." and "`crates/wyrd-core` \| Embeddable local node: namespace, snapshots, mutations, materialization, sync control. Never FUSE, argument parsing, errno mapping, or process supervision." |
| D-4 | `README.md:135` and `:212` | The CLI row and the closing prose describe the binary as "`init`, `mount`, `export`". It implements **~20** subcommands (`crates/wyrd-cli/src/main.rs:79-217`): `member`, `device`, `sync`, `pin`, `unpin`, `evict`, `cache`, `snapshot`, `remove`, `set-owner`, `resolve`, `invite`, `reissue-invitation`, `join`, `pairing-request`. | "`init`, `mount`, `export`, `member`, `device`, `sync`, `pin`/`unpin`/`evict`, `cache`, `snapshot`, diagnostics, exit codes over the daemon's surface." |
| D-5 | `README.md:83-106` (Status) | Status names the mailbox, serving router, and mount but omits the headless surface, materialization policy, membership administration, and snapshot merge — the four largest user-visible additions. This is an omission, not a falsehood. | Add one sentence: "`wyrd sync status`/`now`, `wyrd member` administration, `wyrd snapshot merge`, and `wyrd pin`/`unpin`/`evict`/`cache` are also in place." |
| D-6 | `README.md:269-275` ("What it is not") | "peer sync is not hardened (signer-session wiring is still open and live-internet relay evidence stays opt-in)". Both halves are true, but "not hardened" directly contradicts `ROADMAP.md:203-227`, where v0.2's whole thesis is "Trustworthy live synchronization" and the Ship list is largely landed. For an alpha this is defensible caution; for a *release cut* it under-sells. | "peer sync is bounded but not yet proven at scale: signer-session (NIP-46) wiring is still open, live-public-relay runs stay opt-in hand evidence rather than a gate, and the e2e partition/heal suite is not in CI." |
| D-7 | `docs/cli.md:13-25` | The usage block **omits `wyrd snapshot` entirely**, although the body documents it at `docs/cli.md:172-218` and `crates/wyrd-cli/src/main.rs:136` defines it. | Add the line: `wyrd snapshot --identity-file <path> --passphrase-file <path> <drive_dir> (list | heads | plan [--head <id>...] | merge [--head <id>...] [--default @N] [--take path=@N]... [--drop path]...)` |
| D-8 | `docs/epochs.md:443`, `:536`; `crates/wyrd-fuse/README.md:10-11`; `crates/wyrd-fuse/Cargo.toml:6`; `crates/wyrd-fuse/src/lib.rs:1` | Five more places assert that superseded/stranded/voided snapshots are "visible through time travel" / that the crate is "the live view and time travel". Same false claim as D-1, in the normative epoch doc and in a crate's own front matter. | Replace "visible through time travel" with "visible through the head listing (`wyrd snapshot heads`) with their classification and reason; their contents are never projected and never served to a live view". Replace "time travel" in the `wyrd-fuse` descriptions with "conflict-version lookup". |

D-7 and D-8 are inside `docs/` and `crates/`, which the brief scoped to
README/ROADMAP; I include them because they are the same defect as D-1
and leaving them out would send the next reader looking in the wrong
place. I did not touch the `page/` marketing site, which carries the same
claim in three places (`page/index.html:587`, `:613`, `:747-753`).

**Not a finding, recorded so it is not re-filed:** `README.md:41-43`
(peer-repair fallback) and `:46` (vault metadata) now match
`docs/peer-repair.md` and `docs/trust.md` T17 closely enough that I found
no claim to correct. `README.md:99-101`'s relay-pool description matches
`crates/wyrd-core/src/mailbox/mod.rs` and `docs/sync-and-peers.md:67-79`.

## 2.4 ROADMAP's limitations paragraph vs the StoreLocked reality

`ROADMAP.md:229-277` "Known v0.2 limitations" says: "the local
store is **cooperative**, so concurrent non-cooperating writers are
outside the supported concurrency model."

That is now stale in its first half. `DurableStore::open` takes an
exclusive `flock` on `<drive_dir>/LOCK` before it reads or writes
any store state, and returns `DurableError::StoreLocked` on
`WouldBlock`:

- `crates/wyrd-sync/src/durable/store.rs:121-133` — the lock, the
  `try_lock`, the `WouldBlock → StoreLocked` mapping.
- `crates/wyrd-sync/src/durable/store.rs:113-120` — the code comment
  already states the correct distinction: "The lock guards cooperating
  callers — every open runs through here; the commit chain still detects
  damage from non-cooperating writers, it never serialized them."

So the code comment is right and the ROADMAP sentence is the stale
artifact. The honest sentence needs both halves. What is genuinely
still cooperative: `flock` is advisory and inode-scoped, so a writer
that bypasses the store API (direct writes into the directory, a copy of
the drive directory at a different inode, a filesystem that does not
honour `flock` such as some NFS/CIFS mounts) is not serialized.

**Proposed replacement text for `ROADMAP.md:231-233`:**

> The local store takes an exclusive lock on its directory before it
> reads or writes any state, so a second cooperating process
> fails closed with a lock error rather than racing. The residual is the
> lock's own semantics: it is advisory and inode-scoped, so a writer
> that bypasses the store API — writing into the directory directly, or
> a copy of it at a different inode — is not serialized. The commit
> chain detects damage from such a writer; it never prevented it.

Pinned by `concurrent_open_is_rejected`, and
`lock_releases_on_drop` (`crates/wyrd-sync/src/durable/tests.rs:63-88`),
and observed from the CLI by `sync_status_refuses_a_locked_drive`
(`crates/wyrd-cli/src/tests_sync.rs:375-387`). `docs/cli.md:265`, `:292-294`
and `:381-384` already state the exclusive-lock behaviour correctly, so
this is a ROADMAP-only drift.

## 2.5 Merged, honest limitations list for the release notes

Consolidating §2.4 and the limitations that live only in other docs, for
the release notes. Each item names where it is currently documented, so
the notes can point rather than restate.

1. **Control-plane delivery is relay-accepted, never recipient-received.**
   The outbox commits a `Delivered` fact only when at least one relay
   accepted the write (`crates/wyrd-sync/src/runtime/author/deliver.rs:172-179`);
   recipient receipt is never reported by the send path. A peer absent
   past the relay's retention finds no event to fetch, and v0.2 provides
   **no re-push and pull path** for control messages never received.
   A refused obligation retries every pass with no ceiling, no backoff, and no attempt counter.
   Documented: `docs/sync-and-peers.md:80-97`,
   `ROADMAP.md:252-261`. **Operator visibility: none.** `SyncStatus`
   (`crates/wyrd-core/src/status.rs`) reports the local tip, held epochs,
   and local obligations; it structurally cannot report what a peer is
   missing, because the peer does not know.
2. **No automatic peer repair and no local scrub.** Corrupt or
   unreachable representations fall back to the next recorded
   representation inside the fetch walk (transport root before storage
   address), hash/AEAD-verified, never committed on mismatch, bounded
   `EIO` when no representation serves. Route publication records **one
   serving peer per snapshot**, so the alternates are representations, not
   providers. Local bitrot is detected on read but never re-fetched: an
   object recorded as local stays local, so a bitrotted object is a
   permanent read error in v0.2. `FetchStatus::Corrupt` and `Unavailable`
   are vocabulary only; `status()` never returns them.
   Documented: `ROADMAP.md:232-241`, `docs/peer-repair.md:14-32`,
   `docs/sync-and-peers.md:296-311`.
3. **Two failure cases, split normatively** — a known snapshot whose
   manifest chain cannot be materialized within the deadline fails
   `open()` bounded (`EIO`); an announcement whose body never arrives
   leaves the snapshot unadopted, so a later snapshot built on it
   classifies `UnknownParent` and its paths never enter the projected
   namespace (`ENOENT`, never a hang). **Both end-to-end legs are
   self-declared UNVERIFIED** — see finding C-4.
   Documented: `ROADMAP.md:242-252`, `docs/fetch-on-open.md:283-311`.
4. **Admission walks the live epoch chain's ancestry in one commit.**
   O(recorded history) allocation and one call, committed with
   the admission batch; past the 65,536-record per-commit ceiling the
   admission is refused whole, never truncated. The walk covers the live
   epoch's chain only, so a newcomer admitted epochs later does not
   re-walk superseded chains — and therefore does not learn the old
   snapshot ids for those epochs. Not a v0.2 blocker: it needs a long
   single-epoch history plus an admission and violates no bound.
   Documented: `ROADMAP.md:262-277`, `docs/resource-limits.md:82-108`.
5. **The local store is lock-guarded, not serialized against
   non-cooperating writers** (corrected text in §2.4).
6. **Stranded local content has no sanctioned path back** until the v0.3
   content-recovery workflow. The recovery-grafting primitive
   (`Engine::author_recovery_snapshot`) is public and contract-tested,
   with **no CLI command and no daemon entry point**; the owner
   recovery-snapshot creation workflow is v0.3. This is **crash recovery
   only** in what v0.2 ships.
   Documented: `ROADMAP.md:215-217`, `:279-289`.
7. **Serving is member-hosted in v0.2.** The serving endpoint opens from
   a member process holding the identity, epoch keys, and the live
   mailbox, and has **no per-requester admission**: it withholds
   *discovery* (no listing, no enumeration, and the (address, hash)
   pairs that make a lookup possible travel only inside sealed
   announcements to members and readers). A member who can name a
   `StorageId` can request its ciphertext from any serving member; a
   **removed** device that retained a previously announced route can
   still fetch any content whose transport root it already learned
   (removal bounds *acquisition* — it cannot open announcements bound to
   epochs after its removal because it never receives those epoch keys).
   This is an availability/enumeration property, not a confidentiality
   break: the holder already holds the epoch material that makes the
   ciphertext meaningful.
   Documented: `docs/trust.md:868-873`, `:875-917`, T17 at `:983`;
   `crates/wyrd-sync/src/serving.rs:759-782`.
   **The removed-device residue is stated nowhere else** — not in the
   ROADMAP limitations, not in `docs/cli.md`'s `member remove` section.
   New finding, below.
8. **Peer roles are not wired.** `vault` and `mirror` are protocol
   vocabulary; the shipped serving surface is member-hosted. No operator
   surface declares a role.
   Documented: `README.md:77`, `docs/sync-and-peers.md:169-186`.
9. **Live bulk-fetch concurrency is unbounded**; backpressure is a
   per-pass byte and admission budget, not a semaphore.
   Documented: `docs/resource-limits.md:26-30`, `:131-142`,
   `ROADMAP.md:129-134`.
10. **The retained-bytes quota is unset by default** and, when set,
    covers only the mounted write path: fetched bytes, the vault, the
    fact log, and pre-live `put_file`/`remove` all raise the count
    without a refusal, so the device's total is not bounded by that
    number.
    Documented: `docs/resource-limits.md:57`,
    `docs/storage-growth.md`.

**New finding from this merge:**

| # | Finding | Evidence |
|---|---|---|
| A-5 | **Removing a device does not stop it fetching content whose transport root it already learned, and this is stated in no operator-facing doc.** The serving endpoint has no per-requester check by design (`crates/wyrd-sync/src/serving.rs:759-769`), announcement history is append-only with no cryptographic invalidation (`docs/trust.md` T17), and the removal contract explicitly scopes out the snapshot-transfer half: "The snapshot-transfer half (announcement plus bulk fetch) is out of scope" (`crates/wyrd-contracts/src/removal_contracts.rs:6-9`). `docs/trust.md` frames the accepted consequence for *members* ("a member who can name a `StorageId` can request that ciphertext from any serving member") but never for a *removed* device. `docs/cli.md`'s `member remove` section says nothing about retained content or retained routes. | as cited |
| A-6 | **`sync now` with no `--relay` exits 0 having done nothing**, pinned as success by `sync_now_on_quiet_drive_completes` (`crates/wyrd-cli/src/tests_sync.rs:681-688`). The only signal is `warning: no --relay given; control-plane intake stays idle` on **stderr** (`crates/wyrd-cli/src/main.rs:1730-1732`). A cron or systemd unit keying on exit status cannot distinguish this from a converged sync. `docs/cli.md:320-322` documents the flag's effect but not the automation hazard. | as cited |

A-6 is a real automation hazard for the "operated without a mounted
FUSE filesystem" DoD clause, which is exactly where cron lives. Cheapest
fix is a line of documentation; the code fix would be refusing
`sync now` without `--relay` unless `--offline` is passed.

## 2.6 Does the scope contradiction still exist?

**No. It has been resolved by an explicit, recorded decision, and the
resolution is enforced in both the human and the machine half.**

The 10-02 and Luna passes both flagged this: `ROADMAP.md:215-220`
says "Explicitly do not ship … release distribution", while
`.ngit/release.yaml` and `.ngit/act/workflows/dist.yml` ship archives.
Commit `a9e7b88` / `8682305` ("chore(release): keep v0.2 distribution
disabled") resolved it:

- `.ngit/release.yaml:1-8` is a banner above the schema: "# v0.2 SCOPE:
  distribution is out of scope for this milestone … Do NOT cut a v0.2
  release: no tag, no `build --strict` release run, no `ngit release
  publish`. The runbook below resumes with the v0.3 dogfood
  distribution track. (The CI half is enforced by `if: false` on the
  dist.yml publishing job; this banner gates the human half.)"
- `.ngit/act/workflows/dist.yml:37-40`: `if: false` on the only job that
   builds or uploads anything, with the comment "The name says
  why a tag-triggered run skips this job without opening the file."
- `README.md:220-224` now says "Release archives … ship with ngit
  releases — but v0.2 publishes none: distribution is explicitly out of
  scope for this milestone … so there is nothing to download yet."
- `docs/cli.md` and the ROADMAP do not need to change; the gate is
  enforced, not merely described.

So the contradiction is closed, in the direction of the ROADMAP. The
residual is finding A-3: the archive *name* still derives from
`Cargo.toml:15`, so the machinery is present and would produce a
misnamed artifact if someone tagged without bumping.

**My judgement on the scope question itself:** this is the right call
for v0.2 and I would not argue against it. Shipping four per-platform
tarballs on top of a release whose own release notes do not exist would
create a distribution surface with no documented compatibility story —
which is exactly the `docs/upgrade-contract.md:158-161` break, handed to
users as a download.

## 2.7 Does the pipeline produce what the release notes will claim?

Reviewed `.ngit/release.yaml`, `.ngit/act/workflows/workflow.yml`,
`.ngit/act/workflows/dist.yml`, `deny.toml`,
`flake.nix`'s `wyrd-dist`.

**The pipeline is complete and, for v0.2, correctly inert.**

| Element | Verdict | Evidence |
|---|---|---|
| `.ngit/release.yaml` manifest | Well-formed; names four platforms with the `wyrd-{version}-{platform}` template; notes extracted from `CHANGELOG.md` by version section | read in full, `:1-67` |
| dist publishing | **Disabled for v0.2 by `if: false`**, deliberately, with a comment naming the re-enable procedure (delete the `if:` line and the comment block) | `dist.yml:37-40` |
| Build pipeline (`workflow.yml`) | `cargo check`, `clippy -D warnings`, a production-feature-graph assertion (`insecure-fast-kdf` must not appear), `nextest run --workspace`, `nextest --profile slow` (master only), doctests, `cargo audit`, `cargo deny check`, `nix flake check`, and a master-only release-archive smoke test through `.ngit/scripts/build.sh --verify` | `workflow.yml:95-260`, `:330-352` |
| `deny.toml` | `[advisories] yanked="warn" unmaintained="workspace" unsound="all"` — the 10-02 NB-9 (no `unsound` policy) is **fixed**; the `faster-hex` RUSTSEC-2026-0306 precedent is recorded with the resolution and no exception needed. Licenses, sources, bans all fail closed; duplicate versions warn. | `deny.toml:17-30`; I ran `cargo deny check`: **advisories ok, bans ok, licenses ok, sources ok** |
| `nix flake check` | I ran it: **all checks passed**, with nix's own note that it "omitted these incompatible systems: aarch64-linux, x86_64-darwin, x86_64-linux" on this aarch64-darwin host | my run |
| `nix build .#wyrd-dist` | I ran it: produced `wyrd-0.1.0-alpha.1-macos-aarch64.tar.gz` — the build works, the name is version-derived (finding A-3) | my run |
| microVM e2e suite in CI | **Not in any workflow.** `grep -n 'microvm\|lima' .ngit/act/workflows/*.yml` returns nothing. `AGENTS.md:88-90` calls it "the hardened gate", and the ROADMAP's DoD clauses "survive partition, survive restart" are only provable there. | grep; `AGENTS.md:88-90` |
| live-relay tests in CI | **Not in any workflow, by rule.** `.config/nextest.toml` and `workflow.yml:150-153` state opt-in tests needing a public relay or kernel FUSE "stay `#[ignore]`d and never run in CI". I ran them; they pass. | `workflow.yml:150-153`; my run |
| `cargo audit` | Installed and run by the pipeline. I did not run it separately (the 10-02 pass did: exit 0). | `workflow.yml:262-280` |

**The answer to the task's question is "no, and that is deliberate."**
The pipeline produces nothing for v0.2, and the release notes the
pipeline would extract are empty (§2.1). There is no claim to match yet.
When the gate is flipped, the pipeline *will* produce what the manifest
names — with the caveat that the version source is `Cargo.toml`, not the
tag, and they currently disagree.

---

*Part 2 (Tasks B–H) follows below.*

---

# 3. Task B — "multi-relay mailbox operation" and "relay interoperability"

## 3.1 Inventory of every relay used in tests

| Relay | Where | Kind | What it models | Run by me? |
|---|---|---|---|---|
| `MiniRelay` | `crates/wyrd-core/src/mailbox/mini_relay.rs`; `#[cfg(test)]`-only (`mailbox/mod.rs:193-194`) | Minimal in-process NIP-01 over `tokio-tungstenite`, localhost `ws://` | `EVENT` publish (store, `OK`, broadcast to matching subs), `REQ` (replay + `EOSE` + register), `CLOSE`; hard outage (abort accept + core + every connection task) and serving; restart on the same URL **with retained history**; three policy knobs: `reject_writes` (`OK false`, nothing stored or broadcast), `close_subscriptions` (`CLOSED`, nothing registered or replayed), `challenge_auth` (NIP-42 `AUTH` after replay, before `EOSE`, then served normally). Deliberately **no signature verification** (`:5-7`) so tests can inject garbage. Store is an unbounded `Vec<Event>` (`:45`, `:409`). | yes — 30+ tests |
| `RealRelay` | `crates/wyrd-core/src/mailbox/tests_crossimpl.rs:41-97` | `nostr_sdk::local_relay::LocalRelay` on its own multi-thread runtime | Real NIP-01: event-id/signature verification, real `OK` frames, in-memory database with real query and replay. Real shutdown (breaks accept loop + connection tasks) and restart on the same URL with the same database. | yes — 1 test, in the default gate |
| `nostr-rs-relay` (process) | `tests/alpha-lima.sh` step 6 ("live relay convergence"); `tests/alpha-microvm.sh` + `tests/alpha-microvm-legs.sh`; topology in `nix/microvm/` | Real relay **process** in a NixOS guest / microVM | Real TLS-less websocket relay, real policy, two hosts. **One relay URL per run** (`tests/alpha-microvm.sh:35-40`). | **NO** — needs a Lima guest / Linux KVM |
| Public relays | `crates/wyrd-core/src/mailbox/tests_interop.rs:94`, `:144` — two `#[ignore]`d tests | Real internet relay, default `wss://relay.primal.net`, override with `WYRD_TEST_RELAY_URL`; enforced `wss://` (`:68-71`) | Real TLS, real relay write/read policy, real history retention and replay. **One relay per run.** | **YES — 4 invocations, 8/8 pass** |

The 10-02 pass reported "no multi-relay test" and named
`nos.lol` as the proven relay. Both are now stale: `tests_multirelay.rs`
exists (§3.3) and the proven relay is `relay.primal.net`, with the
policy evidence for `relay.damus.io` (attaches, ACKs writes, `CLOSED:
auth-required` on every gift-wrap `REQ`) and `nos.lol` (no TCP from the
author's vantage) recorded in the test file's own header
(`tests_interop.rs:20-29`).

## 3.2 Real-relay behaviors MiniRelay does **not** model

For each: what the supervisor in `crates/wyrd-core/src/mailbox/mod.rs`
actually does, with the code path.

| Behavior | Modeled? | Supervisor behavior (cited) | Assessment |
|---|---|---|---|
| **Retention / eviction** | **No** — store is an unbounded `Vec` (`mini_relay.rs:45`, `:409`) | **Nothing.** No code path in `mailbox/mod.rs` tracks a relay's retention, and none could: the mailbox has no cursor to lose (`:29-32`) and redelivery is expected to come from relay replay. | The documented v0.2 hole. `ROADMAP.md:256-261`, `docs/sync-and-peers.md:95`. `disconnected_peer_acquires_missed_history_over_real_relay` proves acquisition **within** retention and says so itself (`tests_catchup.rs:29-32`). Accepted limitation; see B-1. |
| **Rate limiting / `OK false` with a reason** | Yes — `reject_writes` (`:218-225`, core at `:401-412`) | `send` classifies per relay into accepted / not-accepted with the relay's verbatim message, logs `mailbox send relay outcome` at debug (`mailbox/mod.rs:1659-1668`), returns `SendReport{accepted}`; the engine keeps the obligation **pending** when `accepted == 0` (`deliver.rs:172-179`) | **Covered.** `tests_delivery.rs:190-215` (zero acceptance, recipient hears nothing, accept mode resumes), `:248-270` (engine outbox through a live refusal: `deliver_pending` returns 0, `has_pending_outbound` true, then discharges), `:310-338` (log line carries the message verbatim), `tests_mailbox.rs:458-484` (classifier with one accepted + one refused). |
| **NIP-42 auth challenges** | Partly — `challenge_auth` sends `AUTH` after replay, before `EOSE`, **then serves normally** (`mini_relay.rs:93-98`, `:442-444`) | Warns loudly, never answers (`mailbox/mod.rs:1135-1142`) — correct: answering signs with the device key, which `trust.md` forbids | Half-covered. `tests_delivery.rs:1351` asserts via `observed_frames` that the client never emits an `AUTH` frame. **Not** modeled as the composed real episode (challenge **then** `CLOSED`, which is what `relay.damus.io` does). The two halves are each modeled; the composition is not. Low risk. |
| **Duplicate delivery** | Yes — two relays both broadcast the same wrap | `recv` collapses on seen / poison / held before a handover is minted (`mailbox/mod.rs:1688-1693`); the drainer listens to **both** SDK arms because `Message` fires for every `EVENT` frame including resubscribe replay (`:1089-1092`, pinned by `mailbox::tests_classification`) | **Covered.** `tests_multirelay.rs:54-65` asserts two payloads delivered exactly once then `assert_quiet`. |
| **Out-of-order delivery** | Weakly — store order only; `Command::Inject` appends (`mini_relay.rs:414-417`) | Order-independence lives in the engine, not the mailbox | **Covered hermetically**, not live: `reversed_arrival_converges_to_the_same_outcome` (`engine/tests_properties.rs:84`), and `tests_catchup.rs:210-215` explicitly notes its counts "depend on relay store order" and pins them anyway. Fine. |
| **`EOSE` timing** | Synchronous, immediately after replay (`:445`) | **Ignored entirely** — `EOSE` is not in the drainer's match arms (`mailbox/mod.rs:1154`, `_ => None`) | **Non-issue by design.** The mailbox has no cursor and no "stream complete" signal, so relay `EOSE` timing cannot affect it. Stated because the task asked: this behavior is modeled by *not needing it*. |
| **Subscription limits per connection** | No — subs are keyed `(conn, sub_id)` so many are accepted | Own defense: one stable subscription id per mailbox, `CLOSE` before `REQ` (`resubscribe`, `mailbox/mod.rs:1271-1291`) | **Covered.** `tests_catchup.rs:524-535` asserts `relay.subscription_count() == 2` for two mailboxes after a resubscribe; `saturation_recoveries_keep_single_subscription` (slow profile, passed). A relay that caps subscriptions sends `CLOSED`, now counted and surfaced (`closed_subscriptions`). |
| **Connection drop mid-subscription** | Yes — `shutdown` aborts accept + core + every connection task; the per-connection task drives socket and outbound queue in one `select!`, so the abort always closes the socket (`:298-317`, and the comment there explains exactly this) | `stream_alive` false → `recover_stream` episode (fresh drainer, `client.connect()`, resubscribe, capped backoff, unbounded attempts); zero connected for 3 ticks → `recover_relays` episode (`mailbox/mod.rs:1396-1466`) | **Covered hermetically and in the slow profile.** `relay_outage_marks_down_and_recovery_redelivers`, `unacked_and_mid_recovery_mail_survive_stream_recovery`, `same_mailbox_acquires_missed_snapshots_across_relay_restart`. Slow profile: **9/9 pass** (I ran it). |
 | **Relays that accept but silently drop** | **No** — `reject_writes` answers `OK false`; there is no mode that answers `OK true`, stores nothing, and broadcasts nothing | **Indistinguishable from success on both sides.** The sender commits `Delivered` (accepted >= 1, `deliver.rs:185`); the recipient never receives; `MailboxHealth` has no counter for "delivered but never received" | **The sharpest remaining control-plane gap.** See finding B-2. |
| **Event size limits relay-side** | No | Not reachable: Wyrd's own outbound bytes are bounded before send (`check_outbound_size`, `deliver.rs:148`, `:727`); an inbound oversize wrap is rejected at `check_relay_event_size` (`mailbox/mod.rs:272-301`) before NIP-59 unwrap, plus the SDK wire backstop (`:269`) | **Covered on the read side** (`docs/resource-limits.md:48-49`). The write side needs no relay cooperation. |
| **`since`/`until` filter handling** | Honored relay-side — `filter.match_event` is nostr's own matcher (`mini_relay.rs:462`, `:482`) | The mailbox sends **no** time cursor; no-cursor is a deliberate decision (`mailbox/mod.rs:29-32`) | **Non-issue.** Filter semantics are the crate's, not ours. |

## 3.3 What `tests_multirelay.rs` and `tests_delivery.rs` cover

`two_relays_cover_publication_replay_outage_and_recovery`
(`crates/wyrd-core/src/mailbox/tests_multirelay.rs:22-181`) — two
independent `MiniRelay` instances (separate sockets, stores, histories),
in one episode:

**Covered.**
- Addressed publication through both; each wrap surfaces exactly once (`:46-65`).
- **Per-relay replay on a fresh log, each relay alone** (`:68-93`). This is the leg that actually proves fan-out, and the comment at `:69-74` explains why a single two-relay subscriber could not: it would see the same two deliveries whether one or both relays replayed.
- Reopen on the original log absorbs the full double replay into silence (`:95-116`).
- One-relay outage → survivor intake; a pool send still resolves `Ok` and still reaches the survivor (`:118-147`).
- Recovered relay rejoins; absorbed replay; new mail once (`:149-180`).

`heterogeneous_relays_cover_publication_replay_outage_and_recovery` (`tests_crossimpl.rs:112-252`) — the
same episode against `MiniRelay` + rust-nostr's real `LocalRelay`, plus
a fresh-log replay against the **rebooted real relay**, which is the
genuine cross-implementation proof (`:216-229`).

**Not covered, and my judgement on each.**

| Scenario | Status | Consequence of the gap | My call |
|---|---|---|---|
| **Partial publication acceptance** (one relay accepts, one refuses) with the count asserted | Not asserted live. The multirelay outage leg sends through the pool with one relay dead and does not check `report.accepted`; the doc comment at `tests_multirelay.rs:120-124` says so explicitly ("the survivor accepts here, so the refusal path is not what this leg observes"). | None material: the classifier is unit-pinned for a mixed outcome (`tests_mailbox.rs:458-484`) and the consumer gate is two-valued — `accepted: 0` retains (`engine/tests_delivery.rs:118`), `accepted: 1` discharges (`engine/tests_harness.rs:332`). Semantics are pinned; only the live count is unasserted. | **Info.** Not worth an e2e leg. |
| **All relays down** | No test. | `is_live()` false, `send` yields `accepted: 0`, obligations stay pending, `sync now` parks or trips the cap. Implied by the single-relay outage leg plus the zero-acceptance leg, never exercised with an empty pool. | **Info.** Cheap unit addition if desired. |
| **Divergent contents across relays** (same wrap on A, not on B) | Not constructed. | Would be benign — dedupe collapses either way. | **Skip.** Low value. |
| **Replay across relays after eviction** | Untestable without extending `MiniRelay` with retention. | This is the past-retention hole (§4.2). | **See B-1 / §4.5 sketch.** |

## 3.4 Is anything in the Definition of done only provable with two real relays?

**No.** The DoD reads "two or more legitimate Wyrd peers connected through
**real relay infrastructure**" (`ROADMAP.md:222-225`) — singular,
"infrastructure", not two relay *implementations*. The e2e suites use a
real `nostr-rs-relay` process, which satisfies the letter; the
heterogeneous hermetic pair satisfies the spirit for pool logic.

The one thing only two live relays could prove is that a **relay-set
disagreement cannot produce a double-commit or a lost obligation**. The
code path is three lines (`classify_send_outcome` → `SendReport.accepted`
→ the `report.accepted == 0` continue in `deliver.rs:172`), the classifier
is unit-pinned for a mixed outcome, and the gate is pinned at both
values. I do not think that needs a live test.

**Smallest additional e2e leg, if you want one:** in
`tests/alpha-microvm.sh`, add a second relay URL for the relay VM and
assert only (a) both peers report 2/2 relays attached after start, (b)
with relay B stopped, a snapshot authored on A is still delivered to the
member, (c) after B restarts, the existing convergence assertion still
passes. Roughly 15 lines reusing the existing relay-VM service and
convergence helper.

**My recommendation: do not add it for v0.2.** The pool logic is pinned
hermetically (two instances), cross-implementation (fake + real), and at
the classifier; the marginal evidence is small next to the cost of
another hand-maintained e2e leg.

## 3.5 The interop run — exact command, and my result

The command (network **was** available, so this is a PASS, not
UNVERIFIED):

```
# default (relay.primal.net)
cargo nextest run -p wyrd-core --run-ignored ignored-only -E 'test(external_relay)'

# explicit
WYRD_TEST_RELAY_URL=wss://relay.primal.net cargo nextest run -p wyrd-core --run-ignored ignored-only -E 'test(external_relay)'
```

Correction to the task's suggested filter: `-E 'test(interop)'`
**matches nothing**. The module is `mailbox::tests_interop` but the two
tests are named `external_relay_gift_wrap_round_trip_over_tls` and
`external_relay_restart_replay_converges`, so the correct expression is
`test(external_relay)`.

Result — 4 invocations (one with the default URL, three with the
override), **8/8 pass**, ~9s each:

```
PASS [   3.898s] wyrd-core mailbox::tests_interop::external_relay_gift_wrap_round_trip_over_tls
PASS [   9.729s] wyrd-core mailbox::tests_interop::external_relay_restart_replay_converges
```

Also note the 10-02 finding that the file documented the wrong crate name
(`-p wyrd-daemon`) is **fixed**: `tests_interop.rs:17-18` now reads
`cargo test -p wyrd-core external_relay -- --ignored`.

## 3.6 Findings

**B-1 — Past-relay-retention has no code path, no test, and exactly one
documentation home. Accepted limitation, but under-evidenced.**
Severity: accepted. Not a defect; listed so §2.5 limitation #1 is read
with its true weight.

**B-2 — A relay that answers `OK true` and silently discards is
unmodelable in the harness, untested, and operator-invisible on both
sides.** Severity: real; the sharpest remaining control-plane gap, and
**absent from every limitations list**.

- `MiniRelay` has no mode for it: `reject_writes` answers `OK false` (`mini_relay.rs:218-225`), `Inject` broadcasts (`:414-417`). The state "acknowledged, stored, never delivered" is not expressible.
- On success the sender commits `Fact::{Announcement,Transition,Capability}Delivered` (`deliver.rs:185`), so the obligation is **permanently retired**.
- The recipient never receives, and `MailboxHealth` (`mailbox/mod.rs:427-466`) exposes no counter that distinguishes this from a peer that is simply absent.
- `docs/sync-and-peers.md:80-97` is precise about relay-*acceptance* being the maximum guarantee, but it never names this case: it says "Recipient received — not guaranteed unless separately acknowledged", which reads as a missing acknowledgement, not as a relay that acknowledged and dropped.

This is the honest limit of the "relay-accepted" contract, and it is
inherent to the design rather than a bug. But it belongs in the release
notes. Cheapest honest fix, one sentence in §2.5 limitation #1:

> Relay acceptance is not evidence of relay storage: a relay that
> acknowledges a write and discards it is indistinguishable from
> delivery, on the sender and on the recipient.

The real fix is an intake-side gap report (known epoch N vs newest
announced epoch M) so `wyrd sync status` can say something — which is a
protocol-adjacent change, already the booked shape of the existing
catch-up issue. I would document, not build, for v0.2.

---

## 4. Task C — acquisition vs convergence, and head gating

### 4.1 The two domains are genuinely separated, and I can name which assertion fails in which regression

**Domain A — state convergence** (given the evidence, do peers reach the same state?): `engine/tests_convergence.rs` (`two_devices_converge_on_shared_history`, `restart_between_intake_and_planning_loses_nothing`, `repeated_restarts_are_idempotent`, `restart_after_partial_plan_resumes_to_convergence`), `engine/tests_properties.rs` (`reversed_arrival_converges_to_the_same_outcome`, `re_execute_without_new_work_commits_nothing`, `large_announcement_history_converges_with_exact_reports`), plus `assert_agreement` over both devices.

**Domain B — history acquisition** (does a peer obtain the *bytes and closure* it missed?): `mailbox/tests_catchup.rs::disconnected_peer_acquires_missed_history_over_real_relay` — asserts 4 snapshot bodies + 4 manifests over live iroh, then 8 objects (chunks + tree blobs), with route counts pinned at exactly 16; and `same_mailbox_acquires_missed_snapshots_across_relay_restart`.

**Which assertions fail in which regression — this is the part that matters:**

| Regression | Fails in domain A | Fails in domain B | Would either domain alone catch it? |
|---|---|---|---|
| Intake drops an announcement | `two_devices_converge_on_shared_history` (heads diverge) | the catch-up test's `acquired.accepted >= 3` loop guard and `ordinary_recorded` check | **Yes, domain A** — the DoD's independence is real in this direction |
| Fetch stops fetching bytes but records announcements | `restart_after_partial_plan_resumes_to_convergence` | catch-up's `first.snapshot_bodies == 4`, `second.objects == 8`, and `objects.get(chunk) == payload` | **Both** — but the *content* assertion exists only in domain B. Domain A's tests use a `MemoryBulkSource` that always fulfills, so they cannot detect a content shortfall |
| Heads install over a partial closure | `partial_head_set_never_projects_mixed_validity_heads`, `a_gated_head_mounts_only_after_its_tree_lands_and_survives_restart` | — | **Domain A** (closure gate tests live in the head-gating set) |
| A peer that missed history still reaches the same *heads* but lacks the *history* | — | nothing asserts this | **Neither.** This is the blind spot the DoD names. It's not reachable today (heads cannot install without bodies), but it is precisely what C-1 below is about |

So: acquisition regressions are caught by both domains; **content-shortfall regressions are caught only by domain B**, because domain A's fixtures always fulfill. That is the correct division and it is what the DoD asks for.

### 4.2 What happens to a peer that reconnects after the relay evicted events

Enumerating the mechanism, not guessing it:

1. The sender retired the obligation when a relay accepted (`deliver.rs:172-185`). There is no re-push list.
2. There is no pull path. `Message` has exactly four variants — `MembershipTransition`, `SnapshotAnnouncement`, `Capability`, `KeyRotation` (`control/message.rs`). No request, no gap-announcement, no "I am missing epoch N".
3. On reconnect the mailbox re-`REQ`s and the relay replays only what it retained. The evicted wraps are gone.
4. The peer's membership log stops advancing. Intake defers announcements bound to unseen transitions (`intake/mod.rs:533` region).
5. Terminal state: the mount shows a **permanently stale drive**, no error anywhere. `reissue-invitation` does not help — it re-mints secrets `1..=epoch-of-admission` (`author/admission.rs:344-357`), not the missed epochs.

**Is it visible via `sync status`?** **No, and it structurally cannot be.** `SyncStatus` reports the local tip, held epochs, and local obligations. Reporting the peer's gap requires the peer to know its own gap, which it cannot: nothing in the message set lets it ask. `sync now` prints intake and fetch counts and an `unfetchable heads` number, which reports *unclosable local heads*, not *missing remote history* — a peer missing epoch 4 has no head for epoch 4 to be unfetchable about.

**Is it silent?** **Yes** — and this is the single most important item in this review for an operator. `ROADMAP.md:256-261` does name it: "The remaining hole is relay retention: a peer absent past retention finds no event to fetch, and v0.2 provides no re-push or pull path for control messages never received." The 10-02 pass correctly called this Blocker 2 and correctly noted it appears in no limitations list; **it is now in the ROADMAP limitations**, added by commit `6b046a6`/`7029a11`. So the documentation half is fixed.

**What is still missing:** the *diagnosability* half. After `ROADMAP.md:256-261`, a peer in this state still cannot tell anyone — not via `sync status`, not via logs (nothing logs "I am missing epoch N" because nothing knows). Cheap partial fix: when intake defers a message because its transition is unseen, log and count it — the deferral is already counted (`deferred` in `DrainReport`), so the operator signal exists but is unlabeled. Suggest: name the deferral reason in the count so `sync status`/`sync now` can say "12 deferred, all membership-unseen" rather than a bare number.

### 4.3 Closure and head gating — where a head becomes live or served, and proof each requires closure completeness

Every install site, and what each requires:

| Site | Requires closure? | Requires authorization? | Cited |
|---|---|---|---|
| `WyrdNode::refresh_live_heads` — **the only production projection into the view** (`node.rs:159-162`) | Yes — `partition_heads` runs `verify_head_closure` per head; `Incomplete` counts as **pending**, not publishable | Yes — `Engine::live_heads` returns only `dag.eligible_head_bodies` (`engine/mod.rs:1160`), each re-verified through `AuthorizedSnapshot::authorize` → `verify_snapshot` | `node.rs:169-197`, `live.rs:548-618`, `engine/mod.rs:1154-1167` |
| Live loop publication | Same `partition_heads`, same gate | Same | `live.rs:548-618` |
| `live_base` for authoring | Yes — it *reads* `live_heads()`, so it inherits the gate | Yes | `node.rs:262-269` |
| Serving (`VaultSource::from_state`) | Serves **representations by transport root from the durable vault** — a head is not a serving input | n/a | `serving.rs:944` |
| Fetch plan | Requires the epoch key per candidate (`UnavailableKey` when absent, `fetch/mod.rs:375-379`) | Yes — epoch key comes from the durable keyring rebuilt from facts | `fetch/mod.rs:375-379` |

**Is there a path where a head is installed or served with a missing manifest, tree, or epoch key?**

- **Manifest/tree: no.** `verify_head_closure` runs on every head before install; `is_pending()` covers the three not-yet-fetched variants (`closure.rs:168-175`); an all-pending set leaves the previously installed heads untouched rather than blanking the view (`node.rs:188-194`); damage fails the refresh closed with per-class counts (`live.rs:587-618`). Pinned by `a_gated_head_mounts_only_after_its_tree_lands_and_survives_restart`, `a_damaged_head_beside_an_installed_one_fails_the_pass_closed`, `snapshot_manifest_closure_correspondence`, `a_mismatched_snapshot_manifest_never_mounts`, `partial_head_set_never_projects_mixed_validity_heads`, and a 19-variant exhaustive `rejection_class` table (`closure.rs:495-515`, `:878-998`).
- **Epoch key: no.** A head whose closure references an epoch the device holds no secret for cannot fetch its content, so it cannot pass closure verification; and the plan itself reports `UnavailableKey` rather than fetching.
- **A bypass exists, but it is not a vulnerability — it is an API-shape observation.** `AuthorizedSnapshot::authorize` verifies **only** the drive-bound BIP-340 signature (`durable/mod.rs:237-245` → `predicates.rs:29-37`); head *eligibility* is enforced by the composer's call site, not by the token. A downstream embedder can therefore obtain a token for a superseded or voided snapshot and install it as a view head. Nothing blocks this at the type level; `wyrd-fuse/view/head.rs:1-34` documents the token as an `unsafe` capability whose "verification already happened upstream". Consequences: (a) not a security boundary — the code doing it already holds the identity and local plaintext; (b) the read still fails closed if the historical bytes are not local (`Materialization` reports `RemoteOnly`). This is finding **C-1**.
- **The `debug_assert!(false, "closure gate saw {unexpected:?}")`** at `live.rs:604` is a genuine internal-invariant tripwire, not peer-reachable: `rejection_class()` returns `None` only for `ObjectStore` and `Incomplete` only for the three `is_pending()` variants, and both have earlier arms at `:580`/`:572`.

**C-1 — `AuthorizedSnapshot` is signature-only; head eligibility is a composer convention, not a type invariant.** Severity: low, and *not* a defect — `trust.md` and `AGENTS.md` both describe this as the "verification-proof token". But two consequences deserve a line in the crate docs: a library consumer can install a dead fork as a live head, and contract 34's crossing-count check pins the *mint* site but cannot pin *which* snapshots get minted. Proposed text for `crates/wyrd-sync/src/durable/mod.rs` and `wyrd-fuse/src/view/head.rs`:

> `AuthorizedSnapshot` proves a drive-bound signature and nothing else. It is **not** a statement that the snapshot is a live head: head eligibility is derived by `SnapshotDag::eligible_head_bodies` and enforced at the composition site (`WyrdNode::refresh_live_heads`). A consumer that constructs a view from tokens obtained any other way can project retained history, which is outside the v0 operator surface.

### 4.4 Fetch-walk alternate-representation fallback, and fallback, and the tests that pin it

Located at `crates/wyrd-sync/src/runtime/fetch/mod.rs`, three nested fallbacks in one pass, all fail-closed (`docs/peer-repair.md:14-32`):

1. **Across representations of one content** — `fetch::object`, walk unit is the representation, not the provider (`fetch/mod.rs:358`).
2. **Across routes of one representation** — transport root, then storage address (`fetch_representation`, `:285-299`). Oversize is representation-terminal; a zero-slice fallback grant does not mask the primary outcome (`:280-283`).
3. **Across providers of one address** — `IrohBulkSource::fetch_candidates` (`bulk.rs:467`), populated with >1 entry **only in tests**; production publishes one peer per snapshot (`transport/routes.rs:34,61`).

**Ordering guarantee: invalid bytes are never committed and never served.** `object()` does `verify(&` (AEAD + identity) **then** the chunk-length ceiling **then** `vault.import(&sealed)` **then** `objects.insert_verified` (`fetch/mod.rs:420-455`). So verified ciphertext is the only thing that reaches the serving vault, and verified plaintext the only thing that reaches the object store.

**Tests that pin it:**

| Assertion | Test |
|---|---|
| Corrupt representation strikes even when a fallback fulfills; candidate order is forced deterministically by a probe loop over manifest-id sort order | `corrupt_candidates_strike_even_when_a_fallback_fulfills` (`fetch/tests_fetch.rs:1584`) |
| Corrupt bytes rejected, absent representation never strikes, corrupt representation cooled | `tests_fetch.rs:1552` region (`absent_representations_do_not_strike` and the cool-down arms above it) |
| Invalid bytes **not committed** | `plan_rejects_corrupt_bulk_without_poison` (`plan/tests_accounting.rs:23`, asserts `!objects.has(...)` at `:168`); `fetch/tests_limits_e2e.rs:313` |
| Oversize response is representation-terminal | `oversize_transport_response_is_representation_terminal` (`tests_fetch.rs:260`) |
| Dead/stale transport falls back to the storage route | `dead_transport_route_falls_back_to_the_storage_route`, `a_stale_transport_field_degrades_to_the_storage_route`, `fallback_route_serving_a_forked_identity_commits_nothing` |
| Repeated invalid reps back off; deadline slices burn budget without striking | `repeatedly_invalid_representations_back_off` (`:473`), `deadline_slices_burn_backoff_without_striking`, `deadlines_count_per_representation_not_per_item` (`:1070`) |
| Bounded `EIO` at the POSIX boundary on deadline | `wait_returns_on_success_and_on_deadline` (`core/src/want.rs`), `read_deadline_is_eio_and_releases_the_want` (`daemon/src/fuse/tests_want.rs`) |

**C-4 — two end-to-end legs are self-declared UNVERIFIED, and the ROADMAP's limitations paragraph leans on both.** This is the most substantive finding in this section, because the limitations text says "The case split is normative in `docs/fetch-on-open.md`" — and the doc says the two legs have no test.

`docs/fetch-on-open.md:293-296`, on the manifest-chain case:
> "a manifest-chain `open()` blocking all the way to `EIO` has no dedicated test and is unverified until one lands."

`docs/fetch-on-open.md:308-311`, on the body-never-arrives case:
> "(No dedicated test pins the body-never-arrives adoption stall end to end; the classification half is pinned by the authorization conformance suite. Treat the end-to-end stall as unverified until such a test lands.)"

Severity: this is an **evidence** gap, not a defect, and the doc is scrupulously honest about it — which is why I am reporting it as evidence rather than as a bug. But a release whose limitations paragraph is the user-facing version of those two cases, and whose own design doc says the end-to-end legs are unverified, has a DoD clause resting on unproven ground. Fix: two tests. Sketches (not code, per the brief):

- `manifest_chain_open_fails_bounded_eio_when_no_representation_serves` — build a rig with a pinned path whose manifest records **two** representations, serve the first with bytes that fail AEAD and the second from a source that returns `None`. Assert: `open()` blocks, the deadline elapses, `errno == EIO`, the want registry is drained, no bytes committed for either representation, and a second `open()` re-registers the want rather than returning a cached error.
- `body_never_arriving_leaves_the_snapshot_unadopted_and_paths_enoent` — deliver an announcement whose root manifest is served but whose **body root** is never servable. Assert: the announcement is recorded; `live_heads()` does **not** include it; `view.lookup("payload")` returns `ENOENT` (never a hang, never `EIO`); a snapshot authored on top of it classifies `Undecided(UnknownParent)`; and no fact is poisoned. The classification half is already pinned by the authorization conformance suite, so this only adds the end-to-end adoption stall.

### 4.5 The three most dangerous untested sequences

Constructed from the code, ranked. For each I say whether a test exists — and I refuted two of my own candidates.

**1. Relay-accepted-but-discarded (finding B-2), end to end.** Sender commits `Delivered`; recipient never receives; no counter on either side; no re-push; drive permanently stale; no error. **No test exists and none can exist today** — `MiniRelay` cannot express the state. This is my #1.

**2. Announcement route replacement arriving between plan construction and the fetch's route use, with the serving endpoint restarting inside the walk.** **Refuted as a gap — well covered.** `reannouncements_update_routes_and_reject_forks`, `announcement_route_updates_replace_the_recorded_route`, `deferred_route_updates_flush_in_arrival_order`, `a_stale_transport_field_degrades_to_the_storage_route`, `announced_head_serves_from_the_author_vault_after_author_restart`, and `fetch_recovers_after_serving_restart_with_accumulated_failures` (slow profile, **184s**, passed under my run). The content-addressed store is immutable per root, so a route change cannot corrupt a transfer in flight — it can only redirect, and both arms are pinned.

**3. A peer disconnected past relay retention, reconnecting into a permanently stuck chain (§4.2).** **No test exists** — unmodelable without adding eviction to `MiniRelay`. The mechanism is read directly from the code and documented at `ROADMAP.md:256-261`, so this is a known hole rather than a discovered one, but it is the only path I found where a peer ends **permanently** unrecoverable without operator action.

**Refuted candidate I want on the record:** *self-removal or mid-fetch membership transition invalidating an in-flight fetch*. I looked for a membership check in the fetch plan and there is none. `execute_inner` rebuilds from durable facts each outer iteration and takes its keyring from `rebuilt.keyring` (`runtime/plan/mod.rs:75-77`). So a device removed at epoch N+1 keeps fetching content sealed under epoch N, because it already holds epoch N's key.

That is by design, not a gap. `docs/trust.md` states the boundary as "revocation bounds acquisition": removal stops new secrets arriving, it does not unlearn held ones. The same mechanism appears as the late-joiner horizon in `ROADMAP.md:262-271`, which is documented and tracked.

**Verdict: refuted. Not a finding, no test needed.** I record it so the next pass does not file it.

---

## Task D (§5) — "can be operated without a mounted FUSE filesystem"

**`sync now` does:** opens the keystore (`Engine::open_keystore`), composes `WyrdNode<DriveView<FsObjectStore, RuntimeMaterialization>>`, calls `refresh_live_heads()`, then `into_live(Duration::from_secs(30), &LiveConfig::for_local_sync())`, drops the presentation parts, connects `LiveMailbox` over the given relays, binds a real `IrohBulkSource`, and calls `drive_quiet`. It **does not** bind a serving endpoint, opens no FUSE session, and never reads or mounts anything (`crates/wyrd-cli/src/main.rs:1701-1785`).

**Documented behavior confirmed in code:** route-less authoring. `sync_now` passes no route, so announcements carry no `node_addr` and peers see them as known-but-unfetchable until a mount publishes a route via the normal route-update path (`main.rs:1695-1700`; `docs/cli.md:324-333`).

**The two-peer-neither-mounts scenario: they cannot converge on content.** Both announce route-less; each records the other's announcement; both report the head as unfetchable; neither can fetch. Control-plane convergence (membership, transitions, announcements, capabilities) **does** happen — that part works headlessly. Content acquisition does not.

**Is that a DoD violation?** I judge it **no, as scoped**, and here is why. The DoD clause is "can be operated without a mounted FUSE filesystem" (`ROADMAP.md:226`), not "two headless peers exchange content." Read as "headless sync means catch up from a serving peer," the clause is met and well-tested: `headless_loop_converges_a_real_outbox_in_staged_passes`, `headless_sync_now_converges_a_joined_device_to_current_heads`, `headless_loop_discharges_without_a_route`, `headless_loop_reports_unfetchable_instead_of_spinning`, `headless_loop_trips_the_cap_on_permanent_send_failure`, `sync_now_on_quiet_drive_completes`, `sync_status_reports_genesis_and_idle_mailbox`, `sync_status_with_relays_stays_fully_offline`, `sync_status_after_invite_shows_pending_obligations` (`crates/wyrd-cli/src/tests_sync.rs`). Read as "the product can be operated unattended without FUSE," it is **oversold for v0.2**: a vault that must serve peers needs a mount, because only the mount opens the serving endpoint. That capability exists only through the Rust API (`WyrdNode::open_serving`, `crates/wyrd-core/src/node.rs:219-229`), pinned by `node_composes_and_serves_without_a_presentation_backend` and `node_serves_over_a_view_defined_outside_the_fuse_crate` (`crates/wyrd-contracts/src/node_contracts.rs`). **That is a v0.3 dogfood concern** ("`wyrd vault` on a server should be forgettable", `ROADMAP.md:313-320`), so I would change one sentence in the v0.2 notes rather than block the cut: state that headless operation means *catching up from a serving peer*, and that headless *serving* is v0.3.

**Exit-code semantics.** `RunOutcome::{Quiet, RemoteStalled}` → `Ok(())`; `PassLimit` → `CliError::Incomplete` → exit 2 (`main.rs:1663-1671`). Automation hazards, all real:

1. **`RemoteStalled` exits 0.** The run prints `completed: quiet with N unfetchable heads (known but not local)`. A cron unit keying on exit status reads success while the drive is permanently stale. `docs/cli.md:307` documents this explicitly ("automate on the `unfetchable heads` count, not the exit status") — the hazard is documented, but stdout-only automation still gets it wrong.
2. **`sync now` with no `--relay` exits 0 having done nothing** — pinned as success by `sync_now_on_quiet_drive_completes` (`tests_sync.rs:681-688`). The only signal is a **stderr** warning (`main.rs:1730-1732`). This is finding **A-6** and it is the one that bites cron, which is exactly where the DoD clause points.
3. **A relay-closed subscription keeps exit 0 and is visible only on stdout.** The run prints `mailbox: degraded (1 of 1 relays connected, 1 subscription closed by relay)` *before* the report (`main.rs:1747-1764`), and `docs/cli.md:271-274` says the exit status reflects the local run only. Attachment looks healthy while intake is dead — a correct design choice (nothing auto-resubscribes a policy close) with a real automation trap.
4. `sync status` cannot be mistaken for liveness: it prints "liveness visible on sync now or mount" (`main.rs:1620-1623`) and never connects.

**Does `sync now` need FUSE?** No. `cargo tree -i fuser` shows `fuser` reached only from `wyrd-cli`, `wyrd-daemon`, and `wyrd-contracts`. `wyrd-sync` and `wyrd-core` reach no `fuser` at all; `wyrd-namespace` depends only on `wyrd-format`. `sync now`'s call graph never touches the FUSE adapter. (The `wyrd` binary still *links* fuser because `main.rs` also hosts `mount` — a link-graph fact, not a dependency of `sync now`.)

---

## Task E (§6) — ingest attack surface

**Panics: zero.** A systematic audit of non-test code (stripping `#[cfg(test)]` modules and `tests_*.rs`/`*properties.rs`/`conformance`/`fuzz.rs`/`mini_relay.rs`), then tracing every candidate backwards ≤5 hops to a network decode site, found **no peer-reachable panic**. Both 10-02 candidates are refuted a second time:

- **M2 `PublicKey::from_byte_array`** — nostr 0.45.5 declares `pub const fn from_byte_array(bytes: [u8; 32]) -> Self` (`public_key.rs:106-108`). Bare value, not a `Result`; no panic primitive exists. The recipient also isn't attacker-controlled on either path: send-path recipients come from owner-signed membership state (`deliver.rs:170`), receive-path sets `recipient: self.owner` (`mailbox/mod.rs:974`).
- **M3 `establish_drainer` expect** — gone. `await_drainer_ready` returns `Err(MailboxError::Transport("drainer task died before signaling readiness"))` (`mailbox/mod.rs:1200-1206`); pinned by `dropped_readiness_reports_a_transport_error_not_a_panic`.

Every decoder guards before slicing: `control/message.rs` (`need` with `checked_add`; `blob` caps pre-allocation at `1 << 20`), `control/{mod,bootstrap,rotation,nip46}.rs`, `keys/capability/{model,encoding}.rs`, `manifest.rs`, `tree.rs`, `snapshot.rs`, `membership.rs`, `envelope.rs`, `seal.rs`, `durable/codec.rs`. The highest-risk surface — peer-supplied `node_addr` — uses `.get(..)` throughout and re-encodes to compare against the input bytes (`transport/addr.rs:90-137`), so non-canonical spellings, duplicates, and trailing garbage all fail closed. Two 32-bit-only `usize` overflow shapes exist (`transport/addr.rs:128`, `control/bootstrap.rs:292`) that cannot fire on any supported target.

**Limits and enforcement.** Read-side is thorough and each bound names its enforcer: mailbox wire 512 KiB (SDK), relay event 256 KiB (`check_relay_event_size`, `mailbox/mod.rs:272-301`), notification channel 1024, held handovers 1024, poison cache 4096, NIP-44 ciphertext 96 KiB and opened bytes 64 KiB (`MAX_MAILBOX_CIPHERTEXT_LEN`/`MAX_MAILBOX_OPEN_BYTES`), intake commits 1024/pass and 256/sender/pass, engine pending 1024, bulk `Limits::V0`, serving mirror queue 64 items / 64 MiB. All documented in `docs/resource-limits.md:37-58` with the tests named. **Untested limit: none that I could find** — the one place the honest gap sits is not a missing limit but a missing *behavior* (B-2).

### Serving router

The endpoint has **no per-requester admission, by design**. `Router::builder(...).accept(iroh_blobs::ALPN, BlobsProtocol::new(&store, None))` — the second argument is a telemetry sink, not an admission hook, and the comment at `crates/wyrd-sync/src/serving.rs:759-782` says so explicitly, citing `trust.md` T17.

**What it withholds is discovery, not hashes:**
- no listing, no enumeration — an unheld root is answered with a protocol error
- every request on the wire names its hash, so the (address, hash) pairs that make a lookup possible travel only inside sealed announcements, addressed to members and readers
- the push half lands nothing: pushes through the public client never register in the mirror. Pinned behaviorally by `serving_mount_refuses_push_and_leaves_the_mirror_unchanged`, with the comment noting that upstream's `push: Disabled` in `EventMask::DEFAULT` is *not* consulted on the request path in iroh-blobs 0.103.0 — so the test, not the mask, is what carries the posture across a dependency bump

**Can a non-member obtain ciphertext?** Only if they already know both a transport root and a reachable endpoint id. A non-member who knows neither cannot: roots are inside sealed announcements, and the iroh node key is a fresh ephemeral per endpoint, published only inside those sealed announcements — never inferable from the wire, and distinct from device identity (`docs/trust.md:911-914`).

**Can a removed device?** This is finding **A-5**, and it is the part no operator-facing doc states:

- The endpoint cannot know who is asking, so removal cannot be enforced there. `trust.md:868-873` frames the accepted consequence for a **member** — "a member who can name a `StorageId` can request that ciphertext from any serving member" — and calls it "an availability and enumeration property, not a confidentiality break," because the holder already has the epoch material.
- That argument was never extended to a **removed** device. Announcement history is append-only with no cryptographic invalidation (T17), so a removed device retains its old route bytes and every root it ever learned, and can keep fetching those forever.
- It cannot learn *new* roots: announcements bound to epochs after its removal are sealed under keys it never receives, so it cannot open them. Removal bounds acquisition; it does not revoke retained knowledge. That is a coherent position — it is the standard revocation boundary, and `docs/trust.md` states the principle elsewhere ("revocation bounds acquisition").
- The removal contract explicitly scopes out the half that would pin it: "The snapshot-transfer half (announcement plus bulk fetch) is out of scope" (`crates/wyrd-contracts/src/removal_contracts.rs:6-9`).

So: **not a confidentiality break, not a defect, and not a new capability.** It is a missing sentence. The cheapest honest fix is one line in `docs/cli.md`'s `member remove` section, and one in the merged limitations list from Task A:

> Removal bounds acquisition, not knowledge: a removed device keeps its local plaintext, and can keep fetching any content whose transport root it learned before removal, from any serving member that still answers. It learns no new roots — announcements bound to epochs after its removal are sealed under keys it never receives.

**Against the README claim.** `README.md:46` The claim at `README.md:46` **holds**, and it matches `docs/trust.md:894-917` item for item:

- object kinds are a deliberate leak: the sealed header carries a cleartext `kind` byte, so a vault classifies every blob it holds
- ciphertext sizes leak because there is no padding in v0
- object counts and timing are network-layer observations by the operator, not endpoint telemetry
- no cryptographic linkability exists between two blobs, or between a blob and a drive
- ContentIds, paths, tree structure never appear

One word could mislead. README says "vaults," but the shipped serving surface is member-hosted: it opens from a member process holding the identity, epoch keys, and live mailbox (`WyrdNode::open_serving`). `docs/trust.md:882-887` flags this itself and says the keyless replica is the posture future serving surfaces must preserve, not a description of the current composer. README:77 covers it ("the dedicated vault-peer role surface is not yet wired at runtime").

**Verdict: accurate.** No correction needed.

---

## Task F (§7) — shutdown and restart

### 7.1 Ordering and every wait, with its bound

From `crates/wyrd-cli/src/main.rs:927-1058`, in order:

| # | Step | Cites | Bound |
|---|---|---|---|
| 1 | Poll the shutdown latch in 250ms slices | `main.rs:927-943` | 250ms slice, unbounded total (this is the wait, not a step) |
| 2 | `unmounter.unmount()` | `main.rs:952` | **UNBOUNDED** (syscall) |
| 3 | `server.join()` | `main.rs:961` | **UNBOUNDED** |
| 4 | `supervisor.close_admission()` | `main.rs:986` | synchronous |
| 5 | `drive.join()` | `main.rs:988` | **UNBOUNDED** in form |
| 6 | mailbox stop (handover from the joined loop) | `main.rs:999` | — (bounded wait is step 7) |
| 7 | `mailbox.shutdown(SHUTDOWN_DEADLINE)` | `main.rs:1031` | 5s (`main.rs:667`) |
| 8 | `bulk.shutdown(TRANSPORT_SHUTDOWN_DEADLINE)` | `main.rs:1034` | 60s (`main.rs:682`) |
| 9 | `drop(bulk)` | `main.rs:1044` | none needed (releases an owned current-thread runtime whose task-drop does not wait) |
| 10 | `serving.shutdown(TRANSPORT_SHUTDOWN_DEADLINE)` | `main.rs:1046` | 60s |
| 11 | `combine_status` | `main.rs:1053` | folds every outcome |

Steps 3 and 6 are the session join and the mailbox stop; I have listed them once each above. The ordering itself is correct and matches the
documented contract: session first (so `destroy` commits dirty handles
against the still-open queue), admission close second (the session join
is the submission boundary), loop join third, transport last (`docs/architecture.md:243-248`, `wyrd-daemon/src/lifecycle.rs:22-33`).

**Step 2 is the unbounded wait, and step 3 inherits it.** `umount` on a
busy mountpoint returns `EBUSY`, the code prints
`warning: unmount failed: {error}` (`main.rs:953`), and then
`server.join()` waits for a session loop the kernel never tore down.

**Is it surfaced to the operator?** Partially, and this is worth
recording precisely. `docs/cli.md:40-42` is explicit:

> "A process holding a file open on the mount delays the session join
> until it closes — unmount refuses a busy mount — so SIGINT waits for the
> last descriptor; the stop budgets bind the unmount itself, not a wedged
> holder."

So the *cause* is documented and a warning naming it is printed. What is
missing is anything after the warning: no "waiting for busy mount" line,
no timeout, no second warning. To an operator watching a hung `SIGINT`,
the last thing on screen is one warning line, then silence. My call:
this is documented behavior with thin telemetry, not a defect. Cheap
improvement: print the wait explicitly after a failed unmount.

**Step 5 is unbounded in form but not in practice.** After
`close_admission()`, the loop thread's `drain_until_closed()` returns on
the close. The panic path is the deliberate exception and it is handled:
a panicked loop closes admission on the spot so blocked submitters
resolve instead of hanging the join
(`lifecycle.rs:186-203`).

**Test coverage of teardown is strong**, and I ran it:
`tests_teardown.rs` (6 tests), `tests_run_loop.rs`,
`close_deadline_reports_a_stalled_close`,
`zero_deadline_trips_a_stalled_stop_but_spares_a_ready_one`,
`live_close_returns_past_a_zero_deadline`,
`live_serving_stop_returns_past_a_zero_deadline`,
`poisoned_mirror_lock_reports_but_still_shuts_down`,
`combine_status_reports_transport_shutdown_failures`, plus
`loop_thread_panic_tears_down_bounded`.

### 7.2 Crash windows

`docs/crash-consistency.md` enumerates them and names a pinning test
for each. Every window in that document has a test; I verified the
mapping while reading it.

| Window | Restart behavior | Pinned by |
|---|---|---|
| Fact-log commit, 8 stages | before-state XOR full batch, never hybrid | `crash_matrix_never_hybrid`, `orphan_files_are_ignored` |
| Membership authoring (transition + capability + all catch-up obligations in one batch) | no window where a transition is durable and its outbox is not | `failed_admit_leaves_no_phantom_tip`, `admit_queues_and_delivers_newcomer_catch_up` |
| Namespace carry across transitions (4 sub-windows) | stage-only: heads still eligible, drain discharges; post-transition: staged set survives and completes | `stage_only_crash_serves_the_still_eligible_head`, `interrupted_carry_resumes_after_restart_without_memory_bases`, `torn_carry_commit_discharges_without_duplicates`, `missing_tree_carry_fails_closed` |
| Snapshot authoring (imports, then one batch) | torn commit restarts headless and re-authors; orphaned vault envelopes stay unreferenced | `a_torn_authoring_commit_leaves_no_half_advertised_state`, `crash_before_announce_resumes_without_reauthoring` |
| Outbox discharge, mid-loop | resends only the unacked, byte-identical | `partial_send_then_resends_only_the_unacked` (actual name `partial_send_then_restart_resends_only_the_unacked`) |
| Stale capability obligation (3 shapes x 3 boundaries) | resumes by sending committed bytes, never re-minting stale | 12 tests named at `crash-consistency.md:120-133` |
| Keystore and custody | genesis deterministic and owner-verified; member secret reused idempotently | `an_interrupted_bootstrap_resumes_on_open`, `join_round_trip_reopens_as_member` |
| Escrow sidecars | committed epoch with no sidecar (degraded recovery); every later authoring backfills | `failed_escrow_persists_heals_on_next_authoring`, `conflicting_escrow_sidecar_fails_owner_open_closed` |
| Vault import | torn import leaves a temp file, never a servable root | `torn_plan_commit_is_ignored_on_reopen` |
| Mirror write-through queue | heals via `reconcile_held`; full queue is backpressure, never a silent drop | `a_full_mirror_queue_applies_backpressure_without_losing_the_vault`, `serving_reopen_rebuilds_the_mirror_from_the_vault` |
| Poisoned durability bookkeeping lock | fails the operation, never the process | `poisoned_pending_fails_reconcile_at_the_first_acquire` |
| Mailbox ack / intake | commit precedes settle; a commit failure never settles, so it redelivers | intake restart suite + resilience suite |
| Fetch and plan | torn batch ignored on reopen; refetch heals exactly-once | `torn_plan_commit_is_ignored_on_reopen`, `plan_fetches_bodies_and_live_heads_survive_a_restart` |
| Materialization policy | one batch; a torn file is ignored on reopen like any other | `batched_materializations_commit_once`, `pin_survives_restart` |

**Every crash window in the document has a named injection test.** This
is the strongest area of the codebase and I found no window that is only
described.

### 7.3 Restart equivalence

In-memory-only state that affects protocol behavior.

*[Session note: the rest of §7.3 (want registry, route table, fork gates, seen-id log per the brief) was destroyed by output-stream corruption — repeated fragments with no recoverable content. The StoreLocked walkthrough and the terminology check from the brief are absent too.]*

*Session note: Tasks C (§4) through F (§7) were recovered from later chat messages in the review session (ses_efe52f57dffe2zNpAmnnQIFEXO) with stream corruption repaired (test names and quotes restored against the tree). Cut as unrecoverable and marked inline: the original end of the §4.5 refuted candidate (later completed from a follow-up message), the original verdict after the README.md:46 quote (likewise completed), most of §7.3, and the StoreLocked walkthrough and terminology check from the brief, which are absent. Per the author there is no Task H: the review ends here.*

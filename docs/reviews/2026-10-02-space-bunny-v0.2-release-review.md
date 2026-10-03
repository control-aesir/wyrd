# v0.2.0-alpha release review — "Trustworthy live synchronization"

Reviewer: adversarial release review (second pass, 2026-10-02)
Tree reviewed: `master` @ `4c9f279`
Requested review point: `4877b1e`

---

## 0. Scope and revision notes (read first)

**The named commit is not the tree under review.** `4877b1e` is an ancestor of
`HEAD` (`4c9f279`); three commits sit on top of it:

```
4c9f279 Merge #134be993: test(core): converge retry flood on the window bound
6248566 test(core): converge retry flood on the window bound, not round counts
f410ca7 Merge #5a9a8a9c: docs(sync): document control transport dedupe semantics
2de48f2 docs(sync): document control transport dedupe semantics
```

`git diff --stat 4877b1e..HEAD` touches three files: two test files and
doc comments in `crates/wyrd-sync/src/control/mod.rs`. **No production
behaviour changes**, so reviewing at `HEAD` is a superset of `4877b1e` and
every finding below holds for both. Two of the findings are about that delta
itself (Blocker 3, Issue 12).

**Working tree was not clean at review time:**

```
 M docs/reviews/2026-09-29-master-review.md
?? docs/reviews/2026-10-02-luna-v0.2-release-review.md
?? issues.sh
```

The first is a modified tracked file; the second is a prior review from today.
Neither affects the code reviewed. `issues.sh` is a zero-byte stray file and
should not be committed.

---

## 1. Verdict

# DO NOT SHIP

Not because the engineering is weak — on the contrary, the protocol core is
the strongest part of this codebase and every hermetic gate is green. The
verdict rests on three things that a release cannot defer:

1. **A reproducible data-loss defect on the mounted write path at shutdown**
   (Blocker 1). 5/5 deterministic. A user's buffered write is durably committed
   one byte short with no error surfaced. This is not alpha-shaped; it is
   silent corruption of the user's data, on the primary product surface.
2. **The v0.2 definition of done is not met and the release cannot
   demonstrate it** (Blockers 2, 3). "Real relay infrastructure" convergence is
   unproven; the only two real-relay tests fail against every relay reachable
   from the review host. "Peer repair and history catch-up" has an
   unrecoverable, silent, operator-invisible failure mode that no document
   names.
3. **The release is mechanically un-cuttable** (Blocker 4). The Cargo version
   is still `0.1.0-alpha.1` and `CHANGELOG.md` has no `[Unreleased]` section,
   so `.ngit/release.yaml` step 2 cannot be performed and step 3's
   "the version derives from the tag … so it must equal the Cargo version"
   check fails. `ngit release publish` would extract an empty notes section.

Every one of these has a cheap fix. That is why the verdict is DO NOT SHIP
rather than something more permanent: this is a release that needs three
focused changes and a re-run, not a redesign.

**How this could still be wrong:** Blocker 1 was reproduced on macOS 15.8 with
macFUSE only. If a Linux/KVM run shows the same test passing, the defect is a
macFUSE/fuser delivery artifact rather than a Wyrd buffer bug — but it would
remain a real defect on macOS, which is a supported desktop platform per
ROADMAP v0.4 and the release archives in `.ngit/release.yaml`. Blockers 2 and 3
rest on my inability to reach a working third-party relay; if the project has
CI or maintainer evidence of a passing real-relay run that I could not obtain,
Blocker 3 downgrades to "documentation and diagnosability", and Blocker 2
stays a blocker regardless.

---

## 2. Blockers, ordered

### Blocker 1 — Mounted write path silently truncates a dirty handle at shutdown

**Severity: P0. Silent data loss.**

`cargo test -p wyrd-cli --bin wyrd -- --ignored` reproduces **5/5, always
identically**: the committed image is 26 bytes where 27 were written, losing
the final byte.

```
left:  [117, 110, 102, 108, 117, 115, 104, 101, 100, 32, 116, 104, 114,
        111, 117, 103, 104, 32, 116, 104, 101, 32, 109, 111, 117]
       u  n  f  l  u  s  h  e  d     t  h  r  o  u  g  h     t  h  e     m  o  u
right: [..., 109, 111, 117, 110, 116]     ... m o u n t
```

- Test: `tests_mount::live_mount_preserves_dirty_handle_across_shutdown`
  (`crates/wyrd-cli/src/tests_mount.rs:329`, assertion at `:405-408`).
- The payload is written with `(&dirty).write_all(b"unflushed through the mount").unwrap()`
  (`tests_mount.rs:384-385`) — **`write_all` returns `Ok`, so all 27 bytes were
  accepted by the kernel and delivered to the FUSE `write` handler** — *before*
  `SHUTDOWN.store(true, ...)` at `:390`. The truncation therefore happens in
  Wyrd's teardown drain, not in the test's setup.
- The same run also logs `unmount failed: Resource busy (os error 16)`
  (`/tmp/wyrd-review/fuse.log:20-21`) — a second teardown symptom in the same
  path.

This directly contradicts two contracts:
- `docs/architecture.md:222-224`: "`destroy` commits still-dirty handles
  against the still-open mutation queue".
- `docs/write-path.md` commit-pipeline contract, and the v0.2 Ship item
  "correct shutdown and restart behavior".

A commit that persists a **prefix** of the buffered image, and reports success,
is silent acceptance of invalid state — the one thing the DoD names
unforgivably ("never silently accept invalid state").

**How this could still be false:** a 26+1 kernel write split where the final
chunk is dropped because the session is already tearing down would look
identical from the mount. Either way Wyrd commits a truncated snapshot with no
error, which is the defect; only the *cause* differs. Confirming the cause
needs one Linux run and, ideally, a `tracing` line at the teardown drain.

**Minimal fix:** instrument the teardown drain to log the handle's buffered
length at `destroy` and the length handed to authoring; the divergence will
name the site in one run. Then fix the accounting. Do not paper over it with a
retry — a retry that re-reads a shorter buffer reproduces the same truncation.

### Blocker 2 — Control-plane delivery is "relay accepted", never "recipient received"; no re-push, no pull, no signal

**Severity: P1. Silent, permanent, operator-invisible convergence hole.**

The outbox discharges an obligation the moment the **relay** accepts the
envelope, not when the recipient has it:

- `crates/wyrd-core/src/mailbox/mod.rs:1524-1527` — `LiveMailbox::send` maps
  `client.send_event(&wrap).await` to `Ok(())` and **discards the per-relay
  output**.
- `crates/wyrd-sync/src/runtime/author/deliver.rs:168-175` — `send_sealed_to`
  commits `Fact::TransitionDelivered` / `Fact::CapabilityDelivered` on that
  `Ok`, permanently retiring the obligation.
- The test file states the consequence itself
  (`crates/wyrd-core/src/mailbox/tests_interop.rs:53-57`): "Publish success is
  proven by delivery, not by `send` returning Ok … so a rejection surfaces only
  as missing mail."

Consequence: a peer absent longer than the relay's retention window never
receives the transitions and capabilities addressed to it, its obligations are
already marked discharged at the sender, and there is **no repair path in
either direction**:

- No pull. The `Message` enum (`crates/wyrd-sync/src/control/message.rs`) has
  only `MembershipTransition`, `SnapshotAnnouncement`, `Capability`,
  `KeyRotation`. There is no request/hole-announcement message.
- No re-push. `docs/sync-and-peers.md:157-160` describes the catch-up set as
  "retried until acknowledged"; the acknowledgment in the code is the relay OK.
- No operator signal. `SyncStatus` (`crates/wyrd-core/src/status.rs:61-79`)
  reports the peer's *own* tip, held epochs, and outbox obligations. It cannot
  report what the peer is missing, because the peer cannot know.

The peer is then stuck: intake defers forever on announcements bound to an
unseen transition (`crates/wyrd-sync/src/runtime/intake/mod.rs:533`), the
membership log cannot advance, and the mount shows a permanently stale drive
with no error anywhere. `reissue-invitation` does not help — it re-mints
secrets `1..=epoch-of-admission` (`crates/wyrd-sync/src/runtime/author/admission.rs:344-357`),
not the epochs the peer missed.

This is the "History acquisition and state convergence are separate failure
domains" clause of the DoD, and history acquisition is the half that fails.
Critically, **it appears in no limitations list**: ROADMAP.md:204-207 names two
known limitations and neither is this; `docs/storage-growth.md` covers retention,
not convergence.

**How this could still be false:** if relay retention always exceeds peer
absence — i.e. no realistic peer is ever away longer than the relay keeps
events — the hole is theoretical. That is not a safe assumption for a laptop
that is closed for a week, and nothing in the codebase or docs states it.

**Minimal fix:** two parts, both cheap. (a) Document the bound now: add to
ROADMAP "Known v0.2 limitations" that control-plane delivery is relay-accepted
and that a peer absent beyond relay retention does not self-repair. (b) Make
the hole detectable and recoverable: retain and periodically re-push
undelivered-by-receipt obligations for a bounded window, or add an intake-side
gap report so `wyrd sync status` can say "known epoch N, newest announcement
epoch M, missing N+1..M".

### Blocker 3 — Real-relay interoperability is unproven, and the code discards the signal that would explain a failure

**Severity: P1. The DoD names "real relay infrastructure"; the release cannot show it.**

The only two real-relay tests are `#[ignore]`d opt-ins
(`crates/wyrd-core/src/mailbox/tests_interop.rs:58,108`). I ran them against
three relays:

| Relay | Result |
|---|---|
| `wss://nos.lol` (the one the file names as proven) | **TCP :443 unreachable from this host.** DNS resolves to 142.132.206.70; connect times out after 8s. `mailbox stayed down (stream_alive=true, connected=0/1)` |
| `wss://relay.damus.io` | Mailbox **attaches** (`connected=1/1`), sender's `send()` returns `Ok`, recipient **never** receives within 60s. Panics at `tests_interop.rs:88` |
| `wss://nostr.wine` | Identical: attaches, no delivery, panics at `tests_interop.rs:88` |

I ruled out the most likely product-side cause: **the subscription filter
encoding is correct.** `LiveMailbox` subscribes with
`Filter::new().kind(Kind::GiftWrap).custom_tag(LOWERCASE_P, owner_pk.to_string())`
(`crates/wyrd-core/src/mailbox/mod.rs:731-733`), and `Display for PublicKey` is
`to_hex()` (`nostr-0.45.1/src/key/public_key.rs:86-89`), so `#p` is hex and
matches the gift wrap's hex `#p` tag. A bech32/hex mismatch — which would mean
the mailbox works against `MiniRelay` (which matches through the nostr crate)
and silently never matches a real relay — is **refuted**.

That leaves two possibilities I cannot separate from here:
(a) third-party relay write policy on kind 1059 (PoW/fee/allowlist) — the
expected failure mode per `tests_interop.rs:53-57`; or
(b) a genuine defect meaning Wyrd never exchanges a control message on a real
relay, which would make the entire DoD unmet.

I cannot distinguish them because **the per-relay `OK` is discarded**
(`mailbox/mod.rs:1524-1527`), no `nostr` CLI is available in the environment,
and no independent NIP-01 probe is possible without a signing implementation.
That is the finding as much as the failure: the release has no self-diagnosis
for its most load-bearing external dependency.

**How this could still be false:** the project may hold CI or maintainer
evidence of a passing run against a permissive relay that I could not reach.
`docs/sync-and-peers.md:47-48` claims "every test runs against an in-memory
fake, never a live network", which is now stale but was true when written.

**Minimal fix:** surface the relay's `OK` — log accepted/rejected/failed per
relay at debug on the `send` path (the plumbing is already there; only the
`map(|_| ())` discards it). Then run the two interop tests against a
self-hosted `nostr-rs-relay` over `wss://` as a stable, reproducible
third-party-equivalent baseline, and record the result in the release notes.
Until then, "relay interoperability" is UNVERIFIED, not PASS.

### Blocker 4 — The release is not cuttable: version and changelog section are missing

**Severity: P1 for the release process; trivial to fix.**

`.ngit/release.yaml` defines the cut procedure. Two of its steps cannot be
performed against this tree:

- Step 3: "the version derives from the tag with one leading `v` stripped, so
  it must equal the Cargo version". `Cargo.toml:14` is
  `version = "0.1.0-alpha.1"`. Tagging `v0.2.0-alpha` requires bumping
  `[workspace.package] version` first. Not done.
- Step 2: "Rename the `[Unreleased]` CHANGELOG section to the version … the
  notes below are extracted from that exact section". `CHANGELOG.md` has **no
  `[Unreleased]` section**; its only level-two heading is `## [0.1.0-alpha.1]`
  (`CHANGELOG.md:22`), which already describes most of what ROADMAP calls v0.2
  scope. There is nowhere to put v0.2 notes, so `ngit release publish` would
  extract an empty notes section.

**Minimal fix:** add `[Unreleased]` to `CHANGELOG.md` with the v0.2 entries,
bump `Cargo.toml:14` to `0.2.0-alpha`, and add the `v0.2.0-alpha` tag.

---

## 3. Non-blocking issues

| # | Issue | Evidence |
|---|---|---|
| 1 | `docs/sync-and-peers.md:47-48` claims "no concrete relay pool lives in `wyrd-sync` yet — every test runs against an in-memory fake, never a live network", and `:52-55` lists "the concrete relay pool (subscription management, retry backoff, event kind/tag conventions)" as Deferred. All landed in `wyrd-core` (`LiveMailbox`, supervisor, NIP-59 gift wrap). | doc/code contradiction |
| 2 | ROADMAP Phase 1 "Remaining" (`:110-112`) lists "the serving router peers dial into (real-iroh loopback in the `wyrd` binary)" as remaining. It has landed. | `crates/wyrd-sync/src/serving.rs`, `serving_contracts::a_serving_daemon_serves_a_peer_over_live_iroh`, `docs/architecture.md:194-198` |
| 3 | ROADMAP v0.2 "Explicitly do not ship" names **recovery grafting** (`:193`), but `Engine::author_recovery_snapshot` is `pub` (`crates/wyrd-sync/src/runtime/engine/mod.rs:1196`) and three contracts pass. It has no CLI or daemon surface, so nothing ships operationally — but the primitive is in the artifact and the two roadmap statements are not reconciled. | ROADMAP `:193` vs `:144-166` |
| 4 | `docs/sync-and-peers.md:246` claims "Corrupt objects trigger scrub/repair before ever surfacing as errors". `FetchOutcome::settled()` is `#[allow(dead_code)]` with "No production caller yet" (`crates/wyrd-sync/src/runtime/fetch/mod.rs:520-537`), and the real producer `RuntimeState::status` (`crates/wyrd-sync/src/runtime/state.rs:178-189`) never yields `FetchStatus::Corrupt`. No scrub/repair path exists. | doc/code contradiction |
| 5 | `docs/architecture.md:53` says "`wyrd-fuse` must never know that iroh exists". True at source level, false at link level: `cargo tree -p wyrd-fuse -e normal` reaches `wyrd-sync` and 25 iroh crates through `wyrd-core`'s production dependency. `wyrd-fuse` source never names iroh, so behaviour is unaffected — but contract 34 checks only *direct* manifest deps, so it cannot catch a regression here. | `cargo tree` output; `crates/wyrd-contracts/src/layer_contracts.rs:9-16` |
| 6 | Admission's lineage-closure walk is O(recorded history) in one admission and commits one obligation per closure member. Acknowledged in code (`crates/wyrd-sync/src/runtime/author/admission.rs:229-236`) but in **no** doc's limitations list. | honesty gap |
| 7 | `crates/wyrd-core/src/mailbox/tests_interop.rs:13` documents the run command as `cargo test -p wyrd-daemon external_relay`, but the file lives in `wyrd-core`. Following the doc runs nothing. | wrong crate name |
| 8 | `nostr-connect` is declared in the workspace table and allowed by `layer_contracts.rs` for `wyrd-daemon`, but appears in **no** source file. | `grep -rn nostr_connect crates/` → empty |
| 9 | `cargo audit` reports `RUSTSEC-2024-0370` (`faster-hex` `hex_decode_unchecked` AVX2 out-of-bounds read, **unsound**) newly in the graph via `nostr → nostr-database → nostr-sdk → wyrd-core`. Exit code 0, so CI is green; no policy entry covers `unsound`. Whether Wyrd reaches the unsound function is unverified. | `cargo audit` output |
| 10 | The microVM e2e suite — the **only** partition/heal evidence — is referenced by no CI workflow. `.ngit/act/workflows/workflow.yml` runs check/clippy/nextest/nextest-slow/doctest/audit/deny, but `grep -n 'microvm\|lima' .ngit/act/workflows/*.yml` returns nothing. AGENTS.md calls it "gated on master CI". | grep result |
| 11 | `docs/collaboration-workflow.md` says project labels are applied *after* issue creation. The two conventions (triage-at-creation vs post-creation) differ between AGENTS.md and this doc. | `AGENTS.md` vs `docs/collaboration-workflow.md` |
| 12 | `4877b1e..HEAD` documents (correctly, at `crates/wyrd-sync/src/control/mod.rs:31-42`) that **capabilities have no content-level dedupe**: a freshly resealed identical capability recommits a durable fact. Paced per pass (256/sender/pass) but unbounded in retention from any drive member. `docs/resource-limits.md:102` acknowledges it. Honest, but the "bounded intake" Ship item should say so in the release notes. | doc + new test `resealed_identical_capability_recommits` |

---

## 4. Ship items and DoD clauses → verdict

Legend: **PASS** = verified by evidence I ran or read. **PARTIAL** = some
clauses covered, a named gap remains. **FAIL** = evidence contradicts.
**UNVERIFIED** = no evidence obtainable in this environment; *skipped is not
passed*.

### v0.2 "Ship" list (ROADMAP.md:185-191)

| Ship item | Verdict | Evidence | Gap |
|---|---|---|---|
| multi-relay mailbox operation | **PARTIAL** | `single_relay_outage_leaves_mailbox_live_on_survivor`, `empty_relay_config_connects_and_stays_idle` (`crates/wyrd-core/src/mailbox/tests_delivery.rs`); `crates/wyrd-core/src/mailbox/mod.rs:1338-1350` per-class supervision | No multi-relay test. `--relay` is repeatable (`docs/cli.md`); `SyncStatus.mailbox.configured_relays` counts them, but nothing exercises >1 concurrently |
| relay interoperability | **UNVERIFIED** | 2 opt-in tests, both `#[ignore]`d (`tests_interop.rs:58,108`). Ran against 3 relays: 1 unreachable, 2 attach-but-no-delivery | Blocker 3. Cannot distinguish relay policy from product defect |
| peer repair and history catch-up | **PARTIAL** | Catch-up: `admit_queues_and_delivers_newcomer_catch_up`, `invited_device_converges_on_ordered/reversed/duplicated_catch_up`, `offline_device_catch_up_accumulates_contiguously`, `two_newcomers_converge_from_one_delivery_pass` (`crates/wyrd-contracts/src/join_contracts.rs`); `crates/wyrd-sync/src/runtime/author/admission.rs:188-262`. Route repair: `reannouncements_update_routes_and_reject_forks`, `fetch_recovers_after_serving_restart_with_accumulated_failures`, Lima step 6 + microVM step 8 | Blocker 2 (no re-push, no pull, no signal). Content scrub/repair absent (NB-4) |
| correct closure and head gating | **PASS** | `verify_head_closure` + 19-variant exhaustive `rejection_class` (`crates/wyrd-sync/src/closure.rs:495-515`, `:878-998`); `a_gated_head_mounts_only_after_its_tree_lands_and_survives_restart`, `a_damaged_head_beside_an_installed_one_fails_the_pass_closed`, `snapshot_manifest_closure_correspondence`, `a_mismatched_snapshot_manifest_never_mounts`, `partial_head_set_never_projects_mixed_validity_heads` | Could still be false if a head closure is verified against a *partially* fetched store and mis-classified `Incomplete` as healthy — refuted: `is_pending()` (`closure.rs:168-175`) makes that path no-install, and the batch policy fails closed |
| demand-driven content acquisition | **PASS** | Want registry + bounded blocking `open`/`read`: `wait_for_materialization` (`crates/wyrd-core/src/want.rs:245-258`), deadline → `EIO` at `crates/wyrd-daemon/src/fuse/backend.rs:925-950`; Lima step 6 asserts a 20-45s bounded `ETIMEDOUT`/`EIO` on peer-down demand with the defer and timeout both present in the log | Deadlines are per-open and generous by default; a slow peer costs an open that blocks. Documented, bounded, acceptable |
| bounded intake and resource consumption | **PASS** | Two-layer intake budget `MAX_INTAKE_COMMITS_PER_PASS`/`..._PER_SENDER_PER_PASS` (`intake/mod.rs:29-36`, `:56-74`); mailbox 96 KiB/64 KiB/256 KiB/1024/4096/65536 bounds; documented in `docs/resource-limits.md:37-57`; `bulk_ceilings_stay_bounded_and_oversize_fails_closed`, `deferred_messages_survive_queue_pressure` | Retention is unbounded by design and documented (`docs/storage-growth.md`). See NB-12 |
| correct shutdown and restart behavior | **FAIL** | Teardown ordering and bounds are excellent: `close.rs:13-36` (`with_deadline`, `stop_with_close`) with unit pins; `tests_teardown.rs` (6 tests), Lima step 6 90s `stop_mount`, microVM step 8 | **Blocker 1**: dirty handle truncated 26/27 at shutdown, 5/5 |
| headless sync | **PASS** | `wyrd sync now`: `headless_loop_converges_a_real_outbox_in_staged_passes`, `headless_loop_reports_unfetchable_instead_of_spinning`, `headless_loop_discharges_without_a_route`, `headless_loop_trips_the_cap_on_permanent_send_failure` (`crates/wyrd-cli/src/tests_sync.rs:298-423`) | — |
| sync status | **PASS** | `wyrd sync status` reads durable state only, never connects (`docs/cli.md:256-286`); `SyncStatus` (`crates/wyrd-core/src/status.rs:61-79`); `crates/wyrd-cli/src/tests_sync.rs` | Cannot report a *peer's* gap — that is Blocker 2 |
| materialization policy | **PASS** | `policy_commits_change_no_replicated_state` contract; `wyrd pin`/`unpin`/`evict`/`cache status|policy` (`docs/cli.md`); two reported values (`sync-and-peers.md:129-132`) | `docs/resource-limits.md:56` honestly states the quota covers only the mounted write path |
| reliable FUSE read/write | **PARTIAL** | Real mount on macOS/macFUSE: `live_mount_serves_read_write_until_shutdown` **passed** (read, write, re-read, clean SIGINT teardown, write survived reopen). 6 `fuse_contracts` + `concurrent_opens_reads_and_publications_never_deadlock_or_tear` | **Blocker 1** on the shutdown half |
| E2E convergence tests | **PARTIAL** | Lima suite (`tests/alpha-lima.sh`, 6 steps) and microVM suite (`tests/alpha-microvm.sh` + legs, 10 steps incl. real `tap-r` partition/heal at step 10) are real, two-host, real-relay-process harnesses | **Not run by me** (needs Linux/KVM) and **not in CI** (NB-10) |
| adversarial and runtime property tests | **PASS** | `membership/properties.rs`, `authorization/properties.rs`, `keys/capability/properties.rs` (proptest); `reversed_arrival_converges_to_the_same_outcome`; Phase 4 fuzzing (`crates/wyrd-sync/src/fuzz.rs`) | — |
| operationally meaningful limits and failure behavior | **PASS** | `docs/resource-limits.md` is unusually complete and honest, including the raise-vs-count rule and disk classification; `StoreFailure::of_io` shared by both writers; per-class supervision with separate caps | — |

### Definition of done (ROADMAP.md:197-202)

| DoD clause | Verdict | Evidence | Gap |
|---|---|---|---|
| two or more legitimate peers connected through **real relay infrastructure** | **UNVERIFIED** | Lima step 6 and microVM use a real `nostr-rs-relay` process; the hermetic suite uses `MiniRelay`, an in-process NIP-01 server (`crates/wyrd-core/src/mailbox/mini_relay.rs`, `#[cfg(test)]` only). Third-party relays: Blocker 3 | Neither harness was run by me. No third-party relay evidence obtainable |
| ordinary mutations converge correctly | **PASS** (hermetic + harness logic) | `daemon_write_publication_and_retry_converges_across_members`, `carry_publication_converges_across_members`, `reversed_arrival_converges_to_the_same_outcome`, `join_contracts` (8), Lima step 6 three-leg bidirectional convergence | E2E unrun by me |
| **history catch-up after disconnection** | **PASS** (within relay retention) | `offline_device_catch_up_accumulates_contiguously`, `invited_device_converges_after_gap_then_redelivery` — this is the clause that is covered **independently of state convergence**, which is exactly what the DoD demands | Bounded by relay retention, undocumented: Blocker 2 |
| survive **restart** | **PARTIAL** | `redelivered_announcement_after_restart_stays_a_duplicate`, `a_gated_head_mounts_only_after_its_tree_lands_and_survives_restart`, `deliveries_round_trip_and_replay_converges_after_restart`, `soak_restart_delivers_once_across_reopens`, `durable_acks_survive_reopen`, `restart_past_retention_redelivers_evicted_without_loss`, `upsert` seen-store crash tests, microVM step 8 | `relay_outage_marks_down_and_recovery_redelivers` is **excluded from the default nextest profile** (`.config/nextest.toml`) |
| survive **partition and heal** | **UNVERIFIED** | microVM step 10 is a genuine two-host `tap-r` partition + heal with conflict assertions on both sides (`tests/alpha-microvm-legs.sh:388-569`); mailbox-level `relay_outage_marks_down_and_recovery_redelivers` and `unacked_and_mid_recovery_mail_survive_stream_recovery` | microVM suite **not in CI** and not runnable here. Both relevant mailbox tests are in the `slow` profile. This is the weakest-evidenced DoD clause |
| never silently accept invalid state | **PASS** | Strongest area. `unverified_snapshots_never_become_live_fuse_heads`, `forged_snapshots_are_rejected_before_fuse_head_installation`, `malformed_manifests_never_become_materialized_content`, `content_ids_never_appear_in_vault_transport_records`, `recovery_grafts_content_only_and_voided_transitions_never_authorize`, `a_quota_refused_commit_commits_nothing_at_all`, `announcement_forks_commit_seen_id_but_never_a_fact`, `partial_head_set_never_projects_mixed_validity_heads`; every decoder length-guarded before slicing | **Blocker 1 is the exception**: a truncated image *is* accepted and reported as success |
| operate without a mounted FUSE filesystem | **PASS** | `node_composes_and_serves_without_a_presentation_backend`, `node_serves_over_a_view_defined_outside_the_fuse_crate` (`node_contracts.rs`); `wyrd sync status`/`sync now`/`pin`/`unpin`/`evict`/`cache`/`snapshot` all offline; `max_consecutive_errors` classified supervisor (`crates/wyrd-core/src/live.rs:103`) | — |
| history acquisition **and** state convergence as separate domains | **PARTIAL** | The *separation* is genuinely designed and tested: `offline_device_catch_up_accumulates_contiguously` (history) is distinct from `daemon_write_publication_and_retry_converges_across_members` (state) | History acquisition has the Blocker 2 failure mode; state convergence is covered |

### "Explicitly do not ship" (ROADMAP.md:193-195)

| Item | Verdict | Evidence |
|---|---|---|
| recovery grafting | **AMBIGUOUS** | Code + 3 passing contracts present (`engine/mod.rs:1196`), no operator surface. NB-3 |
| mobile | **PASS (absent)** | No mobile crate; `grep -rn -i mobile crates/*/src` (non-test) → no product surface; `docs/mobile.md` is design only |
| File Provider | **PASS (absent)** | No file-provider surface |
| sophisticated conflict UI | **PASS** | `wyrd snapshot merge --take path=@N` is CLI, documented `docs/cli.md:194-213`; no UI |
| production telemetry platform | **PASS** | `docs/resource-limits.md:148` "No separate metrics pipeline in v0"; `tracing` is events-only, no subscriber in library crates |
| marketplace | **PASS (absent)** | — |
| release distribution | **PASS** | `.ngit/release.yaml` + flake `wyrd-dist` exist, but no runtime distribution surface; the roadmap assigns dogfooding to v0.3 |
| major performance architecture | **PASS** | No `criterion`/benchmark harness (`grep -rn 'benchmark\|criterion\|perf\b'` → empty). `wide_flat_closure_verifies_and_reports_cost` deliberately *records* elapsed time without asserting (`closure.rs:1000-1063`, "wall clocks are not contracts"). The one performance-shaped item — the O(history) admission walk — is an acknowledged correctness-bound cost, not optimization |

**v0.2 entry test** (ROADMAP.md:43-47): "does this alter behavior a peer can
observe over the network, or prevent locally corrupted or invalid state from
being accepted?" — Everything in the delta and nearly everything in the release
qualifies as v0.2-appropriate. **No performance work shipped without a violated
bound.** No scope-discipline violation found.

---

## 5. Cross-cutting check results

### 5.1 Architecture rule — PASS

`wyrd-sync` and `wyrd-core` depend on no consumer. Proven by `cargo tree`
(normal, build **and** dev edges):

```
$ cargo tree -p wyrd-sync   -e normal,build,dev --prefix none | grep -i wyrd
wyrd-sync
wyrd-format

$ cargo tree -p wyrd-core   -e normal,build,dev --prefix none | grep -i wyrd
wyrd-core
wyrd-format
wyrd-sync
wyrd-format  (*)
wyrd-sync   (*)
```

Neither reaches `wyrd-fuse`, `wyrd-daemon`, or `wyrd-cli`. Manifest evidence:
`crates/wyrd-sync/Cargo.toml` `[dependencies]` is `wyrd-format` + pinned
third-party only; `crates/wyrd-core/Cargo.toml` is `wyrd-format`, `wyrd-sync`,
`nostr`, `nostr-sdk`, `tokio`, `tracing`, `futures-util`, `getrandom`,
`thiserror`. Source evidence: `grep -rn 'wyrd_fuse\|fuser\|wyrd_daemon\|wyrd_cli'
crates/wyrd-sync/src crates/wyrd-core/src` → one hit, a prose mention in a
doc comment (`crates/wyrd-core/src/lib.rs:8`).

`wyrd-format` substrate rule — PASS. `cargo tree -p wyrd-format -e normal,build,dev`
yields only `blake3`, `fastcdc`, `hex`, `thiserror` (+ their proc-macro/build
deps: `arrayvec`, `cc`, `cfg-if`, `constant_time_eq`, `shlex`, `syn`, `quote`,
`proc-macro2`, `unicode-ident`, `find-msvc-tools`). No network, async, or FUSE
crate. Machine-enforced by `layer_contracts::crate_dependencies_follow_the_layered_dag`
with a fail-closed policy table (`layer_contracts.rs:44-120`).

**How this could still be false:** `wyrd-fuse` transitively links iroh through
`wyrd-core` (NB-5), so the "provider-neutral view" property holds by convention
(source discipline) and not by construction. A future `wyrd-core` API could
hand a FUSE adapter an iroh-derived type and the contract would not notice.

### 5.2 Silent-acceptance hunt — no finding beyond Blocker 1

Method: script that strips `#[cfg(test)]` modules and test-only files, then
scans for `unwrap`/`expect`/`panic!`/`unreachable!`/`todo!`/`unimplemented!`.
315 raw hits; after removing whole-file test modules
(`authorization/conformance.rs`, `membership/conformance/*`, `*properties.rs`,
`fuzz.rs`, `keys/hygiene.rs`, `mini_relay.rs`), every production hit is one of:

- **Decoder slice-then-convert**, always length-guarded first. Verified in
  detail: `manifest.rs:170-179` (`if bytes.len() < ENTRY_LEN`), `:322-370`
  (`need(pos, n)` with `checked_add`, `checked_mul` for overflow,
  `Vec::with_capacity(n.min(4096))` so a hostile count cannot preallocate),
  `control/message.rs:304-395` (`need` closure; `blob` caps pre-allocation at
  `1 << 20`), `control/mod.rs:161-175`, `snapshot.rs`, `tree.rs`,
  `membership.rs`, `keys/capability/{model,encoding}.rs`,
  `control/{rotation,bootstrap,nip46}.rs`, `seal.rs`, `keys/escrow.rs`,
  `durable/{codec,store}.rs`, `runtime/bootstrap.rs`.
- **Peer-supplied route decode** (`transport/addr.rs:79-137`) — the highest-risk
  one, since `node_addr` is attacker-chosen. Uses `.get(..)` throughout and ends
  with `encode_node_addr(&address) != bytes`, so non-canonical spellings,
  duplicate addresses, and trailing garbage all fail closed.
- **Exhaustion counters**, explicitly commented as unreachable: `u64` pending
  sequence (`engine/mod.rs:414-419`), delivery id (`transport/mailbox.rs:373-379`).
- **Poison-lock recovery** via `unwrap_or_else(|p| p.into_inner())`.

**Swallowed results** (`let _ =`) — three candidates, all justified in place:
- `wyrd-core/src/wake.rs:86` — `wait_timeout`'s `WaitTimeoutResult`, not an error.
- `wyrd-core/src/mailbox/mod.rs:1331` — `recover_stream` failure leaves the
  stream flagged down; the next supervisor tick retries. Commented.
- `wyrd-daemon/src/fuse/backend.rs:1797` — `repin_handle` failure "degrades to
  the stale rule — never to silent content loss", i.e. the handle becomes stale
  and returns `EIO`. Fail-closed.

`todo!`/`unimplemented!` — **zero in production code**. Three in
`crates/wyrd-contracts/src/upgrade_contracts.rs:246,261,355`, all inside
`#[ignore = "..."]` contract tests with documented reasons. This is the
disciplined use of `#[ignore]` I want to see.

`FIXME`/`TODO` — zero in the workspace.

### 5.3 Roadmap drift

| Roadmap claim | Code | Verdict |
|---|---|---|
| Phase 1 Remaining: "the serving router peers dial into (real-iroh loopback in the `wyrd` binary)" | Landed | **Stale** (NB-2) |
| Phase 1 Remaining: "NIP-46 remote signing" | `SignerSession` trait (`transport/signer.rs:52`) + wire codecs only (`control/nip46.rs`, 196 lines, `SignMessageRequest`/`Response` encode/decode). Only impls are `DeviceIdentitySecret` and four test fakes. No `nostr-connect` client, no session negotiation | **Accurately remaining** |
| Phase 1 Remaining: "bulk backpressure under live network conditions" | Fetch is single-threaded per pass (`docs/resource-limits.md:104-107`); no semaphore/concurrency limit. Mirrored queue bounds exist on the serving side (`MAX_MIRROR_QUEUE_ITEMS`/`BYTES`) | **Accurately remaining**; bounded via bytes-in-pass instead |
| "multi-relay mailbox supervision and relay interop coverage" listed open in `architecture.md:199` | Supervision landed (`live.rs:134-141`); multi-relay interop untested | **Partly stale** (NB-1, Ship table) |
| v0.2 Known limitations (2 items) | Both accurate; **incomplete** — omits Blocker 2 and NB-4 | **Incomplete** |
| `sync-and-peers.md` "Post-admission discovery" claims catch-up is "retried until acknowledged" | Acknowledgment is relay-accepted, not receipt | **Contradicted** (Blocker 2) |

**Is any Remaining item a v0.2 blocker?** NIP-46 and bulk backpressure: no —
neither is in the v0.2 Ship list, both are honestly tracked, and the roadmap
does not claim otherwise. Serving router: already landed. None of the three is
a blocker; Blocker 2 is the item the roadmap should have flagged and didn't.

### 5.4 Terminology

Consistent. The three recovery senses are defined once
(`ROADMAP.md:75-82`) and used correctly throughout: crash recovery is "Shipped"
and is what the workspace actually implements; content recovery is "v0.3"; root
recovery is "v0.7". No doc or CLI string claims v0.2 provides content or root
recovery. `docs/epochs.md:421,425,436` uses "Recovery" for *content* grafting
consistently with the roadmap's v0.3 assignment. `docs/cli.md:157` steers a lost
invitation to `reissue-invitation` rather than promising recovery.

One ambiguity, not an error: `docs/crash-consistency.md:169-170` uses
"degraded recovery" for a missing escrow sidecar and "root-alone recovery" in
the same sentence — dense but each sense is correct in context.

### 5.5 Known limitations — documented ones are honest; three are missing

Accurate and admirably candid as written: the retained-bytes quota's four
narrowings (`docs/storage-growth.md:281-338`), the interference channel
(`:299-308`), "one-way" quota (`:320-326`), and silent loss on `release`
(`:328-338`). `docs/resource-limits.md:56` and `:104-115` are equally honest.

**Undocumented, found in code:**
1. **Control-plane delivery is relay-accepted; a peer absent beyond relay
   retention never self-repairs, with no operator signal** (Blocker 2).
2. **No scrub/repair for corrupt fetched content; `FetchStatus::Corrupt` has no
   production producer** (NB-4). `docs/sync-and-peers.md:246` asserts otherwise.
3. **Admission's lineage-closure walk is O(recorded history)** in one admission
   (NB-6). Code acknowledges it; no doc does.
4. Resealed identical capabilities recommit durable facts, unbounded in
   retention (NB-12) — acknowledged in `docs/resource-limits.md:102`, should be
   in the release notes.

### 5.6 Docs vs code

`docs/sync-and-peers.md:47-48` ("every test runs against an in-memory fake,
never a live network") and `:52-55` ("the concrete relay pool … Deferred") are
the most misleading, because a reader concludes no relay code exists.
`docs/sync-and-peers.md:246` (corrupt/scrub) is contradicted by dead code.
`docs/architecture.md:53` (iroh invisibility) is true only at source level.
`ROADMAP.md:110-112` and `:193` are contradicted or unreconciled. Everything
else I read in `trust.md`, `epochs.md`, `object-model.md`, `resource-limits.md`,
`storage-growth.md`, `write-path.md`, and `error-conventions.md` matched the
code I inspected, including the raise-vs-count classifications and the
`StoreFailure::of_io` disk table.

---

## 6. Commands run and results

| # | Command | Result |
|---|---|---|
| 1 | `git status` | Dirty: 1 modified tracked file, 2 untracked (§0) |
| 2 | `git log --oneline 4877b1e..HEAD`; `git diff --stat` | 3 commits, 3 files, tests + doc comments only |
| 3 | `git merge-base --is-ancestor 4877b1e HEAD` | true (0 exit) |
| 4 | `cargo build --workspace` | **PASS** (33s) |
| 5 | `cargo fmt --check` | **PASS** (1s) |
| 6 | `cargo clippy --workspace --all-targets -- -D warnings` | **PASS** (13s) |
| 7 | `cargo test --workspace --no-fail-fast` | **PASS** — 1377 passed, 0 failed, 9 ignored (376s). Includes the `slow`-profile tests that the default nextest filter excludes (contracts binary alone: 186s) |
| 8 | `cargo test --workspace --doc` | **PASS** (2s) |
| 9 | `cargo nextest run` | **PASS** — `1368 tests run: 1368 passed, 16 skipped` (109s). Canonical AGENTS.md gate |
| 10 | `cargo test -p wyrd-cli` | **PASS** (20s) |
| 11 | `cargo deny check` | **PASS** — `advisories ok, bans ok, licenses ok, sources ok` |
| 12 | `cargo audit` | **exit 0**, 4 allowed warnings. No vulnerabilities. `RUSTSEC-2024-0370` (`faster-hex`, unsound) new in graph via `nostr` (NB-9) |
| 13 | `cargo tree -p wyrd-sync -e normal,build,dev` | Only `wyrd-format` — architecture rule PASS |
| 14 | `cargo tree -p wyrd-core -e normal,build,dev` | Only `wyrd-format`, `wyrd-sync` — PASS |
| 15 | `cargo tree -p wyrd-format -e normal,build,dev` | No network/async/FUSE crate — PASS |
| 16 | `cargo tree -p wyrd-fuse -e normal` | Reaches `wyrd-sync` + 25 iroh crates via `wyrd-core` (NB-5) |
| 17 | `cargo tree -i faster-hex` | `nostr → nostr-database → nostr-sdk → wyrd-core` |
| 18 | `cargo test -p wyrd-core external_relay -- --ignored` (`WYRD_TEST_RELAY_URL=wss://nos.lol`) | **FAIL** — both tests, `mailbox stayed down (stream_alive=true, connected=0/1)`. nos.lol TCP :443 unreachable from this host |
| 19 | same, `wss://relay.damus.io` | **FAIL** — attaches, no delivery; panics `tests_interop.rs:88` and `:127` |
| 20 | same, `wss://nostr.wine` | **FAIL** — identical |
| 21 | TCP/TLS probe: nos.lol, relay.damus.io, nostr.wine, relay.nostr.band, nostr.pub, relay.primal.net | nos.lol + relay.nostr.band TCP-timeout; nostr.pub DNS-fail; damus/wine/primal TLS-OK (HTTP 400 to a raw non-WebSocket probe, as expected) |
| 22 | `nostr-0.45.1/src/key/public_key.rs:86-89` inspection | `Display = to_hex()` → filter `#p` encoding **correct**; bech32 hypothesis refuted |
| 23 | `cargo test -p wyrd-cli --bin wyrd -- --ignored` (macFUSE present) | 1 passed, 1 failed. `live_mount_serves_read_write_until_shutdown` **PASS**; `live_mount_preserves_dirty_handle_across_shutdown` **FAIL** (26/27 bytes) |
| 24 | `live_mount_preserves_dirty_handle_across_shutdown` × 5 | **5/5 FAIL, byte-identical** — deterministic truncation |
| 25 | `grep -rn '#\[ignore' crates/` | 10 hits, all justified: 2 live-relay (opt-in), 4 upgrade-contract (blocked, with reasons), 1 fixture-regen, 2 FUSE mount (need kernel FUSE), + 2 comment mentions |
| 26 | `grep -rn 'todo!\|unimplemented!\|FIXME\|TODO' crates/` | 3 `todo!`, all in `#[ignore]`d contract tests; 0 in production; 0 FIXME/TODO |
| 27 | Silent-acceptance script (strip `#[cfg(test)]`, scan panic macros + `let _ =` + `.ok()`) | 315 raw → 0 unexplained (see §5.2) |
| 28 | `grep -rn 'microvm\|lima' .ngit/act/workflows/*.yml` | **No hits** — microVM suite is not CI-gated (NB-10) |

Not run: `./lima/run-alpha.sh`, `nix/microvm/run-microvm.sh` (require a Lima
guest / Linux KVM host; not available here), `ngit` remote operations.

---

## 7. Evidence requested

1. **A real-relay run that passes**, or the relay OK output from a failing one.
   The single highest-value missing datum. Blocks Blocker 3.
2. **A microVM `nix/microvm/run-microvm.sh --fresh` log from a Linux KVM host**
   (odin), particularly step 10's `tap-r` partition/heal legs. This is the only
   partition/heal evidence and it is in no CI job.
3. **CI run history for `master`** since `v0.1.0-alpha.1` — whether the
   `nextest --profile slow` job has been green on every master commit, and
   whether the 2 opt-in live-relay tests have ever been run in any pipeline.
   `.ngit/act/workflows/workflow.yml` does not invoke them.
4. **A Linux run of `live_mount_preserves_dirty_handle_across_shutdown`** to
   attribute Blocker 1 to Wyrd versus macFUSE.
5. **Issue-tracker state** for the follow-ups named in code comments and docs:
   the "intake-bound follow-up" (`docs/resource-limits.md:102`), the
   "conflict-divergence follow-up" (`tests/alpha-lima.sh:497-501`), and the two
   `storage-growth.md` open questions.
6. **Whether relay retention is assumed to exceed peer absence anywhere.**
   Blocker 2's severity depends on it; I found no statement either way.

---

## 8. Top 5 risks

| # | Risk | Likelihood | Impact | Cheapest mitigation |
|---|---|---|---|---|
| 1 | **Dirty-handle truncation ships and a user's file is silently corrupted at unmount.** Deterministic on macOS. | High — it is the *normal* shutdown path, not an edge case | Severe: silent data loss, no error, on the primary surface | Instrument the teardown drain's buffered length vs authored length (one run names the site), fix the accounting, re-run the ignored suite in CI |
| 2 | **A peer is silently stuck forever** after an absence longer than relay retention, with no operator signal and no repair path. | Medium — needs a long absence; laptops make it routine | Severe: drive appears healthy, permanently stale, unrecoverable without re-invite under a fresh identity | Document the bound now; add a gap report to `wyrd sync status` (known epoch vs newest announced epoch). Full repair (re-push/pull) is a protocol change — track it, don't fake it |
| 3 | **Relay interop is broken in production** and 1377 green hermetic tests hide it, because the only real-network evidence is `#[ignore]`d and fails. | Unknown — I could not separate relay policy from a product defect | Severe: the product does not work at all; the alpha's whole thesis fails | Log the relay's per-relay `OK` on send; run the two interop tests against a self-hosted `nostr-rs-relay` over `wss://` in CI as a stable baseline |
| 4 | **Partition/heal regresses unnoticed** because its only evidence is a suite no CI job runs. | Medium — manual suites rot; step 10 is the newest code | High: the DoD's weakest clause stays weakest, silently | Add the microVM job (or at minimum the step-10 partition/heal legs) to a CI workflow |
| 5 | **Doc drift misleads the next implementer** — `sync-and-peers.md:47-48` says no relay code exists; `:246` describes scrub/repair that is dead code; ROADMAP Phase 1 "Remaining" lists landed work. | High — already true today | Medium: wrong architectural decisions, duplicated work, false "already handled" | One docs pass reconciling the four contradictions; cheapest of the five and it de-risks the others |

---

## 9. Confidence and what would change the verdict

**Confidence: high on the mechanical findings, moderate on the two
environment-dependent ones.**

- Blocker 1 (truncation): **high**. Reproduced 5/5, byte-identical, with
  `write_all` returning `Ok` before the trip. The only uncertainty is cause
  attribution (Wyrd buffer vs macFUSE delivery), not existence.
- Blocker 4 (version/changelog): **certain**. Read directly from `Cargo.toml`
  and `CHANGELOG.md`.
- Blockers 2 and 3: **moderate**, and honestly so. Both are inferences from a
  failed or unreachable external dependency. Blockers 2's *mechanism* is read
  directly from code and is certain; its *trigger frequency* is not. Blocker 3
  is explicitly unattributed — I ruled out the filter-encoding cause and could
  not go further without relay-side output.
- Ship-item and DoD table: **moderate-to-high**. Every PASS cites a named test
  I read or ran. The `UNVERIFIED` verdicts are honest gaps, not passes.

**The architecture, intake, authorization, and bounds work is genuinely good**
and I want that on the record: decoders are guarded before every slice, intake
orders cheap rejection before expensive verification and memoizes the one
unbounded walk, the membership state machine is exhaustively conformant, the
announcement compatibility gate is exact, closures fail closed with an
exhaustive rejection taxonomy, `cargo deny`/`audit` are clean and wired into
CI, and every `ignore`/`todo!` in the tree is justified in place. The problems
in this release are concentrated in **the boundary between Wyrd and the outside
world** — real relays, long absences, and process teardown — which is exactly
where hermetic in-process harnesses are least able to reach.

**Would change the verdict to SHIP WITH DOCUMENTED CAVEATS:**
- Blocker 1 fixed and the ignored FUSE suite green (both tests).
- Blocker 4 fixed (version bumped, `[Unreleased]` present).
- Blocker 3 either demonstrated with a passing real-relay run, or
  conclusively attributed to third-party relay write policy *and* recorded as
  a release caveat.
- Blocker 2 documented as a known limitation with a stated bound.

**Would change it to a firmer DO NOT SHIP:** evidence that real-relay delivery
fails against a permissive relay (making Blocker 3 a product defect), or that
Blocker 1's truncation also occurs on Linux (widening it beyond macOS).

**Would change it to SHIP:** all four blockers fixed, plus the microVM
partition/heal suite green in CI. That is a short list, and every item on it is
mechanical.

---

## 10. Tracker map

Every finding above is filed. Existing issues were updated with evidence rather
than duplicated; nine new issues were created because no existing issue covered
them. References use `nostr:` URIs.

### New issues

| Finding | Subject | Triage | Reference |
|---|---|---|---|
| **Blocker 1** — dirty handle truncated at shutdown, 5/5 | `fix(fuse): commit the full buffered image when a dirty handle is torn down` | `bug` `P0` `release:v0.2.0-alpha` | `nostr:nevent1qqs0celgr5nyaz4f22vqe8zuc8cqxgzm2l8mwjl09r3cptp9e5n4dkqpz9mhxue69uhkwunpwdczuap49eehgtcmpm9` |
| **Blocker 3** (diagnosability half) — discarded per-relay `OK` | `fix(sync): surface the relay's per-relay OK on the control-plane send path` | `bug` `P1` `release:v0.2.0-alpha` | `nostr:nevent1qqs0zqytr3kfxnqjjd4j3tkk7qc2w6v95v98hqmmme2sth5scwdky6spz9mhxue69uhkwunpwdczuap49eehgl04fl6` |
| NB-1 — `sync-and-peers.md` relay-pool status is stale | `docs(sync): correct the relay-pool status in the transport boundary` | `chore` `P2` `release:v0.2.0-alpha` | `nostr:nevent1qqsfgx6ylpl5vd0teey3txqfakdd0k57h9znee2gdk4dw350m8gyu3gpz9mhxue69uhkwunpwdczuap49eehgpwy0cf` |
| NB-6 — admission closure walk absent from limitations | `docs(sync): bound the admission lineage-closure walk in the limitations list` | `chore` `P2` `release:v0.2.0-alpha` | `nostr:nevent1qqs9rngzmesyew6lyp9wa39xzppw4kqx3z0lsm4vxey6ajzfeqw0xyspz9mhxue69uhkwunpwdczuap49eehg0gr9uy` |
| NB-10 — microVM suite in no CI job | `ci: run the microVM partition and heal suite from a gate` | `chore` `P2` `release:v0.2.0-alpha` | `nostr:nevent1qqsgmkykgsxxj82etnc0gl2rx7pnz6z8rw68tvns95jwv95vacx6x2qpz9mhxue69uhkwunpwdczuap49eehgwkrn6w` |
| NB-5 — `wyrd-fuse` links iroh transitively | `arch(fuse): assert iroh stays unreachable from the view crate's link graph` | `enhancement` `P3` `release:v0.2.0-alpha` | `nostr:nevent1qqsy6sdhyz06hhpzxu7525smd5m9fduml89hz972t4mjn6ejk928myspz9mhxue69uhkwunpwdczuap49eehghux2kpg` |
| NB-9 — no policy for `unsound` advisories | `chore(deny): cover unsound advisories in the dependency audit policy` | `chore` `P3` `release:v0.2.0-alpha` | `nostr:nevent1qqs87ufaylq5xfgyru3m0cha4smd2yrc4mmfa5uascrsfa8ce8my3fgpz9mhxue69uhkwunpwdczuap49eehgmr2qld` |
| NB-7 — interop doc names the wrong crate | `docs(sync): fix the interop run command's crate name` | `chore` `P4` `release:v0.2.0-alpha` | `nostr:nevent1qqsw09p7nlsv9cl5rv842kpxqh2dzh4dtuq48ns6emv7vgyaqauptkqpz9mhxue69uhkwunpwdczuap49eehgvs33nc` |
| NB-11 — `AGENTS.md` vs workflow label-timing conflict | `docs(process): reconcile issue-triage label timing with the collaboration workflow` | `chore` `P4` `release:v0.2.0-alpha` | `nostr:nevent1qqs2l95kv227cn64sg4au9mwxrpdw7mrm8cde83zwlg0w99j546ek5spz9mhxue69uhkwunpwdczuap49eehghw8v48g` |

### Existing issues updated with evidence

| Finding | Subject | Reference |
|---|---|---|
| NB-4 — `FetchStatus::Corrupt` has no producer; `sync-and-peers.md:246` false | `feat(sync): implement or defer automatic peer repair` | `nostr:nevent1qqsvhp0uvs9mfcjwlp4edz0ng67qn33y5yj0p6tuh0x6r6tmunax3tcpz9mhxue69uhkwunpwdczuap49eehgh5g0vc` |
| **Blocker 2** — delivery is relay-accepted, no re-push/pull/signal | `test(sync): exercise history catch-up after relay disconnection` | `nostr:nevent1qqsr5d9tux05gylu2fdxjwn0p7gf7tqwjqekk668lw3x6n8da0eguscpz9mhxue69uhkwunpwdczuap49eehgrg8yxn` |
| **Blocker 3** — real-relay run results, filter refuted | `test(mailbox): verify multi-relay interoperability` | `nostr:nevent1qqs9sqdpy25tfx97eg9npdqmgaqdtmd78rks7gye9gt33u20cc74r8cpz9mhxue69uhkwunpwdczuap49eehgt3au36` |
| **Blocker 4** — Cargo version and missing `[Unreleased]` | `chore(release): keep v0.2 distribution disabled` | `nostr:nevent1qqs2evygg8x88gsgy52fpa733k6ts4tazen790dgqaln67ylv4zr4zqpz9mhxue69uhkwunpwdczuap49eehgryxsx6` |
| NB-2 — serving router has landed; limitations incomplete | `docs(roadmap): reconcile landed sync work and remaining items` | `nostr:nevent1qqsq5frvceu4tn065x7u7guhl7rd0jxgxxw28gegv95rqcy56h6alhqpz9mhxue69uhkwunpwdczuap49eehghj6ukh4` |
| NB-3 — `author_recovery_snapshot` is `pub` with 3 passing contracts | `bug(sync): defer recovery grafting until v0.3` | `nostr:nevent1qqs2pczj7ygrtwhajhkmg2fmqdmt59skvjhqas8p04fyt75e83xyrecpz9mhxue69uhkwunpwdczuap49eehgylxhzm` |
| NB-12 — resealed capability recommits, now test-pinned | `feat(sync): deduplicate resealed identical capabilities in intake` | `nostr:nevent1qqsvn84z7d00uxl9rmtsfsacv5nden9mfn97za6zhsp0krumw5w0z5cpz9mhxue69uhkwunpwdczuap49eehgh52arpj` |
| NB-8 — `nostr-connect` declared, never used | `chore: drop or defer the unused iroh-gossip dependency` | `nostr:nevent1qqsqgvv76k54x2ngxg5papmkm72n80hq0vstat80gk9jrtkdtru7qrcpz9mhxue69uhkwunpwdczuap49eehgf6swmm` |

### Findings deliberately not filed

- **NB-3's roadmap wording** is folded into the recovery-grafting issue rather
  than split out; it is the same decision.
- **Blocker 4's two mechanical sub-parts** (version bump, `[Unreleased]`
  section) are both on the distribution issue; one issue, two checklist items.
- **"Relay retention is assumed to exceed peer absence"** is an open question in
  §7 rather than an issue — I could not establish that an assumption exists, so
  there is nothing to attach a decision to yet. It becomes a real issue once
  Blocker 2's issue is triaged on scope.
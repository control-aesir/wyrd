# Peer Repair: design note

Status: v0.2 defers dedicated repair (this issue's sanctioned path).
Part 1 shipped in v0.3: generation-scoped terminal fetch state with
waiter completion (`Unavailable(generation)` plus reopen-on-new-waiter;
quarantine, scrub, and diagnostics are the following children).
The v0.2 ship is fetch-walk fallback across recorded representations
with post-fetch verification, fail-closed, bounded `EIO` on exhaustion.
This note records the design the deferral points at, and the protocol
seam it must not cross early.

Central thesis: **repair itself is not a protocol change; deliberate
replication is.** Fetching good bytes from somewhere else and
verifying them uses existing primitives. Deciding that multiple
independently advertised routes for one immutable snapshot are
simultaneously authoritative changes route semantics — that is the
seam to protect.

## v0.2 behavior (shipped, tested)

Three nested fallbacks inside one fetch pass, all fail-closed:

- across representations of one content (`fetch::object`,
  `crates/wyrd-sync/src/runtime/fetch/mod.rs:358`) — the walk's unit
  is the representation (`PendingObjectFetch`), not the provider;
- across routes of one representation (`fetch_representation`, same
  file `:285`): transport root, then storage address;
- across providers of one address (`IrohBulkSource::fetch_candidates`,
  `crates/wyrd-sync/src/bulk.rs:467`) — populated with more than one
  entry only in tests; production publishes one peer per snapshot
  (`transport/routes.rs:34,61`), so live alternates arrive as
  representations recorded via different snapshots.

Backoff: 3 strikes → 8-pass cooldown for `Invalid`/`Transport`,
separate burn ledger for budget deaths, `Missing` never strikes
(`runtime/engine/mod.rs:533-534,1602-1648`). Strike ledgers are
in-memory by decision ("cheaper to reason about than persisting
grudges"). `FetchStatus::Corrupt` is still vocabulary only;
`Unavailable(generation)` projects live once the engine's terminal
evaluation completes a generation with every representation
exhausted (`runtime/engine/mod.rs`: `evaluate_terminal`), overlaid
onto the durable status by the node's materialization projection.

## Part 1 — device-local repair loop (v0.3 core, no protocol change)

Defined as **generation-scoped terminal fetch state + waiter
completion + local quarantine/re-want + diagnostics** — not "wire
`settled()` through."

### Generations, not passes

A cooldown is not evidence of failure in the current pass. Terminality
is defined over a **retry generation / failure epoch**:

- candidate attempted and failed → contributes evidence;
- candidate currently cooled → contributes *known unavailable until
  generation X*, never new evidence;
- terminal when the current generation has accumulated enough failure
  evidence that every currently eligible candidate is exhausted;
- the generation changes when a new waiter reopens a completed
  terminal. Cooldown expiry and newly arrived candidates restore
  eligibility — attempts resume under the background plan — but
  they do not rotate the generation on their own: rotating without
  demand would republish a verdict nobody is reading every cooldown
  cycle (OD-11-2). A completed generation never reopens by itself.

This keeps two states distinct that must not be conflated:

- **no viable provider right now** (wait, keep pending);
- **established that this identity is unavailable** (complete waiters).

### Corrupt and Unavailable stay asymmetric

- `Corrupt`: bytes were obtained and verification rejected them.
  Strong evidence — about *that provider/representation*. Another
  representation or provider may still work.
- `Unavailable`: the fetch could not be obtained or completed.
  Weak evidence — retry may work later.

Three transient network failures must never project `Corrupt` just
because both surface as `EIO`. Terminal state is therefore shaped
like **`Unavailable(generation)`**; `Corrupt` stays attached to
provider/representation failures unless identity-level evidence
establishes every representation bad.

### Waiter invariant

> A terminal fetch result completes current waiters; it never makes
> the identity permanently terminal.

State-driven retry replaces deadline-driven retry: the EIO is a
bounded result of one failed generation, not durable poison. A new
waiter reopens the attempt as a new generation. The demand reaches
the loop as a sticky note, not as a blocked waiter: an unavailable
read records reopen demand and fails fast, and the next pass rotates
the generation for the retry — unless a rejection was observed for
the identity within the repair window (30 s, memory-only), in
which case the waiter waits out the in-flight repair instead of
failing fast on the stale projection. (Corrupt verdicts complete waiters
but record no note: their repair is quarantine's, not rewant's —
see child 12.) Flaky networks cause
EIOs, but each is bounded and recoverable — no EIO-storm-to-permanent
path exists by construction.

### Scrub without tombstones

A verified-corrupt *local artifact* (cache/materialization state) is
removed locally, then the immutable identity is re-wanted and
fetched verified again. This deletes no Wyrd object from logical
history, so the append-only model needs no tombstone and no new
durable-fact kind. The distinction is explicit: if the thing being
deleted is itself durable replicated state, that is a different
problem and out of scope for this design.

Decided for child 12 (OD-12-1 A, OD-12-2 A, SD-1 A):

- **Remove, not quarantine-in-place** (OD-12-1 A): verification has
  established the bytes must not be admitted as usable content, so
  keeping them preserves forensic evidence, not content — and the
  failure path must not consume the resource the retention quota
  protects. There is no quarantine namespace and no bound to tend.
- **Re-want only on the next waiter** (OD-12-2 A): corruption makes
  the current representation ineligible; demand makes the identity
  eligible for a fresh generation. No synthetic waiter, no
  background repair walk. Terminology is *rejected representation /
  repair-on-demand*: after deletion no durable state blocks a later
  waiter from starting generation N+1.
- **Client-plane only** (SD-1 A): the sealed serving vault already
  fails closed on root mismatch, so it is untouched — absence there
  is not more correct than masked corruption, and a client-plane
  repair must not mutate serving capacity as a side effect.
- **Diagnostic before delete**: the diagnostic record identifying
  the representation and the verification failure is emitted before
  the bytes are discarded, as an explicit sequencing contract the
  drain enforces structurally (child 14 owns the record in full).
- **Deletion stays narrow**: only a representation just verified
  invalid may be deleted, through a narrowly named discard — never
  a general `ObjectStore::remove`. The implementation distinguishes
  the bad physical bytes, the durable possession claim (cleared via
  an `ObjectRemoved` commit), and the demand state, so no
  stale claim pretends deleted bytes still exist. Claim-clear
  precedes unlink, so a crash converges either way
  (`docs/crash-consistency.md`, quarantine repair).

Decided for child 13 (OD-13-1 walk-every-pass, OD-13-2
memory-only cursor, OD-13-3 clear-with-size-zero):

- **Walk every pass, capped** (OD-13-1): out-of-band loss has no
  trigger signal, so the presence walk runs on every pass —
  bounded by `max_scrub_per_pass` stats over locally claimed
  identities (O(claims), never O(history)), reusing admission's
  snapshot when it took one. A walk-found loss heals one pass
  later than a read-found one; beside a full sweep's rotation
  that latency is immaterial.
- **Memory-only cursor** (OD-13-2): the sweep position resets on
  restart like the strike ledgers. A restart re-sweeps from the
  beginning, deterministically ordered — coverage, never
  freshness, is what a restart loses.
- **Claim with no manifest entry still clears, with size zero**
  (OD-13-3): the projection must stop lying even when the
  accountant has nothing to subtract, and the reopen walk
  re-seeds the count from the store.
- **Placement: drain ahead of admission, walk after it.** The
  drain clears read-found losses on the same pass they are
  reported, so the waiter's want drives a fresh fetch without
  waiting another pass; the walk submits for the next pass's
  drain. Recorded here because the issue left the placement open.
- **The install gate's tree/chunk asymmetry bounds what the
  placement buys.** `verify_head_closure` reads every tree
  through the store (a lost tree fails the install as
  `TreeUnavailable`) but checks chunks for entry/mapping
  consistency only — so the scrub heals lost chunks behind an
  installed head rather than holding the install. Moving chunk
  presence into the gate is a separate change, deliberately not
  taken here: it would turn every install into a full-store stat
  pass.
- **No second discard path.** The scrub never unlinks: bytes
  already gone need no removal, so there is no narrow-discard
  analogue and no new store operation. The accountant subtract
  is the only state the scrub mutates besides the claim.

## Part 2 — replication serving (after measurement; v0.7 home)

Gated on measuring the actual stranding conjunction first. There are
two different repair problems:

- **A. object stranded**: the control plane knows where the snapshot
  is, but the content provider is dead. Part 1 + existing fallback
  already address this.
- **B. snapshot stranded**: the only route to the snapshot is dead
  and mailbox/history cannot recover another route. Only Part 2
  fixes this.

If live-network evidence shows B is rare (mailbox catch-up reliably
yields another announcer/route), multi-route snapshot replication is
an optimization/hardening story, not the availability fix. Instrument
the conjunction before committing protocol surface.

### Protocol invariants (review before implementation)

1. **One immutable statement per `SnapshotId`.**
2. **Routes are additive to that statement.**
3. **Adding a route can never turn a fork into an accepted update.**
4. **Route ordering is policy, not trust/reputation.**
5. **Route sets are bounded locally.**
6. **Terminal fetch state is generation-scoped and never permanent.**
7. **Corruption evidence and transport unavailability remain distinct.**
8. **Local scrubbing does not create replicated tombstones.**

### Statement-vs-route model

The protocol shape is:

```text
SnapshotId
  └── Statement (author, epoch, membership, body_root, roots...)
       ├── Route A
       ├── Route B
       └── Route C
```

not one authoritative announcement per announcer, and not
`(snapshot, announcer, route-bytes)` as the semantic key — that
tuple is a storage/index key. The model must first establish
*one statement + N routes*, then decide indexing, or two entries
with different keys can carry contradictory statements that both
survive. Fork detection (`SnapshotAnnouncement::check_update`,
`control/message.rs:204-219`) stays exactly as is: differing
immutable fields remain a hard `Fork`, never an accumulable route.

### Ordering without reputation

No observed-reliability scoring: it drags in who-observes,
local-vs-shared, decay, slander/self-promotion, durable ranking,
and post-restart semantics — protocol-adjacent machinery just to
make repair faster. v0 policy: **publication order + existing
fair-share mechanics**, documented as availability-oriented, not
latency-optimized — a newly published healthy route may be tried
after older routes. Coherent trade, tiny footprint.

### Scheduler before routes

`fetch_candidates`' fair-share geometry thins slices geometrically
with candidate count (`bulk.rs:193-213`, documented starvation
tail), so turning one provider into N under the current walk can
make repair *worse* under tight budgets. Part 2's prerequisite is a
candidate-scheduling abstraction — ordered candidates, bounded
attempt budget, per-candidate timeout, fair-share/reservation
policy — that replication plugs into. Changing `Option<Route>`
into `Vec<Route>` and reusing the walk is the wrong seam.

### Route-set bounds

Routes arrive via announcements, so envelope size is unaffected —
but accumulation must still be bounded locally: deduplicate route
identity, cap retained routes per snapshot, preserve deterministic
publication order, and never treat evicting a route as a protocol
statement. Purely local policy; the wire stays additive.

## Scheduling

- **Part 1 → v0.3 core** (durability/recovery/observability), before
  the v0.3-architecture consolidation, which forbids semantic change.
- **Part 2 → only after the (B)-measurement**, home in v0.7
  (replication and residency policy) unless the measurement pulls it
  forward with the scheduler prerequisite attached.
- **Hard stop: v0.8 freeze.** v0.9 bans redesign. Everything
  protocol-shaped lands before the freeze or not at all.

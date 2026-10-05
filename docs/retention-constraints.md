# Retention constraints v0.x must preserve

**Status: decision.** This document specifies the constraints that v0.x
must preserve so a future GC design stays possible. It is not a GC
algorithm: no prune rule, no quorum, no grace period, no reclamation
protocol is decided here.

> **GC is post-v1 implementation scope, but retention is not post-v1
> design scope.** v0.x establishes bounded retention and explicit
> refusal semantics; v1+ may establish safe reclamation.

The quantitative and adversarial analysis lives in `storage-growth.md`;
the authorization half of refusal lives in `trust.md` T18; the DG-4
retention/refusal contract lives in `storage-growth.md`. This document
is the normative v0.x decision derived from that analysis: what v0.x
promises, what it refuses to promise, and what it must not silently
introduce. `storage-growth.md` remains the quantitative and adversarial
analysis; this document governs the resulting v0.x constraints.

## Retention vs residency

Two quantities, two enforcement points, never merged:

* **Retention (bytes admitted):** what this device holds in its local
  immutable store. The v0.x bound is a pre-admission gate: refuse before
  the bytes become irreversible, since the store cannot un-hold them.
  What each path enforces today differs. The mounted write path checks
  `retained_bytes_quota` (`>=` already-retained, before the commit's
  first write, `LiveNode::enforce_retained_quota`): it bounds the
  object-store plaintext dimension only, admits one commit of overshoot,
  and leaves vault ciphertext, snapshot bodies, sealed manifests, and
  the fact log untallied. The receive path has no gate yet (the DG-4 A
  gate is decided, unimplemented), so fetched bytes charge the same
  accountant with no ceiling in scope. The v0.x constraint is that
  every path adding durable bytes converges on this gate; the
  implementation status per path is in `storage-growth.md`.
* **Residency (what is promised):** what this device claims it will
  retain, serve, mirror, or otherwise make available to peers.
  Bounded by a residency refusal after durability. Refusing residency
  changes promises, never stored bytes. Physical storage remains
  retention; residency is a policy and contract state over
  already-retained material.

DG-4 (`storage-growth.md`) splits the refusal right along exactly this
line:

* **A — admission refusal:** decline any new durable admission that
  would exceed the local retention bound, whether locally authored or
  fetched. For fetched representations refusal occurs before local
  storage: refused bytes are never stored and charged nowhere on this
  device. Local mutation admission is governed by the same accounting
  direction (the mounted-path `retained_bytes_quota` check,
  `storage-growth.md`); until the receive-path A gate is enforced, a
  remote author can still spend a peer's local-write headroom, and the
  quota bounds the object-store plaintext dimension only (vault,
  body, manifest, and fact-log bytes untallied; one commit of
  overshoot).
* **B — residency refusal:** after durable local acceptance, decline to
  make those bytes eligible for serving, mirroring, or new retention
  promises under local policy. The bytes remain stored and charged;
  refusal does not erase or un-charge them. Mirror work, promises, and
  serving are withheld. B is not a second storage-admission gate: it
  never undoes A's admission decision and never reduces the
  retained-byte charge.

## Adversary

v0.x designs against this adversary, not against large files alone:

1. **State-transition churn, not just content volume.** The curve is
   transitions retained, not only bytes added. Pure namespace churn
   (`unlink` + `create` in a loop) commits snapshots with zero
   file-content bytes while paying the full fixed per-snapshot cost.
2. **Replica asymmetry.** On a replica the commit rate is set by peers,
   not by the disk owner. The resource owner is not necessarily the
   mutation author.
3. **Structural closure.** Retaining a snapshot means retaining its
   reachable structural closure (snapshot body, root and child
   manifests, tree nodes), whether or not any file content was wanted.
   Accounting that charges only new leaf bytes understates a replica
   by a multiple.
4. **Remote spending of local headroom.** Fetched bytes charge the
   local accountant. Without an admission gate, a remote author can
   consume a peer's local-write quota until the peer's own writes fail
   `ENOSPC` on a healthy drive.

Chunking, deduplication, and per-object ingest ceilings (`Limits::V0`)
bound one commit. They do not bound the count of commits.

## Invariants v0.x preserves

1. **Retention is not deletion.** A replica may refuse further
   retention without deleting what it already holds. No v0.x refusal
   path deletes, un-charges, or rewrites stored bytes.
2. **Residency is not availability.** One device's willingness to
   retain never implies the object is safe to reclaim elsewhere. No
   v0.x signal may be read as global reclaimability.
3. **Quota pressure causes refusal, never reclamation evidence.**
   Reaching a ceiling declines new retention or new promises. It never
   manufactures proof that history is reclaimable.
4. **Reclamation needs a separate authority.** Quorum, grace period,
   offline-vault acknowledgement, and human confirmation belong to the
   future GC design. Nothing in v0.x mints that authority early.
5. **Remote admission is charged locally.** Every representation
  admitted into durable local storage is charged against the admitting
  device's retention budget, on the legs the accountant sees.
6. **v0.3 refusal is local and has no wire representation.** No
  v0.3 control-plane refusal signal: a "peer X declined your content"
  message is an enumeration channel. Refusal is operator-visible locally
  (`wyrd cache policy` names the ceiling), never a protocol event. This
  scopes the v0.3 protocol contract only; it does not forbid a future
  GC or availability protocol from representing inability to retain.
7. **Refusal never looks like loss.** The operator surface and all
  internal loss/repair paths distinguish: never admitted, deliberately
  refused, retained, unavailable (no route, bytes, or capability yet),
  corrupt. The invariant is **refused is not unavailable, and neither
  is lost**: refused content never enters loss/repair as lost, never
  reports as transient fetch failure or quiet absence, and never reads
  as successful replication.
8. **Refusal is durable.** Restart cannot turn "I refused this" into
   "I promised this". Boot rebuild consults durable refusal state;
   serving maps offer only recorded-as-servable state.

## Accounting prerequisites (part of the contract)

These are not incidental implementation work; DG-4 enforcement is gated
on them:

* `RetainedBytes` decrement or authoritative recomputation for any
  existing non-GC path that removes, quarantines, or otherwise ceases
  to count stored objects (today add and get only; without it a
  scrubbed or quarantined object keeps its charge forever). v0.3 does
  not use it to reclaim storage: the decrement must exist before any
  future path can remove or cease charging stored bytes. GC is not
  introduced by this prerequisite.
* A vault-seeing counter beside mirror accounting in `wyrd-sync`,
  recording the retained body and manifest bytes observed through
  vault replication so those untallied bytes participate in local
  accounting. It lives beside mirror accounting where ciphertext
  already lives, not as a widened `wyrd-format` `RetainedBytes`,
  which the plaintext-world split reserves for plaintext accounting.
* Durable refusal state the boot rebuild can consult. The state must
  identify the refused retention/promise unit sufficiently for the
  rebuild to preserve the same refusal decision — this document does
  not fix the unit (content, representation, snapshot, or otherwise);
  the implementation follow-up does.
* `wyrd cache policy` reports the ceiling that caused a refusal,
  alongside the reachable-content census and effective budgets, with
  local quota and receive-side ceilings shown as distinct numbers.

## What v0.3-v0.4 must not introduce

* No eviction-under-pressure (it creates "evicted vs lost" ambiguity
  across provider knowledge, repair, pinning, and GC).
* No promise that a peer or vault retains arbitrary amounts of history
  indefinitely: v0.x must not make unbounded growth the contract for
  peers or vaults.
* No history-depth policy enforced by pruning (observable and
  reportable only, until GC exists).
* No snapshot rate limiting that delays or fails a POSIX-durable
  commit (`flush`/`fsync` equivalence and `O_SYNC` per-write durability
  stand).
* No control-plane refusal signal, no durable `Fact` for a refusal,
  no format or wire change for refusal in v0.3.
* No reclamation based on quota pressure, pin state, cache state, or
  fetch failure counts.

## Dogfood obligation

Product default remains unset (unlimited) for compatibility, so
existing deployments behave as before. Wyrd-operated dogfood
deployments explicitly configure ceilings during v0.3-v0.4 and observe
actual growth: namespace-churn accumulation rate, structural-overhead
share, replication amplification, refusal-boundary usability, and
accounting comprehensibility. That evidence, not speculation, sizes the
eventual reclamation policy.

## Compatibility impact

None on the persistent format and none on the wire: this document
decides constraints only. Drives written before it open unchanged;
peers that never refuse interoperate byte-for-byte with peers that do.

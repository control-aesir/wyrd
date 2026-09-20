# Membership and Epoch State Machine

**Status: NORMATIVE.** Companion contract to `trust.md`, which owns identity,
custody, the key hierarchy, and capability confidentiality; this document
owns the authorization state machine. It answers: *what makes a snapshot an
authorized descendant of another snapshot?* — precisely, given a snapshot, a
membership log, and partial local knowledge.

Design goals, in order:
1. **Offline-first** — no global agreement, no synchronous revocation;
   inconsistency is bounded and self-heals as state propagates.
2. **Exact revocation** — a removed device's write authorization ends at a
   precise, verifiable boundary.
3. **Membership privacy** — membership contents never touch a public relay.

## Vocabulary (two layers, four words)

Two layers are kept strictly separate:

- **Canonical membership state** (the log): which transition is the
  authoritative authorization state per epoch. Advanced **only** by
  transitions.
- **Snapshot history** (the DAG): which signed snapshots descend from the
  canonical authorization states. Its live projection — the **live view** —
  is what FUSE renders.

And four transition properties, each independent:

| Property | Meaning |
|---|---|
| **valid** | passes structure, signature, and derive-the-result checks against its predecessor |
| **rooted** | ancestry terminates at the unique genesis transition, every predecessor valid |
| **canonical** | the selected transition for its epoch on the canonical chain |
| **voided / orphaned** | valid+rooted but lost a conflict (voided); not rooted (orphaned) |

A valid noncanonical transition is retained historical evidence — it can
never authorize snapshots, but it is not deleted and not "invalid".

## Layer 1 — the membership log

Membership is an **append-only chain of signed transitions**, sealed to the
drive (members decrypt; vaults and relays store opaquely):

```
MembershipTransition {
    epoch:        u64              // the epoch this transition creates
    prev:         transition id (None only at genesis)
    resolves:     Vec<TransitionId> // conflict branches voided by this transition
    changes:      Vec<Change>      // Admit | Remove | Rotate | SetOwners
    members_root: hash of the member set AFTER applying changes
    owners_root:  hash of the owner set AFTER applying changes
    author:       Nostr pubkey
    signature:    BIP-340 over the challenge of
                  "wyrd membership v1" || DriveId || signing preimage
                  (challenge derivation pinned in trust.md)
}
```

`transition_id` = domain-separated BLAKE3 over the transition's **signing
preimage ‖ signature** (signing preimage defined in `trust.md`; signatures
are deterministic BIP-340 nonces, so the id is stable). The transition's
**canonical byte encoding is its signing preimage concatenated with its
signature** — transitions are sealed documents, not content-addressed
objects, so they carry no envelope framing (object-model.md, decision 17).

A **membership state** is `(epoch, transition_id, members_root, owners_root)`. A peer's
authoritative knowledge is its **known membership state** — the canonical
tip — not a bare epoch number; known membership epoch ≠ held epoch secrets
(a device can learn epoch N's transition long before its capability for N
arrives). The genesis transition (epoch 1, `prev = None`, empty `resolves`)
is created with the drive; `members_root` and `owners_root` both cover
exactly the owner. Every epoch number has a state, so snapshots can always
reference one — the snapshot's membership reference is never optional.

Set roots are **derived, never authoritative** (verifiers recompute them
from the transition chain): `BLAKE3-derive_key` with the pinned contexts
`"wyrd member set v1"` / `"wyrd owner set v1"` over the set encoded as a
`u32` LE count followed by the 32-byte x-only pubkeys in ascending bytewise
order, duplicates removed (object-model.md, decision 18).

Change application (`apply(state, changes)`), pinned semantics:

- `Admit(d, k)` requires `d ∉ members` and registers `k` as the device's
  delivery encryption key. `Remove(d)` requires `d ∈ members`
  and removes `d` from **members**; removing a device who is an owner is
  allowed only when they are the **sole owner** — the owner set empties
  with them (valid and terminal, per the terminal-state rule below). An
  owner with co-owners can only leave via `SetOwners`. **Removing and
  re-admitting the same device in the same transition is invalid**
  (encryption-key rotation is not expressible this way): the previous
  registration and its delivery key leave membership cleanly; replacing
  a device means a removal transition followed by a later admission.
- `SetOwners(D)` requires `|D| == 1` in **v0** and replaces the owner set
  wholesale; the final invariant `owners ⊆ members` is enforced after all
  changes as the backstop against dangling owners (e.g. `SetOwners` of a
  non-member).
- `Rotate()` changes no member or owner; it exists to force a fresh epoch
  secret.
- Changes apply sequentially; `changes` is non-empty.

### Validity and rootedness

A transition is **valid** iff:

1. Structure: `epoch ≥ 1`; `prev` identifies a valid transition at
   `epoch − 1` (None only at genesis); every entry in `resolves` identifies
   a valid transition at `epoch − 1`; `changes` is non-empty and every
   change is individually well-formed.
2. `apply(state(prev), changes) == (members_root, owners_root)` — the
   resulting roots are **derived, not independently authoritative**; the
   verifier recomputes them. Change rules:
   - `Admit(d, k)` requires `d ∉ members` and registers `k` as the
     device's delivery encryption key; `Remove(d)` requires `d ∈ members`.
   - `SetOwners(D)` requires `|D| == 1` in **v0** (singleton ownership;
     multi-owner is a later extension that relaxes exactly this rule) and
     the device must be a member. Owners are a subset of members.
   - `Rotate()` changes no member or owner; it exists to force a fresh
     epoch secret (compromise response).
3. `T.author` is an owner **in the pre-transition state** (`state(prev)`).
   Signature authority always comes from the state being left — this is
   what makes `SetOwners` and removing the last current owner expressible.
4. `T.signature` verifies, drive-bound, with full BIP-340 key validation
   (`lift_x` on the x-only pubkey; exactly 64-byte signatures; deterministic
   nonce) — exact bytes in `trust.md`.

A valid transition is **rooted** iff its `prev` chain terminates at the
unique genesis transition with every predecessor valid — a hard invariant:

> **A transition is usable as an authorization state only if its predecessor
> chain terminates at the unique Drive genesis transition and every
> predecessor is valid.**

A valid but unrooted transition is **orphaned**: retained, never canonical,
never authorizing. Orphaned transitions are membership bugs or attacks and
surface as drive-level errors.

### Canonicality, conflicts, and resolution

The **canonical chain** is defined by the local log; it is determined
solely by the set of observed transitions — never by their arrival order
and never by snapshot DAG state:

- `canonical(1)` = the unique valid genesis. Two valid genesis transitions
  (same epoch, same predecessor `None`) conflict at epoch 1 like any other.
- Absent a conflict, `canonical(N+1)` = the unique valid transition whose
  `prev` is `canonical(N)`.
- **A conflict exists** iff two or more valid transitions share the same
  canonical predecessor (`prev` both = the same canonical transition, same
  epoch). Competition among children of *different* predecessors is never a
  conflict: a child of a noncanonical or void branch is voided (or
  orphaned) by ancestry — it is historical evidence, not a rival.
- A conflict **freezes** membership evaluation at that epoch: snapshots
  bound to any contested transition are PENDING; a drive-level error is
  surfaced for the owner. Peers never pick a side themselves, and arrival
  order never decides.
- **Resolution is explicit and owner-signed.** The conflict stays frozen
  until a valid transition R at the next epoch whose `prev` names the
  winning branch's tip and whose `resolves` names **exactly** the voided
  siblings — no fewer, no more, no duplicates, no unrelated transitions —
  is observed. On seeing R: the winning branch (and its ancestors to genesis)
  become canonical from the fork point forward; every named sibling is
  voided permanently. R must be the unique valid child of the winning tip
  claiming the next epoch — a *second, contradictory* resolution (naming
  the other sibling) is itself a conflict at the resolution epoch and
  re-freezes evaluation there, pending a further resolution.
- Transitions with a non-empty `resolves` where no conflict exists at
  `prev` are invalid. Voided transitions are retained forever; they cannot
  be deleted or re-signed.
- **A resolution is only recognized at the epoch immediately above the
  conflict** (its `resolves` entries sit at the conflict epoch). A
  contested branch that accumulates valid descendants past the conflict
  epoch therefore makes the freeze permanent for v0: no conformant
  resolution can ever name the siblings. Peers surface that as a
  drive-level error for the owner.

v0 has exactly one owner ⇒ a single writer ⇒ conflicts indicate device
duplication or a bug and are treated as errors, not tolerated forks.

### Terminal state: zero owners

`Remove(owner)` when the owner is the only owner is a **valid** transition,
but it terminates the drive's owner-authorized evolution: authority always
comes from the pre-transition owner set, so with an empty owner set no
future transition (including conflict resolution) can ever be authorized.
Membership freezes permanently. Recovery of such a drive requires the root
custody / guardian mechanism (`trust.md`), which is reserved and post-v0.
Implementations MUST warn before applying a last-owner removal.

### Epoch bump triggers

Admit, remove, rotate, owner-set change. One transition = exactly one new
epoch.

## Layer 2 — epoch secrets and capabilities

```
EpochSecret(N): a new uniformly random 256-bit secret is generated for
                every transition; implementations MUST NOT intentionally
                reuse an epoch secret across transitions (accidental
                collision is negligible by construction). Secrets are
                never derived from the DriveRootKey, the epoch number, or
                each other.
```

The root key is **custody, not authority**: it protects drive-level
cryptographic custody and recovery material. Membership-transition
authorization is provided by the owner's Nostr signing key; the root never
signs or derives transitions, and **ordinary members never possess the
root** (a member holding it could not forge transitions, but revocation
reasoning would collapse anyway — root possession is owner/recovery
custody, wrapped at rest per `trust.md`). Key derivation from the epoch
secret is per `trust.md`.

A **capability** delivered to a member of epoch N:

- contains the wrapped secrets for **epochs 1..=N** (new members read full
  history) and nothing beyond;
- is wrapped under a key established by **secp256k1 ECDH** between a fresh
   owner-ephemeral key and the recipient device's registered encryption
   key (HKDF to
   the AEAD key — the encryption key is a secp256k1 key like the signing
   keys, so the same ECDH construction applies; the exact instantiation
   is implemented in `wyrd-sync/src/control/`) with associated data
   `domain("wyrd capability v1") || DriveId || recipient DeviceId ||
   recipient encryption key || transition_id || epoch` — the AAD binds the context; the ECDH-wrapped
  AEAD is what actually authenticates the recipient. A capability cannot be
  transplanted or replayed across drives, epochs, or devices.
- is delivered via the Nostr mailbox, so the owner can mint epoch N+1 and
  wrap the new capability while the device is offline. The first
  delivery (the invitation) is ECDH-sealed to the invitee, since the
  device holds no epoch key yet; every later delivery is a *rotation
  delivery* (envelope version `0x01`, decided): ECDH to the
  recipient's registered encryption key under a fresh ephemeral key,
  carrying the wrapped capability plus the authorizing transition's
  bytes, so one drain converges without the recipient holding the
  epoch's control key. The ECDH seal proves nothing about the sender,
  so intake admits a rotation delivery only from a member of the
  authorizing state (the outer mailbox seal authenticates the sender
  device); the transition's owner signature and the capability's
  transition binding are verified on every path, and installation
  stays monotonic and contiguous — secrets only extend the held
  `1..=N` prefix, never skip and never overwrite;

**Capability installation is monotonic:** installing a capability may only
add secrets for epochs the device does not yet hold. It must never decrease
the device's known membership state, remove newer secrets, or roll back —
a replayed older capability is a harmless no-op, not a downgrade.

Security properties, stated as invariants:

1. **Forward secrecy against revocation:** possession of epoch N secrets
   does not permit computing epoch N+1 secrets.
2. **Historical access is explicit:** access to past epochs comes only from
   secrets a capability explicitly contains.
3. **No backward secrecy for admission (intentional):** a newly admitted
   member receives every epoch `1..=N`; compromising a newly admitted
   device exposes the drive's entire encrypted history. Epoch revocation
   bounds *future* acquisition, never the past.
4. **Revocation bounds acquisition, not possession:** removing a device
   prevents it acquiring later-epoch secrets. It cannot revoke secrets,
   ciphertext, manifests, or plaintext the device already holds.
   (The chain list is 32 bytes per epoch — small; compact encodings are a
   later optimization.)

## Layer 3 — snapshot authorization

Snapshots commit to the **exact membership transition that authorizes
them**, not merely to an epoch number. The snapshot carries a membership
reference and a flags byte (`Snapshot` format in `object-model.md`) with
the validity requirement `S.epoch == S.membership.epoch`. An epoch number
says *when*; the membership reference says **which authorization state**.
Both are covered by the snapshot signature.

`timestamp` is display/tiebreak metadata only: it MUST NOT participate in
authorization, conflict resolution, membership ordering, or key derivation.

Predicates, evaluated by a peer over its local DAG and canonical chain
(non-circular; recursion terminates on the acyclic DAG):

```
historically_valid(S)  ⟺  BIP-340 signature verifies (drive-bound, exact
                            bytes, full key validation)
                        AND T = transition(S.membership) is known, valid,
                            and rooted
                        AND S.epoch == T.epoch
                        AND S.author ∈ members(T)

authorized(S)          ⟺  historically_valid(S)
                        AND T is canonical

in_live_lineage(S)     ⟺  authorized(S)
                        AND every parent P:
                                  in_live_lineage(P)
                                  AND P.epoch ≤ S.epoch
                        AND (S.epoch == K
                             OR some child C of S: in_live_lineage(C))

eligible_head(S)       ⟺  in_live_lineage(S)
                        AND S.epoch == K
                        AND S is a DAG head
```

The third clause is the **bounded-fork degradation, made precise**: a
snapshot (even the genesis) is live-lineage only while its epoch is
current or its lineage leads onward to the current epoch. Without it, a
stale parallel fork would remain live-lineage forever after the log
advanced, contradicting the classification table (SUPERSEDED) and the
conformance item "old snapshot becomes superseded when the log advances".
Parentless-ness alone confers nothing once the epoch moves on; the
parents clause is vacuous for the genesis snapshot, and the child clause
is what keeps old ancestry live only while it feeds current work.

where K is the epoch of the peer's known membership state (the canonical
tip). Historical validity is intrinsic to the snapshot against the *valid,
rooted* log — it does not depend on canonicalization outcomes;
`authorized(S)` adds canonicality; `in_live_lineage` adds ancestry. Only
the layer-3 lineage relation depends on canonicality, and canonicality
itself never depends on the DAG.

Same-epoch ancestry, settled explicitly:

- **Chains within one epoch are normal** (offline commits): `S1 → S2 → S3`
  all at epoch K is the expected shape.
- A new snapshot may parent onto **any subset of the live-lineage heads it
  knows** — including a merge of multiple heads. **Partial parent sets are
  allowed and stay valid:** a snapshot built on one of two known eligible
  heads does not become invalid when the second head surfaces later; there
  is no merge-completeness requirement.
- Parenting onto a snapshot that is not live-lineage is forbidden — that is
  the adoption rule. There is no notion of one epoch-K snapshot
  "superseding" another at the same epoch; they coexist as parallel heads
  until a descendant merges or the epoch advances.
- "Head" always means DAG head (no descendants); eligibility is per
  snapshot, and becoming a parent merely removes a snapshot from the head
  set.

Classification:

| Condition | State | Effect |
|---|---|---|
| malformed / signature or key validation fails, or author ∉ members(T) | **REJECTED** | not valid history; drop (and flag the sender); retaining locally for audit is permitted |
| referenced transition unknown, orphaned, contested (conflict freeze), or a parent unknown | **PENDING** | park; re-evaluate when the log/DAG catches up |
| valid history but referenced transition voided | **VOIDED** | retained; its authorization branch never became canonical; content only via recovery |
| `in_live_lineage`, `epoch == K`, DAG head | **ELIGIBLE** | may advance the live view |
| `in_live_lineage`, not an eligible head | **canonical snapshot history** | the accepted past |
| valid+authorized history, `epoch < K`, not live-lineage | **SUPERSEDED** | stale fork; browsable via time travel, never live |
| valid+authorized history, `epoch == K`, not live-lineage | **STRANDED** | legitimate work on a doomed fork; owner recovery is the remedy |

Terminology note: **superseded ≠ revoked-author.** A snapshot becomes
superseded because its epoch's canonical chain moved past it, whether or not
its author was removed. An old snapshot by a still-active member is
superseded exactly like one by a removed device.

**Stranding is inherited and permanent:** a descendant of a superseded (or
stranded) snapshot has a non-live-lineage parent, is therefore never
live-lineage, and becomes stranded or superseded in turn. Descendants of
dead forks are never reclassified back, and implementers must not add
recursive rescue logic. Recovery grafts *content*, never *lineage* — that is
the only path back.

The two central semantics, restated:

- **Valid signature ≠ valid current-state transition.** Ciphertext-valid
  work by a later-removed device remains valid history forever; it cannot
  advance the live view past the revocation boundary.
- **Bounded-fork:** while a peer still knows only epoch K = N, it may
  temporarily accept an epoch-N snapshot from a device removed at N+1. When
  its log advances, the snapshot degrades from eligible to superseded. This
  transient inconsistency is expected, safe (fails closed), and self-heals
  on propagation.

**The stranded-descendant case, stated deliberately:** a peer that has not
yet learned of a removal may build on a snapshot that later becomes
superseded, stranding the peer's own (perfectly legitimate) work along with
it. This is accepted, not an oversight. The owner's recovery snapshot is the
single sanctioned remedy.

## Per-event behavior

| Event | Peer action |
|---|---|
| receive valid transition extending the canonical tip, empty `resolves` | verify; known membership state = N+1; deliver/await capability (knowledge and key material are separate — knowing N+1 does not mean holding N+1 secrets yet) |
| receive valid transition with `resolves` matching an active conflict at `prev` | mark named siblings voided; the winning branch becomes canonical; recompute; reclassify snapshots |
| receive valid transition that conflicts (same canonical predecessor, same epoch) or contradicts an existing resolution | retain; freeze evaluation at that epoch; surface drive-level error |
| receive valid but unrooted transition | retain as orphaned; drive-level error |
| receive snapshot bound to unknown/orphaned/contested transition | PENDING |
| receive snapshot bound to a voided transition | VOIDED (retained, never eligible) |
| receive snapshot whose author ∉ members of the referenced transition | REJECTED (flag the sender) |
| receive snapshot claiming `S.epoch == K` | evaluate `eligible_head`; eligible heads join the head set |
| receive snapshot claiming `S.epoch > K` | PENDING; park until the log advances (object bytes may stream in meanwhile) |
| local write (member of canonical epoch K) | parent onto any subset of locally live-lineage heads; publish with `membership` bound to the canonical epoch-K transition; announce via control plane |
| local write at K while owner has minted K+1 | writes continue at K and become superseded when K+1 arrives — the cost of offline operation, accepted |
| membership conflict | freeze; drive-level error (see Canonicality) |

## Heads, live view, and recovery

- **Heads** = snapshots not referenced as a parent by any known snapshot.
- The live view renders **eligible heads only**. One eligible head = live
  state; multiple = conflicted (existing rule). Superseded, stranded, and
  voided snapshots are visible through time travel, never in the live view.
- **Recovery snapshots** are owner-authored snapshots with the **recovery
  flag** set (a distinct, authenticated snapshot type — v0 format `flags`
  bit 0, so implementations can audit recovery and never confuse it with
  ordinary writing). Authorization: the author must be the **current
  canonical owner**. Their DAG parents MUST be current eligible heads, and
  their tree is rebuilt from **explicitly identified recovered content** —
  content/tree objects referenced directly by ContentId from any historical
  epoch for which the owner holds decryption capability. Recovery never
  parents onto superseded or stranded history: the owner is deliberately
  republishing specific bytes under the current epoch, not adopting a
  fork. It is always a deliberate act, never automatic.
- Owner recovery visibility: the owner can recover only content it can
  decrypt — historical epoch secrets are in its capability only if it has
  been continuously a member. Recovery resurrects bytes, not the old fork's
  lineage.
- Superseded, stranded, and voided objects are never deleted (append-only);
  GC rules, when they exist someday, may revisit this.
- **Post-corruption projection behavior (v0, decided):** when replay or
  classification cannot produce a valid projection from the durable
  state, Wyrd preserves the last successfully installed heads and
  surfaces the projection error to the caller. The installed projection
  is not an endorsement of the newly replayed state — observed is not
  valid, and a failed projection never replaces a previously installed
  trustworthy projection with less trustworthy state. Wyrd does not
  automatically repair, resynchronize, or clear the installed heads in
  v0, and v0 defines no persistent daemon error-state model: a future
  presentation layer may expose "operating from the last known-good
  projection while durable state reports an integrity error" as a
  degraded state, but the runtime does not invent one.

## Edge cases

- **Removed then re-admitted (new Nostr key):** a new device with a fresh
  capability; nothing special.
- **Capability lost / fresh device restore:** re-pair via a new owner
  bootstrap invitation (genesis plus wrapped capability, sealed to the
  device encryption key; new epoch not required for mere re-delivery of
  the same epoch's secrets; a rotate is still recommended if the loss
  was a compromise).
- **Offline vault:** epochs are irrelevant to it — it holds ciphertext of
  every epoch and accepts fetches for any StorageId it stores.
- **Compromise response:** remove + rotate in one transition (new epoch,
  fresh epoch secret, old secrets remain historical).
- **Clock/hole in the log:** a peer missing transitions N..K cannot
  evaluate snapshots in (N, K]; it parks them as PENDING and fetches the
  missing entries — the log is small and control-plane-announced.

## Invariants

1. The membership log is append-only and owner-signed; per epoch at most
   one transition is **canonical**; validity, rootedness, and canonicality
   are independent properties; canonicality is determined solely by the
   observed transition set — never by arrival order or snapshot DAG state.
2. Conflicts freeze evaluation and are resolved **only** by an explicit
   owner-signed resolution transition naming winner (`prev`) and voided
   siblings (`resolves`); contradictory resolutions re-freeze at the next
   epoch.
3. Transitions are authorized by the **pre-transition** owner set; their
   resulting member/owner state is deterministically derived from
   `prev` + `changes` and committed via roots that verifiers recompute. v0
   enforces singleton ownership; removing the last owner is valid but
   terminal.
4. Every snapshot commits to the exact membership transition that
   authorizes it; eligibility requires the **canonical** transition of the
   peer's known epoch — an epoch number alone never authorizes anything.
5. Authorization evaluation is deterministic given the observed (log, DAG)
   sets and known membership state: two peers with identical knowledge
   reach identical verdicts. It never depends on wall-clock time —
   `timestamp` is display-only — or arrival order.
6. `in_live_lineage` is non-circular (recursive over DAG ancestors only);
   superseded/stranded/voided snapshots can never enter the live view; the
   only path back is an owner-signed recovery snapshot (recovery flag,
   current canonical owner) grafting explicit content onto eligible heads.
7. Epoch secrets: fresh uniformly random per transition, never reused
   intentionally, never derived from the root or each other; they flow only
   to members of that epoch; capabilities never include future epochs, are
   ECDH-wrapped and AAD-bound to (drive, device, encryption_key, transition, epoch), and
   install monotonically.
8. Ordinary members never possess the DriveRootKey; the root is custody for
   recovery material, never a transition authority or epoch-material source.

## Conformance tests (the contract's test list)

These are the behaviors the state machine must be tested against before
implementation is considered conformant.

**Membership:** genesis transition; two valid geneses (conflict at epoch 1);
invalid genesis `prev`; epoch gap; wrong predecessor; wrong author; author
owner *before* the transition (valid) vs author made owner *by* the
transition (invalid); author removed by the transition (invalid); remove
last owner (valid, terminal); invalid `SetOwners` (non-member, multiple
owners in v0); duplicate admission; duplicate removal; empty changes; valid
`Rotate`; rotation produces a distinct epoch secret; non-empty `resolves`
with no active conflict (invalid); conflicting transitions with same
predecessor (conflict); conflicting transitions with different predecessors
(voided-by-ancestry, not a conflict); conflict resolution by explicit
resolution transition; contradictory resolutions (re-freeze); unrooted
transition (orphan); resolution delivery order independence (winner named
by the resolution, not by arrival).

**Snapshots:** valid snapshot; bad signature; wrong DriveId; invalid pubkey
(fails `lift_x`); unknown membership transition; transition from a voided
branch (VOIDED); orphaned transition reference (PENDING); author not in
committed membership (REJECTED); epoch/membership mismatch; snapshot bound
to a noncanonical (contested) transition; valid old snapshot after
revocation; old snapshot becomes superseded when the log advances;
same-epoch child of an eligible head; same-epoch child of a
non-live-lineage head; descendant of a superseded snapshot; snapshot with
unknown parent; partial-head parenting then late arrival of the second head
(stays valid); merge of eligible heads; merge including a stranded head;
recovery snapshot with recovery flag by current canonical owner; recovery
snapshot by non-owner (invalid); recovery parenting a stranded head
(invalid); recovery from stranded content; determinism: identical (log,
DAG) ⇒ identical verdicts regardless of arrival order.

**Capabilities:** correct recipient; wrong recipient; wrong DriveId; wrong
epoch; wrong transition; replay of an older capability (no-op, no
downgrade); replay after removal (no future secrets); capability containing
a future epoch secret (invalid); capability containing the DriveRootKey
(invalid by construction); missing historical epochs in a fresh member's
capability (invalid — must be 1..=N); known epoch without held capability
(authorization waits for keys, knowledge does not imply decryption);
rotation delivery to a device holding ≤ N converges (grant installs,
transition observes, retained epoch-sealed traffic opens on redelivery);
rotation from a non-member sender is refused; rotation for another
device is refused; out-of-order rotation converges on redelivery
(contiguous install, no gaps, no volatile-only observations).

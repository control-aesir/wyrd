# Trust Model and Key Hierarchy

**Status: DRAFT.** The identity, custody, transport, and rotation decisions
below are made. The last piece before this document is normative is the
**membership/epoch state machine**, now drafted in `epochs.md` — the precise
answer to "what makes a snapshot an authorized descendant of another
snapshot?" Reviewing and promoting those two docs together is the final
gate for `wyrd-sync` implementation.

The boundary this document owns: **drive membership → keys → manifests →
Content IDs → Storage IDs → device authorization.**

Governing principle:

> **Nostr provides identity and asynchronous authenticated messaging. Wyrd
> provides authorization, encryption, content identity, and storage.**

## Identity: the Nostr boundary

Wyrd does not define a device identity system. A Wyrd device identity **is**
a Nostr secp256k1 public key; snapshot authorship and membership
authorization use Nostr-compatible Schnorr signatures.

The boundary, stated as a rule:

> **Nostr answers "who are you?" Wyrd answers "what are you authorized to
> decrypt?"**

- **Nostr cryptography: yes. Nostr event format: no.** Snapshots remain Wyrd
  canonical objects (`wyrd ‖ version ‖ kind ‖ payload`, BLAKE3 domain
  separation). We reuse the keypair and Schnorr signature conventions, not
  Nostr's event serialization or its SHA-256 event IDs.
- **No social Nostr.** No profile metadata, follows, NIP-05, public relay
  presence, or social graph is required. A participant is a secp256k1
  keypair using Nostr conventions.
- **Membership state is never public.** Membership, invitations, capability
  distribution, and rotation travel only in encrypted channels. A public
  relay must never learn "pubkey A is a member of drive X".
- **NIP-44 is not object encryption.** NIP-44 solves pairwise A→B messages;
  Wyrd objects use drive-derived per-object AEAD (below). Nostr's encrypted
  message formats may carry the *control plane*, never object content.
- **Device identity is immutable.** If a Nostr key is rotated, that is a new
  device: remove the old membership, admit the new key. Nostr's social
  identity-continuity conventions are not inherited.
- **NIP-46 remote signing is optional, scoped, and default-deny** (see
  below): the signing key may live in a hardware signer, phone, or bunker
  while the Wyrd daemon requests signatures. Wyrd never receives the nsec.

Three distinct uses of Nostr, kept separate:

| Use | Carries |
|---|---|
| public | identity (pubkeys), optional discovery/relay hints |
| encrypted control plane | membership changes, invitations, capabilities, rotation, snapshot announcements |
| direct P2P (iroh) | objects, manifests, bulk data |

## Principals

| Principal | Identity | Purpose / Holds |
|---|---|---|
| drive | `DriveId` — random 256-bit, immutable | logical encrypted namespace; distinct from every other identifier |
| device | Nostr public key (`DeviceId`) | a Wyrd participant; holds a wrapped drive capability + its Nostr signing key |
| owner | one or more Nostr public keys | membership administration (v0: exactly one owner; owner *sets* and threshold policies are a later extension this model already accommodates) |
| vault | transport identity only | stores ciphertext; holds no keys, no Wyrd authorization |

Every identifier answers a different question — this separation is deliberate:

```
DriveId      "which logical drive?"
Nostr pubkey "which participant?"
ContentId    "which logical content?"
StorageId    "which physical encrypted representation?"
```

## Root custody (decided)

The Drive Root Key is a **random 256-bit secret, not a passphrase
derivative**. The passphrase is a key-*encryption* mechanism, not the source
of cryptographic identity:

```
random DriveRootKey
    │
    ▼
wrapped with a key derived from the user's passphrase
    │
    ▼
local Wyrd keystore (OS secure storage where available)
```

Changing the passphrase re-wraps the root key — the drive's cryptographic
universe is untouched. Hardware-backed unwrapping (Secure Enclave / TPM /
OS keychain) is a later storage upgrade that changes nothing about the
format.

**Deferred:** multiple owners, Shamir/threshold recovery. Those are a
*recovery architecture* (share lifecycle, quorum UX, backup procedures), not
a prerequisite for the storage architecture.

## Key hierarchy: epochs

Membership epochs are the revocation primitive. A **membership change
creates a new epoch**; keys are derived from the *epoch secret*, not from an
eternal root directly:

```
Drive Root Key (random, passphrase-wrapped at rest)
    │
    ▼  (owner rotates on membership change)
Epoch Secret (per membership epoch)
    ├─ ManifestKey  = KDF(epoch secret, "manifest", ...)
    └─ ObjectKey    = KDF(epoch secret, "object", ContentId, kind, version)
    └─ (snapshot manifest keys derive from the epoch secret + snapshot id)
```

Rules:

- **Rotation creates a new cryptographic epoch; it never rewrites immutable
  historical objects.** Old objects remain encrypted under their old epoch;
  new material is unreadable to devices that hold only old-epoch
  capabilities.
- A device removed at epoch N cannot obtain epoch N+1 secrets — the epoch
  secret is distributed only to the members of that epoch, via wrapped
  capabilities.
- Per-object derivation keeps any member able to decrypt any object of its
  epoch; no pairwise keys exist.
- Per-snapshot manifest keys (`KDF(epoch, "manifest", snapshot_id)`) let
  revocation be as fine-grained as snapshots without a global key change.

## Control plane: Nostr is the mailbox, iroh is the data plane (decided)

**Both transports, different responsibilities:**

- **Nostr = asynchronous, authenticated control plane.** Invitations,
  membership changes, rotation announcements, and snapshot announcements.
  This is what makes the offline-vault/offline-device case work: the owner
  can authorize a new phone while it sleeps; the phone discovers its
  encrypted invitation later and joins.
- **iroh = live Wyrd protocol and bulk data.** Manifest requests, object
  transfers, ranges, synchronization, acknowledgements. Nostr is never the
  authoritative sync transport, and bulk state never flows through it.

Wyrd defines its **own control message types** — `Invitation`,
`MembershipChange`, `KeyRotation`, `SnapshotAnnouncement` — as Wyrd payloads
that encrypted Nostr events merely *transport*:

```
Nostr event (transport envelope, encrypted)
    └─ Wyrd control message (Wyrd-defined, Wyrd-canonical)
```

Replacing Nostr as the rendezvous mechanism would not change Wyrd's
cryptographic model.

## AEAD binding (decided construction)

Every ciphertext is authenticated not only as bytes but as *an object of a
specific kind and logical identity*:

```
AEAD(
    key    = object_key (epoch-derived, above),
    nonce  = fresh random per encryption,
    aad    = format_version || object_kind || ContentId,
)
```

Storage ID = domain-separated hash over `nonce || ciphertext || aad`.

Invariant: **successful decryption alone is never sufficient.** A device
accepts an object only when (a) the AEAD tag verifies over the bound AAD,
and (b) the plaintext hashes to the expected Content ID. Two independent
checks, either of which catches a mismatched manifest mapping. The epoch is
implicit in the key. Re-encryption under a new epoch produces a new
ciphertext, a new Storage ID, and a manifest update — the Content ID never
changes.

## Snapshot authorization and epochs (decided; state machine in `epochs.md`)

The snapshot gains an epoch field:

```
Snapshot {
    parents:   Vec<SnapshotId>
    tree:      ContentId of root tree
    author:    Nostr public key (the DeviceId)
    epoch:     u64 — the membership epoch the author claims
    timestamp: u64 (ms, HLC-ordered, display/tiebreak only)
    signature: Schnorr signature over
               "wyrd snapshot v1" || DriveId || canonical bytes (sans signature)
}
```

The core rule:

> **Membership state is part of the signed snapshot DAG, and authorization
> is evaluated against the member/epoch state known at the snapshot's
> parents.**

Consequences:

- A snapshot is *authorized* iff its signature verifies, its author was a
  member in the epoch it claims, and that epoch is consistent with the
  membership state reachable from its parents.
- **Valid signature ≠ valid current-state transition.** A snapshot signed by
  a removed device, claiming the pre-removal epoch, remains a cryptographically
  valid *historical fork* — but cannot advance canonical state past the
  revocation boundary.
- **Bounded-fork semantics.** Propagation races are expected and bounded:
  while a peer hasn't yet learned a removal (epoch N → N+1), it may
  temporarily accept the removed device's epoch-N snapshots; once the
  membership state advances, those branches are marked obsolete forks.
  Global instantaneous revocation is impossible in an offline-capable system
  and is not a goal.

The precise **membership/epoch state machine** — what triggers an epoch
bump, how membership state is embedded in the DAG, epoch-chain encoding,
reconciliation of obsolete forks — is specified in `epochs.md`.

## Device admission (decided)

- The owner mints a **device capability** — the wrapped epoch secrets plus
  registration of the member's Nostr pubkey — and **signs the membership
  transition** with the owner's Nostr key. The membership record reads:
  `pubkey, status = active, admitted_by = <owner pubkey>, epoch`.
- Membership is signed, encrypted, replicated state: members agree on who is
  a member of which epoch, and no public relay learns the membership graph.
- Admission is explicit and additive; delivery rides the Nostr mailbox, so
  the new device need not be online.

## Device removal and rotation (decided semantics)

- **Removal** is a signed membership transition (`status = revoked`) by the
  owner, which **creates a new epoch**: remaining members receive new
  wrapped capabilities (new epoch secret → new manifest keys / object key
  base). The removed device's capability stops being honored, and future
  snapshots and objects are unreadable to it.
- **Cached plaintext already on the removed device stays readable to that
  device.** Revocation bounds future knowledge, not past possession — and
  the *epoch* model makes the boundary exact: everything under epochs the
  device held is readable; nothing after is.
- **No re-encryption of history.** If excluding remaining members from
  old-epoch content is ever wanted, that is an explicit, separate migration
  (re-encrypt + new manifests), never an implicit side effect.
- **Who may rotate when the owner is offline** is an authorization-policy
  question over the owner set (`1-of-2 may add`, `2-of-2 to remove an
  owner`, …) rather than a new key system. v0 ships exactly one owner.

## Recovery (reserved design, post-v0 implementation)

Without the root key, ciphertext is unrecoverable once every device holding
capabilities is lost — so recovery **is** root-key custody. The design
reserved for it (deferred with the Shamir decision, but the design space is
held open now):

- **Guardians ("emergency contacts")**: a set of Nostr pubkeys recorded as
  first-class state in the membership log. Guardians hold Shamir shares of
  the root key, **k-of-n required to reconstruct**; shares are delivered and
  stored as opaque blobs via the encrypted Nostr mailbox — guardians learn
  only "I hold a share for drive X", never Wyrd contents or membership.
- **Reconstruction flow**: k guardians return their shares → an owner device
  reconstructs the root key → mints a fresh capability / new epoch. Compromised
  or lost guardians are handled by rotating the shares (re-split, re-deliver).
- **Web of trust's role is vetting, not crypto**: Nostr social conventions
  (web of trust, NIP-05) help verify *that a guardian pubkey is the person
  you think it is*. The threshold scheme carries the actual security.
- Implementation is post-v0; the membership-log fields for the guardian set
  are reserved so adding recovery later does not change the epoch model.

## NIP-46 remote signing (optional, scoped, default-deny)

The daemon may delegate identity operations to a remote signer (hardware,
phone, bunker) over NIP-46, and must never receive the nsec:

```
Wyrd daemon ── "sign this snapshot" ──▶ scoped signer session ──▶ signature
```

Scoping rules: the Wyrd signer session exposes `get_public_key` and
`sign_event` restricted to Wyrd event kinds only. No `nip44_decrypt`,
no arbitrary event signing, unless a concrete feature demands it —
**default-deny**. This is especially desirable when the daemon runs as a
privileged system service.

## What each party can know (the security boundary, stated precisely)

| Party | Can know | Cannot know |
|---|---|---|
| vault | Storage IDs, ciphertext sizes, counts, timing, traffic patterns | plaintext, paths, structure, **cryptographic equality of plaintexts** (fresh nonces make ciphertext equality meaningless) |
| public relay | pubkeys that choose to be publicly visible; opaque encrypted control messages | membership graphs, invitation flow, any Wyrd payload |
| drive member | full plaintext world of its epochs, all Content IDs, cross-device equality via manifests | other epochs' material it never held |
| removed device | plaintext it cached, plus old-epoch objects it already stored | anything from later epochs |

Note the deliberate asymmetry: **Content IDs are an equality oracle to
members.** That is what makes dedup and history work, and it is why the
member/vault boundary is a security boundary, not an implementation detail.

## Decision record

| # | Decision | Rationale |
|---|---|---|
| T1 | Device identity = Nostr pubkey; Schnorr signatures; no Nostr event formats; immutable device identity | deletes a bespoke identity subsystem; Nostr answers "who", Wyrd answers "what can you decrypt" |
| T2 | Root key: random 256-bit, passphrase-*wrapped* at rest; hardware later; Shamir deferred | password changes must not touch the drive's cryptographic universe; recovery architecture ≠ storage architecture |
| T3 | Control plane: Nostr (async mailbox) + iroh (live data plane); Wyrd-defined control messages inside encrypted Nostr events | offline devices/vaults need asynchronous rendezvous; bulk never through Nostr; rendezvous must be replaceable |
| T4 | Epoch-derived keys: membership change → new epoch secret → manifest/object KDFs; never re-encrypt history | revocation without rewriting immutable objects; fine-grained via per-snapshot manifest keys |
| T5 | Snapshots carry `epoch`; authorization evaluated against membership state at the parents; removed-device snapshots stay valid historical forks but cannot advance state | valid-signature ≠ valid transition; bounded-fork semantics for propagation races |
| T6 | NIP-46 optional, scoped, default-deny; daemon never holds the nsec | protects identity keys from the (possibly privileged) daemon process |
| T7 | Recovery reserved: guardian set (emergency contacts) as membership-log state; Shamir k-of-n shares over the encrypted Nostr mailbox; WoT for vetting only | root-key loss is unrecoverable by crypto alone; social recovery is the deferred Shamir decision given UX; design space held open without changing the epoch model |

## Open questions

1. **Membership/epoch state machine** — drafted in `epochs.md`; its review
   (with this document) is the final gate for `wyrd-sync`.
2. Manifest partition encoding details (sharding, chunked transfer).
3. Live-view conflict naming (e.g. by author id / snapshot timestamp).
4. Gossip message framing for snapshot announcements.
5. Chunk-size parameters (benchmark before the v1 freeze).
6. Keystore format: passphrase KDF choice and parameters (e.g. Argon2id),
   OS secure-storage integration.
7. Guardian share lifecycle details (re-split procedure, share expiry,
   guardian-offline handling) — blocked behind the post-v0 recovery
   implementation.

# Wyrd

> *Wyrd (Old English): Fate; the accumulated weight of past actions. You cannot edit the past—only act upon the present.*

**Wyrd** is a decentralized, append-only, content-addressed drive system. 

It combines the peer-to-peer replication of Syncthing, the Merkle tree object model of Git, and the user experience of Apple's Time Machine—demoting the delete key to a state suggestion rather than an erasure command.

---

## The Core Concept: Immutability as the Atom

Wyrd treats a storage drive as an append-only, content-addressed store. 

- Files are split into hash-addressed chunks.
- A **drive state** is a lightweight root object pointing into a Merkle tree.
- **Writing** consists of adding new objects and publishing a new root object.

Nothing is ever mutated in place. Deduplication, cryptographic integrity, and revision history are fundamental properties of the architecture rather than added features.

Snapshots describe a **logical drive**; each device materializes whatever subset of it it needs — pinned for offline use, cached by access, or fetched on demand.

---

## Architectural Principles

### 1. Snapshots, Not Files
Every state change publishes a new snapshot. Snapshots reference their parents, forming an append-only DAG: heads are the drive's state, and "current" is a policy over heads — one head is the live view, multiple heads mean the drive is conflicted.

### 2. Deletion is a State Change
Deleting a file or folder publishes a new snapshot without that path reference. The underlying objects remain untouched until explicit garbage collection occurs, protecting against accidental loss, ransomware, or bad scripts.

### 3. Roles and Materialization Are Independent
Peers serve specialized functions, and what a peer *holds* is a separate decision:
* **Roles:** *vaults* (e.g., NAS, offsite servers) replicate every object and retain history; *mirrors* (e.g., laptops) participate in live sync with prunable local state.
* **Materialization policies:** full, partial (pinned paths), or on-demand with a cache cap.

A phone is not a replica; it is a materialized view of the drive. Pin and evict decisions change what a device holds, never what the drive contains.

### 4. Continuous Self-Healing Integrity
Because objects are addressed directly by their cryptographic hashes, integrity checking (scrubbing) is low-overhead. If a chunk becomes corrupted, Wyrd detects the hash mismatch and automatically repairs the chunk from another peer holding the object.

### 5. Zero-Trust Storage Peers
Objects are encrypted client-side before they ever leave the device—in transit and at rest. Vault peers store and replicate only opaque, encrypted blobs, so offsite backends can run on untrusted VPS providers or remote drives without compromising data privacy. The precise claim: **vaults cannot decrypt object contents**—they see ciphertext, sizes, and timing, never paths, structure, or equality between objects.

### 6. Explicit Conflict Visibility
When concurrent modifications occur across peers, Wyrd keeps both heads reachable and retains both versions as separate immutable objects. Conflicts are surfaced in the filesystem/UI for user resolution rather than automatically merged or overwritten.

### 7. No Data Lock-In
The local object store is a documented CAS of immutable Wyrd objects; the logical object format is specified independently of any encrypted storage or transport representation. Exporting your data is as simple as materializing a chosen snapshot into a standard directory tree on a conventional filesystem.

---

## Planned: Conservative Garbage Collection

*Not part of the contract yet* — today the store is append-only indefinitely.
When GC arrives, it will be the only way data is removed, and it will require:
* A quorum of configured peer nodes.
* A mandatory grace period (e.g., 30 days).
* Explicit human confirmation.

---

## User Interface & Presentation

Wyrd mounts via **FUSE** to present standard filesystem interfaces:

* **Live View:** Operates as a standard read/write local folder.
* **Time Travel:** Historical snapshots and previous roots can be browsed or restored using ordinary file manipulation tools or a web UI.

---

## Operational Tradeoffs

* **Storage Overhead:** Maintaining snapshot history requires storage space. Deduplication mitigates growth, but at least one dedicated **Vault peer** is strongly recommended.
* **Dedup Topology:** Deduplication happens at devices, via encrypted manifests—a member that knows another member already uploaded ciphertext for a given content reuses it. Vaults cannot dedup on their own (they must never learn equality), so redundant ciphertext can accumulate across devices and requires eventual reconciliation.
* **GC Distributed Consensus:** Coordinating garbage collection across multiple nodes is a complex distributed systems problem—with offline vaults it requires a retention/acknowledgement protocol, not just quorum. Initial versions default to an *append-only indefinitely* model prior to full distributed GC enablement.

---

## Status

Pre-alpha. Wyrd is in design; the v0 format spec is normative (`docs/object-model.md`), the peer protocol is not yet stable. The initial implementation scope is deliberately small: a content-addressed store, the snapshot DAG, and one vault peer. Garbage collection comes later.

---

## Why Not Just…?

* **Syncthing** replicates live, mutable state: deletions and corruption propagate to every peer, and there is no history to fall back on.
* **borg / restic** are strong backup tools, but one-directional (client → repository), with no peer roles, no live view, and no cooperative retention.
* **git-annex** comes closest on the object model, but its workflow is repository-shaped rather than drive-shaped.
* **Time Machine** nails time travel, but is single-machine and bound to Apple's filesystem stack.

Wyrd's bet is that these are one system: git's object model, Syncthing's replication, Time Machine's manners.

---

## Repository Layout

| Crate | Purpose |
|---|---|
| `crates/wyrd-format` | The format contract: two identities (content/storage), canonical encoding, chunking, Merkle file trees, snapshot DAG |
| `crates/wyrd-sync` | Peer replication on iroh: snapshot announcements, encrypted manifests, roles × materialization, two-phase content, zero-trust encryption |
| `crates/wyrd-fuse` | The drive as a filesystem: live view, time travel, visible conflicts |

Design docs live in `docs/` (`architecture.md` is the one-page entry point);
`AGENTS.md` holds repository conventions and hard rules.

---

## Quick Start

*(Implementation instructions, build steps, and basic mounting commands go here.)*

```bash
# Example mounting command (placeholder)
wyrd mount /path/to/vault /mnt/wyrd
```

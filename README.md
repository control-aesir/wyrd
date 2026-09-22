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
Because objects are addressed directly by their cryptographic hashes, integrity checking (scrubbing) is low-overhead. If a chunk becomes corrupted, Wyrd detects the hash mismatch and automatically repairs the chunk from another peer holding the object (automatic peer repair is not yet wired at runtime: the bulk transport contract, fetch-on-open demand machinery, and the real-iroh serving router exist — a serving peer answers fetches by transport root and route updates rewire serving on address changes).

### 5. Zero-Trust Storage Peers
Objects are encrypted client-side before they ever leave the device—in transit and at rest. Vault peers store and replicate only opaque, encrypted blobs, so offsite backends can run on untrusted VPS providers or remote drives without compromising data privacy. The precise claim: **vaults cannot decrypt object contents**—they see ciphertext, sizes, and timing, never paths, structure, or equality between objects.

### 6. Explicit Conflict Visibility
When concurrent modifications occur across peers, Wyrd keeps both heads reachable and retains both versions as separate immutable objects. Conflicts are surfaced in the filesystem/UI for user resolution rather than automatically merged or overwritten.

### 7. No Data Lock-In
The local object store is a documented CAS of immutable Wyrd objects; the logical object format is specified independently of any encrypted storage or transport representation. Exporting your data is as simple as materializing a chosen snapshot into a standard directory tree on a conventional filesystem (`wyrd export`; see `docs/cli.md`).

---

## Planned: Conservative Garbage Collection

*Not part of the contract yet* — today the store is append-only indefinitely.
When GC arrives, it will be the only way data is removed, and it will require:
* A quorum of configured peer nodes.
* A mandatory grace period (e.g., 30 days).
* Explicit human confirmation.

---

## User Interface & Presentation

Wyrd mounts via **FUSE** to present standard filesystem interfaces (pre-alpha today: a read-write FUSE mount via the daemon):

* **Live View:** Operates as a standard read-write local folder; writes commit as snapshots.
* **Time Travel:** Historical snapshots and previous roots can be browsed using ordinary file manipulation tools.

---

## Operational Tradeoffs

* **Storage Overhead:** Maintaining snapshot history requires storage space. Deduplication mitigates growth, but at least one dedicated **Vault peer** is strongly recommended (peer serving and fetching ride real iroh; the dedicated vault-peer role surface is not yet wired at runtime).
* **Dedup Topology:** Deduplication happens at devices, via encrypted manifests—a member that knows another member already uploaded ciphertext for a given content reuses it. Vaults cannot dedup on their own (they must never learn equality), so redundant ciphertext can accumulate across devices and requires eventual reconciliation.
* **GC Distributed Consensus:** Coordinating garbage collection across multiple nodes is a complex distributed systems problem—with offline vaults it requires a retention/acknowledgement protocol, not just quorum. Initial versions default to an *append-only indefinitely* model prior to full distributed GC enablement.

---

## Status

Pre-alpha. The v0 format spec (`docs/object-model.md`) and the trust +
epoch contracts (`docs/trust.md`, `docs/epochs.md`) are normative, and the
format and sync **protocol/core** layers implement them: content-addressed
store, snapshot DAG, membership and authorization engines, epoch keys and
capabilities, sealed objects and manifests, escrow records, the
control-plane message set, ingest limits, and the control-plane transport
boundary. The runtime is assembling: durable local state with crash
recovery and restart reconciliation, author-side manifest generation,
fetch-on-open demand machinery, author-signed snapshot announcements with
transport identities, the real-iroh serving router (a serving endpoint
over the durable vault answers peer fetches by transport root), and a
read-write FUSE mount via the daemon (`wyrd mount`, writes committing as
snapshots) are in place and under test. Still pending: relay pool supervision
and signer-client wiring (NIP-46), automatic peer repair, and garbage
collection (post-v1 by contract).

See `ROADMAP.md` for the current phase plan and issue links.

---

## License

MIT. See [LICENSE](LICENSE).

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
| `crates/wyrd-daemon` | Composition library: engine + view + presentation backends (read-write FUSE today) |
| `crates/wyrd-cli` | The `wyrd` process host: `init`, `mount`, `export`, diagnostics, exit codes over the daemon's surface |
| `crates/wyrd-contracts` | Cross-crate architectural contract suite: one named test per review contract, composed end to end |

Design docs live in `docs/` (`architecture.md` is the one-page entry point);
`AGENTS.md` holds repository conventions and hard rules.

---

## Quick Start

Wyrd is pre-alpha (see Status above). To hack on it:

```bash
# enter the dev environment (rust toolchain, git hooks)
devenv shell

# build and test the workspace
cargo check
cargo nextest run
```

On macOS, the `wyrd-cli` and `wyrd-contracts` test binaries link the
system FUSE library at load, and `wyrd mount` needs the kernel extension,
so running them requires system macFUSE: `brew install --cask macfuse`,
then approve the "Benjamin Fleischer" system software under System
Settings, Privacy & Security (kernel-extension user consent must be
enabled; on Apple Silicon that needs Reduced Security, set once in
Recovery via Startup Security Utility), and reboot. If the mount still
fails, make sure macFUSE's mount daemon is running
(`pgrep -af io.macfuse.app.launchservice.daemon`); if it is not,
`sudo launchctl kickstart -k system/io.macfuse.app.launchservice.daemon`.
`wyrd mount` fails fast when the kext is unloaded and otherwise names its
stage (serving, bulk, FUSE session); on macOS a session failure also
prints a checklist, because macFUSE can fail without setting errno and a
bare errno may be stale. The `devenv`
environment only provides build-time stubs for fuser's probe; it cannot
supply the runtime library or the kernel extension. `cargo check` and the
`wyrd-format`, `wyrd-sync`, and `wyrd-fuse` suites need no FUSE at all.

`crates/wyrd-format` carries the format contract and `crates/wyrd-sync`
the cryptography and state machines (both under test); the read-write
FUSE backend is implemented in `crates/wyrd-daemon` and driven by the
`wyrd` process host in `crates/wyrd-cli` (`wyrd init`, `wyrd
mount`), which also opens the drive's real-iroh serving endpoint.

To try the alpha without installing Rust:

```bash
nix run .#wyrd -- --help
```

Prebuilt `wyrd-{version}-{platform}.tar.gz` archives ship with each ngit
release (built reproducibly per platform via `nix build .#wyrd-dist`). Alpha caveat: the on-disk format, the trust protocol, and the CLI
can all change between alphas — `CHANGELOG.md` leads with the format
version so you can tell whether two builds interoperate.

### Running the alpha release

Each archive holds one binary, `bin/wyrd`. It does two things: create a
drive, and mount one.

```bash
# 1. Credentials: an identity secret (32 raw bytes or 64 hex chars) and a
#    passphrase (UTF-8 text). Both must be regular files owned by you with
#    private permissions; the binary refuses anything else.
printf 'my-passphrase' > passphrase.txt && chmod 600 passphrase.txt
head -c 32 /dev/urandom > identity.bin && chmod 600 identity.bin

# 2. Create a drive: identity, root custody, genesis membership.
wyrd init ./mydrive --identity-file ./identity.bin --passphrase-file ./passphrase.txt

# 3. Mount a live read-write projection of it.
mkdir -p ./mnt
wyrd mount ./mydrive ./mnt --identity-file ./identity.bin --passphrase-file ./passphrase.txt
# Stop with Ctrl-C (SIGINT/SIGTERM shuts down cleanly: flush, unmount, exit).

# 4. Export a plain copy any time: files, directories, symlinks, and the
#    executable bit land as an ordinary tree that needs no wyrd software
#    to read. Conflicts export as `name@N` siblings. Offline, and the
#    destination must not exist or must be empty.
wyrd export ./mydrive ./plain-copy --identity-file ./identity.bin --passphrase-file ./passphrase.txt
```

Mounting needs system FUSE (macFUSE on macOS, libfuse on Linux — see the
macFUSE notes above). `--relay <url>` (repeatable) connects the
control-plane mailbox so the daemon syncs; without relays intake stays
idle and the drive is local-only. `--verbose` turns on FUSE request
diagnostics when a mount misbehaves.

What this alpha is: a local encrypted drive you can create, mount, read,
and write, with demand-driven fetch (opening non-local content blocks
bounded, then surfaces `EIO` on expiry) and a serving endpoint other
peers can fetch from.

What it is not: peer sync is not hardened (signer-session wiring and
multi-relay supervision are still open), there is no garbage collection
(the store grows forever), writes are whole-file (append/truncate flags
are refused), there is no export command and no auto-update, and drives
created by one alpha may not open under the next. Bugs go to the
repository's ngit issues.

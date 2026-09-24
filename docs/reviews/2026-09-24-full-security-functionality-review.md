# Wyrd full security and functionality review - 2026-09-24

Reviewer: OpenCode agent

Scope: committed base `db06780` on the current `pr/escrow-scope` worktree,
all seven workspace crates, the contract suite, and the normative documents
in `docs/`. The working branch itself is not treated as finalized.
The review treated `trust.md`, `epochs.md`, `object-model.md`,
`write-path.md`, `fetch-on-open.md`, `resource-limits.md`, and
`capability-bindings.md` as contracts rather than suggestions.

No production source was changed as part of this audit. Existing issue
records were updated and distinct gaps were filed separately.

## Verdict

# NO-GO for hostile relay or hostile-current-member exposure

The format, cryptographic, membership, and durable-state foundations remain
strong. I found no primitive-level cryptographic bypass, no cross-user FUSE
ACL bypass in the default CLI, and no confirmed corruption of the historical
membership DAG. The remaining blockers are at the live boundaries: resource
bounds, serving order and authorization, hostile fetched structure, chained
symlink resolution, capability issuer provenance, and carry eligibility.

The implementation is suitable for continued local pre-alpha development. It
is not yet safe to describe the live multi-member path as complete.

## Validation performed

The following completed successfully before this report was written:

- `cargo check --workspace`
- `cargo nextest run --workspace` - 1,022 tests passed on the complete rerun;
  the first parallel run had one intermittent failure in
  `mailbox::tests_dedupe::settled_ids_collapse_to_watermark`
- `cargo clippy --workspace --all-targets -- -D warnings` passed
- `cargo test --workspace --doc` passed (1 doctest)

The issue and report work after the current validation did not modify Rust
source, so these results remain applicable to the reviewed code. The mailbox
watermark failure should remain tracked as a test-isolation/flakiness issue,
not be silently reported as a clean first run.

## High-severity findings

### H1 - The live mailbox still has no byte bound before NIP-59 processing

**Severity: high**

`LiveMailbox` bounds the number of unacknowledged handovers, not the size of
each relay event. `recv` can therefore hold 1,024 multi-megabyte events and
pass each through NIP-59 gift-wrap unwrapping before the Wyrd mailbox
ciphertext ceiling is consulted.

- `crates/wyrd-core/src/mailbox/mod.rs:834-858` unwraps the gift wrap and
  extracts the inner rumor.
- `crates/wyrd-core/src/mailbox/mod.rs:1399-1422` admits the resulting
  envelope into the bounded hand-over queue.
- `crates/wyrd-sync/src/transport/mailbox.rs:181-203` checks the inner
  ciphertext and decrypted Wyrd bytes, but only after the NIP-59 and
  inner-ciphertext allocations have occurred.
- `nostr-sdk` accepts relay messages substantially larger than the 96 KiB
  Wyrd handover ceiling.

The existing count bound and FIFO seen-log retention are real improvements,
but they do not bound the memory represented by a valid count of large
events. A public relay peer can force repeated NIP-59 processing, cloning,
and retained ciphertext before the semantic gate rejects the message.

Required work: an outer relay-event and NIP-59-inner-size gate before
unwrap, a defined overflow behavior that preserves relay retention, and a
regression test with a large but structurally valid wrap.

Tracking: the applied issue was reopened and updated:
`nostr:nevent1qqsytvqr68x7zdrm6mprwn7xqxqr6evtwl5n3aczf7m0g7swfuq6pagpz9mhxue69uhkwunpwdczuap49eehgyjzcvq`.

### H2 - Local announcements are not gated by serving readiness

**Severity: high**

The normative write path requires the serving mirror to be flushed before an
announcement is discharged. Production composition only performs that flush
once during startup.

- `crates/wyrd-core/src/live.rs:529-612` applies mutations, publishes the
  projection, and then calls `publish`.
- `crates/wyrd-core/src/live.rs:437-455` sends delivery and announcement
  outbox work without a serving callback or barrier.
- `crates/wyrd-cli/src/main.rs:500-519` calls `ServingEndpoint::flush` only
  once, before the live loop starts.
- `crates/wyrd-sync/src/serving.rs:118-188` writes the durable vault and only
  asynchronously enqueues the mirror import.
- `docs/write-path.md:291-324` requires `servable` before announcement
  discharge and defines the failure behavior when serving is not ready.

A peer can receive a valid announcement and attempt a fetch before the
representation has landed in the iroh-blobs store. If the mirror import
fails, the failure is sticky until restart even though the announcement has
already been sent.

The same production path also leaves route restarts stale: a new endpoint is
created on restart, but persisted sealed announcement bytes retain the old
`node_addr` and are intentionally resent byte-identically. This is tracked in
the reopened serving-router issue:
`nostr:nevent1qqs20s65ztzkegm8r64q53cd3kt3g9xusv6z0w78mt5szx3hmjnecnqpz9mhxue69uhkwunpwdczuap49eehg56ukhs`.

### H3 - Symlink confinement is lexical and can be bypassed through a chain

**Severity: high**

The current policy rejects absolute targets and targets whose lexical
`..` depth goes above the drive root. It does not resolve symlink components
inside the target. An individually confined link can therefore participate
in a chain whose later `..` component escapes.

For example, store `a/b/s -> ../..` and `a/b/link -> s/../../outside`.
Each target passes the lexical check. When the host resolves `link`, `s`
redirects to the drive root, and the following `..` walks above it.
`wyrd export` writes the target verbatim, and the FUSE adapter returns it
to the host kernel.

- `crates/wyrd-core/src/view.rs:291-323`
- `crates/wyrd-core/src/export.rs:558-570,669-673`
- `crates/wyrd-daemon/src/fuse/backend.rs:2082-2102`

The prior absolute and direct-`..` tests do not cover compositional
resolution. The applied confinement issue was reopened and updated:
`nostr:nevent1qqsqrrew3krrz6g6wd5zwdqa07p248kzpz38wljmhn3vgsjzwahgk6spz9mhxue69uhkwunpwdczuap49eehgy3h6mt`.

### H4 - Remote fetch bypasses the structural snapshot and chunk limits

**Severity: high**

`Limits::V0` is enforced for control messages and for several local authoring
paths, but the remote fetch path does not call the structural helpers that
were designed for fetched objects.

- `crates/wyrd-sync/src/ingest.rs:158-208` defines `check_snapshot` and
  `check_chunk_len`.
- A repository-wide search finds those functions only in `ingest.rs` and
  their unit tests.
- `crates/wyrd-sync/src/runtime/fetch/mod.rs:144-189` decodes and accepts a
  fetched snapshot body without `check_snapshot`.
- `crates/wyrd-sync/src/runtime/fetch/mod.rs:311-399` verifies and inserts a
  fetched object without `check_chunk_len`.
- `crates/wyrd-sync/src/closure.rs:245-255` checks a tree only later at the
  head gate, after the fetch and durable-import work has happened.

An authenticated member can publish a body with excessive parents, a chunk
larger than the 256 KiB format maximum, or an oversized tree that is rejected
only after expensive decode and storage work. The total 64 MiB object ceiling
limits one representation, not the aggregate cost of a valid hostile snapshot
and its object fan-out.

The missing gate is now tracked as
`nostr:nevent1qqsgscqjq8q68s0fg50u3p8unpdyttru8ze3uz9ey9v9m5eznw4n0jspz9mhxue69uhkwunpwdczuap49eehg7gld4y`.

### H5 - Rotation capabilities have no wire-level issuer provenance

**Severity: high when hostile current members are in scope; otherwise an
explicitly accepted trust-model limitation**

The capability envelope authenticates the recipient through ECDH/AEAD, but
not the issuer of the epoch-secret vector. Rotation intake then checks that
the outer sender is a member of the transition state. A current member can
construct a valid rotation delivery for another member with an
attacker-chosen secret vector.

- `crates/wyrd-sync/src/control/rotation.rs:211-331` has no issuer signature
  or owner proof.
- `crates/wyrd-sync/src/runtime/intake/mod.rs:514-669` checks the transition,
  recipient binding, and member-sendership, then commits the capability fact.
- `crates/wyrd-sync/src/keys/capability/model.rs:192-230,445-499` validates
  drive, transition, recipient, registered key, and count, but not who minted
  the secrets.
- `docs/epochs.md:254-268` deliberately permits member senders but does not
  explain how that prevents a member from minting arbitrary secrets.

For a target with a vacant epoch, the forged capability can install a
control key derived from the attacker-selected secret. Honest control and
data traffic then fails to open, and a later genuine capability can create a
persistent `EpochConflict` during replay. If the target authors new content
under the poisoned epoch, the attacker knows the key used for that content.

This is separate from recipient or encryption-key substitution, which are
covered by the applied capability-binding issue. The distinct follow-up is
`nostr:nevent1qqsv59ck3ga8r3zqelheltzdzmyq6tgq7t8ry2asey4m555ma0n9kxgpz9mhxue69uhkwunpwdczuap49eehg59ee3k`.

### H6 - Carry obligations can be discharged by an ineligible child

**Severity: high**

The durable carry queue exists to preserve namespace continuity across an
epoch transition. Its completion predicate currently checks only that some
same-epoch child names the staged head as a parent.

- `crates/wyrd-sync/src/runtime/engine/mod.rs:1086-1105` accepts any
  same-epoch child and commits `CarryDone`.
- `crates/wyrd-sync/src/runtime/author/snapshot.rs:247-252` stages the
  obligation for every eligible pre-transition head.
- `crates/wyrd-sync/src/runtime/author/admission.rs:204-225` explicitly
  treats readers as participants, but readers cannot author.
- The intake path can admit a reader-authored body before later
  classification rejects it.

A reader-authored or otherwise ineligible child can therefore make the
pending carry disappear. The drive can become headless after a transition
even though a valid carry was required. The applied carry issue was reopened
and updated:
`nostr:nevent1qqsfwvu2vaymjsx776lxa8mswrkjvmqe55x65l93wfarhaqsrsq3dvqpz9mhxue69uhkwunpwdczuap49eehgndpah6`.

### H7 - Valid large directories can exhaust FUSE memory and inode lifetime

**Severity: high for hostile-member availability**

The format accepts up to 1,000,000 entries in one tree. The FUSE path then
materializes the complete listing, interns every child, stores the complete
listing for the directory handle, and clones that complete vector on every
page request. The inode table has no `forget` reclamation path; the vendored
default `forget` implementation is a no-op.

- `crates/wyrd-fuse/src/view/drive.rs:175-242`
- `crates/wyrd-daemon/src/fuse/backend.rs:1212-1267`
- `crates/wyrd-daemon/src/fuse/backend.rs:1188-1194,1642-1668`
- `vendor/fuser/src/lib.rs:418-433`
- `crates/wyrd-sync/src/ingest.rs:75-82`

A member able to publish a valid large tree can cause large allocations,
repeated page-sized clones, high CPU, and long-lived inode growth. The
existing readdir-union and inode-churn issues cover pieces of this surface but
not the complete bounded-lifetime behavior.

Existing partial tracking was updated:
`nostr:nevent1qqs8z8tzqfkgq0jgs5llwmmgut7jr6huat598xgj5nqt0qeqzpckwxcpz9mhxue69uhkwunpwdczuap49eehg98uayn` and
`nostr:nevent1qqs24nppccd9ll6cue4sqyqpeg75antrwtasmjnumel7x5yz4hw23uqpz9mhxue69uhkwunpwdczuap49eehgpl9nw5`.

## Medium-severity findings

### M1 - The serving authorization contract is not implemented by the production router

`ServingEndpoint` opens a public N0 iroh endpoint and mounts
`BlobsProtocol` directly over the serving mirror. It does not use the
`VaultSource` membership-filtered projection, and `BlobsProtocol` has no
requester authorization callback in the current composition.

- `crates/wyrd-sync/src/serving.rs:324-387`
- `crates/wyrd-sync/src/serving.rs:359-370` rebuilds the mirror from every
  vault root, including unreferenced imports and plaintext snapshot bodies.
- `crates/wyrd-sync/src/serving.rs:484-546` shows the intended filtered
  `VaultSource`, but the production endpoint does not use it.
- `docs/fetch-on-open.md:85-101` and `docs/trust.md:764-769` describe
  membership authorization and ciphertext-only serving.

This is not a claim that file chunks are readable without epoch keys. It is
a policy and confidentiality-boundary gap: route possession is currently the
only practical bearer credential, while the documentation says membership
authorization, and plaintext snapshot bodies are present in the same raw
serving store. Either implement a request authorization/filtered provider or
make the bearer-route posture explicit in the normative contract.

This is covered by the reopened serving-router issue.

### M2 - The serving mirror import queue is unbounded

The vault-to-mirror path uses an unbounded channel and copies each complete
sealed representation into the queue. A slow or failing mirror can grow memory
without an item or byte bound, while the vault itself remains correct only
because it is the source of truth.

- `crates/wyrd-sync/src/serving.rs:180-188,287-320,372-384`

New issue: `nostr:nevent1qqsyy0e4j6jnr7d0v0spcl5uplcze60rmermtla5ngkuutxyyj3h2pgpz9mhxue69uhkwunpwdczuap49eehgr23uat`.

### M3 - A queued FUSE create can recreate a removed parent

`create` resolves a parent path before queuing the mutation, but
`MutationKind::CreateFile` uses the general `put` operation, which creates
missing intermediate directories. Removing or replacing the parent between
lookup and loop execution can resurrect it.

- `crates/wyrd-daemon/src/fuse/backend.rs:816-854`
- `crates/wyrd-core/src/live.rs:647-677`
- `crates/wyrd-format/src/mutation.rs:64-79`

New issue: `nostr:nevent1qqsg76xw2nzh5aczutqfdcl6t9x6sza43rucw5de2gp8h2fvr9uxt9qpz9mhxue69uhkwunpwdczuap49eehg0enstp`.

### M4 - Open handles are count-bounded but not byte-bounded

`OpenFile` clones the entire chunk-ID vector. With 65,536 chunks per file and
4,096 open handles, the configured handle cap does not bound aggregate
pinned metadata. Writable operation paths clone additional image and capture
state.

- `crates/wyrd-core/src/view.rs:148-166`
- `crates/wyrd-fuse/src/view/drive.rs:244-249`
- `crates/wyrd-daemon/src/fuse/backend.rs:590-642`
- `crates/wyrd-core/src/budgets.rs:41-73`

New issue: `nostr:nevent1qqsf8kggskqegmcsy5de7wjla23w87n3wurt8vkkmhexpqpctc393espz9mhxue69uhkwunpwdczuap49eehg6h5gyc`.

### M5 - `getattr` ignores the open handle after unlink or rename

The read path correctly uses the open capture, but `getattr` ignores the
optional file handle and resolves the current path. A valid descriptor can
therefore read bytes while `fstat` or handle-based metadata returns `ENOENT`.

- `crates/wyrd-daemon/src/fuse/backend.rs:1601-1639`
- `docs/write-path.md:484-493`

New issue: `nostr:nevent1qqs9kyffalfgnaydfz7w5x3n3rwvptmmnah866ej2ydeg69u8vfys7cpz9mhxue69uhkwunpwdczuap49eehgmfdrs9`.

### M6 - Mutation failure causes collapse into generic `EIO`

The live mutation path maps authoring, vault, durability, and validation
errors to `MutationError::Engine`. The FUSE boundary then maps that variant
to `EIO`, losing the required `ENOSPC`, `EACCES`, and `EFBIG`
classification.

- `crates/wyrd-core/src/live.rs:642-644,675-677,723-725,800-802,839-841,906-908`
- `crates/wyrd-daemon/src/fuse/backend.rs:92-113`
- `crates/wyrd-sync/src/runtime/engine/mod.rs:86-152`
- `docs/write-path.md:375-388,533-560`

New issue: `nostr:nevent1qqsxw4vwufnyklfmvc8n0axr0cf860wr9mguwumfc200fmdn7e4lvvqpz9mhxue69uhkwunpwdczuap49eehg7pl5ed`.

### M7 - Failed wants append duplicate materialization facts

A timed-out want is retired from the registry while its durable `Cached`
policy remains. A later retry commits another `Fact::Materialization` even
when the state has not changed. Repeated unavailable-content opens therefore
amplify the append-only fact log and fsync work.

- `crates/wyrd-core/src/live.rs:500-555,1180-1199`
- `crates/wyrd-core/src/want.rs:109-151`
- `crates/wyrd-sync/src/durable/store.rs:241-279`

New issue: `nostr:nevent1qqsdc4styznae2hvxpqxp2zalrrx07v0dkuulqkdahjjvvkhh5nrt5cpz9mhxue69uhkwunpwdczuap49eehgmk4433`.

### M8 - Readers do not receive ongoing snapshot announcements

Admission catch-up includes readers, but new snapshot announcement recipient
sets are built from members only. A reader admitted after the current head
set is delivered can remain permanently stale.

- `crates/wyrd-sync/src/runtime/author/snapshot.rs:243-252`
- `crates/wyrd-sync/src/runtime/author/announce.rs:53-73`
- `crates/wyrd-sync/src/runtime/author/admission.rs:204-225`
- `docs/sync-and-peers.md:141-145`

New issue: `nostr:nevent1qqsw0j46ekljlyr5v4whrja94sadylyvycm9wagm0pj78ksdkcygtvcpz9mhxue69uhkwunpwdczuap49eehgxk2e75`.

### M9 - Reader-authored announcements are accepted before role rejection

Intake verifies the signature and transition binding but does not require the
announcement author to be a member before committing an announcement fact.
The later body authorization rejects the reader-authored snapshot, but only
after fact and fetch work has been admitted.

- `crates/wyrd-sync/src/runtime/intake/mod.rs:354-430`
- `crates/wyrd-sync/src/runtime/author/snapshot.rs:149-164`
- `docs/epochs.md:103-110,303-314`

New issue: `nostr:nevent1qqsq5r5fdwugvss907x9alddmxpsfk40sxpsgwrykhw42wdzzu46tlqpz9mhxue69uhkwunpwdczuap49eehg4sz3z9`.

### M10 - Conflict resolution does not freeze on valid losing descendants

Conflict resolution examines only direct children of the contenders. A valid
descendant beyond the conflict epoch is not considered before a resolution is
accepted, despite the permanent-freeze rule in `epochs.md`.

- `crates/wyrd-sync/src/membership/chain.rs:382-423,495-560`
- `docs/epochs.md:193-198`

New issue: `nostr:nevent1qqspa24kdh0ttfx0dhqfp2amhv8s9yg5vayvuaxszfugu5lfuam5pdcpz9mhxue69uhkwunpwdczuap49eehg5aet8m`.

### M11 - The per-pass want budget does not bound structural reconciliation

`max_admit_per_pass` limits newly admitted want identities, but once an
announcement and manifest graph is recorded, `RuntimeState::reconcile` and
`runtime::plan::execute` process all pending structural items to convergence.
The documented byte-in-flight argument therefore does not bound a pass that
expands a large authenticated announcement and manifest fan-out.

- `crates/wyrd-core/src/live.rs:501-511`
- `crates/wyrd-sync/src/runtime/plan/mod.rs:37-240`
- `crates/wyrd-sync/src/runtime/state.rs:620-688`
- `docs/resource-limits.md:64-73`

This should be included in the existing scale/performance tracking rather
than treated as a cryptographic failure.

### M12 - Shutdown can discard dirty handles and wait without a complete bound

The lifecycle supervisor now handles the original FUSE/loop stranding class,
but the production teardown order still stops mailbox, bulk, and serving
before unmounting FUSE. Backend destruction clears the handle table without
committing dirty handles, and one serving shutdown result is discarded.

- `crates/wyrd-cli/src/main.rs:602-667`
- `crates/wyrd-daemon/src/fuse/backend.rs:1112-1127,2074-2079`
- `crates/wyrd-sync/src/bulk.rs:286-289`
- `crates/wyrd-sync/src/serving.rs:455-467`

The applied lifecycle issue was reopened and updated.

## Lower-severity and conditional observations

These are real code observations, but they were not promoted to release
blockers or separate issues because the impact is local, conditional, or
already covered by a broader contract.

| Observation | Evidence | Assessment |
|---|---|---|
| Direct backend callers can read an `O_WRONLY` handle | `crates/wyrd-daemon/src/fuse/backend.rs:617-642,1747-1751` | Low, conditional; the normal kernel VFS path may reject the read first. |
| Directory `..` is returned with the current directory inode | `crates/wyrd-daemon/src/fuse/backend.rs:1231-1234` | Low POSIX compatibility defect, not a containment bypass. |
| Unsupported symlink/link/xattr operations use default `EPERM`/`ENOSYS` rather than the documented `EOPNOTSUPP` distinction | `crates/wyrd-daemon/src/fuse/backend.rs:1559-2079`, `vendor/fuser/src/lib.rs:520-566,780-819` | Low portability issue. |
| Release/write interleaving is possible for direct concurrent backend users | `crates/wyrd-daemon/src/fuse/backend.rs:590-598,904-1014,1117-1127` | Conditional; the current fuser CLI configuration is single-threaded. |
| Export stale-staging ownership is a predictable magic marker plus timestamp | `crates/wyrd-core/src/export.rs:311-429` | Low same-user local-attacker risk. |
| First creation of `mailbox.seen` does not sync its parent directory | `crates/wyrd-core/src/mailbox/seen_store.rs:106-110` | Low crash-durability gap; replay is safe but avoidable. |
| Internal log and seen-log files follow symlinks | `crates/wyrd-cli/src/logging.rs:235-245`, `crates/wyrd-core/src/mailbox/seen_store.rs:106-110,174-193` | Low same-user local-attacker risk. |
| Some append/truncate paths use hardcoded write limits instead of `ResourceBudgets` | `crates/wyrd-core/src/live.rs:748-752,869-876`, `crates/wyrd-daemon/src/fuse/backend.rs:1490-1503` | Low configuration drift; defaults currently match. |
| Production paths still use `expect`/`unwrap` at some lifecycle and exhaustion boundaries | `crates/wyrd-core/src/mutation.rs:614-620`, `crates/wyrd-core/src/mailbox/mod.rs:771-775,972-987`, `crates/wyrd-cli/src/main.rs:1087-1091`, `crates/wyrd-sync/src/durable/store.rs:230-235` | Low convention and recoverability issue. |
| A failed invite claim can be stranded before the invitation is written | `crates/wyrd-cli/src/main.rs:764-800,857-883` | Low retry/liveness issue. |
| The format document describes envelope-byte identity while the store derives ContentId from raw payloads | `docs/object-model.md:68-94`, `crates/wyrd-format/src/store.rs:19-23`, `crates/wyrd-format/src/identity.rs:165-170` | Medium interoperability/documentation drift; the new format-contract issue is `nostr:nevent1qqsrx5gtm4fgmph6wy42e6kfxp364t4f72d40w3jpvrrz7p32xm0sjcpz9mhxue69uhkwunpwdczuap49eehgs5qqrx`. |

## Prior findings verified as fixed

The following historical concerns are present in the current tree and should
not be re-filed as new defects:

- The durable announcement outbox exists in `runtime::author::announce` and
  replay state.
- Live projection refresh is all-or-nothing through `verified_heads`.
- Manifest-authoring traversal is iterative.
- Live-head closure verification runs before installation.
- The live mailbox unacknowledged and durable seen-log state are bounded and
  compacted.
- Mailbox retry, held-message, and poison suppression paths use relay-retained
  or bounded semantics.
- iroh bulk fetch checks verified size before bounded streaming.
- Genesis transition `resolves` handling is corrected.
- Capability recipient, drive, transition, epoch, and registered-key binding
  checks are present.
- FUSE path depth and lock-poison handling have dedicated bounds/errors.
- CLI credential values use `Zeroizing`; the earlier plain-`String` finding
  is withdrawn.

## Explicitly rejected findings

- No confirmed cross-user FUSE authorization bypass was found. The default CLI
  does not enable `AllowOther`, and the default fuser session is owner-scoped.
- No confirmed primitive misuse was found in secp256k1, AEAD, HKDF, ECDH,
  CSPRNG use, or signature verification.
- No orphan-transition propagation defect was found. Valid descendants of an
  invalid or orphaned membership link are explicitly classified as orphaned or
  voided.
- No bulk pre-download oversize defect remains in the current iroh client;
  verified size and bounded streaming precede content buffering.
- A lost want wakeup is a latency issue explicitly permitted by
  `docs/fetch-on-open.md:169-172`, not a deadline violation.

## Required verification work

The highest-value missing tests are:

1. Oversized relay/NIP-59 input rejected before unwrap and before retained
   handover.
2. Local mutation commits, serving mirror flushes, then announcement sends.
3. Serving restart rewrites or re-routes persisted announcements.
4. Chained symlink escape rejected by both export and daemon paths.
5. Remote parent-count, chunk-size, and tree-count limits rejected before
   durable import.
6. Malicious current member cannot install an arbitrary rotation secret vector
   under the chosen threat model.
7. Ineligible same-epoch child does not discharge a carry.
8. Reader receives new heads and reader-authored announcement facts are
   rejected before commit.
9. Contested branch descendants freeze conflict resolution.
10. Large directory, aggregate open-capture, and serving-queue saturation stay
    within configured bounds.
11. Unlinked and renamed handle metadata remains available through the handle.
12. Disk-full, permission, and ingest failures retain their documented errno
    classification.

## ngit issue crosswalk

### Reopened and updated existing issues

- Mailbox outer byte ceiling:
  `nostr:nevent1qqsytvqr68x7zdrm6mprwn7xqxqr6evtwl5n3aczf7m0g7swfuq6pagpz9mhxue69uhkwunpwdczuap49eehgyjzcvq`
- Real iroh serving readiness, authorization, and route restart:
  `nostr:nevent1qqs20s65ztzkegm8r64q53cd3kt3g9xusv6z0w78mt5szx3hmjnecnqpz9mhxue69uhkwunpwdczuap49eehg56ukhs`
- Chained symlink confinement:
  `nostr:nevent1qqsqrrew3krrz6g6wd5zwdqa07p248kzpz38wljmhn3vgsjzwahgk6spz9mhxue69uhkwunpwdczuap49eehgy3h6mt`
- Carry eligibility:
  `nostr:nevent1qqsfwvu2vaymjsx776lxa8mswrkjvmqe55x65l93wfarhaqsrsq3dvqpz9mhxue69uhkwunpwdczuap49eehgndpah6`
- Runtime resource limits:
  `nostr:nevent1qqstrwjc4g4e9hsp2v4jspule4h9w4ujqdkysdt7umlh3txgk7s9k3qpz9mhxue69uhkwunpwdczuap49eehgdzy80r`
- FUSE/live lifecycle teardown:
  `nostr:nevent1qqsywppx64zydjksu8nmpvpekep6r7kk6d9367e4xa5vfjluxqyxcwqpz9mhxue69uhkwunpwdczuap49eehgx9fmgq`

### Updated open issues

- Readdir union scale:
  `nostr:nevent1qqs8z8tzqfkgq0jgs5llwmmgut7jr6huat598xgj5nqt0qeqzpckwxcpz9mhxue69uhkwunpwdczuap49eehg98uayn`
- Inode churn:
  `nostr:nevent1qqs24nppccd9ll6cue4sqyqpeg75antrwtasmjnumel7x5yz4hw23uqpz9mhxue69uhkwunpwdczuap49eehgpl9nw5`
- Intake fact spam:
  `nostr:nevent1qqspf7us2cpqrsljfa3fermsrh3qvkkkmrlp45u9l0cg5y6f4t8x6kqpz9mhxue69uhkwunpwdczuap49eehg2ul6fc`
- Authorized-writer storage amplification:
  `nostr:nevent1qqszfmalx8jpf05j5u6zkcz2zs2a5h3yrt0m5ltq7wkpffu427tfyycpz9mhxue69uhkwunpwdczuap49eehgl4fx5r`
- Control transport dedupe semantics:
  `nostr:nevent1qqsz0uk767zzggv7s08nhtykfrc8eqazmtwswwzmzm4u8fl4uv4rs8spz9mhxue69uhkwunpwdczuap49eehgj8l6aj`
- FUSE lifecycle coverage:
  `nostr:nevent1qqs8zxhumyd3g9arevyvxyv5qnatrcv7uku8yf79uwx53u6nf2cj2lgpz9mhxue69uhkwunpwdczuap49eehglf49cr`
- Serving E2E:
  `nostr:nevent1qqsduan5dark63za8cptzpytdlj95m4tj5mn05u0z500xq8ehtntu3gpz9mhxue69uhkwunpwdczuap49eehg6wjyle`
- Capability binding audit:
  `nostr:nevent1qqsp7aeswq7nnyyta85saxesf02w8f8wfmyra6fgrf872psjcljrndcpz9mhxue69uhkwunpwdczuap49eehg5n8zes`
- Intermittent nextest test/isolation:
  `nostr:nevent1qqsdkkr5tr8gtypejqy7wypxckpck4dxfardss2mc7v7xzgrre2y3ngpz9mhxue69uhkwunpwdczuap49eehgwjfj6h`

### New issues created and triaged

All new issues were created without labels, then given exactly one type,
one priority, and one `release:v0.2.0-alpha` milestone.

- `fix(sync): enforce structural ingest limits on fetched snapshots and chunks` - bug P1:
  `nostr:nevent1qqsgscqjq8q68s0fg50u3p8unpdyttru8ze3uz9ey9v9m5eznw4n0jspz9mhxue69uhkwunpwdczuap49eehg7gld4y`
- `harden(sync): authenticate capability issuer before installing rotation secrets` - bug P1:
  `nostr:nevent1qqsv59ck3ga8r3zqelheltzdzmyq6tgq7t8ry2asey4m555ma0n9kxgpz9mhxue69uhkwunpwdczuap49eehg59ee3k`
- `fix(fuse): fail create when the parent path is replaced or removed` - bug P1:
  `nostr:nevent1qqsg76xw2nzh5aczutqfdcl6t9x6sza43rucw5de2gp8h2fvr9uxt9qpz9mhxue69uhkwunpwdczuap49eehg0enstp`
- `harden(fuse): byte-bound aggregate open-capture memory` - bug P1:
  `nostr:nevent1qqsf8kggskqegmcsy5de7wjla23w87n3wurt8vkkmhexpqpctc393espz9mhxue69uhkwunpwdczuap49eehg6h5gyc`
- `fix(fuse): preserve getattr semantics for unlinked and renamed handles` - bug P1:
  `nostr:nevent1qqs9kyffalfgnaydfz7w5x3n3rwvptmmnah866ej2ydeg69u8vfys7cpz9mhxue69uhkwunpwdczuap49eehgmfdrs9`
- `refactor(fuse): preserve mutation failure causes across errno mapping` - enhancement P2:
  `nostr:nevent1qqsxw4vwufnyklfmvc8n0axr0cf860wr9mguwumfc200fmdn7e4lvvqpz9mhxue69uhkwunpwdczuap49eehg7pl5ed`
- `harden(sync): suppress duplicate materialization facts for failed wants` - bug P1:
  `nostr:nevent1qqsdc4styznae2hvxpqxp2zalrrx07v0dkuulqkdahjjvvkhh5nrt5cpz9mhxue69uhkwunpwdczuap49eehgmk4433`
- `fix(sync): include readers in ongoing snapshot announcements` - bug P2:
  `nostr:nevent1qqsw0j46ekljlyr5v4whrja94sadylyvycm9wagm0pj78ksdkcygtvcpz9mhxue69uhkwunpwdczuap49eehgxk2e75`
- `fix(sync): reject reader-authored snapshot announcements at intake` - bug P2:
  `nostr:nevent1qqsq5r5fdwugvss907x9alddmxpsfk40sxpsgwrykhw42wdzzu46tlqpz9mhxue69uhkwunpwdczuap49eehg4sz3z9`
- `fix(sync): keep conflict resolution frozen when contested branches have descendants` - bug P1:
  `nostr:nevent1qqspa24kdh0ttfx0dhqfp2amhv8s9yg5vayvuaxszfugu5lfuam5pdcpz9mhxue69uhkwunpwdczuap49eehg5aet8m`
- `harden(sync): bound and observe the serving mirror queue` - bug P1:
  `nostr:nevent1qqsyy0e4j6jnr7d0v0spcl5uplcze60rmermtla5ngkuutxyyj3h2pgpz9mhxue69uhkwunpwdczuap49eehgr23uat`
- `docs(format): align object identity with the envelope contract` - enhancement P2:
  `nostr:nevent1qqsrx5gtm4fgmph6wy42e6kfxp364t4f72d40w3jpvrrz7p32xm0sjcpz9mhxue69uhkwunpwdczuap49eehgs5qqrx`

## Final assessment

The protocol core should not be redesigned around these findings. The most
valuable next work is to make the live boundary enforce the contracts that
are already written: early byte limits, per-snapshot serving readiness,
membership-aware serving, compositional symlink resolution, structural fetch
limits, capability issuer provenance, and eligible carry completion. Once
those are closed and the listed adversarial contracts exist, rerun the full
workspace and live-relay test profiles before changing the release verdict.

# Mobile File Surfaces

**Status:** Design plan. Not yet normative. Nothing in this document is a contract: normative behavior lives in `docs/object-model.md`, `docs/trust.md`, `docs/epochs.md`, and `docs/write-path.md` until a tracked issue explicitly adopts a section here.

**Extraction status (2026-09):** the Phase 1 split below is done — `wyrd-core` holds `WyrdNode`, `LiveNode`/`LiveParts`, the mutation/session/projection machinery, and the relay mailbox; `wyrd-daemon` is the desktop composition library; `wyrd-cli` is the `wyrd` process host. Two deliberate deviations from the plan as written: `DriveView` stayed in `wyrd-fuse` (providers program against the `NamespaceView` trait in `wyrd-core` instead), and the moved types were renamed (`Daemon` → `WyrdNode`, `LiveDaemon` → `LiveNode`). Read `Daemon`/`LiveDaemon`/`DriveView` below as their current names; the remaining sections are future mobile work to be re-validated, not descriptions of today.

## Purpose

Wyrd currently exposes a drive through a FUSE mount on desktop. Mobile platforms such as Android and iOS cannot use FUSE and have different process and filesystem integration models.

The goal is for Wyrd to act as a **substrate filesystem**: a platform-independent projection of Wyrd snapshots that can be adapted to native file-access APIs without making filesystem semantics part of Wyrd's storage model.

A typical use case is:

> A note-taking application accesses the `Notes` directory through the platform's native file picker or file provider, reads and writes notes, and those changes become Wyrd snapshots that synchronize to other devices.

The important architectural constraint is that mobile must not introduce a second filesystem implementation. Wyrd's snapshot, projection, handle, mutation, conflict, and durability semantics remain authoritative in the daemon core. Platform adapters translate native APIs into those semantics.

---

## The core insight

`wyrd-fuse::DriveView` is already intended to be presentation-agnostic. The architecture documentation describes FUSE as:

> "The FUSE adapter is the first such backend, not a property of the core."

The mobile surfaces should follow the same model.

The architecture is:

```text
                         Wyrd snapshots
                               │
                               ▼
                        Daemon core
                               │
                         ┌─────┴─────┐
                         │           │
                    DriveView    write handles
                         │           │
             ┌───────────┼───────────┤
             │           │           │
            FUSE      Android       iOS
             │      DocumentsProvider
             │           │      File Provider
             ▼           ▼           ▼
          desktop    mobile apps   Files.app
```

FUSE, Android, and iOS are presentation adapters. They must not independently implement Wyrd's storage or snapshot semantics.

---

# 1. Separation of concerns

There are three distinct layers involved in a file surface.

## 1.1 Projection/query surface

The projection surface resolves the current visible Wyrd namespace:

```text
lookup(path)    -> Node
readdir(node)   -> Vec<DirEntry>
stat(path)      -> Metadata
```

The exact `DriveView` API remains to be finalized, but its responsibility is to answer questions about the currently published projection.

It does not own platform-specific concepts such as FUSE inodes, Android document IDs, or iOS item identifiers.

## 1.2 File-handle surface

A file surface also needs handle semantics:

```text
open(path, flags) -> OpenHandle
read(handle, ...)
write(handle, ...)
flush(handle)
fsync(handle)
release(handle)
```

These operations are governed by the Wyrd write-path design in `docs/write-path.md` — handle identity and stability, buffered overlays, snapshot commits, stale-handle rejection, and `MutationQueue` serialization. The platform adapters must translate their native file lifecycle into those semantics rather than inventing independent write behavior.

## 1.3 Platform lifecycle

Background synchronization, process lifetime, provider callbacks, and operating-system scheduling are separate from the file surface itself.

The architecture should therefore remain:

```text
Platform lifecycle
       │
       ├──────────────┐
       │              │
   Sync runtime   File surface
       │              │
       └───────┬──────┘
               ▼
        Wyrd daemon core
               │
           DriveView
```

A file provider should not need to know whether synchronization is currently performed by:

* a foreground service;
* a background task;
* an always-running daemon;
* a manually triggered synchronization operation;
* or no network synchronization at all.

The provider operates against the current local Wyrd projection.

---

# 2. Crate separation

The preferred crate structure is:

```text
wyrd-format
    │
    ▼
wyrd-sync
    │
    ▼
wyrd-core
    │
    ├───────────────┐
    ▼               ▼
wyrd-daemon     wyrd-mobile
    │               │
   FUSE        platform adapters
```

## 2.1 `wyrd-core`

Platform-independent crate (extracted; see the status note above).

Responsibilities:

* daemon composition;
* `WyrdNode`;
* `LiveNode`/`LiveParts`;
* `NamespaceView` trait (`DriveView` stayed in `wyrd-fuse` as its first implementation);
* projection state;
* projection generations;
* open file handles;
* writable handle state;
* mutation queue;
* snapshot publication;
* local durability lifecycle;
* serving integration where required by the daemon;
* lifecycle methods.

It must not depend on:

* `fuser`;
* Android APIs;
* iOS APIs;
* JNI;
* Swift/Objective-C frameworks;
* Unix-specific filesystem APIs.

The core must remain usable as an embedded library.

## 2.2 `wyrd-daemon`

Desktop-only crate, retaining the current daemon role.

Responsibilities:

* FUSE adapter;
* desktop CLI;
* Unix-specific integration;
* desktop process lifecycle.

It depends on:

```text
wyrd-core
```

and does not contain the authoritative implementation of filesystem semantics.

## 2.3 `wyrd-mobile`

Optional mobile integration crate.

The precise division between Rust and native platform code remains to be determined, but the preferred direction is:

```text
Kotlin / Swift
      │
      ▼
thin platform adapter
      │
      ▼
wyrd-core
```

The mobile layer should contain platform integration rather than duplicate Wyrd policy.

Android and iOS may ultimately use separate platform crates or native bridges if their integration requirements diverge sufficiently. That is an implementation decision rather than a reason to duplicate the core.

---

# 3. `NamespaceView` contract (`DriveView` is its first implementation)

`NamespaceView` is the common projection interface consumed by all file surfaces; `DriveView` implements it today.

It is responsible for:

1. resolving paths;
2. enumerating directories;
3. reporting metadata;
4. opening files;
5. reading immutable materialized content;
6. exposing the current projection generation;
7. coordinating with writable handles where supported.

The exact API should be finalized before platform adapters are implemented.

The key architectural requirement is:

> A platform backend must never bypass `DriveView` to inspect Wyrd's underlying snapshot or object store directly.

The backend may use lower-level APIs for platform-specific caching or transport, but filesystem-visible state must come from the daemon core.

---

# 4. Projection generations

Wyrd already has a concept of projection generation. Mobile providers should use the same concept for cache coherence.

Every successful publication of a new Wyrd projection advances the projection generation.

```text
Snapshot H
    │
    ▼
generation 41
    │
    │ commit
    ▼
Snapshot H1
    │
    ▼
generation 42
```

Provider-side representations are therefore associated with the generation from which they were produced.

For example:

```text
Android document cache
    document-id
    metadata
    generation = 42
```

A cached representation must be revalidated if the underlying projection generation has advanced.

The same principle applies to:

* directory enumeration;
* metadata;
* path lookup;
* document identity mappings;
* materialized file information.

This prevents each platform adapter from developing an independent cache-invalidation model.

---

# 5. Mobile document identity

Native file-provider APIs generally need an identifier for a document that is not necessarily identical to its current filesystem path.

The adapter must therefore define an explicit mapping between platform document identity and Wyrd namespace identity.

The adapter must not silently assume that:

```text
document ID == path
```

because paths can change through rename.

The following possibilities require evaluation:

### Path-derived identity

```text
hash("/Notes/foo.md")
```

Simple, but rename changes identity.

### Wyrd node identity

Use an immutable Wyrd identity where the format provides one.

This potentially gives better rename stability but must be reconciled with Wyrd's namespace identity model.

### Adapter-level opaque identity

The platform adapter maintains:

```text
provider-document-id
        │
        ▼
current Wyrd namespace location
```

This isolates platform identity from Wyrd path semantics.

The preferred choice should be made before the mobile backend contract becomes normative.

Regardless of implementation, the following operations must have defined identity behavior:

* rename;
* replacement;
* unlink;
* recreation of the same path;
* conflict;
* historical versions.

A deleted document must not accidentally regain the identity of a later unrelated file merely because it has the same pathname.

---

# 6. Android DocumentsProvider

Android's `DocumentsProvider` is a natural read/write adapter for Wyrd.

The conceptual mapping is:

```text
DocumentsProvider
       │
       ▼
   DriveView
       │
       ▼
 Wyrd projection
```

Representative mappings include:

```text
queryChildDocuments()
    → lookup() / readdir()

openDocument()
    → lookup() + open()

readDocument()
    → read() on OpenHandle

getDocumentMetadata()
    → stat()

createDocument()
    → create mutation

writeDocument()
    → WritableHandle / write path

removeDocument()
    → namespace mutation
```

The precise Android API mapping should be defined in the platform contract rather than assumed to be a one-to-one mapping.

## 6.1 Process model

The initial Android design keeps the provider in the same application process as the daemon core.

```text
Android application
 ├── DocumentsProvider
 ├── sync runtime
 └── Daemon core
```

This avoids cross-process mutation coordination in the initial implementation.

The provider must nevertheless tolerate Android lifecycle events.

In particular:

* the application process may be killed;
* the provider may be instantiated independently;
* synchronization may not currently be running;
* network access may be unavailable;
* local Wyrd state may still be readable.

The file surface should therefore remain useful against local durable state even when synchronization is unavailable.

## 6.2 Background synchronization

Synchronization is owned by the application's lifecycle layer.

The initial design uses a foreground service where required for sustained background synchronization.

The file provider itself does not own synchronization policy.

---

# 7. iOS File Provider

iOS uses `NSFileProviderExtension` and has a substantially different process model.

The extension is a separate process from the main application.

The conceptual architecture is:

```text
                 App Group storage
                       │
              ┌────────┴────────┐
              │                 │
          Main app        File Provider
              │                 │
          Daemon core       adapter
              │                 │
              └──── coordination ────┘
```

The extension may access shared durable state through the appropriate application-group storage mechanism.

However, **shared storage alone does not make two daemon instances safe**.

---

# 8. iOS process ownership

The most important iOS constraint is that the main application and File Provider extension must not independently author snapshots against the same Wyrd store without an explicit concurrency protocol.

An unsafe model would be:

```text
Main App
   └── Daemon A
        └── shared store

File Provider
   └── Daemon B
        └── shared store
```

Both instances could independently:

* read the current head;
* construct mutations;
* author snapshots;
* publish projections;
* advance generations;
* enqueue announcements.

A file lock around only the `MutationQueue` is not sufficient if either process can make state decisions before acquiring that lock.

For example:

```text
Daemon A                    Daemon B

read head H                 read head H

acquire writer ownership
commit H → H1
publish H1
release

                            acquire writer ownership
                            commit using stale H
```

Therefore the iOS design must establish explicit writer ownership.

---

# 9. Cross-process commit protocol

If more than one process can author mutations, the protocol must be stronger than a simple mutex.

A candidate protocol is:

```text
acquire writer ownership
        │
        ▼
refresh current durable head
        │
        ▼
construct mutation
        │
        ▼
commit against current state
        │
        ▼
publish projection
        │
        ▼
record announcement obligation
        │
        ▼
release writer ownership
```

The exact mechanism remains an open implementation question.

Possible mechanisms include:

* application-group coordination;
* XPC;
* a durable writer lease;
* file locking combined with generation/head validation;
* delegation of all writes to the main application process.

The design must guarantee:

1. only one process performs the local mutation serialization at a time;
2. the writer refreshes current state after acquiring ownership;
3. stale observations cannot silently become new commits;
4. publication and durability follow the same commit ordering as desktop;
5. process death does not leave the store in an ambiguous partially committed state.

The final implementation should preferably make the durable store itself reject invalid concurrent commits rather than relying entirely on cooperative locking.

---

# 10. iOS reads

Read-heavy File Provider operations may use a core instance or a thinner read-only view over shared durable state, provided that this does not allow the extension to independently mutate authoritative state.

The important distinction is:

```text
Read access
    ≠
snapshot-authoring authority
```

A File Provider extension may safely inspect durable Wyrd state provided it follows the same projection and validation rules as the main daemon.

The design should prefer the simplest process model that satisfies iOS lifecycle requirements.

---

# 11. Write path

The Wyrd write path is specified in `docs/write-path.md`: FUSE implements it first, and the mobile surfaces consume that implementation rather than create platform-specific write semantics.

The platform adapter is responsible for translating its native lifecycle into the write-path commit sequence.

It must not independently merge byte ranges, resolve conflicts, or author snapshots.

---

# 12. Mobile write lifecycle

Mobile process lifetime differs substantially from desktop.

A desktop application may keep an open writable handle alive for a long time:

```text
open
write
write
write
fsync
close
```

A mobile process may instead be:

```text
open
write
write
        ↓
process suspended
        ↓
process terminated
```

An open mobile platform handle therefore cannot be assumed to survive process termination.

The design must explicitly distinguish:

* buffered, uncommitted state;
* device-local durable state;
* published projection;
* platform-provider state.

Unless the platform adapter explicitly persists the overlay, uncommitted writable state may be lost if the hosting process terminates before the appropriate durability boundary.

Mobile APIs must not silently promise stronger durability than the underlying Wyrd handle contract provides.

---

# 13. Write support for v0.1

The initial mobile release should prefer a deliberately small write surface.

Candidate support:

* create regular files;
* write existing regular files;
* truncate;
* append;
* rename;
* unlink;
* mkdir;
* rmdir;
* basic executable-bit handling where exposed by the platform.

The exclusions mirror the write-path non-goals in `docs/write-path.md`.

The platform adapter must map unsupported operations to the same error semantics established by the Wyrd write-path contract.

---

# 14. Handle semantics

Mobile adapters inherit the Wyrd writable-handle semantics in `docs/write-path.md` — projection-tied handles, stale-handle rejection, append semantics, terminal failed commits — without modification.

The exact rename/unlink behavior for an already-open writable handle must be resolved in `docs/write-path.md` before mobile writes become normative.

The mobile adapter must not choose different semantics.

---

# 15. Conflict handling

Wyrd explicitly preserves conflict visibility: the conflicted-drives rule in `docs/write-path.md` applies unchanged — with more than one eligible live head, mutations fail closed.

A mobile file surface must not hide or silently resolve multiple eligible live heads merely because the platform expects a single filesystem view.

A provider must translate this into an appropriate platform-level failure.

It must not:

* choose an arbitrary head;
* discard a head;
* automatically merge content;
* rewrite history;
* make a conflict appear as a normal successful write.

Conflict resolution remains outside the v0 mobile file surface unless a separate design explicitly introduces it.

---

# 16. Cache and materialization semantics

Mobile file providers may cache metadata and materialized files.

Those caches are presentation-layer state.

They must not become an alternative source of truth.

The authoritative hierarchy remains:

```text
Wyrd durable state
       ↓
published projection
       ↓
DriveView
       ↓
platform cache
```

A cached representation may be discarded at any time and reconstructed from Wyrd state.

Provider caches must therefore be safe to invalidate without affecting Wyrd durability or history.

Where the platform provides explicit cache eviction or "provide this file" lifecycle operations, the implementation should treat those operations as materialization requests rather than filesystem commits.

---

# 17. Background synchronization

Background synchronization is platform-specific and must remain outside the core file-surface contract.

## Android

Initial design:

```text
Application
    ├── foreground service
    │       └── sync runtime
    │
    └── DocumentsProvider
            └── daemon core
```

The exact Android lifecycle implementation remains to be validated against platform restrictions.

## iOS

Initial design:

```text
Main application
    └── sync runtime

File Provider extension
    └── provider adapter
```

Background execution uses the platform's supported background mechanisms.

The provider must be able to expose local durable state even when synchronization is temporarily unavailable.

Synchronization availability must not be conflated with filesystem availability.

---

# 18. Mutation ownership

There must be one authoritative mutation serialization mechanism for a given local Wyrd store.

In the simplest case:

```text
one process
    └── one MutationQueue
```

For iOS shared-process state, if multiple processes are permitted to issue writes, the architecture must establish an equivalent cross-process ownership protocol.

The invariant is:

> At most one mutation sequence is authoritatively constructing and publishing a new local Wyrd snapshot at any point in time.

A file lock is an implementation mechanism, not the invariant itself.

---

# 19. Durable state and announcement obligations

Mobile does not change Wyrd's commit ordering: the commit pipeline, durability boundary, and announcement-obligation semantics in `docs/write-path.md` apply unchanged — later-stage failure never rolls back earlier durable state.

The exact durable outbox recovery mechanism is shared with the main daemon design and must remain correct across mobile process termination.

---

# 20. Native API mappings

## Android

Conceptual mapping:

| Android operation     | Wyrd operation             |
| --------------------- | -------------------------- |
| `queryChildDocuments` | `lookup` + `readdir`       |
| `openDocument`        | `lookup` + `open`          |
| file read             | `read`                     |
| file write            | `WritableHandle` + `write` |
| metadata              | `stat`                     |
| create                | create mutation            |
| delete                | unlink/rmdir mutation      |
| rename                | rename mutation            |

The exact mapping should be tested against the Android provider lifecycle.

## iOS

Conceptual mapping:

| File Provider operation | Wyrd operation               |
| ----------------------- | ---------------------------- |
| item lookup             | `lookup`                     |
| enumeration             | `readdir`                    |
| metadata                | `stat`                       |
| load contents           | `open` + `read`              |
| provide/materialize     | local object materialization |
| create item             | create mutation              |
| modify item             | writable handle              |
| delete item             | unlink/rmdir mutation        |
| rename item             | rename mutation              |

The exact lifecycle semantics must be established by the iOS adapter contract.

---

# 21. Platform-independent backend invariants

Every file-surface backend must satisfy the following invariants.

### Projection

* It exposes only the currently published Wyrd projection.
* It does not bypass snapshot validation.
* It does not expose unverified snapshots.
* It does not silently select between conflicting eligible heads.

### Identity

* Provider document identity is stable according to the chosen identity contract.
* Deleted identities cannot accidentally alias newly created unrelated nodes.
* Rename behavior is explicit.

### Handles

* Open handles retain the stability guarantees of the Wyrd handle contract.
* Head advancement does not silently invalidate reads.
* Writable handles obey stale-handle rules.

### Mutation

* All mutations pass through canonical Wyrd format validation.
* All protocol and object-size limits remain enforced.
* Platform adapters cannot bypass `check_tree`, `check_manifest`, or equivalent format validation.

### Durability

* Platform-visible success cannot claim stronger durability than the Wyrd commit boundary provides.
* Later-stage failures do not roll back durable state.

### Conflicts

* Multiple eligible heads remain visible as a conflict at the semantic layer.
* Providers do not resolve conflicts implicitly.

### Caching

* Cached provider state is disposable.
* Cache validity is tied to the Wyrd projection generation.
* Cache state cannot become authoritative Wyrd state.

---

# 22. Test matrix

The mobile implementation should extend existing Wyrd contract tests rather than replace them.

## Existing Wyrd invariants

| Contract                                           | Status | Notes                          |
| -------------------------------------------------- | ------ | ------------------------------ |
| unverified snapshots never become live heads       | ✓      | Core invariant                 |
| ContentIds never appear in vault transport records | ✓      | Core crypto invariant          |
| open FDs remain stable across head advancement     | ✓      | Existing `LiveNode` coverage |

## DriveView contracts

| Contract                                       | Status |
| ---------------------------------------------- | ------ |
| lookup reflects current published projection   | TODO   |
| readdir uses a stable enumeration generation   | TODO   |
| stat reflects published state                  | TODO   |
| provider cannot bypass projection validation   | TODO   |
| conflicting heads are surfaced                 | TODO   |
| cache invalidates across projection generation | TODO   |
| path traversal remains confined                | TODO   |
| symlink semantics match the core contract      | TODO   |

## Mobile backend contracts

| Contract                                                               | Status |
| ---------------------------------------------------------------------- | ------ |
| Android document identity is stable                                    | TODO   |
| Android enumeration reflects projection generation                     | TODO   |
| Android reads work from durable local state offline                    | TODO   |
| Android writes use `MutationQueue`                                     | TODO   |
| iOS document identity is stable                                        | TODO   |
| iOS enumeration reflects projection generation                         | TODO   |
| iOS materialization is reconstructible                                 | TODO   |
| iOS provider does not independently author unsafe concurrent snapshots | TODO   |
| provider cache invalidation works                                      | TODO   |
| conflict failures are surfaced without implicit resolution             | TODO   |

## Cross-process contracts

| Contract                                                  | Status |
| --------------------------------------------------------- | ------ |
| writer ownership is exclusive                             | TODO   |
| writer refreshes current head after ownership acquisition | TODO   |
| stale observations cannot become commits                  | TODO   |
| process death during commit is recoverable                | TODO   |
| durable announcement obligations survive process restart  | TODO   |
| concurrent processes cannot corrupt projection generation | TODO   |

---

# 23. Implementation plan

## Phase 1 — Extract the platform-independent daemon

This extraction builds on the tracked composition seam — `refactor(daemon): make runtime ownership and projection publication explicit` (`nostr:nevent1qqsqcuw0w8sltgu77458ckwyepf4xjfh976yryek4c4mjcer8kun67spz9mhxue69uhkwunpwdczuap49eehgwadcsl`) — which establishes single-owner runtime mutation and generation-tagged projection publication. The `wyrd-core` split packages that seam for embedding; it must not redesign it.

* Extract `wyrd-core`. ✅ done (node extraction, contracts 34–36).
* Move `Daemon` and `LiveDaemon` into the new crate. ✅ done as `WyrdNode` and `LiveNode`.
* Move `DriveView` into the new crate if it does not already live at an appropriate platform-independent boundary. ✅ resolved the other way: `DriveView` stayed in `wyrd-fuse`; providers program against the `NamespaceView` trait.
* Move writable-handle and mutation-queue infrastructure into the core as the write path lands. ✅ done.
* Ensure the core has no FUSE or Unix-specific dependencies. ✅ done (contract 34's `wyrd-core` clause forbids fuser, clap, and libc).
* Retain `wyrd-daemon` as the desktop composition layer. ✅ done (library; the binary lives in `wyrd-cli`).
* Keep FUSE behavior unchanged during the extraction. ✅ done (workspace suite green at every phase).

### Exit condition

Desktop FUSE behavior is unchanged and all existing daemon tests pass against `wyrd-core`.

---

## Phase 2 — Define the DriveView and mobile contracts

Before implementing native providers:

* define the complete `DriveView` API;
* define handle semantics;
* define projection-generation semantics;
* define document identity;
* define conflict behavior;
* define provider caching rules;
* define mobile lifecycle semantics.

These contracts should be platform-independent.

---

## Phase 3 — Android read surface

Implement:

* `DocumentsProvider`;
* root discovery;
* directory enumeration;
* metadata;
* file opening;
* local reads;
* projection-generation invalidation.

Initial implementation should be read-only.

Background synchronization remains separate.

### Exit condition

A normal Android application can browse and open Wyrd files through the native document APIs using locally durable state.

---

## Phase 4 — iOS read surface

Implement:

* `NSFileProviderExtension`;
* item lookup;
* enumeration;
* metadata;
* local file materialization;
* provider caching;
* App Group shared storage.

The initial implementation should avoid independent snapshot authoring from the extension.

### Exit condition

Files.app and a native document-aware application can browse and read Wyrd content from the provider.

---

## Phase 5 — Wyrd write path

Implement the authoritative write path:

* format mutations;
* `mkdir`;
* create;
* unlink;
* rmdir;
* rename;
* truncate;
* file writes;
* append;
* `WritableHandle`;
* `MutationQueue`;
* durable commit pipeline;
* projection publication;
* serving flush;
* announcement outbox.

This implementation is shared by all file surfaces.

FUSE is the first surface on the common write path: it proves the handle, queue, and commit semantics that the mobile adapters later consume.

---

## Phase 6 — Android writes

Map Android write operations onto the common Wyrd write path.

Test:

* create;
* overwrite;
* append;
* truncate;
* rename;
* delete;
* concurrent handles;
* stale handles;
* process termination;
* offline operation;
* resource exhaustion;
* conflicts.

---

## Phase 7 — iOS write coordination

Choose and implement the cross-process ownership mechanism.

The preferred architecture should minimize independent snapshot-authoring engines.

Possible approaches:

1. delegate writes from the extension to the main application;
2. use an explicit cross-process writer lease;
3. use App Group coordination plus durable head validation;
4. permit multiple daemon instances only after the durable store has a process-safe transactional commit protocol.

Do not treat a simple file lock as sufficient without proving the complete commit protocol.

---

# 24. Open questions

## 1. What is the canonical mobile document identity?

Choose between:

* path-derived identity;
* Wyrd node identity;
* opaque adapter-level identity.

The choice must define rename, delete, replacement, and recreation behavior.

## 2. What is the iOS writer ownership model?

Determine whether writes should:

* delegate to the main application;
* use XPC;
* use an App Group writer lease;
* or support multiple independent daemon instances safely.

## 3. What is the minimum write surface for v0.1?

Determine which mutations are necessary for the first mobile release.

The recommended initial set is:

* create;
* write;
* truncate;
* append;
* rename;
* unlink;
* mkdir;
* rmdir.

## 4. How should mobile process termination affect writable handles?

Determine whether uncommitted overlays are:

* explicitly disposable;
* persisted;
* committed at additional platform lifecycle boundaries.

The implementation must not imply stronger guarantees than it can provide.

## 5. What is the background synchronization model?

Determine the exact Android foreground-service and iOS background-task behavior.

This remains a lifecycle concern rather than a `DriveView` concern.

## 6. How should provider cache invalidation be notified?

Determine how projection-generation changes become native provider change notifications.

The underlying validity rule should remain generation-based even if the notification mechanism differs by platform.

## 7. How should conflicts be represented by native providers?

The platform mapping should expose failure without silently resolving the conflict.

A richer conflict presentation can be added later without changing Wyrd's core semantics.

---

# 25. Decision record

| #  | Decision                                                                     | Status            | Rationale                                                                       |
| -- | ---------------------------------------------------------------------------- | ----------------- | ------------------------------------------------------------------------------- |
| 1  | Split `wyrd-daemon` into `wyrd-core` + desktop `wyrd-daemon`                 | Proposed          | Isolate platform dependencies and make daemon functionality embeddable          |
| 2  | Mobile file surfaces consume `DriveView`, not FUSE                           | Proposed          | FUSE is a presentation adapter, not part of the filesystem model                |
| 3  | Android `DocumentsProvider` initially runs in the application process        | Proposed          | Avoid unnecessary cross-process coordination                                    |
| 4  | iOS File Provider is a separate process                                      | Fixed by platform | `NSFileProviderExtension` has its own process lifecycle                         |
| 5  | iOS shared storage does not by itself authorize multiple daemon writers      | Proposed          | Shared durable state requires explicit mutation ownership                       |
| 6  | Mobile background synchronization is separate from the file-surface contract | Proposed          | Platform lifecycle must not leak into Wyrd filesystem semantics                 |
| 7  | Mobile provider caches are subordinate to Wyrd projection generations        | Proposed          | Gives all presentation layers one cache-coherence model                         |
| 8  | Mobile writes use the common Wyrd write path                                 | Proposed          | Prevents platform-specific snapshot semantics                                   |
| 9  | Conflict resolution is not performed by mobile adapters                      | Proposed          | Preserves Wyrd's explicit conflict visibility principle                         |
| 10 | Read-only mobile surfaces precede mobile writes                              | Proposed          | Allows platform integration to stabilize before introducing mutation complexity |
| 11 | FUSE writes come first and lay the groundwork for the common write path    | Proposed          | The mounted write surface proves the handle, queue, and commit semantics that mobile adapters later consume; avoids maintaining multiple write implementations |
| 12 | The iOS "independent daemon over shared storage" design remains provisional  | **Open**          | Requires a real cross-process commit/ownership protocol                         |

---

# 26. Non-goals

This design does not attempt to:

* turn Wyrd into a conventional mutable filesystem;
* make mobile storage a second source of truth;
* implement platform-specific snapshot semantics;
* make synchronization a prerequisite for local reads;
* silently merge conflicting snapshots;
* expose Wyrd's internal object store directly to applications;
* make provider caches durable Wyrd state;
* solve peer repair or garbage collection;
* introduce hard links, sparse files, ACLs, or xattrs;
* guarantee writable-handle survival across mobile process termination without an explicit persistence mechanism;
* make multiple daemon instances concurrently author the same store without a defined transactional ownership protocol.

---

# 27. Architectural invariant

The final architecture should preserve this invariant:

```text
                    Wyrd snapshots
                          │
                          ▼
                   authoritative core
                          │
                 ┌────────┴────────┐
                 │                 │
             projection         mutation
                 │                 │
              DriveView       MutationQueue
                 │                 │
       ┌─────────┼─────────┐       │
       │         │         │       │
      FUSE    Android     iOS      │
       │         │         │       │
       └─────────┴─────────┴───────┘
                 │
                 ▼
          platform file APIs
```

The platform layer translates.

It does not reinterpret.

In particular:

> **Wyrd remains the filesystem substrate; FUSE, Android DocumentsProvider, and iOS File Provider are projections of that substrate, not independent filesystem implementations.**


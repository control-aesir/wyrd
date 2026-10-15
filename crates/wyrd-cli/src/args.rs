//! The `wyrd` command line: clap argument definitions. The doc
//! comments here are the `--help` text, so this module moves only
//! with a byte-identical help comparison (see the CLI-split issue,
//! `nostr:nevent1qqsyfxq3flw7nx0slwkvmvpuau47a9xmfsgstk5leulu297af7fvkqgpz9mhxue69uhkwunpwdczuap49eehgfncncm`).
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

/// The `wyrd` binary: create a drive, mount its live projection,
/// export its namespace to a plain directory tree, administer its
/// membership, pair a new device, or sync headless. All subcommands need the
/// credential files (read and hardened by wyrd code, never by clap);
/// `--relay` is deployment state shared by every networked
/// subcommand — nothing in the keystore names relays, so they arrive
/// as flags, defaulted from the drive's `default.toml` when the flags
/// name none (see `drive_config`).
/// Export is offline by construction: no relays, no serving, no FUSE.
#[derive(Debug, Parser)]
#[command(name = "wyrd", version, about)]
pub(crate) struct Cli {
    /// Drive deployment configuration elsewhere than the drive
    /// directory's `default.toml`: every subcommand reads the same
    /// file, so one override covers them all. A missing override is
    /// a named error, never an empty configuration; an absent
    /// default is simply no configuration.
    #[arg(long, global = true, value_name = "PATH")]
    pub(crate) config: Option<PathBuf>,
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Args)]
pub(crate) struct Credentials {
    /// Nostr identity secret: 32 raw bytes or 64 hex characters.
    /// Defaults to the configuration file's `identity_file` when
    /// the flag is absent; the flag always wins.
    #[arg(long, value_name = "PATH")]
    pub(crate) identity_file: Option<PathBuf>,

    /// Keystore passphrase, UTF-8 text. Defaults to the
    /// configuration file's `passphrase_file` when the flag is
    /// absent; the flag always wins.
    #[arg(long, value_name = "PATH")]
    pub(crate) passphrase_file: Option<PathBuf>,
}

/// Control-plane relays: repeatable deployment state shared by every
/// networked subcommand. Nothing in the keystore names relays, so
/// they arrive as flags with identical parsing and identical
/// empty-means-idle semantics everywhere — mount and sync must never
/// drift into subtly different relay handling. When the flags name
/// none, the drive's configuration file supplies the list (see
/// `drive_config`); explicit flags replace the configured list
/// rather than appending to it, so the effective set is knowable.
#[derive(Debug, Args)]
pub(crate) struct RelayArgs {
    /// Control-plane relay; repeatable. With none given and none
    /// configured, intake stays idle and the command runs offline
    /// (`sync now` additionally requires `--offline` to say so
    /// explicitly).
    #[arg(long, value_name = "URL")]
    pub(crate) relay: Vec<String>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Create a new drive: identity, root custody, genesis membership.
    Init {
        /// Directory holding the drive's keystore and object store.
        drive_dir: PathBuf,
        #[command(flatten)]
        credentials: Credentials,
    },
    /// Mount a live projection at `mountpoint` (read-write).
    Mount {
        /// Directory holding the drive's keystore and object store.
        drive_dir: PathBuf,
        /// Where to serve the projection.
        mountpoint: PathBuf,
        #[command(flatten)]
        relays: RelayArgs,
        /// Verbose mount diagnostics: debug-level FUSE request logs
        /// (opcode + latency + reply errno) in stderr and `mount.log`.
        /// Without it the mount logs at info level, and each request
        /// costs one enabled-check.
        #[arg(long)]
        verbose: bool,
        /// Live-loop idle pacing in whole seconds: bounds how long
        /// total silence may delay a sync pass (default 5). Producers
        /// wake the loop immediately, so this only paces quiet
        /// stretches — it is the e2e wall-time knob, not a semantic
        /// bound. Range 1-86400 (a day): zero would busy-spin the loop
        /// and past a day the deadline stops being pacing, so both are
        /// usage errors.
        #[arg(long, value_name = "SECS", default_value_t = 5)]
        interval: u64,
        #[command(flatten)]
        credentials: Credentials,
    },
    /// Export the drive's namespace to a plain directory tree: files,
    /// directories (empty ones included), symlinks, and the executable
    /// bit, with multi-head conflicts as `name@N` siblings. The output
    /// needs no wyrd software to read — this is the offline egress
    /// path guaranteed before any format break.
    Export {
        /// Directory holding the drive's keystore and object store.
        drive_dir: PathBuf,
        /// Destination directory: must not exist or must be empty.
        out_dir: PathBuf,
        #[command(flatten)]
        credentials: Credentials,
    },
    /// Administer drive membership: list members, inspect the log,
    /// invite a device, or author remove/rotate/set-owner transitions.
    /// Reads are offline projections of the keystore; writes commit
    /// one transition plus catch-up obligations, delivered on the
    /// next mounted sync.
    Member {
        /// Directory holding the drive's keystore and object store.
        drive_dir: PathBuf,
        #[command(subcommand)]
        action: MemberAction,
        #[command(flatten)]
        credentials: Credentials,
    },
    /// Inspect snapshots and merge conflicted heads: list the live
    /// heads, classify every DAG head, or author one merge snapshot
    /// over explicit sources plus a path spec. Reads are offline
    /// projections of the keystore; a merge authors one snapshot
    /// with ordinary member authority and queues the usual
    /// announcements for the next mounted sync.
    Snapshot {
        /// Directory holding the drive's keystore and object store.
        drive_dir: PathBuf,
        #[command(subcommand)]
        action: SnapshotAction,
        #[command(flatten)]
        credentials: Credentials,
    },
    /// Pair this device with a drive: identify it, stage pairing
    /// material for the owner, or join from a sealed invitation. The
    /// owner admits the staged key via `member invite`; the invitation
    /// file travels out-of-band.
    Device {
        /// Directory holding the drive's keystore and object store.
        drive_dir: PathBuf,
        #[command(subcommand)]
        action: DeviceAction,
        #[command(flatten)]
        credentials: Credentials,
    },
    /// Headless sync: report sync state or run a bounded sync without
    /// mounting. Status never connects and never mutates durable
    /// state; `now` connects when given a relay (and refuses a
    /// relay-less run without `--offline`), may mutate durable
    /// state, and reports liveness.
    Sync {
        /// Directory holding the drive's keystore and object store.
        drive_dir: PathBuf,
        #[command(flatten)]
        relays: RelayArgs,
        #[command(subcommand)]
        action: SyncAction,
        #[command(flatten)]
        credentials: Credentials,
    },
    /// Run a headless vault: the mount's live loop and serving
    /// surface with no presentation session. The persistent process
    /// (OD-22-B option A) — `sync now` stays the bounded one-shot,
    /// this never stops syncing until SIGINT/SIGTERM. Needs at least
    /// one `--relay`; states what the device is doing, never what it
    /// guarantees (OD-22-E: retention promises wait for DG-4). Bare
    /// `wyrd vault <drive>` starts the process (the 22b surface);
    /// `wyrd vault <drive> status` queries it (22c).
    Vault {
        /// Directory holding the drive's keystore and object store.
        drive_dir: PathBuf,
        #[command(flatten)]
        relays: RelayArgs,
        /// Optional log file, appended (never truncated): stderr
        /// always carries the ready line and failures for the
        /// supervisor to capture (OD-22-D option A+C). Start-only:
        /// status never writes diagnostics.
        #[arg(long, value_name = "PATH")]
        log_file: Option<PathBuf>,
        /// Start (default) or query the vault. Relay and log-file
        /// flags are start-only; status takes neither, because it
        /// never constructs a mailbox (matrix H9).
        #[command(subcommand)]
        action: Option<VaultAction>,
        #[command(flatten)]
        credentials: Credentials,
    },
    /// Promise retention for a subtree: every byte under `path` is
    /// pinned durably on this device. Policy only — never fetches,
    /// never authors, never touches heads. Offline by construction.
    Pin {
        /// Directory holding the drive's keystore and object store.
        drive_dir: PathBuf,
        /// Drive path to pin (drive-relative; empty means the root).
        path: String,
        #[command(flatten)]
        credentials: Credentials,
    },
    /// Release retention promises under `path`: pinned content
    /// returns to cacheable policy. Never deletes bytes, never
    /// touches heads. Promises are per content identity, so
    /// unpinning a subtree also releases shared chunks other paths
    /// relied on. Offline by construction.
    Unpin {
        /// Directory holding the drive's keystore and object store.
        drive_dir: PathBuf,
        /// Drive path to unpin (drive-relative; empty means the root).
        path: String,
        #[command(flatten)]
        credentials: Credentials,
    },
    /// Return unpinned content under `path` to REMOTE_ONLY policy.
    /// Refuses the whole subtree while any of it is pinned (unpin
    /// first). Changes intent only: no bytes are deleted, files that
    /// stay fully local keep reading, heads are untouched. Offline
    /// by construction.
    Evict {
        /// Directory holding the drive's keystore and object store.
        drive_dir: PathBuf,
        /// Drive path to evict (drive-relative; empty means the root).
        path: String,
        #[command(flatten)]
        credentials: Credentials,
    },
    /// Report residency: per-file retention policy against physical
    /// presence, or device totals plus the effective budgets. Reads
    /// durable state only; never connects, never mutates.
    Cache {
        /// Directory holding the drive's keystore and object store.
        drive_dir: PathBuf,
        #[command(subcommand)]
        action: CacheAction,
        #[command(flatten)]
        credentials: Credentials,
    },
    /// Device-local materialization role: what this device intends to
    /// be (`mirror`: prunable participant; `vault`: replicates every
    /// object, never prunes). A role is retention posture, never
    /// replicated state — setting one writes one local file, no fact,
    /// no snapshot. It is not the `vault` process: a device can hold
    /// the role without running one, and one can run without the
    /// role. Setting needs no credentials, so a role is settable on
    /// a machine whose keystore is unavailable; only status opens
    /// the node.
    Role {
        /// Directory holding the drive's keystore and object store.
        drive_dir: PathBuf,
        #[command(subcommand)]
        action: RoleAction,
    },
    /// Upgrade this installation from a local release archive:
    /// quiesce, flush, stop, swap the binary atomically, verify the
    /// new build against the actual store, and hand back to the
    /// supervisor (U1=B: the operator supplies the archive; U3=B:
    /// this command never supervises). Credential paths are
    /// forwarded to the verification child, never read here. Every
    /// terminal outcome records `<exe>.update-verdict` (done,
    /// rolled-back, or refused) beside the binary, so automation
    /// that cannot observe stdout still reads the result.
    Update {
        /// Directory holding the drive's keystore and object store.
        drive_dir: PathBuf,
        /// Local release archive under its canonical name
        /// (`wyrd-<version>-<os>-<arch>.tar.gz`): resolved and
        /// validated before anything is stopped.
        #[arg(long, value_name = "PATH")]
        archive: PathBuf,
        /// Control-plane relays, forwarded to the vault child under
        /// `--restart` only; refused otherwise.
        #[command(flatten)]
        relays: RelayArgs,
        /// After the update resolves, transfer into long-running
        /// supervision of the vault instead of handing back:
        /// this process runs the new vault as its child (or the
        /// restored vault after a rollback) and does not return.
        /// Exit status then reports the supervised run, not the
        /// update — the update's own outcome is the `update done:`
        /// / `update rollback:` / `update refused:` line plus the
        /// durable `<exe>.update-verdict` record. Needs at least
        /// one `--relay`.
        #[arg(long)]
        restart: bool,
        #[command(flatten)]
        credentials: Credentials,
    },
    /// Verify a drive with this binary and report compatibility:
    /// the update transaction's authoritative check, run by the
    /// staged new binary against the actual store. Internal and
    /// unstable (double underscore): operators use `wyrd update`,
    /// never this directly. Opens the store, replays every commit
    /// through this build's readers, authorizes the live heads,
    /// restores epoch keys, and proves byte-identical durable
    /// state afterwards — then prints the U4 report and exits 0
    /// if and only if it is verified.
    #[command(name = "__update_verify", hide = true)]
    UpdateVerify {
        /// Directory holding the drive's keystore and object store.
        drive_dir: PathBuf,
        #[command(flatten)]
        credentials: Credentials,
    },
    /// Report this binary's compiled format versions, lock-free: app
    /// version, envelope version, control version. Internal and
    /// unstable (double underscore): the update preflight runs it
    /// on the staged binary and compares against its own. Three
    /// `update <key>: <value>` lines on stdout, exit 0, no store
    /// touched.
    #[command(name = "__build_info", hide = true)]
    BuildInfo,
}

/// One membership administration action. Only an owner authors
/// transitions; the engine enforces that, never the CLI.
#[derive(Debug, Subcommand)]
pub(crate) enum MemberAction {
    /// List members and owners at the canonical tip.
    List,
    /// Show the membership log: every observed transition with its
    /// canonical status.
    Log,
    /// Show membership status: known tip, frozen conflicts, and held
    /// epoch secrets (knowledge is not possession).
    Status,
    /// Remove a device (owner-only). Removing the sole owner is valid
    /// but terminal and requires `--yes`.
    Remove {
        /// Device to remove, 64 hex characters.
        device: String,
        /// Confirm a last-owner removal.
        #[arg(long)]
        yes: bool,
    },
    /// Force a fresh epoch secret (owner-only). Membership unchanged.
    Rotate,
    /// Hand ownership to a member (owner-only). v0 ownership is a
    /// singleton.
    SetOwner {
        /// The new owner, 64 hex characters.
        device: String,
    },
    /// Resolve a frozen membership conflict (owner-only): name the
    /// winning tip and exactly the voided siblings. The engine
    /// proves the closed resolution (all ids live contenders at the
    /// frozen epoch, void set exactly the winner's rivals,
    /// pre-transition owner authority) before authoring; anything
    /// less fails closed with no transition. The carry obligations
    /// staged ahead of authoring still commit on a refusal — benign:
    /// the next drain discharges them without authoring while the
    /// heads stay eligible.
    Resolve {
        /// Winning tip, 64 hex characters.
        winner: String,
        /// Voided sibling, repeatable, 64 hex characters each.
        #[arg(long = "void")]
        voided: Vec<String>,
    },
    /// Admit a device (owner-only) and write its sealed invitation to
    /// a file for out-of-band delivery. The transition commits with
    /// the usual catch-up obligations; the newcomer joins from the
    /// invitation file. With `--reader` the device joins read-only:
    /// it holds every epoch secret but authors nothing.
    Invite {
        /// Device to admit, 64 hex characters.
        device: String,
        /// Its encryption key, 64 hex characters (from its
        /// pairing-request output).
        encryption_key: String,
        /// Where to write the sealed invitation.
        out: PathBuf,
        /// Admit as a reader instead of a member.
        #[arg(long)]
        reader: bool,
    },
    /// Reissue a device's sealed invitation from durable state, for
    /// an admission whose invitation never reached a file. Authors
    /// nothing; the reseal opens identically, with fresh randomness.
    ReissueInvitation {
        /// Device whose invitation to reissue, 64 hex characters.
        device: String,
        /// Where to write the sealed invitation.
        out: PathBuf,
    },
}

/// One snapshot inspection or merge action. Head references are
/// `@N` over the selected heads in ascending SnapshotId order —
/// head-wise, not the mount's per-path `name@N` numbering (which
/// skips heads that lack the path), and relative to the selection
/// when `--head` narrows it.
#[derive(Debug, Subcommand)]
pub(crate) enum SnapshotAction {
    /// List the live heads with their `@N` numbers.
    List,
    /// Classify every DAG head: eligible, superseded, stranded,
    /// voided, pending, or rejected. Eligible heads carry their
    /// `@N` merge numbers.
    Heads,
    /// Preview a merge without authoring: one row per root path
    /// with each selected head's version, so the operator sees
    /// which paths are agreed and which need a `--take` line.
    /// Sources default to all live heads, like `merge`. A short
    /// selection with no eligible heads on a membership-frozen
    /// drive is refused with a pointer to `member resolve`.
    Plan {
        /// Source head, 64 hex characters. Repeatable; omitted means
        /// all live heads.
        #[arg(long = "head")]
        heads: Vec<String>,
    },
    /// Merge source heads into one snapshot. Sources default to all
    /// live heads; `--head` narrows to an explicit subset (at least
    /// two). Conflicted root paths take `--take path=@N`, drop with
    /// `--drop path`, or fall back to `--default @N`; paths every
    /// source agrees on take themselves. The merged snapshot parents
    /// onto exactly the selected heads at the current epoch. A
    /// short selection with no eligible heads on a
    /// membership-frozen drive is refused with a pointer to `member
    /// resolve`; a pre-conflict fork still merges.
    Merge {
        /// Source head, 64 hex characters. Repeatable; omitted means
        /// all live heads.
        #[arg(long = "head")]
        heads: Vec<String>,
        /// Default source for conflicted paths without a `--take`
        /// line, `@N` over the selected heads.
        #[arg(long)]
        default: Option<String>,
        /// Take a conflicted root path from one source,
        /// `path=@N`. Repeatable, one line per path.
        #[arg(long = "take")]
        takes: Vec<String>,
        /// Drop a conflicted root path from the merge.
        /// Repeatable.
        #[arg(long = "drop")]
        drops: Vec<String>,
    },
    /// Recover stranded bytes into a recovery-flagged snapshot:
    /// republish selected content from a dead fork under the
    /// current epoch without adopting its lineage. Plan first,
    /// then run — like `merge`, the dry run shows every row
    /// before anything commits.
    Recover {
        #[command(subcommand)]
        action: RecoverAction,
    },
}

/// One owner-recovery step: preview the graft, or author it.
#[derive(Debug, Subcommand)]
pub(crate) enum RecoverAction {
    /// Preview a recovery without authoring: one row per source
    /// root path with its status, so the operator sees what is
    /// graftable, what is already live, and what is gone before
    /// selecting.
    Plan {
        /// Source snapshot, 64 hex characters: the stranded fork
        /// whose bytes are grafted.
        #[arg(long = "from")]
        from: String,
    },
    /// Graft selected source rows into a recovery snapshot
    /// parented onto the current eligible heads. Owner-only: a
    /// non-owner fails closed with the engine's refusal before
    /// anything commits.
    Run {
        /// Source snapshot, 64 hex characters.
        #[arg(long = "from")]
        from: String,
        /// Source root path to graft. Repeatable, one path per
        /// line; root-entry granularity like merge.
        #[arg(long = "take")]
        takes: Vec<String>,
        /// Graft the whole source tree instead of `--take` lines.
        #[arg(long = "all")]
        all: bool,
        /// Explicit content id to graft under its hex name, for
        /// content whose path the operator no longer knows.
        /// Repeatable.
        #[arg(long = "content")]
        contents: Vec<String>,
    },
}

/// One local-device pairing action. Pairing and join are offline file
/// exchanges; the drive directory holds the staged secret and (after
/// join) the member custody record.
#[derive(Debug, Subcommand)]
pub(crate) enum DeviceAction {
    /// Identify this device: its id plus the encryption key the
    /// membership state registers for it (`unregistered` until the
    /// device's admission arrives — a fresh join only holds genesis).
    /// Also the cheapest reopen probe: it opens the keystore.
    Id,
    /// Stage this device's pairing secret and write the public
    /// pairing material (device plus encryption key, no secrets) for
    /// the owner. Re-running returns the same key.
    PairingRequest {
        /// Where to write the pairing material.
        out: PathBuf,
    },
    /// Join a drive from the owner's sealed invitation. Writes member
    /// custody before accepting, so the device reopens afterwards.
    Join {
        /// The sealed invitation file.
        invitation: PathBuf,
    },
}

/// One vault action. `Start` is the 22b process; `Status` is the 22c
/// operator query: process posture from the sidecar (never the
/// store) beside durable state when the drive is stopped. The two
/// sections stay separate in the output — a fresh posture is not
/// convergence, and durable state is unavailable (not guessed) while
/// the vault holds the lock.
#[derive(Debug, Subcommand)]
pub(crate) enum VaultAction {
    /// Start the persistent vault process. The default when no
    /// subcommand is given, so the shipped `wyrd vault <drive>`
    /// keeps starting.
    Start,
    /// Report the running process's posture and, when the drive is
    /// stopped, its durable state. Never opens the store for the
    /// process section; never claims liveness.
    Status,
}

/// One headless sync action. Status observes durable state only;
/// `now` runs the same sync machinery the mount runs, headless.
#[derive(Debug, Subcommand)]
pub(crate) enum SyncAction {
    /// Show pending outbox obligations (queued, delivered, pending
    /// per snapshot, transition, and epoch), the membership tip
    /// against held epoch secrets, live heads with classification,
    /// and mailbox posture. Never connects, sends, or touches the
    /// seen log or outbox; needs the drive un-mounted.
    Status,
    /// Run bounded sync passes headless: drain, deliver, announce,
    /// fetch — no FUSE session, same live budgets as mount. Stops on
    /// the first quiet pass; the pass limit reports incomplete. A
    /// relay-less run exits 0 having contacted nothing, which reads
    /// as converged to automation — so without `--relay` the command
    /// refuses unless `--offline` explicitly opts into the local run.
    /// Reports per-class fetch diagnostics (client-position counts,
    /// never identities) beside the unfulfilled total.
    Now {
        /// Run without relays: intake stays idle, only local
        /// obligations discharge, nothing new is fetched. Cannot be
        /// combined with --relay.
        #[arg(long)]
        offline: bool,
        /// Bind a serving endpoint for the run (OD-23-V option A):
        /// the headless composition opens the mount's serving
        /// surface, flushes it before announcing, and gates
        /// announcement discharge on its readiness — so peers can
        /// fetch what this run announces. A bridge/compatibility
        /// composition, not a server: the bounded drain keeps its
        /// verdict and exit code, then the endpoint serves the
        /// converged snapshot until SIGINT/SIGTERM and shuts down in
        /// order. Cannot be combined with --offline (no relay means
        /// no route publication, so nothing could discover it).
        #[arg(long)]
        serve: bool,
    },
}

/// One cache reporting action. Both read durable state only: never
/// connect, never mutate, and need the drive un-mounted like every
/// other offline command.
#[derive(Debug, Subcommand)]
pub(crate) enum CacheAction {
    /// Show every reachable file under `path` with its retention
    /// policy (PINNED / REMOTE_ONLY — what this device intends to
    /// retain) against physical presence (PRESENT / ABSENT — what
    /// bytes happen to exist locally). The two columns are
    /// independent: REMOTE_ONLY + PRESENT is ordinary (eviction
    /// releases intent, never deletes bytes), and only all-chunks
    /// PINNED + PRESENT reads with a retention promise.
    Status {
        /// Drive path to report (drive-relative; empty means the
        /// whole drive).
        #[arg(default_value = "")]
        path: String,
    },
    /// Show device totals over reachable content (pinned files and
    /// chunks, quadrant counts) plus the effective retention and
    /// fetch budgets. Policy facts are per content identity, not per
    /// path, so pinned paths are not listed — only what they amount
    /// to.
    Policy,
}

/// One role action. `set` names the posture; `status` reports the
/// configured role, any in-flight narrowing, and the effective
/// retention posture — the same numbers `cache status` reports,
/// because there is one effective policy, not two.
#[derive(Debug, Subcommand)]
pub(crate) enum RoleAction {
    /// Set this device's materialization role, durably and offline.
    /// Widening toward `vault` takes effect immediately. Narrowing
    /// away from it requires `--yes` and records an acknowledged
    /// transition: effective posture stays `vault` until withdrawal
    /// completes, and completion is reported, never assumed.
    Set {
        /// The role to hold: `mirror` or `vault`.
        role: String,
        /// Acknowledge a narrowing (leaving `vault`). Intent only:
        /// withdrawal still has to complete before the posture flips.
        #[arg(long)]
        yes: bool,
    },
    /// Report the configured role, transition, and effective
    /// retention posture. Reads durable state only; never connects,
    /// never mutates.
    Status {
        #[command(flatten)]
        credentials: Credentials,
    },
}

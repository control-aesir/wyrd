use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::logging::{init_mount_diagnostics, init_vault_diagnostics};
use crate::probes::combine_status;
#[cfg(target_os = "macos")]
use crate::probes::macos_preflight;
use crate::probes::TeardownStatus;
use clap::{Args, Parser, Subcommand};
use fuser::{Config, MountOption};
use wyrd_core::export::export_tree;
use wyrd_core::mailbox::{LiveMailbox, MailboxHealth};
use wyrd_core::mutation::WriteStats;
use wyrd_core::policy::{
    evict_subtree, pin_subtree, residency_census, unpin_subtree, LocalPresence, ResidencyCensus,
    RetentionPolicy,
};
use wyrd_core::status::{observe, SyncStatus};
use wyrd_core::view::NamespaceView;
use wyrd_daemon::core::RuntimeMaterialization;
use wyrd_daemon::fuse::{DriveView, FuseBackend};
use wyrd_daemon::{
    run_vault, shutdown_transport, TransportDeadlines, VaultEvent, VaultLoopEnd, VaultRun,
};
use wyrd_daemon::{
    FailureClass, LiveConfig, LiveError, LiveNode, LoopError, ResourceBudgets, Supervisor,
    SyncReport, WyrdNode,
};
use wyrd_format::FsObjectStore;
use wyrd_format::{
    DeviceEncryptionKey, DeviceId, MembershipTransition, ObjectStore, SnapshotId, TransitionId,
    RECOVERY_FLAG,
};
use wyrd_sync::control::SealedBootstrap;
use wyrd_sync::keys::DeviceIdentitySecret;
use wyrd_sync::membership::TransitionStatus;
use wyrd_sync::runtime::{Engine, EngineError, MergeSelection, RoutePublishing};
use wyrd_sync::transport::mailbox::Mailbox;
use zeroize::Zeroizing;

/// The `wyrd` binary: create a drive, mount its live projection,
/// export its namespace to a plain directory tree, administer its
/// membership, pair a new device, or sync headless. All subcommands need the
/// credential files (read and hardened by wyrd code, never by clap);
/// `--relay` is deployment state shared by every networked
/// subcommand — nothing in the keystore names relays, so they arrive
/// as flags.
/// Export is offline by construction: no relays, no serving, no FUSE.
#[derive(Debug, Parser)]
#[command(name = "wyrd", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Args)]
struct Credentials {
    /// Nostr identity secret: 32 raw bytes or 64 hex characters.
    #[arg(long, value_name = "PATH")]
    identity_file: PathBuf,

    /// Keystore passphrase, UTF-8 text.
    #[arg(long, value_name = "PATH")]
    passphrase_file: PathBuf,
}

/// Control-plane relays: repeatable deployment state shared by every
/// networked subcommand. Nothing in the keystore names relays, so
/// they arrive as flags with identical parsing and identical
/// empty-means-idle semantics everywhere — mount and sync must never
/// drift into subtly different relay handling.
#[derive(Debug, Args)]
struct RelayArgs {
    /// Control-plane relay; repeatable. With none given, intake
    /// stays idle and the command runs offline (`sync now`
    /// additionally requires `--offline` to say so explicitly).
    #[arg(long, value_name = "URL")]
    relay: Vec<String>,
}

#[derive(Debug, Subcommand)]
enum Command {
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
    /// guarantees (OD-22-E: retention promises wait for DG-4).
    Vault {
        /// Directory holding the drive's keystore and object store.
        drive_dir: PathBuf,
        #[command(flatten)]
        relays: RelayArgs,
        /// Optional log file, appended (never truncated): stderr
        /// always carries the ready line and failures for the
        /// supervisor to capture (OD-22-D option A+C).
        #[arg(long, value_name = "PATH")]
        log_file: Option<PathBuf>,
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
}

/// One membership administration action. Only an owner authors
/// transitions; the engine enforces that, never the CLI.
#[derive(Debug, Subcommand)]
enum MemberAction {
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
enum SnapshotAction {
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
enum RecoverAction {
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
enum DeviceAction {
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

/// One headless sync action. Status observes durable state only;
/// `now` runs the same sync machinery the mount runs, headless.
#[derive(Debug, Subcommand)]
enum SyncAction {
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
enum CacheAction {
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

#[cfg(unix)]
#[allow(unsafe_code)]
fn current_uid() -> u32 {
    // SAFETY: geteuid has no pointer or aliasing preconditions and only
    // reads the calling process's kernel credential.
    unsafe { libc::geteuid() }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum CliError {
    #[error("{0}")]
    Usage(String),
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("credential file {path}: {reason}")]
    Credential { path: PathBuf, reason: &'static str },
    #[error("identity file must contain exactly 32 raw bytes or 64 hex characters")]
    IdentityFormat,
    #[error("invitation file does not decode as a sealed bootstrap")]
    InvitationFormat,
    #[error("invitation file exceeds the 1 MiB size limit")]
    InvitationTooLarge,
    #[error("identity secret is invalid: {0}")]
    Identity(#[from] wyrd_sync::keys::CryptoError),
    #[error("engine failed: {0}")]
    Engine(#[from] wyrd_sync::runtime::EngineError),
    #[error("daemon construction failed: {0}")]
    WyrdNode(#[from] wyrd_daemon::NodeError),
    #[error("object store failed: {0}")]
    Store(String),
    #[error("retention quota misconfigured: {0}")]
    Quota(#[from] wyrd_core::live::QuotaCheckError),
    #[error("mailbox failed: {0}")]
    Mailbox(#[from] wyrd_sync::transport::mailbox::MailboxError),
    #[error("live sync failed: {0}")]
    Live(#[from] LiveError),
    #[error("serving endpoint failed: {0}")]
    Serving(std::io::Error),
    #[error("bulk source failed: {0}")]
    Bulk(std::io::Error),
    #[error("export failed: {0}")]
    Export(#[from] wyrd_core::export::ExportError),
    #[error("policy failed: {0}")]
    Policy(#[from] wyrd_core::policy::PolicyError),
    /// A bounded headless run stopped at the pass limit with work
    /// still owed: rerun to continue converging. Reported, never
    /// silent, so automation cannot mistake a capped run for a
    /// converged device. Exits non-zero like any other failure.
    #[error("sync incomplete: pass limit ({passes}) reached with {pending} obligations pending")]
    Incomplete { passes: u32, pending: usize },
    /// A run that went quiet with received reconciliation statements
    /// still unanswered: a peer asked this device to prove its state
    /// and the run could not answer — an epoch it never learned, or
    /// a statement that landed after the last answer pass. The gap is
    /// control-plane, so the run fails even though the outbox is
    /// quiet: automation keying on exit status must see it. Exits
    /// non-zero like any other failure.
    #[error(
        "sync incomplete: {unanswered} reconciliation statements awaiting answer, {stalled} stalled"
    )]
    ReconciliationOutstanding { unanswered: usize, stalled: usize },
    /// A run that stopped on a quiet local state while the mailbox
    /// could not prove intake worked: no relay connected, a relay
    /// closed our subscription mid-run, or a blind stretch healed
    /// mid-run (a non-zero recovery-attempt total proves a
    /// supervisor episode ran — post-attachment only, so a slow cold
    /// start never counts). Quiet observed through a blind intake is
    /// unverified, never converged — automation must not mistake it
    /// for success. Exits non-zero like any other failure; the stdout
    /// lines still carry the pass and pending counts for forensics.
    /// The counts use wyrd-core's unit (loop iterations, not
    /// episodes): one slow episode converges over several attempts.
    #[error(
        "sync unverified: mailbox degraded ({connected} of {total} relays connected, {closed} subscriptions closed by relay, {attempts} recovery attempts during the run)"
    )]
    Unverified {
        connected: usize,
        total: usize,
        closed: u64,
        attempts: u64,
    },
    /// No mailbox snapshot was ever recorded on the report. Unreachable
    /// in production (`sync_now` always stores the observed snapshot),
    /// and it exists so that any future path that renders or maps a
    /// report without observing the mailbox fails closed instead of
    /// inheriting a fabricated posture.
    #[error("sync unverified: mailbox posture was never recorded")]
    Unobserved,
    #[error("macOS FUSE preflight failed: {0}")]
    #[cfg(any(test, target_os = "macos"))]
    Preflight(String),
    #[error("FUSE mount failed: {0}")]
    Mount(#[from] std::io::Error),
}

fn command(args: Vec<String>) -> Result<(), CliError> {
    // `args` carries user arguments only (main strips argv[0]); clap's
    // parse_from expects the binary name first. Help/version requests
    // arrive as errors too: print them as asked and exit successfully.
    let cli = match Cli::try_parse_from(std::iter::once("wyrd".to_owned()).chain(args)) {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) =>
        {
            let _ = error.print();
            return Ok(());
        }
        Err(error) => return Err(CliError::Usage(error.to_string())),
    };
    let (identity, passphrase) = match &cli.command {
        Command::Init { credentials, .. } => read_credentials(credentials)?,
        Command::Mount { credentials, .. } => read_credentials(credentials)?,
        Command::Export { credentials, .. } => read_credentials(credentials)?,
        Command::Member { credentials, .. } => read_credentials(credentials)?,
        Command::Snapshot { credentials, .. } => read_credentials(credentials)?,
        Command::Device { credentials, .. } => read_credentials(credentials)?,
        Command::Sync { credentials, .. } => read_credentials(credentials)?,
        Command::Vault { credentials, .. } => read_credentials(credentials)?,
        Command::Pin { credentials, .. } => read_credentials(credentials)?,
        Command::Unpin { credentials, .. } => read_credentials(credentials)?,
        Command::Evict { credentials, .. } => read_credentials(credentials)?,
        Command::Cache { credentials, .. } => read_credentials(credentials)?,
    };

    match cli.command {
        Command::Init { drive_dir, .. } => {
            Engine::create(drive_dir, &passphrase, identity)?;
            Ok(())
        }
        Command::Mount {
            drive_dir,
            mountpoint,
            relays,
            verbose,
            ..
        } => mount(
            drive_dir,
            mountpoint,
            relays.relay,
            verbose,
            &passphrase,
            identity,
        ),
        Command::Export {
            drive_dir, out_dir, ..
        } => export(drive_dir, out_dir, &passphrase, identity),
        Command::Member {
            drive_dir, action, ..
        } => member(drive_dir, action, &passphrase, identity),
        Command::Snapshot {
            drive_dir, action, ..
        } => snapshot(drive_dir, action, &passphrase, identity),
        Command::Device {
            drive_dir, action, ..
        } => device(drive_dir, action, &passphrase, identity),
        Command::Sync {
            drive_dir,
            relays,
            action,
            ..
        } => sync(drive_dir, relays.relay, action, &passphrase, identity),
        Command::Vault {
            drive_dir,
            relays,
            log_file,
            ..
        } => vault(drive_dir, relays.relay, log_file, &passphrase, identity),
        Command::Pin {
            drive_dir, path, ..
        } => pin(drive_dir, &path, &passphrase, identity),
        Command::Unpin {
            drive_dir, path, ..
        } => unpin(drive_dir, &path, &passphrase, identity),
        Command::Evict {
            drive_dir, path, ..
        } => evict(drive_dir, &path, &passphrase, identity),
        Command::Cache {
            drive_dir, action, ..
        } => cache(drive_dir, action, &passphrase, identity),
    }
}

/// Read and harden the credential files. The passphrase keeps its
/// trailing newline stripped; the identity may be raw or hex.
fn read_credentials(
    creds: &Credentials,
) -> Result<(DeviceIdentitySecret, Zeroizing<String>), CliError> {
    let identity = read_identity(&creds.identity_file)?;
    let passphrase_bytes = read_secret_file(&creds.passphrase_file)?;
    let passphrase_text = std::str::from_utf8(&passphrase_bytes)
        .map_err(|_| CliError::Usage("passphrase file must contain UTF-8 text".into()))?;
    let passphrase = Zeroizing::new(passphrase_text.to_owned());
    let passphrase = passphrase
        .strip_suffix("\r\n")
        .or_else(|| passphrase.strip_suffix('\n'))
        .unwrap_or(&passphrase);
    // Kept scrubbing: the passphrase lives in process memory until the
    // command completes, so it stays in a `Zeroizing` rather than a
    // plain `String`. Callers pass `&passphrase` as `&str` through
    // deref coercion.
    Ok((identity, Zeroizing::new(passphrase.to_owned())))
}

/// Read a bounded credential file without following symlinks. On Unix the
/// file must belong to the current user and not grant group/other access.
fn read_secret_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, CliError> {
    const MAX_BYTES: usize = 4096;
    #[cfg(not(unix))]
    return Err(CliError::Credential {
        path: path.to_path_buf(),
        reason: "credential-file protection is only implemented on Unix",
    });

    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(
        &mut options,
        libc::O_NOFOLLOW | libc::O_CLOEXEC,
    );
    let mut file = options.open(path).map_err(|source| CliError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let metadata = file.metadata().map_err(|source| CliError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(CliError::Credential {
            path: path.to_path_buf(),
            reason: "not a regular file",
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != current_uid() {
            return Err(CliError::Credential {
                path: path.to_path_buf(),
                reason: "must be owned by the current user",
            });
        }
        if metadata.mode() & 0o077 != 0 {
            return Err(CliError::Credential {
                path: path.to_path_buf(),
                reason: "must not be accessible by group or other users",
            });
        }
    }
    let mut bytes = Zeroizing::new(Vec::new());
    std::io::Read::by_ref(&mut file)
        .take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| CliError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() > MAX_BYTES {
        return Err(CliError::Credential {
            path: path.to_path_buf(),
            reason: "exceeds the 4096-byte size limit",
        });
    }
    Ok(bytes)
}

fn read_identity(path: &Path) -> Result<DeviceIdentitySecret, CliError> {
    let bytes = read_secret_file(path)?;
    let raw = if bytes.len() == 32 {
        let mut raw = Zeroizing::new([0; 32]);
        raw.copy_from_slice(&bytes);
        raw
    } else if let Ok(text) = std::str::from_utf8(&bytes) {
        let text = text.trim_matches(|character: char| character.is_ascii_whitespace());
        if text.len() != 64 {
            return Err(CliError::IdentityFormat);
        }
        let decoded = Zeroizing::new(hex::decode(text).map_err(|_| CliError::IdentityFormat)?);
        let mut raw = Zeroizing::new([0; 32]);
        raw.copy_from_slice(&decoded);
        raw
    } else {
        return Err(CliError::IdentityFormat);
    };
    DeviceIdentitySecret::from_bytes(*raw).map_err(CliError::Identity)
}

/// Process-wide shutdown latch for the mounted loop: signal handlers
/// may only set a flag (async-signal-safe), and the loop polls it.
pub(crate) static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// How long teardown waits for the mailbox tasks to stop before
/// aborting them: bounded so shutdown never hangs on a relay outage
/// that never clears.
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(5);

/// How long teardown waits for the serving endpoint's graceful
/// close: much longer than the task-cancel bound above, because the
/// close drains in-flight transfers over the same degraded links the
/// drive syncs over — a throttled loopback legitimately needs tens of
/// seconds, and mistaking a slow close for a wedged one turns clean
/// shutdowns into mount failures. Still bounded, so a peer that
/// never answers cannot hang teardown forever; a timeout still fails
/// the mount. (Bulk no longer uses this bound: it closes under the
/// graceful-or-abort policy in `wyrd_sync` (`GRACEFUL_CLOSE_DEADLINE`),
/// which succeeds on expiry instead of failing.) This is a
/// per-endpoint wedge bound, not a share of a total: back-to-back
/// wedge timeouts can exceed the e2e stop budgets, but any timeout
/// already fails the step — the 90s budget binds the clean-but-slow
/// path on the big-vault step: 10-14s for the owner stop under
/// throttle, 44s for the member dead-route TERM stop after the
/// throttle is removed.
const TRANSPORT_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(60);

/// Arm SIGINT/SIGTERM to trip [`SHUTDOWN`]. Best-effort: if the
/// platform cannot install the handler, termination falls back to the
/// default disposition (same as dying in `fuser::mount` today).
///
/// Portability scope: validated on Linux, where the libc-crate union
/// convention (`sa_sigaction as usize`) addresses the handler union.
/// Other Unix targets keep the gate but are untested — the handler
/// touches only a lock-free flag, so the worst case is the
/// pre-existing default-disposition behavior, never memory unsafety.
#[cfg(unix)]
#[allow(unsafe_code)]
fn install_shutdown_handler() -> Result<(), CliError> {
    // SAFETY: the handler stores to an AtomicBool (lock-free,
    // async-signal-safe) and touches nothing else. sigaction itself
    // runs at startup on the main thread.
    unsafe extern "C" fn on_signal(_signal: libc::c_int) {
        SHUTDOWN.store(true, Ordering::Relaxed);
    }
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = on_signal as usize;
        libc::sigemptyset(&mut action.sa_mask);
        action.sa_flags = 0;
        for signal in [libc::SIGINT, libc::SIGTERM] {
            if libc::sigaction(signal, &action, std::ptr::null_mut()) != 0 {
                Err(std::io::Error::last_os_error())?;
            }
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn install_shutdown_handler() -> Result<(), CliError> {
    // Credential files already restrict this binary to Unix; without a
    // handler the process dies on signal exactly as before.
    Ok(())
}
/// The startup retention cross-check, shared by every composer that
/// starts a live node in this binary (`mount`, `sync_now`): a quota
/// below what the mounted store already holds would refuse every
/// write, so refuse to start with both numbers instead of discovering
/// it per write. Unset quotas skip the walk entirely. One helper so
/// the next live-node composer inherits the check instead of the
/// omission. Composers that never start a live loop (`export`, policy
/// commands) correctly do not call it: with no loop there is no
/// `ENOSPC` stream to pre-empt.
fn check_startup_retention(config: &LiveConfig, store: &FsObjectStore) -> Result<(), CliError> {
    if let Some(quota) = config.budgets.retained_bytes_quota {
        wyrd_core::live::check_retained_ceiling(quota, store)?;
    }
    Ok(())
}

fn mount(
    drive_dir: PathBuf,
    mountpoint: PathBuf,
    relays: Vec<String>,
    verbose: bool,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> Result<(), CliError> {
    // Diagnostics first: the bridge plus stderr/file layers must exist
    // before preflight, the serving endpoint, or the session thread
    // emit anything — otherwise a failed handshake or a dying loop
    // leaves no record.
    let log_path = init_mount_diagnostics(&drive_dir, verbose)?;
    let mount_span = tracing::info_span!(
        "mount",
        drive = %drive_dir.display(),
        mountpoint = %mountpoint.display(),
        verbose = verbose,
    );
    let _mount_guard = mount_span.enter();
    tracing::info!(stage = "start", log = %log_path.display(), "mount diagnostics initialized");

    let engine = Engine::open_keystore(drive_dir.clone(), passphrase, identity.clone())?;
    // Operational policy in one place: the loop and the serving
    // backend share this config's budgets, wired into both halves
    // by `into_live` below. Constructed through `for_local_sync`
    // (never `Default` directly) so headless sync shares these exact
    // budgets and ceilings — several are correctness boundaries, and
    // a mount-only default must never silently diverge them. One
    // value from here to `into_live`, so the startup check below and
    // the loop compare against the same numbers.
    let config = LiveConfig::for_local_sync();
    let store = FsObjectStore::open(drive_dir.clone())
        .map_err(|error| CliError::Store(error.to_string()))?;
    // Fail fast on macOS before binding any endpoint: a missing
    // macFUSE runtime can never mount, and every later stage would
    // report the same opaque failure.
    #[cfg(target_os = "macos")]
    if let Err(error) = macos_preflight(&mountpoint) {
        tracing::error!(stage = "preflight", error = %error, "macOS FUSE preflight failed");
        return Err(error);
    }
    #[cfg(target_os = "macos")]
    tracing::info!(stage = "preflight", "macOS FUSE preflight passed");
    // The startup cross-check runs after platform preflight and before
    // composition: a quota below what the mounted store already holds
    // would refuse every write, so starting is refused with both
    // numbers instead. Unset quotas skip the walk — and the binary
    // ships none, so this fires only for future configuration surfaces.
    check_startup_retention(&config, &store)?;
    let mut daemon = WyrdNode::new(engine, store)?;
    daemon.refresh_live_heads()?;

    // Serving: a real-iroh endpoint over the drive's durable vault, so
    // peers holding an announcement route can fetch what this drive
    // holds. The fetch side is the matching real bulk source; routes
    // publish from recorded announcements on every sync pass.
    let serving = daemon
        .open_serving(&drive_dir, false)
        .map_err(CliError::Serving)?;
    let bulk = bind_bulk_source()?;
    tracing::info!(stage = "bulk", "bulk source bound");
    let serving_id = hex::encode(serving.addr().id.as_bytes());
    eprintln!("serving over iroh: {serving_id}");
    tracing::info!(stage = "serving", iroh_id = %serving_id, "serving endpoint bound");

    // The loop and the serving backend share the config's budgets
    // through `into_live` below.
    let (mut live, parts) = daemon.into_live(Duration::from_secs(30), &config)?;
    // Flush the serving endpoint before announcing its address, so the
    // first seal carries a route peers can already dial. The loop owns
    // sends from here: every pass publishes undischarged announcement,
    // transition, and capability obligations to the relay.
    serving.flush().map_err(CliError::Serving)?;
    live.set_node_addr(Some(serving.node_addr_bytes()));
    // Gate every publish pass's announcement discharge on mirror
    // readiness: a peer acting on an announcement must find every
    // announced representation importable, not just the first seal's.
    // Endpoint ownership (and shutdown below) stays here; the loop
    // holds only the cloneable readiness handle.
    live.set_serving_barrier(std::sync::Arc::new(serving.handle()));
    // The composer builds its presentation backend from the node's
    // live parts; the node itself never names the backend type.
    // The quarantine channel rides along: readers submit observed
    // verification failures for the loop's drain to repair.
    let mut backend = FuseBackend::shared_with_wants(
        parts.projection,
        parts.wants,
        parts.mutations,
        parts.open_timeout,
        &parts.budgets,
    );
    backend.set_quarantine(std::sync::Arc::clone(live.quarantine_queue()));
    backend.set_scrub(std::sync::Arc::clone(live.scrub_queue()));

    // The mailbox signs with the local identity key: open and signer
    // are the same key by construction, which is exactly the identity
    // binding `LiveMailbox` enforces. Two mailbox holders by necessity
    // (signer `Keys` plus `open_keys`): the generic signer boundary
    // forbids sharing one holder, so the open-secret clone out of the
    // signer `Keys` is structural, not gratuitous. The full process
    // graph — this identity, its engine clone above, the one bare key
    // moved into `open_keys`, and both `Keys` — is inventoried under
    // "Signer secret boundary" in `wyrd-core`'s mailbox docs.
    // Delegating signing to a NIP-46 session is a separate tracked
    // issue.
    let signer_keys = identity.signer_keys();
    let open_secret = signer_keys.secret_key().clone();
    let seen_path = drive_dir.join("mailbox.seen");
    let mailbox = LiveMailbox::connect(signer_keys, open_secret, relays.clone(), seen_path)?;
    // New mail wakes intake immediately: the drainer pokes the same
    // pacing signal the loop parks on, so delivery latency is bound by
    // the relay round trip, not the five-second idle interval.
    mailbox.attach_waker(Arc::clone(live.waker()));
    if relays.is_empty() {
        eprintln!("warning: no --relay given; control-plane intake stays idle");
        tracing::warn!(
            stage = "mailbox",
            "control-plane intake stays idle: no --relay given"
        );
    }

    // Arm shutdown before mounting: every post-mount failure path
    // below returns through the unmount-and-join sequence, never
    // leaking a detached session.
    install_shutdown_handler()?;
    // On macOS the reported errno may be stale: macFUSE's libfuse2
    // mount can fail without setting errno at all, so name the
    // checklist alongside the raw error instead of trusting it.
    #[cfg(target_os = "macos")]
    let mut session = match fuser::Session::new(backend, &mountpoint, &session_config()) {
        Ok(session) => session,
        Err(error) => {
            eprintln!("{MACOS_MOUNT_HINT}");
            return Err(CliError::Mount(error));
        }
    };
    #[cfg(not(target_os = "macos"))]
    let mut session = fuser::Session::new(backend, &mountpoint, &session_config())?;
    let mut unmounter = session.unmount_callable();
    // One lifecycle supervisor owns the stop flag, the mutation queue,
    // and the loop's pacing signal: session end trips shutdown below,
    // loop return trips it on the loop thread. Either direction alone
    // strands somebody — a dead session with a syncing loop, or a dead
    // loop with blocked submitters — so both are wired. The signal is
    // created and attached by `into_live`; sharing it here means a
    // trip also pokes the loop out of its idle wait.
    let supervisor = Supervisor::new(
        Arc::clone(live.mutations()),
        &SHUTDOWN,
        Arc::clone(live.waker()),
    );
    let session_supervisor = supervisor.clone();
    // Exit triggers: the session thread reports its exit and the loop
    // thread reports its return; the composer tears down on the first
    // of those or a shutdown trip. A dedicated channel (not the
    // loop's pacing signal) carries the triggers, so steady-state
    // pokes are never stolen from the loop's wait.
    let (trigger_tx, trigger_rx) = std::sync::mpsc::channel::<()>();
    let session_trigger = trigger_tx.clone();
    // The session loop owns the backend: log its exit immediately on
    // the thread, then trip shutdown so the live loop exits promptly
    // instead of syncing and serving behind a dead presentation
    // surface. The unmount-and-join sequence below still reaps the
    // thread and reports the combined outcome.
    let server = std::thread::spawn(move || {
        let outcome = session.run();
        match &outcome {
            Ok(()) => tracing::info!(stage = "session", "FUSE session loop exited cleanly"),
            Err(error) => {
                tracing::error!(stage = "session", error = %error, "FUSE session loop exited with error");
            }
        }
        session_supervisor.note_session_ended();
        // The composer may already be tearing down (loop-first exit):
        // the trigger is advisory, the join below is authoritative.
        let _ = session_trigger.send(());
        outcome
    });
    // The live loop runs supervised on its own thread so the
    // composer can unmount and reap the session while the queue is
    // still open: destroy's dirty-handle commits submit against a
    // live queue, and the post-return drain executes them
    // concurrently. The supervisor owns the thread body (run, report,
    // drain, panic-recover); the composer keeps the join handle and
    // everything it comes back with.
    let loop_trigger = trigger_tx;
    let drive = supervisor.spawn_loop(
        live,
        mailbox,
        Some(bulk),
        config,
        loop_trigger,
        move |error: &LiveError, consecutive: u32| {
            // `consecutive` counts failures of this error's class, not
            // of every class combined: each class backs off and trips
            // its cap independently.
            let class = FailureClass::from(error);
            eprintln!(
                "live sync pass failed ({class:?} class, {consecutive} consecutive): {error}"
            );
            tracing::warn!(
                stage = "sync",
                class = ?class,
                consecutive,
                error = %error,
                "live sync pass failed"
            );
        },
    );
    // Teardown trigger: the first session exit, loop return, or
    // shutdown trip starts the ordered teardown below. The wait polls
    // the process latch in slices because a signal-handler trip cannot
    // notify the channel — the same slow-path guarantee as the loop's
    // own stop polling, and fast enough for a path that already
    // budgets seconds for transport closes.
    loop {
        if SHUTDOWN.load(Ordering::Relaxed) {
            tracing::info!(stage = "teardown", "shutdown latch tripped");
            break;
        }
        match trigger_rx.recv_timeout(Duration::from_millis(250)) {
            Ok(()) => {
                tracing::info!(stage = "teardown", "teardown trigger received");
                break;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                tracing::info!(stage = "teardown", "trigger senders gone");
                break;
            }
        }
    }
    // Presentation down first: unmount so the kernel releases the
    // mountpoint, then reap the session thread (`destroy` commits
    // dirty handles here, against the still-open queue the loop
    // thread's drain executes concurrently) before cutting transport.
    // A dead loop must not keep serving reads while its shutdown
    // drains, and the session teardown lands at the earliest point
    // the queue state allows — destroy can only preserve handles
    // while the queue is live and drained.
    // Stage latencies below are measured from here, so a slow
    // shutdown names its stage instead of just its total.
    let teardown_start = std::time::Instant::now();
    if let Err(error) = unmounter.unmount() {
        eprintln!("warning: unmount failed: {error}");
        tracing::warn!(stage = "session", error = %error, "unmount failed");
    } else {
        tracing::info!(stage = "session", "unmounted");
    }
    // The exit itself is already logged on the session thread above;
    // the join outcome is shutdown sequencing (debug), except a panic,
    // which has no thread-side record and fails the mount as an error.
    let session_result = match server.join() {
        Ok(result) => {
            match &result {
                Ok(()) => tracing::debug!(stage = "session", "session thread joined cleanly"),
                Err(error) => {
                    tracing::debug!(stage = "session", error = %error, "session thread joined with error");
                }
            }
            result.map_err(CliError::Mount)
        }
        Err(_) => {
            tracing::error!(stage = "session", "FUSE session thread panicked");
            Err(CliError::Mount(std::io::Error::other(
                "FUSE session thread panicked",
            )))
        }
    };
    // The session is joined: destroy ran, so no teardown action can
    // submit anymore — close admission before reaping the loop, whose
    // drain exits on the close after one final sweep. Closing before
    // the join would strand destroy's submits; closing after the loop
    // join would leave the drain parked. Every teardown outcome is
    // collected, not short-circuited: a failed loop or serving
    // close must not skip the remaining shutdowns, and the combined
    // status reports the first failure.
    supervisor.close_admission();
    tracing::info!(
        stage = "teardown",
        elapsed_ms = teardown_start.elapsed().as_millis(),
        "admission closed"
    );
    let returned = match drive.join() {
        Ok(returned) => returned,
        Err(_) => {
            // The supervision catches loop/drain panics itself, so a
            // join failure means the supervision died — fail loudly.
            tracing::error!(stage = "sync", "supervised loop thread failed");
            return Err(CliError::Mount(std::io::Error::other(
                "supervised loop thread failed",
            )));
        }
    };
    let mut mailbox = returned.mailbox;
    // Unreachable by construction: the composer passes `Some`, and
    // the thread hands it back untouched on every path (including the
    // panic recovery). Expect, so a future refactor that breaks the
    // pairing fails loudly here instead of skipping transport
    // teardown.
    let bulk = returned.bulk.expect("loop thread returns the bulk source");
    // Dropped at scope end, after transport teardown — the same
    // effective lifetime the node always had.
    let _live = returned.live;
    tracing::info!(
        stage = "teardown",
        elapsed_ms = teardown_start.elapsed().as_millis(),
        "loop thread joined"
    );
    let loop_result = match returned.result {
        Ok(summary) => Ok(summary),
        Err(LoopError::Live(error)) => Err(CliError::Live(error)),
        Err(LoopError::Panicked) => {
            // The panic recovery already closed admission, so destroy
            // resolved; the recovered handles shut down below like
            // every other outcome.
            tracing::error!(
                stage = "sync",
                "live loop thread panicked; teardown continued with bounded loss"
            );
            Err(CliError::Mount(std::io::Error::other(
                "live loop thread panicked",
            )))
        }
    };
    // One transport tail for every loop composer (see the vault
    // module): stop the mailbox tasks, close bulk graceful-or-abort,
    // release bulk, close serving — every stage runs, and the serving
    // outcome folds into the exit below. Stage latencies log from the
    // shared tail's own start, seconds behind the teardown base above.
    let transport = shutdown_transport(
        &mut mailbox,
        Some(bulk),
        serving,
        &TransportDeadlines {
            mailbox: SHUTDOWN_DEADLINE,
            bulk: wyrd_sync::GRACEFUL_CLOSE_DEADLINE,
            serving: TRANSPORT_SHUTDOWN_DEADLINE,
        },
    );
    let serving_status = transport.serving.map_err(CliError::Serving);
    combine_status(TeardownStatus {
        loop_result: loop_result.map(|_| ()),
        session_result,
        serving_result: serving_status,
    })
}

/// Export the drive's namespace to a plain tree. The open path
/// mirrors mount's preamble (keystore, object store, live heads)
/// minus everything export refuses to need: no diagnostics file, no
/// serving endpoint, no bulk source, no mailbox, no FUSE session.
/// The composed view type arrives through the daemon's surface, so
/// this host never names the view crate directly.
fn export(
    drive_dir: PathBuf,
    out_dir: PathBuf,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> Result<(), CliError> {
    let engine = Engine::open_keystore(drive_dir.clone(), passphrase, identity)?;
    let mut daemon: WyrdNode<DriveView<FsObjectStore, RuntimeMaterialization>> = WyrdNode::new(
        engine,
        FsObjectStore::open(drive_dir.clone())
            .map_err(|error| CliError::Store(error.to_string()))?,
    )?;
    daemon.refresh_live_heads()?;
    let report = export_tree(daemon.view(), &out_dir)?;
    eprintln!(
        "exported {} files, {} dirs, {} symlinks ({} conflicts, {} bytes) to {}",
        report.files,
        report.dirs,
        report.symlinks,
        report.conflicts,
        report.bytes,
        out_dir.display()
    );
    Ok(())
}

/// Offline policy node: the engine plus its read view over the
/// drive's own store, heads installed once up front. Every
/// pin/unpin/evict/cache command composes this shape — no loop, no
/// mailbox, no bulk source — so policy changes never depend on
/// network availability. Heads install once and the walk never
/// re-refreshes: one invocation observes one generation, and a
/// concurrent local write cannot mix generations into it.
type PolicyNode = WyrdNode<DriveView<FsObjectStore, RuntimeMaterialization>>;

fn open_policy_node(
    drive_dir: PathBuf,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> Result<PolicyNode, CliError> {
    let engine = Engine::open_keystore(drive_dir.clone(), passphrase, identity)?;
    let mut node: PolicyNode = WyrdNode::new(
        engine,
        FsObjectStore::open(drive_dir.clone())
            .map_err(|error| CliError::Store(error.to_string()))?,
    )?;
    node.refresh_live_heads()?;
    Ok(node)
}

/// Promise retention for a subtree, durably and offline.
fn pin(
    drive_dir: PathBuf,
    path: &str,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> Result<(), CliError> {
    let mut node = open_policy_node(drive_dir, passphrase, identity)?;
    let report = {
        let (engine, view) = node.parts_mut();
        pin_subtree(engine, view, path)?
    };
    print!("{}", pin_render(path, &report));
    Ok(())
}

/// Structured first, rendered below: what one pin promised.
fn pin_render(path: &str, report: &wyrd_core::policy::PinReport) -> String {
    let mut out = format!(
        "pinned {} objects ({} already pinned) across {} files, {} dirs under {}\n",
        report.pinned,
        report.already_pinned,
        report.files,
        report.dirs,
        display_policy_path(path),
    );
    if report.symlinks_skipped > 0 {
        out.push_str(&format!(
            "note: {} symlinks skipped (a link names no content of its own)\n",
            report.symlinks_skipped
        ));
    }
    out
}

/// Release retention promises under a path, durably and offline.
fn unpin(
    drive_dir: PathBuf,
    path: &str,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> Result<(), CliError> {
    let mut node = open_policy_node(drive_dir, passphrase, identity)?;
    let report = {
        let (engine, view) = node.parts_mut();
        unpin_subtree(engine, view, path)?
    };
    print!("{}", unpin_render(path, &report));
    Ok(())
}

fn unpin_render(path: &str, report: &wyrd_core::policy::UnpinReport) -> String {
    let mut out = format!(
        "unpinned {} objects ({} already unpinned) across {} files, {} dirs under {}\n",
        report.released,
        report.already_unpinned,
        report.files,
        report.dirs,
        display_policy_path(path),
    );
    out.push_str("note: released content returns to cacheable policy; bytes stay local\n");
    if report.symlinks_skipped > 0 {
        out.push_str(&format!(
            "note: {} symlinks skipped (a link names no content of its own)\n",
            report.symlinks_skipped
        ));
    }
    out
}

/// Return unpinned content under a path to REMOTE_ONLY policy.
/// Intent only: bytes stay, heads stay.
fn evict(
    drive_dir: PathBuf,
    path: &str,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> Result<(), CliError> {
    let mut node = open_policy_node(drive_dir, passphrase, identity)?;
    let report = {
        let (engine, view) = node.parts_mut();
        evict_subtree(engine, view, path)?
    };
    print!("{}", evict_render(path, &report));
    Ok(())
}

fn evict_render(path: &str, report: &wyrd_core::policy::EvictReport) -> String {
    let mut out = format!(
        "evicted {} objects ({} already remote-only) across {} files, {} dirs under {}\n",
        report.released,
        report.already_remote,
        report.files,
        report.dirs,
        display_policy_path(path),
    );
    out.push_str("note: eviction releases intent only — no bytes deleted, files that stay fully local keep reading\n");
    if report.symlinks_skipped > 0 {
        out.push_str(&format!(
            "note: {} symlinks skipped (a link names no content of its own)\n",
            report.symlinks_skipped
        ));
    }
    out
}

/// Report residency: per-file policy vs presence, or device totals
/// plus the effective budgets.
fn cache(
    drive_dir: PathBuf,
    action: CacheAction,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> Result<(), CliError> {
    let node = open_policy_node(drive_dir, passphrase, identity)?;
    match action {
        CacheAction::Status { path } => {
            let (engine, view) = node.parts();
            let census = residency_census(engine, view, &path)?;
            print!("{}", cache_status_render(&path, &census));
            Ok(())
        }
        CacheAction::Policy => {
            let (engine, view) = node.parts();
            let census = residency_census(engine, view, "")?;
            // Three walks at report time, never cached: the enforced
            // object-store count plus the two observational dimensions.
            let retained_content = view
                .store_read()
                .map_err(|error| CliError::Store(error.to_string()))?
                .retained_bytes()
                .map_err(|error| CliError::Store(error.to_string()))?;
            // One budgets read for the whole report: the quota line and
            // the budget lines below must come from the same value, or
            // the report can disagree with itself.
            let budgets = LiveConfig::for_local_sync().budgets;
            let accounting = RetentionAccounting {
                retained_content,
                fact_log: engine.fact_log_bytes()?,
                sync_vault: engine
                    .vault()
                    .resident_bytes()
                    .map_err(|error| CliError::Store(error.to_string()))?,
                quota: budgets.retained_bytes_quota,
            };
            print!("{}", cache_policy_render(&census, &accounting, &budgets));
            Ok(())
        }
    }
}

/// Empty path addresses the drive root; render it as `/` so the
/// report reads like a path instead of an empty string.
fn display_policy_path(path: &str) -> &str {
    if path.is_empty() {
        "/"
    } else {
        path
    }
}

fn policy_word(policy: RetentionPolicy) -> &'static str {
    match policy {
        RetentionPolicy::Pinned => "PINNED",
        RetentionPolicy::RemoteOnly => "REMOTE_ONLY",
    }
}

fn presence_word(local: LocalPresence) -> &'static str {
    match local {
        LocalPresence::Present => "PRESENT",
        LocalPresence::Absent => "ABSENT",
    }
}

/// Structured data first; the CLI renders text, future consumers
/// render their own. One row per reachable file plus quadrant
/// totals — the rows name what is held, the totals name what it
/// amounts to.
fn cache_status_render(path: &str, census: &ResidencyCensus) -> String {
    let mut out = format!(
        "cache status under {}\nPOLICY       LOCAL    PATH\n",
        display_policy_path(path)
    );
    for file in &census.files {
        out.push_str(&format!(
            "{:<12} {:<8} {}\n",
            policy_word(file.policy),
            presence_word(file.local),
            file.path
        ));
    }
    for conflict in &census.conflicts {
        out.push_str(&format!("{:<12} {:<8} {}\n", "CONFLICT", "-", conflict));
    }
    out.push_str(&cache_quadrant_summary(census));
    if census.symlinks_skipped > 0 {
        out.push_str(&format!(
            "note: {} symlinks skipped (a link names no content of its own)\n",
            census.symlinks_skipped
        ));
    }
    out
}

fn cache_quadrant_summary(census: &ResidencyCensus) -> String {
    format!(
        "files: {} (PINNED/PRESENT: {}, PINNED/ABSENT: {}, REMOTE_ONLY/PRESENT: {}, REMOTE_ONLY/ABSENT: {}), dirs: {}\n",
        census.files.len(),
        census.quadrant(RetentionPolicy::Pinned, LocalPresence::Present),
        census.quadrant(RetentionPolicy::Pinned, LocalPresence::Absent),
        census.quadrant(RetentionPolicy::RemoteOnly, LocalPresence::Present),
        census.quadrant(RetentionPolicy::RemoteOnly, LocalPresence::Absent),
        census.dirs,
    )
}

/// Device totals over reachable content plus the budgets that
/// bound retention and fetch. The budgets are the live loop's own
/// (`for_local_sync`, the same config mount runs): what the report
/// calls effective is what the daemon enforces, not a parallel
/// copy. Only the retention- and fetch-relevant bounds print here;
/// the full table lives in `docs/resource-limits.md`.
fn cache_policy_render(
    census: &ResidencyCensus,
    accounting: &RetentionAccounting,
    budgets: &ResourceBudgets,
) -> String {
    let pinned_files = census.quadrant(RetentionPolicy::Pinned, LocalPresence::Present)
        + census.quadrant(RetentionPolicy::Pinned, LocalPresence::Absent);
    // Per identity, deduplicated across files that share chunks: a
    // chunk pinned through two paths is one promise, not two.
    let pinned_chunks = census.pinned_chunk_union().len();
    let mut out = format!(
        "cache policy (reachable content)\npinned files: {pinned_files}\npinned chunks: {pinned_chunks}\n",
    );
    out.push_str(&cache_quadrant_summary(census));
    // Totals silently skip conflicted subtrees, so name the gap:
    // without this the numbers read as complete on a drive where
    // whole paths were never walked. One row per path, like the
    // status report, instead of one unbounded joined line.
    if !census.conflicts.is_empty() {
        out.push_str(&format!(
            "conflicts: {} skipped (never walked):\n",
            census.conflicts.len()
        ));
        for conflict in &census.conflicts {
            out.push_str(&format!("  {conflict}\n"));
        }
    }
    out.push_str("budgets (effective):\n");
    match accounting.quota {
        Some(quota) => out.push_str(&format!("  retained_bytes_quota: {quota}\n")),
        None => out.push_str("  retained_bytes_quota: unlimited\n"),
    }
    out.push_str(&format!(
        "  max_admit_per_pass: {}\n  max_pending_wants: {}\n  max_quarantine_per_pass: {}\n",
        budgets.max_admit_per_pass, budgets.max_pending_wants, budgets.max_quarantine_per_pass,
    ));
    // The retention breakdown: one row per resident dimension, each
    // labelled with whether it backs enforcement or merely observes.
    // `retained content` is the enforcement quantity — the number the
    // ceiling is compared against. The fact log and the sync vault
    // are resident but unenforced (auxiliary growth): folding them
    // into the enforced number would silently widen what a refusal
    // rejects, so they report separately and the total is labelled
    // observational. See the retained / resident / auxiliary terms in
    // `docs/storage-growth.md`.
    let total = accounting
        .retained_content
        .saturating_add(accounting.fact_log)
        .saturating_add(accounting.sync_vault);
    out.push_str("retention accounting (bytes):\n");
    out.push_str(&format!(
        "  retained content: {} (quota-enforced)\n",
        accounting.retained_content
    ));
    out.push_str(&format!(
        "  fact log: {} (observational)\n",
        accounting.fact_log
    ));
    out.push_str(&format!(
        "  sync vault: {} (observational)\n",
        accounting.sync_vault
    ));
    out.push_str(&format!("  total accounted: {total} (observational)\n"));
    // No implicit ceiling: with no configured quota the report advises
    // one instead of applying one. The recommendation is explicitly
    // advisory and non-authoritative — a starting point for the
    // operator's decision, never a default by another name. A quota is
    // an operator-selected refusal boundary, not an implicit product
    // policy: anything at or below current retention refuses every
    // write, so the advice starts there.
    if accounting.quota.is_none() {
        out.push_str(&format!(
            "  advisory ceiling (non-authoritative): no lower than {} \
             (current retention); no default is applied\n",
            accounting.retained_content
        ));
    }
    out
}

/// Measured byte dimensions behind `cache policy`'s retention
/// breakdown: the enforcement quantity plus the two resident-but-
/// unenforced dimensions. Measured at report time from the mounted
/// store, the fact log, and the vault — three walks, never cached,
/// so the report cannot disagree with the disk.
struct RetentionAccounting {
    /// Object-store bytes: the quota-enforced quantity.
    retained_content: u64,
    /// Fact-log commit bytes: resident, observational.
    fact_log: u64,
    /// Sealed vault representations: resident, observational.
    sync_vault: u64,
    /// The effective quota, if one is configured.
    quota: Option<u64>,
}

/// Safety cap on one headless run: a peer that keeps intake
/// non-idle forever (a mount absorbs that by running forever) must
/// not turn a one-shot command into an unbounded loop. Reaching the
/// cap reports incomplete, never converged. The cap bounds
/// iterations; each pass is separately bounded by the fetch budget
/// and each non-progressing pass additionally parks the settle
/// window, so the whole-run bound is
/// `MAX_SYNC_NOW_PASSES × (settle + fetch_pass_budget)` of wall
/// clock plus actual work — bounded waiting, never a tight loop.
const MAX_SYNC_NOW_PASSES: u32 = 32;

/// Settle window for intake races: relay delivery is asynchronous
/// after the subscription REQ, and `recv` is non-blocking, so a pass
/// that drains immediately after connect normally sees nothing. A
/// quiet verdict is only trusted after mail has had one relay round
/// trip (+ margin) to arrive; arrival pokes the waker and
/// short-circuits the wait, so only the no-mail case burns the full
/// window. Distinct from the mount's five-second staleness bound —
/// this covers the subscribe gap, not steady-state cadence. Skipped
/// entirely with no relays configured (intake is idle by
/// construction, so there is nothing to settle).
const SYNC_NOW_SETTLE: Duration = Duration::from_secs(2);

/// How one headless run stopped: converged, converged with heads
/// whose closure is not local, or capped with work still owed. The
/// three states are distinct in the type — not just in rendered
/// text — so automation can tell converged from stuck-but-remote:
/// `Quiet` means nothing is owed anywhere, `RemoteStalled` means
/// the outbox is empty but known heads are not locally closable (a
/// rerun without external change — a route, bytes, or a capability
/// — cannot advance them), and `PassLimit` means the cap tripped
/// with local work still owed (a rerun may advance it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunOutcome {
    /// A pass left no actionable work.
    Quiet,
    /// The outbox is empty but known heads are not locally
    /// closable. Exits 0 with a healthy mailbox: locally there is
    /// nothing more to do, so a non-zero exit would only invite
    /// pointless retries. A degraded mailbox fails as unverified
    /// instead — the empty outbox was observed through a blind
    /// intake, so "nothing left to do" is unproven.
    RemoteStalled,
    /// The pass cap tripped with obligations still pending.
    PassLimit,
}

/// Totals across one headless run: per-pass intake/fetch sums plus
/// the stopping outcome, the obligations still owed, and heads whose
/// closure is not local. Structured data first; the CLI renders it
/// to text below, future consumers render their own.
#[derive(Debug)]
struct SyncRunReport {
    passes: u32,
    accepted: usize,
    duplicates: usize,
    deferred: usize,
    deferred_unseen: usize,
    deferred_status_blocked: usize,
    deferred_shed: usize,
    /// Pending-bound sheds whose wait was classified, accumulated
    /// like the rest: stored for the surface that renders them (the
    /// deferred-clause renderer below owns the shed detail — this
    /// report must not print it, or the two collide here).
    deferred_shed_unseen: usize,
    deferred_shed_status_blocked: usize,
    skipped: usize,
    discarded: usize,
    manifests: usize,
    snapshot_bodies: usize,
    objects: usize,
    unfulfilled: usize,
    /// Fetch-attempt diagnostics, accumulated like the rest: stored
    /// for the surface that renders them (`14-fetch-failure-
    /// diagnostics` owns the class renderer — this report must not
    /// print them, or the two collide here).
    transport_errors: usize,
    deadlines: usize,
    missing: usize,
    invalid: usize,
    unavailable_keys: usize,
    local_failures: usize,
    /// Rejected-representation repair, accumulated like the rest:
    /// stored for the surface that renders them
    /// (`14-fetch-failure-diagnostics` owns the class renderer —
    /// this report must not print them, or the two collide here).
    quarantined_observed: usize,
    quarantine_claims_cleared: usize,
    quarantine_bytes_discarded: usize,
    quarantine_failures: usize,
    /// Out-of-band loss repair, accumulated like the rest and
    /// stored under the same rule: `14-fetch-failure-diagnostics`
    /// owns the class renderer, so this report must not print
    /// them either.
    scrubbed_observed: usize,
    scrub_claims_cleared: usize,
    scrub_bytes_subtracted: usize,
    scrub_failures: usize,
    /// Outbound sends committed by per-pass publication.
    sent: usize,
    /// Distinct senders named by intake envelopes this run (OD-17-4
    /// option B): the union of every pass's observed senders, in
    /// ascending byte order. A sender is any key that mailed us,
    /// member or not — this is a sender list, never a membership
    /// roster. Rendered here with full `DeviceId`s — this process
    /// connected and the operator holds the keys — and never on the
    /// durable surface, which has no live peer set to report.
    peers_observed: Vec<DeviceId>,
    outcome: RunOutcome,
    pending: usize,
    /// Received reconciliation statements the run never answered:
    /// the end-of-run control-plane gap. A live gauge, not a durable
    /// projection — answering is volatile — captured once after the
    /// loop beside `pending`, never accumulated per pass. Nonzero
    /// with a quiet outbox still fails the run: the peer asked and
    /// this device could not prove its state.
    reconciliation_outstanding: usize,
    /// Evaluated-but-stuck statements whose requester is still owed
    /// ("asked, nothing delivered"): the stall half of the gap beside
    /// the unanswered half above. Same capture discipline — once at
    /// the end, never per pass — and the same failure: a permanently
    /// skipped peer renders as a healthy drive without it.
    reconciliation_stalled: usize,
    /// Heads known but not locally closable at the last pass: a
    /// remote condition (no route, no bytes, no capability yet),
    /// never local work. Reported, never spun on.
    unfetchable_heads: usize,
    /// Identities holding a completed terminal fetch generation when
    /// the run stopped: a live gauge read once at the end beside
    /// `pending`, never accumulated per pass. Fulfillment dissolves
    /// terminality and reopen clears it, so this answers "how many
    /// are terminal now", never a cumulative total.
    terminal_identities: usize,
    /// Mailbox posture the stopping verdict rests on. `drive_quiet`
    /// is generic over the mailbox and cannot observe it, so it
    /// leaves `None` and `sync_now` stores the observed snapshot
    /// before rendering or mapping the outcome. `None` means "not
    /// observed", never "healthy": both consumers fail it closed,
    /// so a future path that forgets the snapshot inherits an
    /// unverified run, not a fabricated success.
    mailbox: Option<MailboxHealth>,
    /// Lifetime write-path totals read off the node after the run:
    /// snapshot rate, source breakdown, admission-to-commit latency.
    write: WriteStats,
}

impl SyncRunReport {
    /// Fold one pass into the run totals: every counter the report
    /// carries, every pass including the quiet-confirmation one. The
    /// two call sites (the main loop and the confirm pass) share
    /// this so a counter added here cannot be forgotten there.
    fn accumulate(&mut self, pass: &SyncReport) {
        self.passes += 1;
        // The shed sub-counters partition the shed total: a pass
        // reporting more classified sheds than sheds is corrupt
        // input, and the renderer's saturating arithmetic would
        // silently hide it — fail here instead.
        debug_assert!(
            pass.drained.deferred_shed_unseen + pass.drained.deferred_shed_status_blocked
                <= pass.drained.deferred_shed,
            "shed sub-counters partition the shed total: {pass:?}"
        );
        self.accepted += pass.drained.accepted;
        self.duplicates += pass.drained.duplicates;
        self.deferred += pass.drained.deferred;
        self.deferred_unseen += pass.drained.deferred_unseen;
        self.deferred_status_blocked += pass.drained.deferred_status_blocked;
        self.deferred_shed += pass.drained.deferred_shed;
        self.deferred_shed_unseen += pass.drained.deferred_shed_unseen;
        self.deferred_shed_status_blocked += pass.drained.deferred_shed_status_blocked;
        self.skipped += pass.drained.skipped;
        self.discarded += pass.drained.discarded;
        self.manifests += pass.fetched.manifests;
        self.snapshot_bodies += pass.fetched.snapshot_bodies;
        self.objects += pass.fetched.objects;
        self.unfulfilled += pass.fetched.unfulfilled;
        self.transport_errors += pass.fetched.transport_errors;
        self.deadlines += pass.fetched.deadlines;
        self.missing += pass.fetched.missing;
        self.invalid += pass.fetched.invalid;
        self.unavailable_keys += pass.fetched.unavailable_keys;
        self.local_failures += pass.fetched.local_failures;
        self.quarantined_observed += pass.quarantined.observed as usize;
        self.quarantine_claims_cleared += pass.quarantined.claims_cleared as usize;
        self.quarantine_bytes_discarded += pass.quarantined.bytes_discarded as usize;
        self.quarantine_failures += pass.quarantined.failures as usize;
        self.scrubbed_observed += pass.scrubbed.observed as usize;
        self.scrub_claims_cleared += pass.scrubbed.claims_cleared as usize;
        self.scrub_bytes_subtracted += pass.scrubbed.bytes_subtracted as usize;
        self.scrub_failures += pass.scrubbed.failures as usize;
        self.sent += pass.sent;
        self.unfetchable_heads = pass.pending_heads;
        // Union, not append: the same peer heard on twelve passes is
        // one observed peer. Sorted so reruns over the same traffic
        // render identically.
        for peer in &pass.drained.peers_observed {
            if !self.peers_observed.contains(peer) {
                self.peers_observed.push(*peer);
            }
        }
        self.peers_observed.sort();
    }
}

/// True when no stopping verdict can rest on this snapshot. A
/// relay-less (offline) snapshot is never degraded: idle intake is
/// the explicit request there, so there is nothing to distrust —
/// `mailbox_line` reports the same case as idle, and the agreement
/// test pins the two together. This early return is explicit on
/// purpose: it must not lean on `is_live`'s zero-relay special
/// case, or tightening that predicate would turn `--offline` into
/// a self-contradicting idle-line-plus-exit-2 report. Otherwise the
/// verdict covers the whole run, not just the terminal sample: a
/// down intake (no relay connected), a blind stretch that never
/// healed (a relay closed our subscription, which takes no
/// resubscribe without operator action), or a blind stretch that
/// did (a non-zero recovery-attempt total proves a supervisor
/// episode ran during this run — the counters start at zero per
/// mailbox and episodes only spawn after first attachment and a
/// sustained outage, so they cannot be stale and a slow cold start
/// never counts). A recovered run may in fact have
/// converged, but the quiet verdict may have been reached through
/// the blind window; failing it as unverified is the conservative
/// direction for a convergence-verdict command, and the error names
/// the attempt count so the operator knows a rerun settles it.
/// Saturation replays deliberately do not count: a replay
/// re-requests and redelivers through dedupe, so post-replay
/// intake is whole again.
fn mailbox_degraded(health: &MailboxHealth) -> bool {
    if health.total_relays == 0 {
        return false;
    }
    !health.is_live()
        || health.closed_subscriptions > 0
        || health.stream_recovery_attempts > 0
        || health.relay_recovery_attempts > 0
}

/// Whether the degraded sample convicts the run: the observation-
/// validity gate over [`mailbox_degraded`]. The sample predicate
/// above reports what the last supervisor tick saw; this verdict
/// decides whether that seeing counts. Two rules, both about not
/// mistaking "not observed yet" for "observed zero":
///
/// A. A degraded verdict requires at least one completed post-start
/// health observation (`supervisor_ticks > 0`). The counters start
/// at zero per mailbox, and a run that exits before the first tick
/// reads the initial zeros — that is unobserved, not degraded.
///
/// B. Relay communication in either direction with no observed
/// attachment proves the relay talked to this run: delivered intake
/// or relay-accepted sends both contradict an "unreachable relay"
/// diagnosis, so a stale zero-connected sample cannot convict.
/// This is corroboration, not a health claim — a relay that
/// communicated once and then died is still convictable, because
/// the attachment latch below flips once any tick observes presence
/// and never flips back. So communication exempts only the
/// never-attached case; attached-then-lost still fails.
///
/// Positive-evidence arms (a relay-closed subscription, a
/// supervisor episode that ran) fail immediately under both rules:
/// they are observed trouble, not absent observations, and the
/// tick gate never applies to them.
fn mailbox_verdict_failed(
    health: &MailboxHealth,
    intake_observed: bool,
    sent_accepted: usize,
) -> bool {
    if health.total_relays == 0 {
        return false;
    }
    if health.closed_subscriptions > 0
        || health.stream_recovery_attempts > 0
        || health.relay_recovery_attempts > 0
    {
        return true;
    }
    if !health.is_live() {
        if health.supervisor_ticks == 0 {
            return false;
        }
        if (intake_observed || sent_accepted > 0) && !health.relay_attached {
            return false;
        }
        return true;
    }
    false
}

/// Whether the run's drainer observed any relay-delivered envelope:
/// accepted, duplicate, deferred, skipped, or discarded all arrived
/// over the relay — each is a delivery the sample counters cannot
/// take back. The verdict path reads it as corroborating
/// communication evidence (see `mailbox_verdict_failed`).
fn report_intake_observed(report: &SyncRunReport) -> bool {
    report.accepted + report.duplicates + report.deferred + report.skipped + report.discarded > 0
}

/// Recovery attempts over the run, both kinds: a stream death or a
/// relay outage each leaves intake blind until its episode
/// converges, so the run-level verdict counts either. Loop
/// iterations, matching wyrd-core's unit — not episodes.
fn recovery_attempts(health: &MailboxHealth) -> u64 {
    health
        .stream_recovery_attempts
        .saturating_add(health.relay_recovery_attempts)
}

/// Drive bounded sync passes until the first settled-quiet pass,
/// a remote stall, or the pass cap: drain, deliver, announce, fetch per pass through
/// the shared `sync_once` machinery — never a reimplementation. A
/// failed pass fails the run closed like the mount's loop abort.
/// Quiet is never trusted on first sight: relay delivery races the
/// first drain, so a quiet verdict parks one settle window (arrival
/// short-circuits it) and confirms with a second pass. A head
/// closure that is not local is a remote condition, not local work:
/// two consecutive zero-progress passes with pending heads and an
/// empty outbox stop the run as `RemoteStalled` rather than
/// burning the cap — the second pass is the grace one, because
/// per-pass budgets replenish and backoff ledgers evolve, so a
/// single stalled pass may precede a completing one, while two
/// identical ones cannot advance. Zero-progress passes park the
/// settle window too, so dead churn waits on the relay instead of
/// spinning; active passes continue immediately.
fn drive_quiet<V, M, B>(
    live: &mut LiveNode<V>,
    mailbox: &mut M,
    bulk: &mut Option<B>,
    settle: Option<Duration>,
) -> Result<SyncRunReport, LiveError>
where
    V: NamespaceView<Materialization = RuntimeMaterialization>,
    V::Store: ObjectStore,
    <V::Store as ObjectStore>::Error: std::fmt::Debug,
    V::Store: wyrd_format::DiscardRejectedRepresentation,
    <V::Store as wyrd_format::DiscardRejectedRepresentation>::Error: std::fmt::Debug,
    M: Mailbox,
    B: RoutePublishing,
{
    let mut report = SyncRunReport {
        passes: 0,
        accepted: 0,
        duplicates: 0,
        deferred: 0,
        deferred_unseen: 0,
        deferred_status_blocked: 0,
        deferred_shed: 0,
        deferred_shed_unseen: 0,
        deferred_shed_status_blocked: 0,
        skipped: 0,
        discarded: 0,
        manifests: 0,
        snapshot_bodies: 0,
        objects: 0,
        unfulfilled: 0,
        transport_errors: 0,
        deadlines: 0,
        missing: 0,
        invalid: 0,
        unavailable_keys: 0,
        local_failures: 0,
        quarantined_observed: 0,
        quarantine_claims_cleared: 0,
        quarantine_bytes_discarded: 0,
        quarantine_failures: 0,
        scrubbed_observed: 0,
        scrub_claims_cleared: 0,
        scrub_bytes_subtracted: 0,
        scrub_failures: 0,
        sent: 0,
        outcome: RunOutcome::Quiet,
        pending: 0,
        reconciliation_outstanding: 0,
        reconciliation_stalled: 0,
        unfetchable_heads: 0,
        terminal_identities: 0,
        mailbox: None,
        peers_observed: Vec::new(),
        write: WriteStats::default(),
    };
    // Consecutive zero-progress passes with pending heads and an
    // empty outbox: the first is grace, the second stops the run.
    let mut stalled_streak = 0u32;
    let stop = AtomicBool::new(false);
    let park = |live: &LiveNode<V>| {
        if let Some(window) = settle {
            live.waker().wait(&stop, window);
        }
    };
    loop {
        let pass = live.sync_once(mailbox, bulk.as_mut())?;
        report.accumulate(&pass);
        let progressed = pass.drained.accepted > 0
            || pass.fetched.manifests > 0
            || pass.fetched.snapshot_bodies > 0
            || pass.fetched.objects > 0
            || pass.published;
        if live.is_quiet(&pass)? {
            // Settle then confirm: mail in flight during the verdict
            // shows up here instead of being missed by the exit.
            park(live);
            let confirm = live.sync_once(mailbox, bulk.as_mut())?;
            report.accumulate(&confirm);
            if live.is_quiet(&confirm)? {
                report.outcome = RunOutcome::Quiet;
                break;
            }
            stalled_streak = 0;
        } else if !progressed && pass.pending_heads > 0 && live.pending_obligations()?.is_empty() {
            stalled_streak += 1;
            if stalled_streak >= 2 {
                report.outcome = RunOutcome::RemoteStalled;
                break;
            }
            park(live);
        } else {
            stalled_streak = 0;
            if !progressed {
                park(live);
            }
        }
        if report.passes >= MAX_SYNC_NOW_PASSES {
            report.outcome = RunOutcome::PassLimit;
            break;
        }
    }
    report.pending = live.pending_obligations()?.len();
    // The control-plane gap beside the obligation backlog: received
    // statements this run never answered (an epoch it never learned,
    // or a statement that landed after the last answer pass). Read
    // once at the end like `pending` — answering is volatile, so a
    // per-pass accumulation would misread re-evaluation as growth.
    report.reconciliation_outstanding = live.unanswered_statements();
    report.reconciliation_stalled = live.stalled_statements()?;
    // The terminal count beside the gap gauges: identities whose
    // fetch generation completed terminally and still hold the
    // verdict. Read once at the end like `pending` — terminality is
    // volatile attempt state, so a per-pass accumulation would
    // misread reopening as growth.
    report.terminal_identities = live.terminal_identities();
    // Lifetime write-path totals: the run's own passes above carry
    // sync load; this carries the local durability load the run
    // observed, so the report distinguishes the two.
    report.write = live.write_stats();
    Ok(report)
}

/// Render a structured status report. Built as a string so tests
/// assert the rendering without capturing stdout.
fn sync_status_render(status: &SyncStatus) -> String {
    /// Group pending pairs by their leading identity for per-item
    /// display: one line per snapshot, transition, or epoch. A renderer
    /// helper, kept next to its only consumer rather than in the
    /// observation module.
    fn group_pending<T: Ord + Copy>(pairs: &[(T, wyrd_format::DeviceId)]) -> BTreeMap<T, usize> {
        let mut grouped = BTreeMap::new();
        for (id, _) in pairs {
            *grouped.entry(*id).or_insert(0) += 1;
        }
        grouped
    }
    let mut out = String::new();
    match &status.tip {
        Some(tip) => {
            out.push_str(&format!("epoch {} tip {}\n", tip.epoch, tip.transition_id));
            let held = status
                .held_epochs
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(" ");
            out.push_str(&format!("held secrets: {held}\n"));
        }
        None => out.push_str("membership: none observed\n"),
    }
    // The drive's durability level (DG-2): what the newest committed
    // snapshot reached — working before the first snapshot, committed
    // while an announcement is queued, published once the outbox is
    // quiet. Committed facts only, so it renders offline.
    out.push_str(&format!("durability: {}\n", status.durability.as_str()));
    let totals = &status.totals;
    let pending = &status.obligations;
    out.push_str(&format!(
        "outbox announcements: {} queued, {} delivered, {} pending\n",
        totals.announcements_queued,
        totals.announcements_delivered,
        pending.announcements.len(),
    ));
    for (snapshot, count) in group_pending(&pending.announcements) {
        out.push_str(&format!("  snapshot {snapshot}: {count} pending\n"));
    }
    out.push_str(&format!(
        "outbox transitions: {} queued, {} delivered, {} pending\n",
        totals.transitions_queued,
        totals.transitions_delivered,
        pending.transitions.len(),
    ));
    for (id, count) in group_pending(&pending.transitions) {
        out.push_str(&format!("  transition {id}: {count} pending\n"));
    }
    out.push_str(&format!(
        "outbox capabilities: {} queued, {} delivered, {} pending\n",
        totals.capabilities_queued,
        totals.capabilities_delivered,
        pending.capabilities.len(),
    ));
    for (epoch, count) in group_pending(&pending.capabilities) {
        out.push_str(&format!("  epoch {epoch}: {count} pending\n"));
    }
    // Reconciliation progress as classes and counts only: the row
    // names no TransitionId, DeviceId, or membership content (the
    // 21d privacy boundary). The outstanding gap lives on `sync now`
    // — answering is volatile — so this row reports progress, never
    // a per-peer backlog.
    let reconcile = &status.reconciliation;
    out.push_str(&format!(
        "reconciliation: {} statements received, {} transitions + {} capabilities retired\n",
        reconcile.statements_received,
        reconcile.transitions_reconciled,
        reconcile.capabilities_reconciled,
    ));
    if status.live_heads.is_empty() {
        out.push_str("live heads: none\n");
    } else {
        out.push_str(&format!("live heads: {}\n", status.live_heads.len()));
        for head in &status.live_heads {
            // Opaque handle, never the author id: this surface names
            // peers by position (OD-17-4 option A). The handle always
            // resolves — observe() derives peers from every identity
            // the status carries — and zero stays opaque rather than
            // leaking the id a broken invariant failed to map.
            out.push_str(&format!(
                "  {} epoch {} author peer-{}\n",
                head.id,
                head.epoch,
                status.peer_handle(&head.author),
            ));
        }
    }
    out.push_str(&format!(
        "peers: {} known ({} members)\n",
        status.peers.len(),
        status.known_members,
    ));
    for entry in &status.peers {
        out.push_str(&format!(
            "  peer-{}: {} pending\n",
            entry.handle, entry.pending
        ));
    }
    let queue = &status.queue;
    out.push_str(&format!(
        "queue: {} outstanding ({} outbox, {} fetch)\n",
        queue.total(),
        queue.outbox,
        queue.fetch,
    ));
    // Staged carries are local re-authoring work owed to nobody, so
    // they count in the outbox total but on no peer line above: name
    // them here so the two can never silently disagree. Projected
    // from the struct, never inferred.
    if queue.carries > 0 {
        out.push_str(&format!(
            "  carries: {} staged (counted in outbox)\n",
            queue.carries
        ));
    }
    let convergence = &status.convergence;
    if convergence.converged {
        out.push_str("convergence: converged\n");
    } else {
        out.push_str(&format!(
            "convergence: not converged ({} outbox, {} fetch, {} heads pending, {} unfetchable)\n",
            queue.outbox, queue.fetch, convergence.pending_heads, convergence.unfetchable_heads,
        ));
    }
    let materialization = &status.materialization;
    out.push_str(&format!(
        "materialization: {} cached, {} pinned, {} local objects\n",
        materialization.cached, materialization.pinned, materialization.local_objects,
    ));
    let classes = &status.head_classes;
    out.push_str(&format!(
        "heads classified: {} eligible, {} canonical-history, {} superseded, {} stranded, {} voided, {} pending, {} rejected\n",
        classes.eligible,
        classes.canonical_history,
        classes.superseded,
        classes.stranded,
        classes.voided,
        classes.pending,
        classes.rejected,
    ));
    if status.mailbox.configured_relays == 0 {
        out.push_str(MAILBOX_IDLE_LINE);
    } else {
        out.push_str(&format!(
            "mailbox: {} relays configured (liveness visible on sync now or mount)\n",
            status.mailbox.configured_relays
        ));
    }
    // OD-17-5 option B: status never connects, so it says so. "Not
    // observed" names the deliberate omission — this command performs
    // no liveness observation — where "unknown" would suggest a
    // failed attempt. Silence would read as healthy.
    out.push_str("connectivity: not observed (this command does not connect)\n");
    out
}

/// The relay-less mailbox posture, shared by the status and now
/// surfaces so the two cannot drift apart.
const MAILBOX_IDLE_LINE: &str = "mailbox: idle (no --relay given)\n";

/// Render the mailbox posture line. Built as a string so tests
/// assert the rendering without capturing stdout. An explicitly
/// relay-less run reads idle, never live: with no relays there is
/// no attachment to be alive, and `is_live` over zero relays would
/// claim otherwise. The verdict word is the run-level one from
/// `mailbox_degraded`, so it agrees with the exit status except for
/// a never-observed sample: the line reports the zero honestly
/// while the exit cannot convict on it (see
/// `mailbox_verdict_failed`). A run that recovered mid-run reads
/// degraded with the episodes named, never a bare live that the
/// exit contradicts.
fn mailbox_line(health: &MailboxHealth) -> String {
    if health.total_relays == 0 {
        return MAILBOX_IDLE_LINE.to_owned();
    }
    let closed = health.closed_subscriptions;
    let attempts = recovery_attempts(health);
    let recoveries = health.saturation_recoveries;
    format!(
        "mailbox: {} ({} of {} relays connected{}{}{})\n",
        if mailbox_degraded(health) {
            "degraded"
        } else {
            "live"
        },
        health.connected_relays,
        health.total_relays,
        if closed == 0 {
            String::new()
        } else {
            format!(
                ", {closed} subscription{} closed by relay",
                if closed == 1 { "" } else { "s" }
            )
        },
        if attempts == 0 {
            String::new()
        } else {
            format!(
                ", {attempts} recovery attempt{} during the run",
                if attempts == 1 { "" } else { "s" }
            )
        },
        if recoveries == 0 {
            String::new()
        } else {
            format!(
                ", {recoveries} saturation recover{} during the run",
                if recoveries == 1 { "y" } else { "ies" }
            )
        },
    )
}

/// Name the degraded cause for the report lines: the current
/// posture when it is down or blind, the mid-run recovery when the
/// mailbox is attached now but ran blind earlier, and the missing
/// observation when there is none. The mid-run arm names the
/// history the mailbox line only counts: the line reads degraded
/// with the attempt total, the report says what the total proves.
fn degraded_reason(mailbox: Option<MailboxHealth>) -> String {
    match mailbox {
        None => "mailbox unobserved".to_owned(),
        Some(health) => {
            let attempts = recovery_attempts(&health);
            if health.closed_subscriptions > 0 || !health.is_live() || attempts == 0 {
                "mailbox degraded".to_owned()
            } else {
                format!("mailbox recovered mid-run ({attempts} recovery attempts)")
            }
        }
    }
}

/// The stopped-quiet reason with the reconciliation gap first: an
/// open gap outranks the mailbox posture because it is the thing
/// the operator must close — a healthy mailbox beside unanswered
/// statements still stopped the run. Falls back to the mailbox
/// reason when the gap is closed, so existing verdicts read
/// unchanged.
fn reconciliation_gap_reason(report: &SyncRunReport) -> String {
    match (
        report.reconciliation_outstanding,
        report.reconciliation_stalled,
    ) {
        (0, 0) => degraded_reason(report.mailbox),
        (unanswered, 0) => format!("{unanswered} reconciliation statements awaiting answer"),
        (0, stalled) => format!("{stalled} stalled reconciliation statements"),
        (unanswered, stalled) => {
            format!("{unanswered} reconciliation statements awaiting answer, {stalled} stalled")
        }
    }
}

/// Render a headless run report. Built as a string so tests assert
/// the rendering without capturing stdout.
fn sync_now_render(report: &SyncRunReport) -> String {
    // Shed detail beside the `shed` total below: pending-bound sheds
    // whose wait was classified, bucketed by that wait, plus the
    // unclassified remainder (budget/quota/charge-time sheds, decided
    // before classification by design). The buckets partition shed —
    // a genuine partition of this count, and of nothing else — so no
    // line here may read as arithmetic on any other total. Prints
    // only when the run shed anything, and only nonzero buckets, so
    // quiet runs stay quiet.
    let shed_detail = {
        let mut parts = Vec::new();
        if report.deferred_shed_unseen > 0 {
            parts.push(format!("{} unseen-wait", report.deferred_shed_unseen));
        }
        if report.deferred_shed_status_blocked > 0 {
            parts.push(format!(
                "{} status-blocked-wait",
                report.deferred_shed_status_blocked
            ));
        }
        let unclassified = report
            .deferred_shed
            .saturating_sub(report.deferred_shed_unseen)
            .saturating_sub(report.deferred_shed_status_blocked);
        if unclassified > 0 {
            parts.push(format!("{unclassified} unclassified"));
        }
        if parts.is_empty() {
            String::new()
        } else {
            format!(" ({})", parts.join(", "))
        }
    };
    let mut out = format!(
        "sync now: {} passes, intake {} accepted ({} duplicates, {} deferred [{} unseen, {} status-blocked, {} shed{}], {} skipped, {} discarded), fetch {} manifests, {} bodies, {} objects ({} unfulfilled), publish {} sends, {} obligations pending, {} unfetchable heads\n",
        report.passes,
        report.accepted,
        report.duplicates,
        report.deferred,
        report.deferred_unseen,
        report.deferred_status_blocked,
        report.deferred_shed,
        shed_detail,
        report.skipped,
        report.discarded,
        report.manifests,
        report.snapshot_bodies,
        report.objects,
        report.unfulfilled,
        report.sent,
        report.pending,
        report.unfetchable_heads,
    );
    // The control-plane gap beside the obligation backlog: received
    // reconciliation statements the run never answered, plus
    // evaluated-but-stuck ones whose requester is still owed. Always
    // printed (zero is the converged case automation greps for), and
    // counts only — no statement digests, no requester identities.
    out.push_str(&format!(
        "reconciliation: {} statements awaiting answer, {} stalled\n",
        report.reconciliation_outstanding, report.reconciliation_stalled,
    ));
    // Fetch-attempt diagnostics beside the `(N unfulfilled)` total
    // above. Each class counts observed attempts, never a share of
    // the total: budget pressure discarded when a fallback reports
    // absence lands in `deadlines` without becoming an unfulfilled
    // item, so the classes are diagnostic counts, not a
    // decomposition of `unfulfilled` — no line here may read as
    // arithmetic on it. The breakdown prints only when the run left
    // work behind and only for classes that fired, so quiet runs
    // stay quiet; `deadlines` and `terminal` print unconditionally
    // because they describe the execution itself, not the backlog.
    // Counts only, grouped by reason — never by identity: this
    // surface is client-position and must stay reusable from a
    // vault, where ContentIds are forbidden.
    let classes = [
        ("transport_errors", report.transport_errors),
        ("missing", report.missing),
        ("invalid", report.invalid),
        ("unavailable_keys", report.unavailable_keys),
        ("local_failures", report.local_failures),
    ];
    if report.unfulfilled > 0 && classes.iter().any(|(_, count)| *count > 0) {
        out.push_str("fetch classes (diagnostic counts, not shares of unfulfilled):\n");
        for (label, count) in classes {
            if count > 0 {
                out.push_str(&format!("  {label}: {count}\n"));
            }
        }
    }
    out.push_str(&format!(
        "deadlines: {} discarded under budget pressure\n",
        report.deadlines,
    ));
    out.push_str(&format!(
        "terminal: {} identities exhausted\n",
        report.terminal_identities,
    ));
    // Repair diagnostics the earlier peer-repair children stored for
    // this renderer: rejected-representation quarantine and
    // out-of-band-loss scrub, one line each, only when the run did
    // repair work. Counts only, like the fetch classes above.
    if report.quarantined_observed > 0
        || report.quarantine_claims_cleared > 0
        || report.quarantine_bytes_discarded > 0
        || report.quarantine_failures > 0
    {
        out.push_str(&format!(
            "quarantine: {} observed, {} claims cleared, {} bytes discarded, {} failures\n",
            report.quarantined_observed,
            report.quarantine_claims_cleared,
            report.quarantine_bytes_discarded,
            report.quarantine_failures,
        ));
    }
    if report.scrubbed_observed > 0
        || report.scrub_claims_cleared > 0
        || report.scrub_bytes_subtracted > 0
        || report.scrub_failures > 0
    {
        out.push_str(&format!(
            "scrub: {} observed, {} claims cleared, {} bytes subtracted, {} failures\n",
            report.scrubbed_observed,
            report.scrub_claims_cleared,
            report.scrub_bytes_subtracted,
            report.scrub_failures,
        ));
    }
    // Local durability load beside sync load: the run's passes above
    // say what the network did; these lines say what the disk did.
    // Sources are variant classes, never paths — the `Debug` impls
    // render paths, and this surface must not inherit that.
    // Write-path statistics are process-local and cover only
    // mutations submitted to this run's in-memory mutation queue.
    // Headless commands such as `sync now` do not submit mutations,
    // so their write-path statistics are zero: honest evidence of no
    // writes by that invocation, not missing telemetry and never a
    // claim about the drive's history. The rate's denominator is the
    // queue lifetime (run length for `sync now`, process lifetime
    // on a mount), printed beside the rate so a lifetime average is
    // never misread as a recent one.
    let write = &report.write;
    out.push_str(&format!(
        "write path: {} snapshots ({:.1} per min over {:.1}s)\n",
        write.snapshots,
        write.snapshots_per_minute(),
        write.started.elapsed().as_secs_f64(),
    ));
    out.push_str(&format!(
        "write sources: mkdir {} create-file {} commit-file {} append-file {} unlink {} rmdir {} rename {} set-attrs {} fold {}\n",
        write.mkdir,
        write.create_file,
        write.commit_file,
        write.append_file,
        write.unlink,
        write.rmdir,
        write.rename,
        write.set_attrs,
        write.fold,
    ));
    out.push_str(&format!(
        "write latency: admission-to-commit mean {}us max {}us over {} commits ({} failures)\n",
        write.commit_latency_us_mean(),
        write.commit_latency_us_max,
        write.commits,
        write.failures,
    ));
    // Senders heard this run (OD-17-4 option B): full identities,
    // because this process connected and the operator holds the
    // keys — with the transport-named caveat that an envelope sender
    // is any Nostr key that mailed us, member or not, so this is a
    // sender list, never a membership roster. The durable surface
    // reports obligation peers as opaque handles; the two answer
    // different questions (who mailed us vs who we owe) and never
    // share a representation.
    if report.peers_observed.is_empty() {
        out.push_str("senders observed: none\n");
    } else {
        out.push_str(&format!(
            "senders observed: {}\n",
            report.peers_observed.len()
        ));
        for peer in &report.peers_observed {
            out.push_str(&format!("  sender {peer}\n"));
        }
    }
    // An open reconciliation gap downgrades both quiet verdicts
    // the way a degraded mailbox does: the outbox is quiet but a
    // peer asked and this run never answered, so the run stopped
    // instead of completing. Checked before the mailbox arms so a
    // healthy offline run with a gap cannot claim completion — a
    // `completed` line beside a non-zero exit would lie to the
    // automation the exit code serves. Either half of the gap —
    // never-evaluated or evaluated-but-stuck — downgrades.
    let reconciliation_open =
        report.reconciliation_outstanding > 0 || report.reconciliation_stalled > 0;
    match report.outcome {
        // A degraded or unobserved mailbox downgrades both quiet
        // verdicts: the local state converged, but intake may have
        // missed mail, so the run stopped instead of completing.
        // The `stopped` prefix matches the pass-limit line — all
        // three exit non-zero. An offline completion keeps its
        // success but names its limits: it fetched nothing, so an
        // operator tailing only the last line sees the scope.
        RunOutcome::Quiet => match report.mailbox {
            Some(health)
                if !mailbox_verdict_failed(&health, report_intake_observed(report), report.sent)
                    && !reconciliation_open => {
                out.push_str("completed: quiet");
                if health.total_relays == 0 {
                    out.push_str(" (offline run: local obligations only)");
                }
                out.push('\n');
            }
            _ => out.push_str(&format!(
                "stopped: quiet locally, {}, convergence unverified\n",
                reconciliation_gap_reason(report),
            )),
        },
        RunOutcome::RemoteStalled => match report.mailbox {
            Some(health)
                if !mailbox_verdict_failed(&health, report_intake_observed(report), report.sent)
                    && !reconciliation_open => {
                out.push_str(&format!(
                    "completed: quiet with {} unfetchable heads (known but not local)",
                    report.unfetchable_heads,
                ));
                if health.total_relays == 0 {
                    out.push_str(" (offline run: local obligations only)");
                }
                out.push('\n');
            }
            _ => out.push_str(&format!(
                "stopped: quiet locally with {} unfetchable heads (known but not local), {}, convergence unverified\n",
                report.unfetchable_heads,
                reconciliation_gap_reason(report),
            )),
        },
        RunOutcome::PassLimit => {
            out.push_str(&format!(
                "stopped: pass limit ({MAX_SYNC_NOW_PASSES}) reached; sync may be incomplete"
            ));
            // A blind mailbox may be why the cap tripped: refusal
            // keeps obligations pending forever, so the run never
            // reaches quiet. Name it here, not just in the stderr
            // error, so the stdout forensics show the cause.
            if !matches!(report.mailbox, Some(health)
                if !mailbox_verdict_failed(&health, report_intake_observed(report), report.sent)) {
                out.push_str(&format!("; {}, convergence unverified", degraded_reason(report.mailbox)));
            }
            out.push('\n');
        }
    }
    out
}

/// Map a headless run outcome to the process result: quiet and
/// remote-stalled succeed (the latter has nothing local left to
/// do), a capped run fails as incomplete with its pass and pending
/// counts. An unobserved mailbox fails as unobserved, and a degraded
/// one fails as unverified, whatever the outcome: `Quiet` and
/// `RemoteStalled` both rest on intake having observed an empty
/// world, which a blind mailbox cannot prove, and the cap trip may
/// itself be the dead mailbox keeping obligations pending —
/// rerunning without operator action cannot converge, so the error
/// names the mailbox, not the pass count. Tested directly;
/// `sync_now` channels through it.
fn run_outcome_error(report: &SyncRunReport) -> Result<(), CliError> {
    let mailbox = match report.mailbox {
        None => return Err(CliError::Unobserved),
        Some(health) => health,
    };
    if mailbox_verdict_failed(&mailbox, report_intake_observed(report), report.sent) {
        return Err(CliError::Unverified {
            connected: mailbox.connected_relays,
            total: mailbox.total_relays,
            closed: mailbox.closed_subscriptions,
            attempts: recovery_attempts(&mailbox),
        });
    }
    match report.outcome {
        RunOutcome::Quiet | RunOutcome::RemoteStalled => Ok(()),
        RunOutcome::PassLimit => Err(CliError::Incomplete {
            passes: report.passes,
            pending: report.pending,
        }),
    }?;
    // The quiet outbox does not imply a closed control plane: a peer
    // may have asked while this run could not answer, or asked and
    // been permanently skipped. Name that gap with its own error
    // (rather than folding it into pending) so the message says what
    // is missing instead of what is owed.
    if report.reconciliation_outstanding > 0 || report.reconciliation_stalled > 0 {
        return Err(CliError::ReconciliationOutstanding {
            unanswered: report.reconciliation_outstanding,
            stalled: report.reconciliation_stalled,
        });
    }
    Ok(())
}

/// Headless sync over the keystore: `status` observes durable state
/// only (no intake, no send, no seen-log or outbox mutation — the
/// relay list only labels the mailbox line), `now` runs the mount's
/// sync machinery without any presentation backend.
fn sync(
    drive_dir: PathBuf,
    relays: Vec<String>,
    action: SyncAction,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> Result<(), CliError> {
    match action {
        SyncAction::Status => {
            let engine = Engine::open_keystore(drive_dir, passphrase, identity)?;
            let status = observe(&engine, relays.len())?;
            print!("{}", sync_status_render(&status));
            Ok(())
        }
        SyncAction::Now { offline, serve } => {
            // --offline means "run without relays": combining it with
            // --relay is contradictory, and silently ignoring the flag
            // would lie about the run. (clap conflicts_with cannot
            // express this: --relay lives on the parent command via
            // flatten, not on the `now` subcommand.)
            if offline && !relays.is_empty() {
                return Err(CliError::Usage(
                    "--offline cannot be combined with --relay".into(),
                ));
            }
            // --serve publishes its route inside relay announcements,
            // so --offline (no relay, no send) would serve content
            // nothing can discover. Refuse the combination rather
            // than run a serving endpoint nobody can dial.
            if serve && offline {
                return Err(CliError::Usage(
                    "--serve cannot be combined with --offline: serving needs a relay to publish its route"
                        .into(),
                ));
            }
            // A relay-less run exits 0 with an idle intake, which a
            // cron or systemd unit keying on exit status cannot
            // distinguish from a converged sync. Refuse it before
            // touching the keystore unless --offline opts in.
            if relays.is_empty() && !offline {
                return Err(CliError::Usage(
                    "sync now needs at least one --relay, or --offline for a relay-less local run"
                        .into(),
                ));
            }
            sync_now(drive_dir, relays, serve, passphrase, identity)
        }
    }
}

/// One bounded headless run: the mount's composition minus
/// presentation. Without `--serve` there is no serving endpoint —
/// so announcements discharge without a retrieval route (route-less
/// authoring: the snapshot is authored and announced, and peers
/// learn it as known-but-unfetchable until a later mount publishes
/// a route) — and no serving barrier either (OD-23-W option A: a
/// barrier with no endpoint would hold obligations nobody can
/// discharge). With `--serve` the run binds the mount's serving
/// surface in the mount's order (open, bulk, flush, route, barrier)
/// and serves the converged snapshot until SIGINT/SIGTERM. Same
/// live budgets as mount via `for_local_sync`.
fn sync_now(
    drive_dir: PathBuf,
    relays: Vec<String>,
    serve: bool,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> Result<(), CliError> {
    let engine = Engine::open_keystore(drive_dir.clone(), passphrase, identity.clone())?;
    let config = LiveConfig::for_local_sync();
    let store = FsObjectStore::open(drive_dir.clone())
        .map_err(|error| CliError::Store(error.to_string()))?;
    // Same startup cross-check as mount: headless runs compose a live
    // node too, so a misconfigured quota must fail here rather than
    // in the first write.
    check_startup_retention(&config, &store)?;
    // The serve phase below parks on this latch, so arm it before the
    // drain: a signal during the drain trips the flag, the drain
    // still reports its own verdict, and the serve phase then tears
    // down immediately instead of parking. The non-serve path never
    // reads the latch, so arming is harmless there.
    if serve {
        install_shutdown_handler()?;
    }
    let mut daemon: WyrdNode<DriveView<FsObjectStore, RuntimeMaterialization>> =
        WyrdNode::new(engine, store)?;
    daemon.refresh_live_heads()?;
    // The serving endpoint lives in the composer (never in the loop):
    // the loop holds only the cloneable readiness handle as its
    // discharge barrier. `None` without `--serve` is the OD-23-W
    // conditional — route-less authoring, ungated discharge, and the
    // exit-on-quiet drain below, all exactly as before.
    let serving = if serve {
        // A real-iroh endpoint like the mount's (never loopback):
        // the announced route must be one a peer on another machine
        // can dial.
        let serving = daemon
            .open_serving(&drive_dir, false)
            .map_err(CliError::Serving)?;
        let serving_id = hex::encode(serving.addr().id.as_bytes());
        eprintln!("serving over iroh: {serving_id}");
        tracing::info!(stage = "serving", iroh_id = %serving_id, "serving endpoint bound");
        Some(serving)
    } else {
        None
    };
    let (mut live, parts) = daemon.into_live(Duration::from_secs(30), &config)?;
    if let Some(serving) = &serving {
        // Mount order: flush before announcing the address, so the
        // first seal carries a route peers can already dial; then
        // publish the route and gate every pass's discharge on mirror
        // readiness. A backed-up mirror leaves the obligation
        // recorded, never discharged.
        serving.flush().map_err(CliError::Serving)?;
        live.set_node_addr(Some(serving.node_addr_bytes()));
        live.set_serving_barrier(std::sync::Arc::new(serving.handle()));
    }
    // The headless consumer has no presentation backend: the live
    // parts (projection handle, wants, mutations) are owned but
    // never served. Dropping them here is the same shape the
    // composition tests use; the queue stays open but nobody
    // submits, so passes only ever see intake and fetch work.
    drop(parts);
    let signer_keys = identity.signer_keys();
    let open_secret = signer_keys.secret_key().clone();
    let seen_path = drive_dir.join("mailbox.seen");
    let mut mailbox = LiveMailbox::connect(signer_keys, open_secret, relays.clone(), seen_path)?;
    // Arrival short-circuits the settle parks below the way it
    // short-circuits the mount's idle wait: without this, every park
    // burns its full window even as mail lands.
    mailbox.attach_waker(Arc::clone(live.waker()));
    let settle = if relays.is_empty() {
        // Only reachable with --offline (the dispatch above refuses
        // a bare relay-less run): intake stays idle by explicit
        // request, so there is no arrival to wait for.
        eprintln!("warning: no --relay given; control-plane intake stays idle");
        None
    } else {
        Some(SYNC_NOW_SETTLE)
    };
    let mut bulk = Some(bind_bulk_source()?);
    let report = drive_quiet(&mut live, &mut mailbox, &mut bulk, settle);
    // Liveness as observed, not inferred: the run connected, so it
    // reports what the relay attachment actually did. A relay-closed
    // subscription keeps the TCP count up while killing intake, so the
    // closure count degrades the verdict even when every relay is
    // connected — this summary is the only human surface on the
    // headless path, and sync_now installs no tracing subscriber for
    // the drainer's warn to reach. The snapshot also travels in the
    // report, so the exit path judges the same posture the line
    // shows — a blind mailbox never exits as converged.
    let health = mailbox.health();
    print!("{}", mailbox_line(&health));
    // Teardown mirrors mount's transport shutdown in miniature: stop
    // the mailbox tasks under a bounded deadline, then close bulk
    // graceful-or-abort (always success; a wedged drain warns inside).
    // A sync failure still tears transport down before returning it.
    mailbox.shutdown(SHUTDOWN_DEADLINE);
    if let Some(bulk) = bulk.take() {
        bulk.shutdown(wyrd_sync::GRACEFUL_CLOSE_DEADLINE);
    }
    drop(bulk);
    drop(live);
    let mut report = match report {
        Ok(report) => report,
        Err(error) => {
            // The drain failed but a `--serve` endpoint is already
            // bound: shut it down before returning so the error path
            // never leaks residency.
            let serving_result = shutdown_headless_serving(serving);
            return combine_status(TeardownStatus {
                loop_result: Err(error.into()),
                session_result: Ok(()),
                serving_result,
            });
        }
    };
    report.mailbox = Some(health);
    print!("{}", sync_now_render(&report));
    let outcome = run_outcome_error(&report);
    // The serve phase serves the converged snapshot — never more
    // syncing. A failed drain tears down immediately with its own
    // error instead of serving half-fetched state, and the verdict
    // above is already printed: the exit below still names the
    // drain, not the residency (Zander's OD-23-V constraint). That
    // is what keeps `--serve` a bridge composition rather than a
    // daemonized drain: quiesce first, reside second, shut down
    // explicitly.
    if serve && outcome.is_ok() {
        eprintln!("serving converged snapshot until shutdown (SIGINT/SIGTERM)");
        tracing::info!(stage = "serving", "serve phase parked on shutdown latch");
        park_serving_until_shutdown();
    }
    let serving_result = shutdown_headless_serving(serving);
    combine_status(TeardownStatus {
        loop_result: outcome,
        session_result: Ok(()),
        serving_result,
    })
}

/// Bind the fetch side's iroh endpoint (N0 relays for peer
/// reachability) and wrap it in the real bulk source.
fn bind_bulk_source() -> Result<wyrd_sync::bulk::IrohBulkSource, CliError> {
    wyrd_sync::bulk::IrohBulkSource::connect_default().map_err(CliError::Bulk)
}

/// Park the `--serve` phase on the shutdown latch: the endpoint
/// serves the converged snapshot while the process waits for
/// SIGINT/SIGTERM. Polls in slices because a signal-handler trip
/// cannot notify a channel — the same slow-path guarantee as the
/// mount's own teardown wait, and fast enough for a path whose
/// teardown already budgets a minute for transport close.
fn park_serving_until_shutdown() {
    loop {
        if SHUTDOWN.load(Ordering::Relaxed) {
            tracing::info!(stage = "serving", "shutdown latch tripped");
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Shut a headless serving endpoint down under the mount's
/// transport bound, or succeed vacuously when `--serve` was absent
/// (OD-23-W: no endpoint, no shutdown, no hang).
fn shutdown_headless_serving(
    serving: Option<wyrd_sync::serving::ServingEndpoint>,
) -> Result<(), CliError> {
    match serving {
        Some(serving) => serving
            .shutdown(TRANSPORT_SHUTDOWN_DEADLINE)
            .map_err(CliError::Serving),
        None => Ok(()),
    }
}

/// A headless vault: the mount's live loop and serving surface with
/// no presentation session. The persistent process (OD-22-B option
/// A): `sync now` stays the bounded one-shot drain, this never stops
/// syncing until SIGINT/SIGTERM. Composition runs through the
/// daemon's vault runner, so the loop order and transport tail stay
/// one copy with the mount — the vault is the second composer the
/// lifecycle prose was written for.
fn vault(
    drive_dir: PathBuf,
    relays: Vec<String>,
    log_file: Option<PathBuf>,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> Result<(), CliError> {
    // A relay-less vault serves routes nothing can discover and never
    // converges: refuse it the way `sync now` refuses a bare
    // relay-less run. Unlike `sync now` there is no `--offline`
    // escape — an offline vault is a process that idles forever, not
    // a run with a verdict.
    if relays.is_empty() {
        return Err(CliError::Usage(
            "vault needs at least one --relay: a relay-less vault serves nothing peers can discover"
                .into(),
        ));
    }
    // Diagnostics first: stderr always carries the ready line and the
    // failures for the supervisor to capture, plus an appended
    // operator-chosen file under `--log-file` — never a
    // drive-resident default, never truncated (a restart must not
    // destroy the previous run's record).
    init_vault_diagnostics(log_file.as_deref())?;
    let vault_span = tracing::info_span!("vault", drive = %drive_dir.display());
    let _vault_guard = vault_span.enter();
    tracing::info!(stage = "start", "vault diagnostics initialized");

    let engine = Engine::open_keystore(drive_dir.clone(), passphrase, identity.clone())?;
    // Same shared budgets as mount and headless sync, through
    // `for_local_sync` (never `Default` directly): several are
    // correctness boundaries, and a vault-only default must never
    // silently diverge them.
    let config = LiveConfig::for_local_sync();
    let store = FsObjectStore::open(drive_dir.clone())
        .map_err(|error| CliError::Store(error.to_string()))?;
    check_startup_retention(&config, &store)?;
    // The vault parks on this latch from its first pass to its last,
    // so arm it before composition: a signal during startup still
    // tears down instead of parking.
    install_shutdown_handler()?;
    let mut daemon: WyrdNode<DriveView<FsObjectStore, RuntimeMaterialization>> =
        WyrdNode::new(engine, store)?;
    daemon.refresh_live_heads()?;
    // A real-iroh endpoint like the mount's (never loopback): the
    // announced route must be one a peer on another machine can dial.
    let serving = daemon
        .open_serving(&drive_dir, false)
        .map_err(CliError::Serving)?;
    let serving_id = hex::encode(serving.addr().id.as_bytes());
    eprintln!("serving over iroh: {serving_id}");
    tracing::info!(stage = "serving", iroh_id = %serving_id, "serving endpoint bound");
    let (live, parts) = daemon.into_live(Duration::from_secs(30), &config)?;
    // The headless consumer has no presentation backend: the live
    // parts (projection handle, wants, mutations) are owned but never
    // served — the same shape the headless composition uses. The
    // queue stays open but nobody submits, so passes only ever see
    // intake and fetch work.
    drop(parts);
    // The mailbox signs with the local identity key: open and signer
    // are the same key by construction (see the mount's inventory
    // comment — the full process graph is unchanged here).
    let signer_keys = identity.signer_keys();
    let open_secret = signer_keys.secret_key().clone();
    let seen_path = drive_dir.join("mailbox.seen");
    let mailbox = LiveMailbox::connect(signer_keys, open_secret, relays.clone(), seen_path)?;
    // Arrival short-circuits the loop's idle wait the way it does for
    // the mount: without this, every park burns its full window even
    // as mail lands.
    mailbox.attach_waker(Arc::clone(live.waker()));
    let bulk = bind_bulk_source()?;
    // The observer's events are the operator surface (SD-2 option A):
    // one ready line after the first routed pass, periodic posture
    // while it runs, failures with the mount's reporting shape. All
    // three go to stderr (the supervisor captures them) and the event
    // stream the log file carries.
    let emit: Arc<dyn Fn(VaultEvent) + Send + Sync> = Arc::new(move |event| match event {
        VaultEvent::Ready { serving_id } => {
            eprintln!("vault ready: serving {serving_id}");
            tracing::info!(stage = "ready", iroh_id = %serving_id, "vault ready");
        }
        VaultEvent::Posture {
            passes,
            errors,
            sent,
            uptime_secs,
        } => {
            eprintln!(
                "vault posture: {passes} passes, {errors} errors retried, {sent} sends, uptime {uptime_secs}s"
            );
            tracing::info!(
                stage = "posture",
                passes,
                errors,
                sent,
                uptime_secs,
                "vault posture"
            );
        }
        VaultEvent::PassFailed {
            class,
            consecutive,
            error,
        } => {
            eprintln!("live sync pass failed ({class} class, {consecutive} consecutive): {error}");
            tracing::warn!(
                stage = "sync",
                class = %class,
                consecutive,
                error = %error,
                "live sync pass failed"
            );
        }
    });
    let outcome = run_vault(VaultRun {
        live,
        mailbox,
        bulk: Some(bulk),
        serving,
        serving_id,
        config,
        deadlines: TransportDeadlines {
            mailbox: SHUTDOWN_DEADLINE,
            bulk: wyrd_sync::GRACEFUL_CLOSE_DEADLINE,
            serving: TRANSPORT_SHUTDOWN_DEADLINE,
        },
        stop: &SHUTDOWN,
        emit,
    })
    .map_err(CliError::Serving)?;
    // Fold like the mount — loop first, then serving — with no
    // session in between. SIGTERM exits 0 here exactly when the loop
    // stopped clean and every transport closed: the mount's rule at
    // `docs/cli.md:440-443` applies to the vault too.
    let loop_result = match outcome.loop_end {
        VaultLoopEnd::Returned(result) => result.map(|_| ()).map_err(|error| match error {
            LoopError::Live(error) => CliError::Live(error),
            LoopError::Panicked => {
                CliError::Mount(std::io::Error::other("live loop thread panicked"))
            }
        }),
        VaultLoopEnd::SupervisionLost => Err(CliError::Mount(std::io::Error::other(
            "supervised loop thread failed",
        ))),
    };
    combine_status(TeardownStatus {
        loop_result,
        session_result: Ok(()),
        serving_result: outcome.transport.serving.map_err(CliError::Serving),
    })
}

/// Administer drive membership offline over the keystore: reads
/// project the membership log, writes author one transition plus
/// catch-up obligations through the engine (which enforces
/// owner-only). Catch-up delivery to other devices happens on the
/// next mounted sync via the mailbox, not here.
fn member(
    drive_dir: PathBuf,
    action: MemberAction,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> Result<(), CliError> {
    let mut engine = Engine::open_keystore(drive_dir.clone(), passphrase, identity)?;
    match action {
        MemberAction::List => {
            print!("{}", member_list_report(&engine)?);
            Ok(())
        }
        MemberAction::Log => {
            print!("{}", member_log_report(&engine)?);
            Ok(())
        }
        MemberAction::Status => {
            print!("{}", member_status_report(&engine)?);
            Ok(())
        }
        MemberAction::Remove { device, yes } => {
            let device = parse_device_id(&device)?;
            require_last_owner_confirmation(&engine, &device, yes)?;
            let (transition, carried) = transition_with_carry(&mut engine, &drive_dir, |engine| {
                engine.remove_device(device)
            })?;
            println!(
                "removed {device} at epoch {} ({} carried)",
                transition.epoch, carried
            );
            Ok(())
        }
        MemberAction::Rotate => {
            let (transition, carried) =
                transition_with_carry(&mut engine, &drive_dir, |engine| engine.rotate_epoch())?;
            println!(
                "rotated to epoch {} ({} carried)",
                transition.epoch, carried
            );
            Ok(())
        }
        MemberAction::SetOwner { device } => {
            let device = parse_device_id(&device)?;
            let (transition, carried) =
                transition_with_carry(&mut engine, &drive_dir, |engine| engine.set_owners(device))?;
            println!(
                "owner is now {device} at epoch {} ({} carried)",
                transition.epoch, carried
            );
            Ok(())
        }
        MemberAction::Resolve { winner, voided } => {
            let winner = parse_transition_id(&winner)?;
            let mut void_ids = Vec::with_capacity(voided.len());
            for id in &voided {
                void_ids.push(parse_transition_id(id)?);
            }
            let (transition, carried) = transition_with_carry(&mut engine, &drive_dir, |engine| {
                engine.resolve_conflict(winner, void_ids.clone())
            })?;
            println!(
                "resolved at epoch {} (prev {}, {} voided, {} carried)",
                transition.epoch,
                transition
                    .prev
                    .map(|id| id.to_string())
                    .as_deref()
                    .unwrap_or("genesis"),
                transition.resolves().len(),
                carried
            );
            Ok(())
        }
        MemberAction::Invite {
            device,
            encryption_key,
            out,
            reader,
        } => {
            let device = parse_device_id(&device)?;
            let encryption_key = parse_encryption_key(&encryption_key)?;
            // Claim the destination before the irreversible commit; on
            // admit failure the claim is removed so a retry starts
            // clean. See claim_out for the policy.
            let mut file = claim_out(&out)?;
            let admit = |engine: &mut Engine| {
                if reader {
                    engine.admit_reader(device, encryption_key)
                } else {
                    engine.admit_device(device, encryption_key)
                }
            };
            engine.stage_carry_heads()?;
            let outcome = match admit(&mut engine) {
                Ok(outcome) => outcome,
                Err(error) => {
                    let _ = fs::remove_file(&out);
                    return Err(error.into());
                }
            };
            let carried = carry_pending(&mut engine, &drive_dir)?;
            write_invitation(&out, &mut file, &outcome.invitation.encode())?;
            println!(
                "invited {device}{} at epoch {} -> {} ({} carried)",
                if reader { " as reader" } else { "" },
                outcome.transition.epoch,
                out.display(),
                carried
            );
            Ok(())
        }
        MemberAction::ReissueInvitation { device, out } => {
            let device = parse_device_id(&device)?;
            // Same destination policy as invite: the reseal is new
            // bytes for an old admission, and an existing file is
            // refused rather than silently replaced.
            let mut file = claim_out(&out)?;
            let invitation = match engine.reissue_invitation(device) {
                Ok(invitation) => invitation,
                Err(error) => {
                    let _ = fs::remove_file(&out);
                    return Err(error.into());
                }
            };
            write_invitation(&out, &mut file, &invitation.encode())?;
            println!("reissued invitation for {device} -> {}", out.display());
            Ok(())
        }
    }
}

/// Inspect snapshots and merge conflicted heads offline over the
/// keystore. Merging authors one snapshot with ordinary member
/// authority (the engine enforces eligibility and the merge-spec
/// contract, never the CLI) and queues the usual announcements for
/// the next mounted sync.
fn snapshot(
    drive_dir: PathBuf,
    action: SnapshotAction,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> Result<(), CliError> {
    let mut engine = Engine::open_keystore(drive_dir.clone(), passphrase, identity)?;
    match action {
        SnapshotAction::List => {
            print!("{}", snapshot_list_report(&engine)?);
            Ok(())
        }
        SnapshotAction::Heads => {
            print!("{}", snapshot_heads_report(&engine)?);
            Ok(())
        }
        SnapshotAction::Plan { heads } => {
            let selected = select_merge_heads(&engine, &heads)?;
            let store = FsObjectStore::open(drive_dir.to_path_buf())
                .map_err(|error| CliError::Store(error.to_string()))?;
            let plan = engine
                .merge_plan(&store, selected)
                .map_err(map_merge_error)?;
            print!("{}", snapshot_plan_report(&plan));
            Ok(())
        }
        SnapshotAction::Merge {
            heads,
            default,
            takes,
            drops,
        } => {
            // Sources default to every live head; explicit ids narrow
            // to a subset. Sorted ascending, so `@N` numbers the
            // selection in SnapshotId byte order.
            let selected = select_merge_heads(&engine, &heads)?;
            let resolve_ref = |reference: &str| -> Result<SnapshotId, CliError> {
                let number: usize = reference
                    .strip_prefix('@')
                    .and_then(|number| number.parse().ok())
                    .filter(|number| *number >= 1)
                    .ok_or_else(|| {
                        CliError::Usage(format!("head reference must be @N, got {reference:?}"))
                    })?;
                selected.get(number - 1).copied().ok_or_else(|| {
                    CliError::Usage(format!(
                        "@{number} names no selected head: {} selected",
                        selected.len()
                    ))
                })
            };
            let default = default
                .map(|reference| resolve_ref(&reference))
                .transpose()?;
            let mut spec = BTreeMap::new();
            for take in &takes {
                let (path, reference) = take.split_once('=').ok_or_else(|| {
                    CliError::Usage(format!("--take must be path=@N, got {take:?}"))
                })?;
                let id = resolve_ref(reference)?;
                if spec
                    .insert(check_merge_path(path)?, MergeSelection::Take(id))
                    .is_some()
                {
                    return Err(CliError::Usage(format!(
                        "duplicate selection for path {path:?}"
                    )));
                }
            }
            for drop in &drops {
                let path = check_merge_path(drop)?;
                if spec.insert(path.clone(), MergeSelection::Absent).is_some() {
                    return Err(CliError::Usage(format!(
                        "duplicate selection for path {path:?}"
                    )));
                }
            }
            let mut store = FsObjectStore::open(drive_dir.to_path_buf())
                .map_err(|error| CliError::Store(error.to_string()))?;
            let merged = engine
                .merge_heads(&mut store, selected, default, spec)
                .map_err(map_merge_error)?;
            let parents = merged
                .snapshot()
                .parents
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" ");
            println!(
                "merged {} at epoch {} (parents {parents})",
                merged.snapshot().snapshot_id(),
                merged.snapshot().epoch,
            );
            Ok(())
        }
        SnapshotAction::Recover { action } => match action {
            RecoverAction::Plan { from } => {
                let from = parse_snapshot_id(&from)?;
                let store = FsObjectStore::open(drive_dir.to_path_buf())
                    .map_err(|error| CliError::Store(error.to_string()))?;
                let plan = engine.recovery_plan(&store, from)?;
                print!("{}", recovery_plan_report(&plan));
                Ok(())
            }
            RecoverAction::Run {
                from,
                takes,
                all,
                contents,
            } => {
                check_recovery_owner(&engine)?;
                if all && !takes.is_empty() {
                    return Err(CliError::Usage(
                        "--all grafts the whole source tree: drop the --take lines".into(),
                    ));
                }
                let from = parse_snapshot_id(&from)?;
                let mut checked = Vec::with_capacity(takes.len());
                for take in &takes {
                    checked.push(check_recover_path(take)?);
                }
                let mut ids = Vec::with_capacity(contents.len());
                for content in &contents {
                    ids.push(parse_content_id(content)?);
                }
                let mut store = FsObjectStore::open(drive_dir.to_path_buf())
                    .map_err(|error| CliError::Store(error.to_string()))?;
                let grafted = engine.recover(&mut store, from, &checked, all, &ids)?;
                let parents = grafted
                    .snapshot()
                    .parents
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(" ");
                println!(
                    "recovered {} at epoch {} (parents {parents})",
                    grafted.snapshot().snapshot_id(),
                    grafted.snapshot().epoch,
                );
                Ok(())
            }
        },
    }
}

/// Resolve merge sources: every live head by default, or an
/// explicit id subset. Sorted ascending, so `@N` numbers the
/// selection in SnapshotId byte order — the basis `merge` and
/// `plan` share.
fn select_merge_heads(engine: &Engine, heads: &[String]) -> Result<Vec<SnapshotId>, CliError> {
    let mut selected: Vec<SnapshotId> = if heads.is_empty() {
        engine
            .live_heads()?
            .iter()
            .map(|head| head.snapshot().snapshot_id())
            .collect()
    } else {
        heads
            .iter()
            .map(|head| parse_snapshot_id(head))
            .collect::<Result<_, _>>()?
    };
    selected.sort();
    Ok(selected)
}

/// Where snapshot merging stalls on a membership conflict: the
/// operator resolves with `member resolve`, never by adding heads.
fn frozen_merge_hint(epoch: u64) -> String {
    format!(
        "membership frozen at epoch {epoch}: resolve it with `member resolve` \
        (see `member status`) before merging snapshots"
    )
}

/// Map a merge refusal that names the membership freeze to usage
/// guidance; every other engine verdict passes through untouched.
fn map_merge_error(error: EngineError) -> CliError {
    match error {
        EngineError::MergeBlockedByFreeze(epoch) => CliError::Usage(frozen_merge_hint(epoch)),
        _ => CliError::Engine(error),
    }
}

/// The OD-15-5 presentation check: refuse before the operator
/// composes a selection when this device is not the current
/// canonical owner. Reads the same membership projection the
/// engine enforces, and the engine still wins any race — a pass
/// here never authorizes anything.
fn check_recovery_owner(engine: &Engine) -> Result<(), CliError> {
    let log = engine.membership_log();
    let known = log
        .known_state()
        .ok_or(EngineError::NoCanonicalMembership)?;
    match log.owners_of(&known.transition_id) {
        Some(owners) if owners.len() == 1 && owners.contains(&engine.device()) => Ok(()),
        _ => Err(CliError::Engine(EngineError::RecoveryNotOwner)),
    }
}

/// One merge-spec path: a root entry name. v0 merges at root-entry
/// granularity (a conflicting subtree is taken or dropped whole),
/// so anything deeper is refused at the argument boundary.
fn check_merge_path(path: &str) -> Result<String, CliError> {
    if path.is_empty() || path.contains('/') {
        return Err(CliError::Usage(format!(
            "merge paths are root entries, got {path:?}"
        )));
    }
    Ok(path.to_owned())
}

/// One recovery-selection path: the same root-entry granularity
/// as the merge spec, so a grafted subtree travels whole.
fn check_recover_path(path: &str) -> Result<String, CliError> {
    if path.is_empty() || path.contains('/') {
        return Err(CliError::Usage(format!(
            "recover paths are root entries, got {path:?}"
        )));
    }
    Ok(path.to_owned())
}

/// Author a membership transition plus its namespace carry in one
/// offline step: stage the served heads as durable obligations,
/// commit the transition via `author`, then drain the carry queue
/// at the new epoch (transition continuity: a quiet drive keeps
/// serving its files, and the next write extends the carry instead
/// of bootstrapping from empty). Staging precedes the
/// transition commit, so a crash between the commit and the drain
/// leaves a discoverable obligation: the next drain — after a
/// restart, or after the next transition — completes it. The object
/// store opens only when something is pending, so a fresh drive's
/// transition never touches it. A failed drain reports loudly with
/// the transition already durable at its epoch and the obligation
/// still pending.
fn transition_with_carry(
    engine: &mut Engine,
    drive_dir: &Path,
    author: impl FnOnce(&mut Engine) -> Result<MembershipTransition, EngineError>,
) -> Result<(MembershipTransition, usize), CliError> {
    engine.stage_carry_heads()?;
    let transition = author(engine)?;
    let carried = carry_pending(engine, drive_dir)?;
    Ok((transition, carried))
}

/// Drain the durable carry queue, returning the number carried. The
/// store opens only when obligations are pending.
fn carry_pending(engine: &mut Engine, drive_dir: &Path) -> Result<usize, CliError> {
    if engine.pending_carries()?.is_empty() {
        return Ok(0);
    }
    let store = FsObjectStore::open(drive_dir.to_path_buf())
        .map_err(|error| CliError::Store(error.to_string()))?;
    Ok(engine.carry_pending(&store)?.authored.len())
}

/// Claim an invitation destination before any irreversible step: an
/// existing file is refused outright (no silent overwrite after a
/// membership change), and an uncreatable path fails here with
/// nothing authored. Callers remove the claim when their fallible
/// step fails so a retry starts clean.
fn claim_out(out: &Path) -> Result<fs::File, CliError> {
    if out.exists() {
        return Err(CliError::Usage(
            "invitation destination already exists; remove it or choose another path".into(),
        ));
    }
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() && !parent.is_dir() {
            return Err(CliError::Usage(
                "invitation destination's parent directory does not exist".into(),
            ));
        }
    }
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out)
        .map_err(|source| CliError::Io {
            path: out.to_path_buf(),
            source,
        })
}

/// Publish a sealed invitation through a claimed file. A write
/// failure past the commit removes the claim and reports the
/// standing state (for invite, the admission; for reissue, nothing
/// changed at all).
fn write_invitation(out: &Path, file: &mut fs::File, bytes: &[u8]) -> Result<(), CliError> {
    if let Err(source) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(out);
        return Err(CliError::Io {
            path: out.to_path_buf(),
            source,
        });
    }
    Ok(())
}

/// Pair this device with a drive over the keystore: identify it,
/// stage pairing material, or join from a sealed invitation. Like
/// `member`, everything here is offline — files in, files out.
fn device(
    drive_dir: PathBuf,
    action: DeviceAction,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> Result<(), CliError> {
    match action {
        DeviceAction::Id => {
            let engine = Engine::open_keystore(drive_dir, passphrase, identity)?;
            print!("{}", device_id_report(&engine)?);
            Ok(())
        }
        DeviceAction::PairingRequest { out } => {
            let pairing = Engine::pairing_request(&drive_dir, passphrase, &identity)?;
            fs::write(
                &out,
                format!(
                    "device {}\nencryption-key {}\n",
                    pairing.device, pairing.encryption_key
                ),
            )
            .map_err(|source| CliError::Io {
                path: out.clone(),
                source,
            })?;
            println!(
                "pairing material for {} -> {}",
                pairing.device,
                out.display()
            );
            Ok(())
        }
        DeviceAction::Join { invitation } => {
            let bytes = read_bounded(&invitation, MAX_INVITATION_BYTES)?;
            let sealed = SealedBootstrap::decode(&bytes).map_err(|_| CliError::InvitationFormat)?;
            let engine = Engine::join(drive_dir, passphrase, identity, &sealed)?;
            let epoch = engine
                .membership_log()
                .known_state()
                .map(|tip| tip.epoch)
                .unwrap_or(0);
            println!(
                "joined {} drive {} at epoch {epoch}",
                engine.device(),
                engine.drive()
            );
            Ok(())
        }
    }
}

/// Read a bounded non-credential input file. Invitation bytes are
/// sealed, not secret, so no ownership hardening applies — but an
/// unbounded read lets a corrupt file exhaust memory before decode
/// refuses it.
fn read_bounded(path: &Path, max: usize) -> Result<Vec<u8>, CliError> {
    let mut file = fs::File::open(path).map_err(|source| CliError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take((max + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| CliError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() > max {
        return Err(CliError::InvitationTooLarge);
    }
    Ok(bytes)
}

/// The sealed invitation bound: genesis plus one wrapped capability.
/// Kilobytes in practice; a megabyte leaves headroom no honest
/// inviter approaches.
const MAX_INVITATION_BYTES: usize = 1024 * 1024;

/// This device's id plus the encryption key the membership state
/// registers for it. `unregistered` is honest, not an error: a fresh
/// join holds genesis only, and its own admission arrives with the
/// catch-up set. Built as a string so tests assert the rendering
/// without capturing stdout.
fn device_id_report(engine: &Engine) -> Result<String, CliError> {
    let device = engine.device();
    let log = engine.membership_log();
    let registered = log
        .known_state()
        .and_then(|tip| log.state_of(&tip.transition_id))
        .and_then(|state| state.encryption_key_of(&device).copied());
    Ok(match registered {
        Some(key) => format!("device {device}\nencryption-key {key}\n"),
        None => format!("device {device}\nencryption-key unregistered\n"),
    })
}

/// Parse a device identity from 64 hex characters (x-only pubkey).
fn parse_device_id(hex: &str) -> Result<DeviceId, CliError> {
    let bytes = hex::decode(hex.trim())
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| {
            CliError::Usage("device must be 64 hex characters naming an x-only pubkey".into())
        })?;
    Ok(DeviceId::from_bytes(bytes))
}

/// Parse a snapshot id from 64 hex characters (the merge sources
/// named by `snapshot merge --head`).
fn parse_snapshot_id(hex: &str) -> Result<SnapshotId, CliError> {
    let bytes = hex::decode(hex.trim())
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| {
            CliError::Usage("snapshot must be 64 hex characters naming a snapshot id".into())
        })?;
    Ok(SnapshotId::from_bytes(bytes))
}

/// Parse a content id from 64 hex characters (the `--content`
/// escape hatch for grafting bytes whose path is unknown).
fn parse_content_id(hex: &str) -> Result<wyrd_format::ContentId, CliError> {
    let bytes = hex::decode(hex.trim())
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| {
            CliError::Usage("content must be 64 hex characters naming a content id".into())
        })?;
    Ok(wyrd_format::ContentId::from_bytes(bytes))
}

/// Parse a membership transition id from 64 hex characters (the
/// winner and voided siblings named by `member resolve`).
fn parse_transition_id(hex: &str) -> Result<TransitionId, CliError> {
    let bytes = hex::decode(hex.trim())
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| {
            CliError::Usage("transition must be 64 hex characters naming a transition id".into())
        })?;
    Ok(TransitionId::from_bytes(bytes))
}

/// Parse a device encryption key from 64 hex characters (x-only
/// pubkey, from the newcomer's pairing-request output).
fn parse_encryption_key(hex: &str) -> Result<DeviceEncryptionKey, CliError> {
    let bytes = hex::decode(hex.trim())
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| {
            CliError::Usage(
                "encryption key must be 64 hex characters naming an x-only pubkey".into(),
            )
        })?;
    Ok(DeviceEncryptionKey::from_bytes(bytes))
}

/// Removing the sole owner is valid but terminal (epochs.md): it
/// empties the owner set and no future transition can be authorized.
/// Refuse without explicit confirmation; the protocol stays
/// authoritative and would accept the transition either way.
fn require_last_owner_confirmation(
    engine: &Engine,
    device: &DeviceId,
    yes: bool,
) -> Result<(), CliError> {
    let Some(tip) = engine.membership_log().known_state() else {
        return Ok(());
    };
    let Some(owners) = engine.membership_log().owners_of(&tip.transition_id) else {
        return Ok(());
    };
    if owners.len() == 1 && owners.contains(device) && !yes {
        return Err(CliError::Usage(
            "removing the sole owner permanently ends owner-authorized evolution; pass --yes to confirm"
                .into(),
        ));
    }
    Ok(())
}

/// Members and owners at the canonical tip, one identity per line.
/// Built as a string (not printed) so tests assert the rendering
/// without capturing stdout.
fn member_list_report(engine: &Engine) -> Result<String, CliError> {
    let log = engine.membership_log();
    let Some(tip) = log.known_state() else {
        return Err(CliError::Engine(
            wyrd_sync::runtime::EngineError::NoCanonicalMembership,
        ));
    };
    let members = log.members_of(&tip.transition_id).unwrap_or_default();
    let owners = log.owners_of(&tip.transition_id).unwrap_or_default();
    let readers = log.readers_of(&tip.transition_id).unwrap_or_default();
    let mut out = format!("epoch {} tip {}\n", tip.epoch, tip.transition_id);
    for owner in &owners {
        out.push_str(&format!("owner {owner}\n"));
    }
    for member in &members {
        if !owners.contains(member) {
            out.push_str(&format!("member {member}\n"));
        }
    }
    for reader in &readers {
        out.push_str(&format!("reader {reader}\n"));
    }
    Ok(out)
}

/// Every observed transition in epoch order with its canonical
/// status; frozen conflict epochs are marked. Built as a string so
/// tests assert the rendering without capturing stdout.
fn member_log_report(engine: &Engine) -> Result<String, CliError> {
    let log = engine.membership_log();
    let statuses = log.statuses();
    let frozen = log.frozen_at();
    let mut entries: Vec<(u64, TransitionId)> = statuses
        .keys()
        .filter_map(|id| log.transition(id).map(|t| (t.epoch, *id)))
        .collect();
    entries.sort();
    let mut out = String::new();
    for (epoch, id) in entries {
        let status = statuses.get(&id).expect("statused above");
        let author = log
            .transition(&id)
            .map(|t| t.author.to_string())
            .unwrap_or_else(|| "?".into());
        let frozen_marker = match frozen {
            Some(frozen_epoch) if frozen_epoch == epoch => " frozen",
            _ => "",
        };
        out.push_str(&format!(
            "epoch {epoch} {id} {} author {author}{frozen_marker}\n",
            render_status(status)
        ));
    }
    Ok(out)
}

/// Known tip, frozen conflicts, and held epoch secrets. Knowledge is
/// not possession: a known epoch without its secret authorizes
/// nothing until the capability arrives. Built as a string so tests
/// assert the rendering without capturing stdout.
fn member_status_report(engine: &Engine) -> Result<String, CliError> {
    let log = engine.membership_log();
    let Some(tip) = log.known_state() else {
        return Err(CliError::Engine(
            wyrd_sync::runtime::EngineError::NoCanonicalMembership,
        ));
    };
    let members = log.members_of(&tip.transition_id).unwrap_or_default();
    let owners = log.owners_of(&tip.transition_id).unwrap_or_default();
    let held = engine.held_epochs().map_err(CliError::Engine)?;
    let held_list = held
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    let frozen_line = match log.frozen_at() {
        Some(epoch) => {
            // Rival tips: the live contenders the frozen epoch waits
            // on, from the same derivation the resolver validates
            // against — status can never list a rival resolve then
            // refuses. Sorted for stable output.
            let rivals = engine
                .frozen_contenders()
                .into_iter()
                .map(|id| id.to_string())
                .collect::<Vec<_>>()
                .join(" ");
            format!("frozen at epoch {epoch}\nrivals: {rivals}")
        }
        None => "frozen: no".into(),
    };
    Ok(format!(
        "epoch {} tip {}\nmembers {} owners {}\n{frozen_line}\nheld secrets: {held_list}\n",
        tip.epoch,
        tip.transition_id,
        members.len(),
        owners.len(),
    ))
}

/// Live heads with their `@N` merge numbers, ascending by id —
/// the same order the `name@N` conflict siblings use. Built as a
/// string so tests assert the rendering without capturing stdout.
fn snapshot_list_report(engine: &Engine) -> Result<String, CliError> {
    let heads = engine.live_heads()?;
    if heads.is_empty() {
        return Ok("live heads: none\n".into());
    }
    let mut out = String::from("live heads:\n");
    for (number, head) in heads.iter().enumerate() {
        let snapshot = head.snapshot();
        out.push_str(&format!(
            "@{} {} epoch {} author {} tree {} parents {}{}\n",
            number + 1,
            snapshot.snapshot_id(),
            snapshot.epoch,
            snapshot.author,
            snapshot.tree,
            snapshot.parents.len(),
            recovery_marker(snapshot.flags()),
        ));
    }
    Ok(out)
}

/// Every DAG head with its authorization classification; eligible
/// heads carry their `@N` merge numbers. Built as a string so tests
/// assert the rendering without capturing stdout.
fn snapshot_heads_report(engine: &Engine) -> Result<String, CliError> {
    let heads = engine.snapshot_heads()?;
    if heads.is_empty() {
        return Ok("heads: none\n".into());
    }
    let mut eligible: Vec<SnapshotId> = heads
        .iter()
        .filter(|head| {
            matches!(
                head.classification,
                wyrd_sync::authorization::Classification::Eligible
            )
        })
        .map(|head| head.id)
        .collect();
    eligible.sort();
    let mut out = String::from("heads:\n");
    for head in &heads {
        let number = eligible
            .iter()
            .position(|id| *id == head.id)
            .map(|number| format!(" @{}", number + 1))
            .unwrap_or_default();
        out.push_str(&format!(
            "{}{} {} epoch {}{}\n",
            head.id,
            number,
            render_classification(&head.classification),
            head.epoch,
            recovery_marker(head.flags),
        ));
    }
    Ok(out)
}

/// Preview a merge without authoring: one row per root path over
/// the plan's `@N` basis, naming each head's version. Agreed paths
/// take themselves; conflicted rows are the `--take` lines the
/// merge still needs. Built as a string so tests assert the
/// rendering without capturing stdout.
fn snapshot_plan_report(plan: &wyrd_sync::runtime::MergePlan) -> String {
    use wyrd_format::EntryContent;
    let mut out = format!("merge plan ({} heads):\n", plan.heads.len());
    for path in &plan.paths {
        if path.agreed() {
            out.push_str(&format!("{}: agreed\n", path.path));
            continue;
        }
        let mut versions = Vec::new();
        for (number, head) in plan.heads.iter().enumerate() {
            let version = match path.versions.get(head).and_then(|version| version.as_ref()) {
                None => "absent".to_owned(),
                Some(entry) => match &entry.content {
                    EntryContent::File { size, chunks, .. } => {
                        format!("file:{size}B,{}chunks", chunks.len())
                    }
                    EntryContent::Dir { .. } => "dir".to_owned(),
                    EntryContent::Symlink { .. } => "symlink".to_owned(),
                },
            };
            versions.push(format!("@{}={}", number + 1, version));
        }
        out.push_str(&format!(
            "{}: conflicted {}\n",
            path.path,
            versions.join(" ")
        ));
    }
    out
}

/// The recovery audit marker: a recovery-flagged snapshot names
/// itself in both head views, so grafts stay visible as long as the
/// snapshot is listed at all.
fn recovery_marker(flags: u8) -> &'static str {
    if flags & RECOVERY_FLAG != 0 {
        " recovery"
    } else {
        ""
    }
}

/// Preview a recovery without authoring: one row per source root
/// path with its status, so the operator sees what is graftable,
/// what is already live, and what is gone. Built as a string so
/// tests assert the rendering without capturing stdout.
fn recovery_plan_report(plan: &wyrd_sync::runtime::RecoveryPlan) -> String {
    use wyrd_sync::runtime::RecoveryStatus;
    let mut out = format!("recovery plan (from {}):\n", plan.from);
    for row in &plan.paths {
        let status = match row.status {
            RecoveryStatus::Ready => "ready".to_owned(),
            RecoveryStatus::AlreadyLive => {
                "already-live: a current head holds this path — recovery is the wrong verb"
                    .to_owned()
            }
            RecoveryStatus::Undecryptable => {
                "undecryptable: no held epoch decrypts these bytes".to_owned()
            }
            RecoveryStatus::Missing => "missing: bytes are not local".to_owned(),
        };
        out.push_str(&format!("{}: {status}\n", row.path));
    }
    out
}

/// One-word head class for the heads view; parked and rejected
/// heads carry their machine reason.
fn render_classification(class: &wyrd_sync::authorization::Classification) -> String {
    use wyrd_sync::authorization::Classification;
    match class {
        Classification::Eligible => "eligible".into(),
        Classification::CanonicalHistory => "canonical-history".into(),
        Classification::Superseded => "superseded".into(),
        Classification::Stranded => "stranded".into(),
        Classification::Voided => "voided".into(),
        Classification::Pending(pendency) => format!("pending:{pendency:?}"),
        Classification::Rejected(rejection) => format!("rejected:{rejection:?}"),
    }
}

/// One-word canonical status for the log view; invalid transitions
/// carry their machine reason.
fn render_status(status: &TransitionStatus) -> String {
    match status {
        TransitionStatus::Canonical => "canonical".into(),
        TransitionStatus::Contested => "contested".into(),
        TransitionStatus::Voided => "voided".into(),
        TransitionStatus::Orphaned => "orphaned".into(),
        TransitionStatus::Pending => "pending".into(),
        TransitionStatus::Invalid(reason) => format!("invalid:{reason:?}"),
    }
}

/// macOS mount-failure checklist, printed next to the raw error.
/// macFUSE's libfuse2 mount can return -1 without setting errno, so
/// the errno in the error line may be stale (observed: EOPNOTSUPP
/// left over from an iroh socket op, ENOTTY from elsewhere). The
/// checklist names the fix; the README carries the full procedure.
#[cfg(target_os = "macos")]
const MACOS_MOUNT_HINT: &str = "macOS hint: the errno above may be stale; check \
    the kext (ls /dev/macfuse0; if missing: load macFUSE, approve it in \
    Privacy & Security, reboot), the mount daemon (pgrep -af \
    io.macfuse.app.launchservice.daemon; if missing: sudo launchctl kickstart \
    -k system/io.macfuse.app.launchservice.daemon), and the README macOS section.";

/// Fail fast when the macOS FUSE runtime cannot mount: macFUSE
/// missing entirely, or installed with its kext unloaded. Both states
/// are plain path probes so the logic stays unit-testable; only the
/// wiring (real /Library and /dev roots) is macOS-gated at the call
/// site. The mountpoint itself must already be a directory — fuser
/// would reject anything else with a bare ENOENT.
///
/// Best-effort only: a passing preflight does not guarantee the mount
/// will succeed (stale device nodes, alternate install layouts), and
/// the real mount error remains authoritative.
/// The mount serves read-write: the session backend already carries
/// the live daemon's mutation channel, so the kernel must not gate
/// writes behind a read-only flag. The FSName keeps the volume
/// identifiable in mount tables.
fn session_config() -> Config {
    let mut config = Config::default();
    config.mount_options = vec![MountOption::FSName("wyrd".into())];
    config
}

fn main() {
    if let Err(error) = command(env::args().skip(1).collect()) {
        eprintln!("error: {error}");
        std::process::exit(2);
    }
}

mod logging;
mod probes;

#[cfg(test)]
mod tests_cli;
#[cfg(test)]
mod tests_device;
#[cfg(test)]
mod tests_export;
#[cfg(test)]
mod tests_harness;
#[cfg(test)]
mod tests_member;
#[cfg(test)]
mod tests_mount;
#[cfg(test)]
mod tests_policy;
#[cfg(test)]
mod tests_probes;
#[cfg(test)]
mod tests_snapshot;
#[cfg(test)]
mod tests_sync;

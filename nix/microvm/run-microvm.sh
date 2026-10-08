#!/usr/bin/env bash
# nix/microvm/run-microvm.sh — host runner for the hardened e2e gate.
# Runs on the Linux KVM host (odin) as root: qemu tap devices, the
# virtiofsd share daemons, and the bridge all need privilege (the
# microvm.nix virtiofsd wrapper refuses non-root, and taps attach to
# a host bridge). One command end to end:
#
#   sudo ./nix/microvm/run-microvm.sh [--state-dir DIR] [--fresh] [--keep]
#   sudo ./nix/microvm/run-microvm.sh [--state-dir DIR] [--step N[,N...]]
#   sudo ./nix/microvm/run-microvm.sh --teardown
#
#   --state-dir DIR  host state root (default /var/lib/wyrd-microvm/state)
#   --fresh          wipe $STATE_DIR/run before booting (default: keep,
#                    so a failed run's drives survive for forensics)
#   --keep           leave VMs and network up afterwards for debugging
#   --step           run suite phases 1..N (comma lists allowed; the run
#                    is the prefix closure, since phases build on each
#                    other: 1-5 are the shared-core Lima steps on peer-o,
#                    6-11 the microvm phases in tests/alpha-microvm.sh)
#   --teardown       stop a kept run (daemons, taps, bridge) and exit;
#                    takes the run lock, so it refuses while a suite
#                    is active. State dirs and logs are retained.
#
# Flow: build wyrd + three VM runners -> bridge/taps -> ephemeral ssh
# key + e2e-env.sh into the state share -> boot virtiofsd+qemu per VM
# (own cwd each: qemu uses relative socket paths) -> wait for ssh ->
# wait for the relay control plane -> tests/alpha-microvm.sh ->
# report -> teardown (unless --keep).
# The whole suite runs under `timeout` (90 min): a hung guest must
# fail the run, never the evening. Legs carry their own shorter
# polls; this bound is whole-run pathology cover. Raised from 60
# when the relay-partition conflict phase landed: phases 9 and 10
# each document ~11 and ~20-25 minute nominal worst cases, and an
# opaque SIGKILL at the cap must never be the way a slow conflict
# phase reports.
set -euo pipefail

need() { command -v "$1" >/dev/null || { echo "error: missing host tool: $1" >&2; exit 2; }; }

STATE_DIR="/var/lib/wyrd-microvm/state"
FRESH=0
KEEP=0
TEARDOWN=0
ONLY_STEP=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --state-dir) STATE_DIR="$2"; shift 2 ;;
    --fresh) FRESH=1; shift ;;
    --keep) KEEP=1; shift ;;
    --step)
      # An explicit but empty value is a mistake, not "all phases".
      [[ -n "${2:-}" ]] || { echo "error: --step needs at least one step" >&2; exit 2; }
      ONLY_STEP="$2"
      shift 2
      ;;
    --teardown) TEARDOWN=1; shift ;;
    *) echo "error: unknown flag $1 (see header)" >&2; exit 2 ;;
  esac
done

# Validate --step now, not after the multi-minute build and boot: a
# typo must fail here. The orchestrator re-checks (same grammar), so
# a direct tests/alpha-microvm.sh invocation fails the same way.
if [[ -n "$ONLY_STEP" ]]; then
  # The grammar is a comma list; whitespace is not a separator.
  [[ "$ONLY_STEP" != *[[:space:]]* ]] \
    || { echo "error: --step: '$ONLY_STEP' is not a comma list (got whitespace)" >&2; exit 2; }
  # An empty entry (`,`, `4,,5`, `,4`) is a mistake, not "all phases":
  # without this it would run zero checks and pass.
  [[ ",$ONLY_STEP," != *,,* ]] \
    || { echo "error: --step: '$ONLY_STEP' has an empty entry (expected 1-11 entries)" >&2; exit 2; }
  # Split on commas into a quoted array: an unquoted expansion would
  # glob each entry against the working directory first, so `--step
  # '*'` could pathname-expand into a digit-named file and slip past
  # the grammar.
  _step_entries=()
  IFS=',' read -r -a _step_entries <<< "$ONLY_STEP"
  for _e in "${_step_entries[@]}"; do
    [[ "$_e" =~ ^([1-9]|1[01])$ ]] \
      || { echo "error: --step: '$_e' is not a step (expected a comma list of 1-11)" >&2; exit 2; }
  done
  unset _step_entries _e
fi

[[ "$EUID" == 0 ]] || { echo "error: run as root (taps, bridge, virtiofsd need it)" >&2; exit 2; }
ROOT="$(git rev-parse --show-toplevel 2>/dev/null || { echo 'error: run from the wyrd checkout' >&2; exit 2; })"
cd "$ROOT"

# Tools per mode, checked after flag parsing so --teardown only
# demands what it uses. Flag combos with --teardown fail loudly
# instead of silently ignoring the rest; a non-default --state-dir
# with --teardown is refused for the same reason (taps, bridge, and
# daemon pattern are all host-global, so it would be ignored).
if [[ "$TEARDOWN" == 1 ]]; then
  [[ "$FRESH" == 0 && "$KEEP" == 0 && -z "$ONLY_STEP" ]] || { echo "error: --teardown takes no other flags" >&2; exit 2; }
  [[ "$STATE_DIR" == "/var/lib/wyrd-microvm/state" ]] || { echo "error: --teardown ignores --state-dir (host-global)" >&2; exit 2; }
  for t in git pgrep ps kill pkill ip flock; do need "$t"; done
else
  for t in nix ssh ssh-keygen ip ss timeout flock ps pgrep pkill; do need "$t"; done
fi

# One run at a time per host, not per state dir: taps, the bridge,
# and SOCK_PAT are all host-global, so two runs under different
# --state-dir would still reap each other's daemons and fight over
# br-wyrd. The lock path is fixed for the same reason. Held for the
# whole script via fd 9.
mkdir -p /var/lib/wyrd-microvm
exec 9>/var/lib/wyrd-microvm/lock
flock -n 9 || { echo "error: another run holds /var/lib/wyrd-microvm/lock" >&2; exit 2; }

BRIDGE="br-wyrd"
NET="10.0.7"
RUN="$STATE_DIR/run"
WORK="$STATE_DIR/work"
SSH_KEY="$STATE_DIR/sshkey"

die() { echo "  FAIL: $1" >&2; exit 1; }

# Unique string in every daemon cmdline we start (virtiofsd
# --socket-path and qemu -chardev path). PID files cannot work:
# $! is the spawner subshell (dead on arrival), and kept runs are
# strangers to the next invocation. So both the startup pre-clean
# and the EXIT trap kill by this pattern, which cannot match
# anything but our own daemons.
SOCK_PAT='wyrd-.*-virtiofs-wyrd-state\.sock'

kill_stale_daemons() {
  local pids pid ppid
  pids="$(pgrep -f "$SOCK_PAT" || true)"
  [[ -z "$pids" ]] && return 0
  # Supervisors first (the parents): SIGTERM stops their children
  # cleanly instead of orphaning them into a restart loop.
  for pid in $pids; do
    ppid="$(ps -o ppid= -p "$pid" 2>/dev/null || true)"
    ppid="$(echo "$ppid" | tr -d ' ')"
    if [[ -n "$ppid" && "$ppid" != 1 && "$ppid" != "$$" ]]; then
      kill "$ppid" 2>/dev/null || true
    fi
  done
  sleep 2
  pkill -f "$SOCK_PAT" 2>/dev/null || true
  sleep 1
  # Escalate: a surviving daemon (wedged qemu, respawning
  # supervisor) must not be reported as removed below.
  pids="$(pgrep -f "$SOCK_PAT" || true)"
  [[ -z "$pids" ]] || pkill -KILL -f "$SOCK_PAT" 2>/dev/null || true
  sleep 1
  pids="$(pgrep -f "$SOCK_PAT" || true)"
  [[ -z "$pids" ]] || { echo "  FAIL: stale daemons survive SIGKILL: $pids" >&2; return 1; }
  return 0
}

teardown() {
  if [[ "$KEEP" == 0 ]]; then
    kill_stale_daemons
    for t in tap-o tap-n tap-r; do ip link del "$t" 2>/dev/null || true; done
    ip link del "$BRIDGE" 2>/dev/null || true
  else
    echo "kept: VMs, taps, and $BRIDGE left up (--keep)"
  fi
}
trap teardown EXIT

# Standalone teardown for kept runs: reuse teardown() with keeping
# disabled, so the success line below only prints when the kills
# and link deletions actually succeeded (kill_stale_daemons fails
# loudly on survivors under set -e).
# Never inline SOCK_PAT into `bash -c '...'`: pkill matches our own
# argv and kills this shell. The variable form is safe.
if [[ "$TEARDOWN" == 1 ]]; then
  echo "==> tearing down kept run"
  KEEP=0; teardown
  # Verify, don't claim: a surviving guest with a deleted NIC is
  # worse than a loud failure.
  for t in tap-o tap-n tap-r; do
    ip link show "$t" &>/dev/null && die "tap $t survives teardown"
  done
  ip link show "$BRIDGE" &>/dev/null && die "$BRIDGE survives teardown"
  echo "torn down: daemons, taps, and $BRIDGE removed ($STATE_DIR retained)"
  exit 0
fi

# Reap strangers first: kept runs, killed ssh sessions, and
# supervisor restart loops all leave daemons holding our sockets.
# Idempotent: a no-op when nothing is running. Placed after the
# definitions above; bash reads top-down.
kill_stale_daemons

echo "==> state dir $STATE_DIR"
mkdir -p "$RUN" "$RUN/logs" "$WORK"
[[ "$FRESH" == 1 ]] && rm -rf "$RUN" && mkdir -p "$RUN" "$RUN/logs"
# The share is root-owned from the host; guest e2e (uid 1000, the
# only normal user — numeric, no host user needed) must own the run
# state or every drive/cred/mount mkdir fails. sshkey stays root.
chown -R 1000:1000 "$RUN"

echo "==> building wyrd + VM runners"
if ! WYRD_OUT="$(nix build "$ROOT#packages.x86_64-linux.wyrd" --no-link --print-out-paths --print-build-logs 2>"$RUN/logs/nix-build-wyrd.log" | tail -n 1)"; then
  die "host build failed (see run/logs/nix-build-wyrd.log)"
fi
WYRD_BIN="$WYRD_OUT/bin/wyrd"
[[ -x "$WYRD_BIN" ]] || die "host build produced no wyrd binary (see run/logs/nix-build-wyrd.log)"
echo "    $WYRD_BIN"
# Pinned nak for the opacity probe (see the flake comment): same
# no-link pattern as wyrd, so the suite never floats the registry.
if ! NAK_OUT="$(nix build "$ROOT#packages.x86_64-linux.nak" --no-link --print-out-paths --print-build-logs 2>"$RUN/logs/nix-build-nak.log" | tail -n 1)"; then
  die "host nak build failed (see run/logs/nix-build-nak.log)"
fi
NAK_BIN="$NAK_OUT/bin/nak"
[[ -x "$NAK_BIN" ]] || die "host build produced no nak binary (see run/logs/nix-build-nak.log)"
echo "    $NAK_BIN"
for role in peer-o peer-n relay; do
  nix build "$ROOT#nixosConfigurations.wyrd-$role.config.microvm.runner.qemu" \
    --out-link "$WORK/runner-$role" --print-build-logs 2>&1 | tee "$RUN/logs/nix-build-$role.log"
done

echo "==> network: $BRIDGE ${NET}.0/24"
ip link add "$BRIDGE" type bridge 2>/dev/null || true
ip addr add "$NET.1/24" dev "$BRIDGE" 2>/dev/null || true
ip link set "$BRIDGE" up
declare -A TAP_IP=( [peer-o]=11 [peer-n]=12 [relay]=10 )
declare -A TAP_DEV=( [peer-o]=tap-o [peer-n]=tap-n [relay]=tap-r )

echo "==> ssh key + guest env"
[[ -f "$SSH_KEY" ]] || ssh-keygen -t ed25519 -N "" -f "$SSH_KEY" -q
cp "$SSH_KEY.pub" "$STATE_DIR/authorized_keys.pub"
{
  echo "# Generated by run-microvm.sh; sourced by the suite in guests."
  printf 'WYRD_BIN=%q\n' "$WYRD_BIN"
  printf 'RELAY_PORT=%q\n' "18761"
  printf 'RELAY_HOST=%q\n' "$NET.10"
  printf 'RELAY_MANAGED=%q\n' "0"
  printf 'CHECKOUT=%q\n' "/etc/wyrd-tests"
  printf 'E2E_ROOT=%q\n' "/mnt/wyrd-state/run"
  printf 'E2E_RUST_LOG=%q\n' "${E2E_RUST_LOG:-}"
} > "$STATE_DIR/e2e-env.sh"

echo "==> booting guests"
for role in peer-o peer-n relay; do
  tap="${TAP_DEV[$role]}"
  ip link del "$tap" 2>/dev/null || true
  # multi_queue: the microvm runner attaches with queues=<vcpu>
  # (multiqueue); a single-queue tap fails the attach with EINVAL
  # ("could not configure /dev/net/tun") and the guest never boots.
  ip tuntap add dev "$tap" mode tap multi_queue
  ip link set "$tap" up
  ip link set "$tap" master "$BRIDGE"
  vmdir="$WORK/vm-$role"
  mkdir -p "$vmdir"
  ln -sfn "$WORK/runner-$role" "$vmdir/runner"
  # Stale sockets from a kept run must go: a leftover .sock passes
  # the readiness check below while no daemon listens, and qemu
  # then dies with "Connection refused".
  rm -f "$vmdir"/*.sock
  # 9>&-: the lock fd must not leak into daemons. Kept daemons
  # outlive the runner, and an inherited lock fd would hold the
  # flock forever: no second run could ever start, and --teardown
  # could never acquire the lock it needs to kill them.
  ( cd "$vmdir" \
    && ./runner/bin/virtiofsd-run > virtiofsd.log 2>&1 & ) 9>&-
  # Wait for the socket to LISTEN, not merely exist: the file can
  # appear before virtiofsd accepts, and qemu fails fast on refused.
  for i in $(seq 1 30); do
    ss -xl 2>/dev/null | grep -q "wyrd-$role-virtiofs-wyrd-state.sock" && break
    [[ "$i" == 30 ]] && { tail -n 5 "$vmdir/virtiofsd.log"; die "$role: virtiofsd never listened"; }
    sleep 1
  done
  ( cd "$vmdir" && ./runner/bin/microvm-run > qemu.log 2>&1 & ) 9>&-
  echo "    $role up (tap $tap)"
done

echo "==> waiting for ssh"
SSH="ssh -i $SSH_KEY -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o BatchMode=yes"
for ip in 11 12; do
  for i in $(seq 1 60); do
    $SSH "e2e@$NET.$ip" true 2>/dev/null && break
    [[ "$i" == 60 ]] && die "e2e@$NET.$ip never accepted ssh"
    sleep 2
  done
  echo "    e2e@$NET.$ip reachable"
done

# Relay readiness before the suite: the first relay dial happens
# deep in the legs, where a slow relay boot surfaces as an opaque
# convergence timeout. Fail fast with the real cause instead.
echo "==> waiting for relay"
for i in $(seq 1 30); do
  timeout 2 bash -c "</dev/tcp/$NET.10/18761" 2>/dev/null && break
  [[ "$i" == 30 ]] && die "relay never listened on $NET.10:18761"
  sleep 2
done
echo "    relay control plane reachable"

echo "==> running the suite"
set +e
timeout 5400 env \
  "STATE_DIR=$STATE_DIR" \
  "SSH_KEY=$SSH_KEY" \
  "MICROVM_ONLY_STEP=$ONLY_STEP" \
  "WYRD_BIN=$WYRD_BIN" \
  "NAK_BIN=$NAK_BIN" \
  "RELAY_URL=ws://$NET.10:18761" \
  "PEER_O=e2e@$NET.11" \
  "PEER_N=e2e@$NET.12" \
  bash "$ROOT/tests/alpha-microvm.sh" 9>&-
STATUS=$?
set -e
[[ "$STATUS" == 0 ]] || die "microvm suite failed (exit $STATUS, logs under $RUN/logs)"
echo "microvm: suite green, logs under $RUN/logs"

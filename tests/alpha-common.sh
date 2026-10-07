#!/usr/bin/env bash
# tests/alpha-common.sh — shared e2e contract helpers, sourced (never
# executed) by tests/alpha-lima.sh (single Lima guest) and
# tests/alpha-microvm.sh (multi-host microVM run). Every assertion
# helper here is the suite in both harnesses; steps live in the
# harness scripts.
#
# Layout (all guest-local disk, never a shared fs — FUSE mountpoints
# and drive dirs over 9p are unsupported):
#   $E2E_ROOT/drives/<name>   drive directories under test
#   $E2E_ROOT/creds/<name>    identity/passphrase files (0600)
#   $E2E_ROOT/mnt/<name>      FUSE mountpoints
#   $E2E_ROOT/logs/           per-step stderr captures
#   $PIDDIR/                  mount pid files (default $E2E_ROOT)
#
# Knobs (all optional, with Lima defaults):
#   E2E_ENV_FILE   env file to source (default /tmp/lima/e2e-env.sh)
#   E2E_ROOT       state root (default /tmp/wyrd-e2e)
#   PIDDIR         mount pid files; microVM legs point this at a
#                  per-guest directory so concurrent guests sharing
#                  one E2E_ROOT can never SIGKILL each other's mounts
#   CHECKOUT       repo checkout carrying tests/ (default /mnt/wyrd)
#   RELAY_HOST     relay address peers dial (default 127.0.0.1)
#   RELAY_BIND     address the managed relay binds (default 127.0.0.1)
#   RELAY_MANAGED  1: the suite starts/stops a local relay (Lima);
#                  0: an external relay is used, start/stop are no-ops
#   HOST_LOGS      when set, collect_logs copies LOGDIR there on exit;
#                  when empty, logs stay in LOGDIR for the host to pull
set -euo pipefail

# shellcheck source=/dev/null
source "${E2E_ENV_FILE:-/tmp/lima/e2e-env.sh}"

E2E_ROOT="${E2E_ROOT:-/tmp/wyrd-e2e}"
PIDDIR="${PIDDIR:-$E2E_ROOT}"
DRIVES="$E2E_ROOT/drives"
CREDS="$E2E_ROOT/creds"
MNTS="$E2E_ROOT/mnt"
LOGDIR="$E2E_ROOT/logs"
CHECKOUT="${CHECKOUT:-/mnt/wyrd}"
RELAY_HOST="${RELAY_HOST:-127.0.0.1}"
RELAY_BIND="${RELAY_BIND:-127.0.0.1}"
RELAY_MANAGED="${RELAY_MANAGED:-1}"
HOST_LOGS="${HOST_LOGS:-}"

collect_logs() {
  [[ -n "$HOST_LOGS" ]] || return 0
  # Every step here is masked: this runs in EXIT traps under `set
  # -e`, on shares the guest may not be able to write, and a
  # teardown failure must never flip the run's verdict. The copy
  # itself is time-boxed — an unwritable 9p share must not turn the
  # bounded exit this trap exists for into a new hang. Report the
  # real outcome: a timeout (124) means slow, any other status
  # means failed, and the copy's own stderr carries the reason.
  mkdir -p "$HOST_LOGS" 2>/dev/null || true
  if timeout 60 cp -r "$LOGDIR/." "$HOST_LOGS/"; then
    echo "logs collected under $HOST_LOGS"
  else
    local rc=$?
    if [[ $rc -eq 124 ]]; then
      echo "log copy exceeded 60s, logs stay in $LOGDIR" >&2
    else
      echo "log copy failed (exit $rc), logs stay in $LOGDIR" >&2
    fi
  fi
}

# A failed step must never strand a mount: unmount everything and kill
# leftover mount processes, so the next run starts clean. The unmount is
# attempted unconditionally — gating on `mountpoint -q` or `-e` can skip a
# live mount whose FUSE fs misbehaves under stat. Caller contract: stop
# the relay BEFORE this runs — the bare `wait` below reaps every
# background job of the shell, and a still-live relay blocks it forever
# (the Lima step-failure hang). Mounts are SIGKILLed above, so the wait
# itself is bounded.
cleanup_mounts() {
  local m pidf
  for m in "$MNTS"/*; do
    [[ -e "$m" || -L "$m" ]] || continue
    fusermount3 -uz "$m" 2>/dev/null || umount -l "$m" 2>/dev/null || true
  done
  for pidf in "$PIDDIR"/mount-*.pid; do
    [[ -f "$pidf" ]] || continue
    kill -KILL "$(cat "$pidf")" 2>/dev/null || true
  done
  # Reap anything we killed so no zombies linger.
  wait 2>/dev/null || true
  # A just-killed mount can need a beat before the kernel releases it.
  sleep 1
  for m in "$MNTS"/*; do
    [[ -e "$m" || -L "$m" ]] || continue
    fusermount3 -uz "$m" 2>/dev/null || true
  done
}
trap 'cleanup_mounts; collect_logs' EXIT

PASS_COUNT=0
step()  { echo "=== step $1: $2 ==="; }
pass()  { PASS_COUNT=$((PASS_COUNT + 1)); echo "  PASS: $1"; }
die()   { echo "  FAIL: $1" >&2; exit 1; }

wyrd() { "$WYRD_BIN" "$@"; }

# with_creds <cred-dir> <subcommand> <args...>: credential flags precede
# positionals on every subcommand (`wyrd <sub> --identity-file ... <dirs>`).
with_creds() {
  local c="$1" sub="$2"; shift 2
  "$WYRD_BIN" "$sub" --identity-file "$c/identity" --passphrase-file "$c/passphrase" "$@"
}

# expect_exit <code> <log-name> <cmd...>: run, capture stderr to the log,
# assert the exit code. stdout passes through for command substitution.
expect_exit() {
  local want="$1" name="$2"; shift 2
  local err="$LOGDIR/$name.stderr"
  local out
  set +e
  out="$("$@" 2>"$err")"
  local got=$?
  set -e
  [[ $got -eq "$want" ]] || die "$name: exit $got, want $want (stderr: $(cat "$err"))"
  printf '%s' "$out"
}

# expect_fail2 <log-name> <cmd...>: exit 2 with `error: ...` on stderr.
# A usage error is a bug in the suite, not a closed failure: reject it so a
# misspelled invocation can never pass as a negative case.
expect_fail2() {
  local name="$1"; shift
  expect_exit 2 "$name" "$@" >/dev/null
  grep -qE "Usage:|unexpected argument" "$LOGDIR/$name.stderr" \
    && die "$name: usage error, not a closed failure"
  head -c 7 "$LOGDIR/$name.stderr" | grep -q "^error: " \
    || die "$name: stderr does not start with 'error: '"
  pass "$name fails closed (exit 2, error: ...)"
}

# expect_usage2 <log-name> <cmd...>: exit 2 with a usage error
# (the complement of expect_fail2: here a bad invocation IS the case).
expect_usage2() {
  local name="$1"; shift
  expect_exit 2 "$name" "$@" >/dev/null
  grep -qE "Usage:|unexpected argument" "$LOGDIR/$name.stderr" \
    || die "$name: expected a usage error"
  pass "$name refused as a usage error (exit 2)"
}

# Credential factories. Secrets stay in files plus shell vars for the
# leak check; they never reach logs (asserted per step).
gen_identity() { # <out>: 32 random bytes as 64 hex chars, mode 600
  python3 -c 'import secrets; print(secrets.token_hex(32))' > "$1"
  chmod 600 "$1"
}
gen_passphrase() { # <out>: random passphrase with trailing newline, 600
  python3 -c 'import secrets; print("e2e-" + secrets.token_hex(16))' > "$1"
  chmod 600 "$1"
}

# check_no_leaks <log-file> <secret...>: fail if any secret bytes appear.
check_no_leaks() {
  local log="$1"; shift
  local s
  for s in "$@"; do
    grep -qF "$s" "$log" && die "secret leaked into $log"
  done
  pass "no secrets in $(basename "$log")"
}

# check_no_content_ids <rendered-file>: fail on any 64-hex run — the
# e2e counterpart of the CLI's hex-run detector, guarding the
# identity boundary on operator surfaces. This is NOT a secrets
# check (see check_no_leaks): 64-hex device ids are not secrets,
# and the senders-observed section deliberately names heard peers,
# so those lines are scrubbed first exactly like the unit test
# scrubs them. Never point this at a whole mount debug log: mount
# logs legitimately carry ContentIds on pre-existing warn lines —
# this helper targets rendered command output only.
check_no_content_ids() {
  local log="$1"
  grep -v "^  sender " "$log" | grep -qE "[0-9a-f]{64}" \
    && die "content-id-shaped token in $log"
  pass "no content-id-shaped tokens in $(basename "$log")"
}

# --- mount helpers -------------------------------------------------------
# Mounts run as background jobs in this shell so `wait` reports their real
# exit status. Readiness is polled via mountpoint(1), not via listing: an
# unmounted empty dir lists fine too.
poll_until() { # <seconds> <cmd...>
  local n="$1"; shift
  local i
  for ((i = 0; i < n * 5; i++)); do
    "$@" >/dev/null 2>&1 && return 0
    sleep 0.2
  done
  return 1
}

start_mount() { # <name> <cred-dir> <drive> <mnt> [mount args...]
  local name="$1" c="$2" d="$3" m="$4"; shift 4
  mkdir -p "$m"
  # Debug passthrough for stuck-peer forensics (E2E_RUST_LOG=wyrd_core=debug):
  # empty means the binary's default info level, never an empty filter.
  # Scoped to the mount process only: offline assertions require stderr
  # to start with `error: `, so the restored shell must not leak it.
  local old_rust_log="${RUST_LOG-__unset}"
  [[ -n "${E2E_RUST_LOG:-}" ]] && export RUST_LOG="$E2E_RUST_LOG"
  with_creds "$c" mount "$d" "$m" "$@" \
    >"$LOGDIR/mount-$name.out" 2>"$LOGDIR/mount-$name.err" &
  mkdir -p "$PIDDIR"
  echo $! > "$PIDDIR/mount-$name.pid"
  if [[ "$old_rust_log" == "__unset" ]]; then unset RUST_LOG; else export RUST_LOG="$old_rust_log"; fi
  poll_until 20 mountpoint -q "$m" \
    || die "$name: mountpoint never came up (see mount-$name.err)"
  pass "$name: mountpoint up"
}

stop_mount() { # <name> <signal> [budget-s = 15]: signal, wait for exit,
  # assert exit 0 + unmounted. The budget is a bound, not a target: a
  # mount holding a large vault persists its serving store on the way
  # out, so step 6's post-bulk stop gets a larger one.
  local name="$1" sig="$2" budget="${3:-15}"
  local pid started elapsed
  started=$(date +%s)
  pid="$(cat "$PIDDIR/mount-$name.pid")"
  kill "-$sig" "$pid"
  local i status="timeout"
  for ((i = 0; i < budget * 5; i++)); do
    if ! kill -0 "$pid" 2>/dev/null; then
      set +e; wait "$pid"; status=$?; set -e
      break
    fi
    sleep 0.2
  done
  elapsed=$(( $(date +%s) - started ))
  [[ "$status" == "0" ]] || die "$name: shutdown exit $status on $sig after ${elapsed}s, want clean 0"
  mountpoint -q "$MNTS/$name" && die "$name: still mounted after $sig"
  # Remove the pid file on the clean path: a stale pid plus pid
  # reuse lets a later cleanup_mounts SIGKILL an unrelated process.
  rm -f "$PIDDIR/mount-$name.pid"
  pass "$name: clean shutdown on $sig (exit 0, unmounted, ${elapsed}s)"
}

# stop_relay: TERM, poll briefly, then KILL — never a bare `wait` on a
# process that may ignore or delay SIGTERM. With RELAY_MANAGED=0 the
# relay is an external service (the microVM relay) and this is a no-op.
stop_relay() {
  [[ "${RELAY_MANAGED:-1}" == 1 ]] || return 0
  local pid i
  [[ -f "$E2E_ROOT/relay.pid" ]] || { pkill -x nostr-rs-relay 2>/dev/null || true; return 0; }
  pid="$(cat "$E2E_ROOT/relay.pid")"
  kill -TERM "$pid" 2>/dev/null || true
  for ((i = 0; i < 25; i++)); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.2
  done
  kill -KILL "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}

# converged <file> <want>: file exists with exactly the wanted content.
converged() {
  [[ -f "$1" ]] && [[ "$(cat "$1")" == "$2" ]]
}

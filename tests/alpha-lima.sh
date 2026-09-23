#!/usr/bin/env bash
# tests/alpha-lima.sh — the Lima e2e contract. Runs INSIDE the NixOS guest
# (via lima/run-alpha.sh); every assertion here is the suite. Steps mirror
# the Lima issue's scope 1-6; each step function locks its invariants.
#
# Layout (all guest-local disk, never the 9p share — FUSE mountpoints and
# drive dirs over 9p are unsupported):
#   $E2E_ROOT/drives/<name>   drive directories under test
#   $E2E_ROOT/creds/<name>    identity/passphrase files (0600)
#   $E2E_ROOT/mnt/<name>      FUSE mountpoints
#   $E2E_ROOT/logs/           per-step stderr captures, copied to the host
#                             share on exit (trap) for collection.
set -euo pipefail

# shellcheck source=/dev/null
source /tmp/lima/e2e-env.sh

E2E_ROOT="$HOME/e2e"
DRIVES="$E2E_ROOT/drives"
CREDS="$E2E_ROOT/creds"
MNTS="$E2E_ROOT/mnt"
LOGDIR="$E2E_ROOT/logs"
HOST_LOGS="/tmp/lima/logs/$(date +%Y%m%d-%H%M%S)"

collect_logs() {
  mkdir -p "$HOST_LOGS"
  cp -r "$LOGDIR/." "$HOST_LOGS/" 2>/dev/null || true
  echo "logs collected under $HOST_LOGS (host: /tmp/lima/logs/)"
}

# A failed step must never strand a mount: unmount everything and kill
# leftover mount processes, so the next run starts clean. The unmount is
# attempted unconditionally — gating on `mountpoint -q` or `-e` can skip a
# live mount whose FUSE fs misbehaves under stat.
cleanup_mounts() {
  local m pidf
  for m in "$MNTS"/*; do
    [[ -e "$m" || -L "$m" ]] || continue
    fusermount3 -uz "$m" 2>/dev/null || umount -l "$m" 2>/dev/null || true
  done
  for pidf in "$E2E_ROOT"/mount-*.pid; do
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
  with_creds "$c" mount "$d" "$m" "$@" \
    >"$LOGDIR/mount-$name.out" 2>"$LOGDIR/mount-$name.err" &
  echo $! > "$E2E_ROOT/mount-$name.pid"
  poll_until 20 mountpoint -q "$m" \
    || die "$name: mountpoint never came up (see mount-$name.err)"
  pass "$name: mountpoint up"
}

stop_mount() { # <name> <signal>: signal, wait up to 15s, assert exit 0 + unmounted
  local name="$1" sig="$2"
  local pid
  pid="$(cat "$E2E_ROOT/mount-$name.pid")"
  kill "-$sig" "$pid"
  local i status="timeout"
  for ((i = 0; i < 75; i++)); do
    if ! kill -0 "$pid" 2>/dev/null; then
      set +e; wait "$pid"; status=$?; set -e
      break
    fi
    sleep 0.2
  done
  [[ "$status" == "0" ]] || die "$name: shutdown exit $status on $sig, want clean 0"
  mountpoint -q "$MNTS/$name" && die "$name: still mounted after $sig"
  pass "$name: clean shutdown on $sig (exit 0, unmounted)"
}

# --- step 2: local-only mount --------------------------------------------
step1_init() {
  step 1 "init lifecycle"
  local d="$DRIVES/owner" c="$CREDS/owner"
  mkdir -p "$c"
  gen_identity "$c/identity"; gen_passphrase "$c/passphrase"
  local identity passphrase
  identity="$(cat "$c/identity")"; passphrase="$(cat "$c/passphrase")"

  wyrd --version >/dev/null
  wyrd --help >/dev/null
  pass "version/help exit 0"

  expect_exit 0 step1-init with_creds "$c" init "$d" >/dev/null
  pass "init creates a drive"
  [[ -f "$d/mount.log" ]] && die "init wrote a mount log"
  pass "init logs nothing to disk"

  # The cheapest reopen probe doubles as the credential-hardening probe:
  # `device id` opens the keystore, which exercises credential hardening.
  expect_fail2 step1-reinit with_creds "$c" init "$d"

  local bad="$c/case"; mkdir -p "$bad"
  cp "$c/identity" "$bad/identity"; cp "$c/passphrase" "$bad/passphrase"

  mv "$bad/identity" "$bad/identity-real"
  ln -s "$bad/identity-real" "$bad/identity"
  expect_fail2 step1-identity-symlink \
    with_creds "$bad" device "$d" id
  rm "$bad/identity"; mv "$bad/identity-real" "$bad/identity"

  chmod 640 "$bad/identity"
  expect_fail2 step1-identity-group-readable \
    with_creds "$bad" device "$d" id
  chmod 600 "$bad/identity"

  sudo chown root "$bad/identity"
  expect_fail2 step1-identity-wrong-owner \
    with_creds "$bad" device "$d" id
  sudo chown "$(id -un)" "$bad/identity"

  printf 'not-hex-at-all!!' > "$bad/identity-junk"
  chmod 600 "$bad/identity-junk"
  cp "$bad/identity-junk" "$bad/identity"
  expect_fail2 step1-identity-bad-content \
    with_creds "$bad" device "$d" id
  cp "$c/identity" "$bad/identity"

  python3 -c 'import sys; sys.stdout.write("x" * 5000)' > "$bad/passphrase-big"
  chmod 600 "$bad/passphrase-big"
  cp "$bad/passphrase-big" "$bad/passphrase"
  expect_fail2 step1-passphrase-too-big \
    with_creds "$bad" device "$d" id
  cp "$c/passphrase" "$bad/passphrase"

  mv "$bad/passphrase" "$bad/passphrase-real"
  ln -s "$bad/passphrase-real" "$bad/passphrase"
  expect_fail2 step1-passphrase-symlink \
    with_creds "$bad" device "$d" id
  rm "$bad/passphrase"; mv "$bad/passphrase-real" "$bad/passphrase"

  # init itself rejects bad credentials too (fresh dir, junk identity).
  cp "$bad/identity-junk" "$bad/identity"
  expect_fail2 step1-init-bad-identity \
    with_creds "$bad" init "$DRIVES/owner-bad"
  cp "$c/identity" "$bad/identity"
  [[ -e "$DRIVES/owner-bad" ]] && die "failed init left a drive dir behind"

  # Good credentials still open after all the negative cases.
  expect_exit 0 step1-reopen with_creds "$c" device "$d" id >/dev/null
  pass "good credentials still open"

  local f
  for f in "$LOGDIR"/step1-*.stderr; do
    check_no_leaks "$f" "$identity" "$passphrase"
  done
}

step2_mount() {
  step 2 "local-only mount"
  local d="$DRIVES/owner" c="$CREDS/owner"

  start_mount local "$c" "$d" "$MNTS/local"
  grep -q "warning: no --relay given; control-plane intake stays idle" \
    "$LOGDIR/mount-local.err" || die "local: no idle-intake warning on stderr"
  pass "local: idle-intake warning on stderr"
  grep -q "control-plane intake stays idle: no --relay given" "$d/mount.log" \
    || die "local: idle-intake line missing from mount.log"
  pass "local: idle-intake line in mount.log"

  echo "local-write" > "$MNTS/local/note.txt"
  [[ "$(cat "$MNTS/local/note.txt")" == "local-write" ]] || die "local: read-your-write failed"
  pass "local: reads/writes serve without a relay"

  local first_id
  first_id="$(grep -o "serving over iroh: [0-9a-f]*" "$LOGDIR/mount-local.err" | head -n 1)"
  stop_mount local INT

  # mount.log is truncated per mount: the second mount's log must not
  # contain the first mount's endpoint id.
  start_mount local2 "$c" "$d" "$MNTS/local"
  grep -qF "$first_id" "$d/mount.log" && die "local: mount.log accumulated across mounts"
  pass "local: mount.log truncated per mount"
  [[ "$(cat "$MNTS/local/note.txt")" == "local-write" ]] || die "local: write lost across remount"
  pass "local: writes persist across remount"
  stop_mount local2 TERM

  check_no_leaks "$LOGDIR/mount-local.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
  check_no_leaks "$LOGDIR/mount-local2.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
  check_no_leaks "$d/mount.log" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
}
# --- step 3: write matrix -----------------------------------------------
step3_matrix() {
  step 3 "write matrix"
  local d="$DRIVES/owner" c="$CREDS/owner"

  start_mount matrix "$c" "$d" "$MNTS/matrix"
  set +e
  python3 /mnt/wyrd/tests/alpha-lima-matrix.py "$MNTS/matrix" >"$LOGDIR/matrix.out" 2>&1
  local status=$?
  set -e
  cat "$LOGDIR/matrix.out"
  [[ $status -eq 0 ]] || die "write matrix failed"
  pass "write matrix: all python cases passed"
  stop_mount matrix INT

  check_no_leaks "$LOGDIR/mount-matrix.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
  check_no_leaks "$LOGDIR/matrix.out" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
}

main() {
  # Fresh slate every run: steps build on each other within one run, and a
  # previous partial run must never leak state into the next. Unmount
  # first — rm cannot remove a live mountpoint.
  mkdir -p "$MNTS" "$LOGDIR"
  cleanup_mounts
  rm -rf "$DRIVES" "$CREDS" "$MNTS"
  mkdir -p "$DRIVES" "$CREDS" "$MNTS" "$LOGDIR"
  local only="${E2E_ONLY_STEP:-}"
  local run_all=1
  [[ -n "$only" ]] && run_all=0
  if [[ $run_all -eq 1 || "$only" == "1" ]]; then step1_init; fi
  if [[ $run_all -eq 1 || "$only" == "2" ]]; then step2_mount; fi
  if [[ $run_all -eq 1 || "$only" == "3" ]]; then step3_matrix; fi
  echo "e2e: $PASS_COUNT checks passed"
}

main "$@"

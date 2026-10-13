#!/usr/bin/env bash
# tests/test-e2e-guard.sh — stub suite for tests/e2e-guard.sh. Pure
# bash, no harness, no guest, no nix: run it anywhere with
# `bash tests/test-e2e-guard.sh`. It pins the wrapper-only entry
# contract, so a guard regression fails here before it can reach
# Lima or odin. (Wired into the CI shell-tests job alongside the
# other harness stubs.)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/e2e-guard.sh"

PASS=0
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# run_guard <want-rc> <name> [env-file-content]: the caller token
# comes from WYRD_E2E_TOKEN, the lock path from WYRD_E2E_LOCK; both
# are set per-case below. A fresh token file per case keeps cases
# independent. Content __MISSING__ means no file at all (stale
# checkout, wrong state dir).
run_guard() { # <want-rc> <name> [env-file-content]
  local want="$1" name="$2" content="${3:-}" rc=0 f="$TMP/env-$PASS.sh"
  if [[ "$content" == "__MISSING__" ]]; then
    rm -f "$f"
  else
    printf '%s\n' "$content" > "$f"
  fi
  e2e_require_wrapped "$f" "wrapper-cmd" 2>/dev/null || rc=$?
  [[ "$rc" == "$want" ]] || {
    echo "FAIL: $name: exit $rc, want $want" >&2
    exit 1
  }
  PASS=$((PASS + 1))
  echo "  PASS: $name"
}

# No token at all: the accidental direct invocation. Must refuse
# before even looking at the file.
unset WYRD_E2E_TOKEN; unset WYRD_E2E_LOCK
run_guard 1 "no token refused" "WYRD_E2E_TOKEN=abc"

# Token present but no published file: stale checkout, wrong
# state dir. Must refuse, not pass on env alone.
export WYRD_E2E_TOKEN="abc"
run_guard 1 "missing env file refused" "__MISSING__"

# Token mismatch: another run's token, or a hand-typed guess.
run_guard 1 "mismatched token refused" "WYRD_E2E_TOKEN=def"

# Match: the wrapper's child. Must pass.
run_guard 0 "matching token accepted" "WYRD_E2E_TOKEN=abc"

# Owner-pid tie (microVM orchestrator path): a live owner passes, a
# dead one refuses even with a matching token, and a missing pid
# line refuses. $$ is alive, so it stands in for the wrapper.
run_pid() { # <want-rc> <name> <pid-line>
  local want="$1" name="$2" pidline="$3" rc=0 f="$TMP/env-$PASS.sh"
  { printf 'WYRD_E2E_TOKEN=abc\n'; printf '%s\n' "$pidline"; } > "$f"
  e2e_require_wrapped "$f" "wrapper-cmd" --check-owner-pid 2>/dev/null || rc=$?
  [[ "$rc" == "$want" ]] || {
    echo "FAIL: $name: exit $rc, want $want" >&2
    exit 1
  }
  PASS=$((PASS + 1))
  echo "  PASS: $name"
}
run_pid 0 "live owner accepted" "WYRD_E2E_PID=$$"
# Above the kernel pid ceiling (2^22), so kill -0 can never
# succeed no matter what runs here.
run_pid 1 "dead owner refused" "WYRD_E2E_PID=99999999"
run_pid 1 "missing owner refused" "SOME_OTHER_VAR=1"

# Deliberate bypass: warns on stderr, exits 0 without a token.
unset WYRD_E2E_TOKEN
warn="$(WYRD_E2E_UNWRAPPED=1 e2e_require_wrapped "$TMP/nonexistent" "wrapper-cmd" 2>&1)" || {
  echo "FAIL: explicit bypass refused" >&2
  exit 1
}
[[ "$warn" == *"unwrapped"* ]] || { echo "FAIL: bypass silent" >&2; exit 1; }
PASS=$((PASS + 1))
echo "  PASS: explicit bypass warns and proceeds"

# Lock held by a live wrapper (separate process, as in production):
# accept. Lock free: the token is stale (dead or kept run), refuse.
# flock is Linux-only; skip where absent (the orchestrator runs on
# Linux).
if command -v flock >/dev/null; then
  export WYRD_E2E_TOKEN="abc"
  export WYRD_E2E_LOCK="$TMP/guard.lock"
  # Deterministic, no background job: hold the lock on this shell's
  # own fd (mirroring the runner at nix/microvm/run-microvm.sh) so
  # no scheduling barrier is needed — the guard's probe opens its
  # own file description, which conflicts with fd 9 even in the same
  # process. Closing fd 9 releases the lock outright: no sleep, no
  # kill, no orphaned fd, and no `wait` status for set -e to trip
  # on. (Two earlier forms failed on Linux: kill orphaned a sleep
  # holding an inherited locked fd; a background holder raced the
  # probe's open.)
  exec 9>"$WYRD_E2E_LOCK"
  flock -n 9 || { echo "FAIL: cannot hold $WYRD_E2E_LOCK" >&2; exit 1; }
  run_guard 0 "held lock accepted" "WYRD_E2E_TOKEN=abc"
  exec 9>&-
  run_guard 1 "free lock refused" "WYRD_E2E_TOKEN=abc"
  unset WYRD_E2E_LOCK
else
  echo "  SKIP: flock absent, lock cases skipped"
fi

echo "e2e-guard: $PASS checks passed"

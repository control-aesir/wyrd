#!/usr/bin/env bash
# tests/alpha-microvm-legs.sh — per-guest legs for the microVM hardened
# gate, executed over ssh by tests/alpha-microvm.sh (host). Baked into
# every peer guest at /etc/wyrd-tests/; never run directly.
#
# Each leg is a whole mount lifecycle (start, file ops, stop) so pid
# files never cross pid namespaces. legs report via step/pass/die from
# tests/alpha-common.sh; the host counts PASS lines and fails on a
# non-zero ssh exit.
set -euo pipefail

E2E_ENV_FILE="${E2E_ENV_FILE:-/mnt/wyrd-state/e2e-env.sh}"
# shellcheck source=/dev/null
source /etc/wyrd-tests/alpha-common.sh

# Per-guest pid dir: legs run concurrently on guests sharing one
# E2E_ROOT, and same-image mount pids collide across hosts — a
# shared pid dir lets one leg's EXIT trap SIGKILL the other's live
# mount (or an unrelated pid). Done-files stay shared (rendezvous);
# pids must not be. (alpha-common.sh sources the env file itself.)
PIDDIR="$E2E_ROOT/pids/$(hostname -s)"

# leg_converge_owner <drive> <creds> <relay>: mount, write shared.txt,
# wait for the member's reply, stop.
leg_converge_owner() {
  local d="$1" c="$2" relay="$3"
  step 7 "cross-host owner leg"
  start_mount xowner "$c" "$d" "$MNTS/xowner" --relay "$relay"
  echo "owner-write-1" > "$MNTS/xowner/shared.txt"
  poll_until 90 converged "$MNTS/xowner/from-member.txt" "member-write-1" \
    || die "owner never converged on the member's write"
  pass "owner converges on member writes across hosts"
  touch "$E2E_ROOT/owner-done"
  stop_mount xowner INT
  check_no_leaks "$LOGDIR/mount-xowner.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
}

# leg_converge_member <drive> <creds> <relay>: mount, wait for the
# owner's write, reply, stop.
leg_converge_member() {
  local d="$1" c="$2" relay="$3"
  step 7 "cross-host member leg"
  start_mount xmember "$c" "$d" "$MNTS/xmember" --relay "$relay"
  poll_until 90 converged "$MNTS/xmember/shared.txt" "owner-write-1" \
    || die "member never converged on the owner's write"
  pass "member converges on owner writes across hosts"
  echo "member-write-1" > "$MNTS/xmember/from-member.txt"
  # Stay up until the owner reports convergence (it touches
  # owner-done when done): an early exit here would drop the serving
  # route the owner is still fetching over.
  poll_until 120 test -f "$E2E_ROOT/owner-done" \
    || die "owner leg never finished"
  stop_mount xmember TERM
  check_no_leaks "$LOGDIR/mount-xmember.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
}

# leg_restarted_owner <drive> <creds> <relay>: mount (endpoint 1),
# write the pre-restart marker, wait for the member to converge on
# it, then stop and mount fresh (endpoint 2): the stop+remount IS
# the production restart (new iroh endpoint over a persisted
# route). Write again; the member must converge without remounting.
leg_restarted_owner() {
  local d="$1" c="$2" relay="$3"
  step 8 "serving restart leg"
  start_mount xowner-r1 "$c" "$d" "$MNTS/xowner-r1" --relay "$relay"
  echo "before-restart" > "$MNTS/xowner-r1/before-restart.txt"
  poll_until 120 test -f "$E2E_ROOT/member-ready" \
    || die "member never converged on the pre-restart write"
  pass "member converges before the restart"
  stop_mount xowner-r1 INT
  check_no_leaks "$LOGDIR/mount-xowner-r1.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
  start_mount xowner-r2 "$c" "$d" "$MNTS/xowner-r2" --relay "$relay"
  grep -q "serving over iroh" "$LOGDIR/mount-xowner-r2.err" \
    || die "restarted owner: serving endpoint never bound"
  echo "after-restart" > "$MNTS/xowner-r2/after-restart.txt"
  poll_until 120 test -f "$E2E_ROOT/member-done" \
    || die "member never converged on the restarted owner"
  stop_mount xowner-r2 INT
  check_no_leaks "$LOGDIR/mount-xowner-r2.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
}

# leg_restart_member <drive> <creds> <relay>: mount, converge on the
# pre-restart write, then hold that same mount across the owner's
# restart: the post-restart write must arrive over the re-announced
# route with no remount, no manual repair.
leg_restart_member() {
  local d="$1" c="$2" relay="$3"
  step 8 "restart convergence leg"
  start_mount xmember-r "$c" "$d" "$MNTS/xmember-r" --relay "$relay"
  poll_until 120 converged "$MNTS/xmember-r/before-restart.txt" "before-restart" \
    || die "member never converged before the restart"
  pass "member holds the pre-restart route"
  touch "$E2E_ROOT/member-ready"
  poll_until 120 converged "$MNTS/xmember-r/after-restart.txt" "after-restart" \
    || die "member never converged after the owner's re-announcement"
  pass "re-announcement recovers the route across hosts"
  touch "$E2E_ROOT/member-done"
  stop_mount xmember-r TERM
  check_no_leaks "$LOGDIR/mount-xmember-r.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
}

case "${1:-}" in
  converge-owner) leg_converge_owner "$2" "$3" "$4" ;;
  converge-member) leg_converge_member "$2" "$3" "$4" ;;
  restarted-owner) leg_restarted_owner "$2" "$3" "$4" ;;
  restart-member) leg_restart_member "$2" "$3" "$4" ;;
  *) echo "usage: $0 converge-owner|converge-member|restarted-owner|restart-member <drive> <creds> <relay>" >&2; exit 2 ;;
esac
echo "legs: $PASS_COUNT checks passed"

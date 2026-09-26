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

# shellcheck source=/dev/null
source "${E2E_ENV_FILE:-/mnt/wyrd-state/e2e-env.sh}"
# shellcheck source=/dev/null
source /etc/wyrd-tests/alpha-common.sh

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
}

# leg_restarted_owner <drive> <creds> <relay>: fresh mount (new iroh
# endpoint), write, stop. Exercises the route-update reannouncement:
# the member keeps its mount and must converge with no manual repair.
leg_restarted_owner() {
  local d="$1" c="$2" relay="$3"
  step 8 "serving restart leg"
  start_mount xowner-r "$c" "$d" "$MNTS/xowner-r" --relay "$relay"
  grep -q "serving over iroh" "$LOGDIR/mount-xowner-r.err" \
    || die "restarted owner: serving endpoint never bound"
  echo "after-restart" > "$MNTS/xowner-r/after-restart.txt"
  # Stay up until the member converges (it touches member-done):
  # stopping early would pull the fresh route before the member
  # fetches over it.
  poll_until 120 test -f "$E2E_ROOT/member-done" \
    || die "member never converged on the restarted owner"
  stop_mount xowner-r INT
}

# leg_restart_member <drive> <creds> <relay>: mount, wait for the
# restarted owner's write, stop.
leg_restart_member() {
  local d="$1" c="$2" relay="$3"
  step 8 "restart convergence leg"
  start_mount xmember-r "$c" "$d" "$MNTS/xmember-r" --relay "$relay"
  poll_until 120 converged "$MNTS/xmember-r/after-restart.txt" "after-restart" \
    || die "member never converged after the owner's re-announcement"
  pass "re-announcement recovers the route across hosts"
  touch "$E2E_ROOT/member-done"
  stop_mount xmember-r TERM
}

case "${1:-}" in
  converge-owner) leg_converge_owner "$2" "$3" "$4" ;;
  converge-member) leg_converge_member "$2" "$3" "$4" ;;
  restarted-owner) leg_restarted_owner "$2" "$3" "$4" ;;
  restart-member) leg_restart_member "$2" "$3" "$4" ;;
  *) echo "usage: $0 converge-owner|converge-member|restarted-owner|restart-member <drive> <creds> <relay>" >&2; exit 2 ;;
esac
echo "legs: $PASS_COUNT checks passed"

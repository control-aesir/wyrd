#!/usr/bin/env bash
# tests/alpha-microvm.sh — host orchestrator for the microVM hardened
# gate. Runs on the Linux host (odin) as root; drives the two peers
# over ssh, runs offline ops locally. Never sources alpha-common.sh:
# its EXIT trap would reap guest pid files from the host pid
# namespace, so the host keeps its own minimal pass/die.
#
# Flow (issue: microvm.nix reproducible suite):
#   1. shared core steps 1-5 inside peer-o (unmodified Lima script,
#      E2E_ONLY_STEP prefix closure, relay untouched)
#   2. second member natively on peer-n (pair there, invite+join here —
#      invitation files are the portable artifact by design)
#   3. cross-host convergence legs in parallel (guest legs, done-file
#      rendezvous on the shared state root)
#   4. serving-restart legs (fresh endpoint, route update, no repair)
#   5. fetch-plane legs (blocking cold open, bounded EIO on dead
#      routes, dedupe log with no double-append)
#   6. offline reopen of both drives on the host
#
# Out of scope, tracked as follow-up: relay-partition conflict legs
# (concurrent commits, StaleHandle, ConflictedHeads, name@N export).
# The topology supports them (relay is a VM service the host can
# stop); the assertions need product behavior observed on odin
# first, not encoded blind.
set -euo pipefail

STATE_DIR="${STATE_DIR:-/var/lib/wyrd-microvm/state}"
RUN="$STATE_DIR/run"
SSH_KEY="$STATE_DIR/sshkey"
WYRD_BIN="${WYRD_BIN:?runner sets WYRD_BIN from the host build}"
RELAY_URL="${RELAY_URL:-ws://10.0.7.10:18761}"
PEER_O="${PEER_O:-e2e@10.0.7.11}"
PEER_N="${PEER_N:-e2e@10.0.7.12}"
# Guest-side view of RUN (virtiofs mount): same files, guest prefix.
GUEST_RUN="/mnt/wyrd-state/run"
GUEST_TESTS="/etc/wyrd-tests"
GUEST_ENV="/mnt/wyrd-state/e2e-env.sh"

PASS=0
pass() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
die() { echo "  FAIL: $1" >&2; exit 1; }

# The orchestrator runs as root (taps, VMs), but share files belong
# to uid 1000 (guest e2e, the only normal user) — and the credential
# hardening refuses cross-uid opens both directions. So every host
# wyrd invocation drops privilege to 1000 first. setpriv works with
# numeric ids and needs no passwd entry, unlike su/runuser.
command -v setpriv >/dev/null || die "setpriv missing on the host (util-linux)"
as_guest() { setpriv --reuid 1000 --regid 1000 --clear-groups -- "$@"; }

SSH="ssh -i $SSH_KEY -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o BatchMode=yes"
on_o() { $SSH "$PEER_O" "$@"; }
on_n() { $SSH "$PEER_N" "$@"; }

# --- phase 1: shared core on peer-o ------------------------------------
echo "=== microvm 1-5: shared core on peer-o ==="
on_o "E2E_ENV_FILE=$GUEST_ENV E2E_ONLY_STEP=1,2,3,4,5 bash $GUEST_TESTS/alpha-lima.sh" \
  || die "shared core steps 1-5 failed on peer-o"
pass "shared core steps 1-5 green on peer-o"

# --- phase 2: second member natively on peer-n --------------------------
echo "=== microvm 6: member-n invite/join split ==="
# Created here, not at the top: phase 1's guest pre-clean empties
# the shared state root, so anything made earlier would be wiped
# before the first redirect that needs it.
mkdir -p "$RUN/logs"
MC="$RUN/creds/member-n"
MD="$RUN/drives/member-n"
GMC="$GUEST_RUN/creds/member-n"
GMD="$GUEST_RUN/drives/member-n"
mkdir -p "$MC" "$MD"
# Credential bytes without python: od + tr are always present.
# Created as root, then handed to uid 1000: the guest legs open
# these, and cross-uid opens fail closed.
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$MC/identity"
printf 'e2e-%s\n' "$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')" > "$MC/passphrase"
chmod 600 "$MC/identity" "$MC/passphrase"
chown -R 1000:1000 "$MC" "$MD"
# Guests must carry the baked suite, the runner-written env, and a
# working wyrd binary from the shared host store before anything else.
on_n "test -f $GUEST_TESTS/alpha-common.sh && test -f $GUEST_ENV" \
  || die "peer-n missing baked suite or env file"
on_n "source $GUEST_ENV; test -x \"\$WYRD_BIN\"" \
  || die "peer-n cannot execute WYRD_BIN from the shared store"
on_o "source $GUEST_ENV; test -x \"\$WYRD_BIN\"" \
  || die "peer-o cannot execute WYRD_BIN from the shared store"
pass "both peers carry the suite and execute the shared binary"
as_guest "$WYRD_BIN" device --identity-file "$MC/identity" --passphrase-file "$MC/passphrase" \
  "$MD" pairing-request "$RUN/pairing-n.txt" >"$RUN/logs/pairing-n.out" 2>"$RUN/logs/pairing-n.stderr" \
  || die "member-n pairing-request failed"
pass "member-n pairing stages on the host"
DEV="$(grep '^device ' "$RUN/pairing-n.txt" | cut -d' ' -f2)"
KEY="$(grep '^encryption-key ' "$RUN/pairing-n.txt" | cut -d' ' -f2)"
[[ "${#DEV}" == 64 && "${#KEY}" == 64 ]] || die "member-n pairing material malformed"
as_guest "$WYRD_BIN" member --identity-file "$RUN/creds/owner/identity" \
  --passphrase-file "$RUN/creds/owner/passphrase" "$RUN/drives/owner" \
  invite "$DEV" "$KEY" "$RUN/invitation-n" >"$RUN/logs/invite-n.out" 2>"$RUN/logs/invite-n.stderr" \
  || die "owner invite of member-n failed"
pass "owner invites member-n"
as_guest "$WYRD_BIN" device --identity-file "$MC/identity" --passphrase-file "$MC/passphrase" \
  "$MD" join "$RUN/invitation-n" >"$RUN/logs/join-n.out" 2>"$RUN/logs/join-n.stderr" \
  || die "member-n join failed"
pass "member-n joins"

# --- phase 3: cross-host convergence ------------------------------------
echo "=== microvm 7: cross-host convergence ==="
rm -f "$RUN/owner-done"
OD="$GUEST_RUN/drives/owner"
OC="$GUEST_RUN/creds/owner"
on_n "E2E_ENV_FILE=$GUEST_ENV bash $GUEST_TESTS/alpha-microvm-legs.sh converge-member $GMD $GMC $RELAY_URL" \
  >"$RUN/logs/leg-member.out" 2>&1 &
LEG_N=$!
on_o "E2E_ENV_FILE=$GUEST_ENV bash $GUEST_TESTS/alpha-microvm-legs.sh converge-owner $OD $OC $RELAY_URL" \
  >"$RUN/logs/leg-owner.out" 2>&1 &
LEG_O=$!
wait "$LEG_N" || die "member convergence leg failed (see logs/leg-member.out)"
wait "$LEG_O" || die "owner convergence leg failed (see logs/leg-owner.out)"
pass "owner and member converge across hosts"

# --- phase 4: serving restart -------------------------------------------
echo "=== microvm 8: serving restart ==="
rm -f "$RUN/member-ready" "$RUN/member-done"
on_n "E2E_ENV_FILE=$GUEST_ENV bash $GUEST_TESTS/alpha-microvm-legs.sh restart-member $GMD $GMC $RELAY_URL" \
  >"$RUN/logs/leg-restart-member.out" 2>&1 &
LEG_N=$!
on_o "E2E_ENV_FILE=$GUEST_ENV bash $GUEST_TESTS/alpha-microvm-legs.sh restarted-owner $OD $OC $RELAY_URL" \
  >"$RUN/logs/leg-restart-owner.out" 2>&1 &
LEG_O=$!
wait "$LEG_N" || die "restart member leg failed (see logs/leg-restart-member.out)"
wait "$LEG_O" || die "restarted owner leg failed (see logs/leg-restart-owner.out)"
pass "route update rewires fetch across hosts"

# --- phase 5: fetch plane ---------------------------------------------
echo "=== microvm 10: fetch plane ==="
rm -f "$RUN/member-cold-done" "$RUN/member-listed-done" \
  "$RUN/owner-stopped" "$RUN/member-fetch-done" "$RUN/cold-2.got" \
  "$RUN/stale-1.err" "$RUN/never-announced.err"
on_n "E2E_ENV_FILE=$GUEST_ENV bash $GUEST_TESTS/alpha-microvm-legs.sh fetch-member $GMD $GMC $RELAY_URL" \
  >"$RUN/logs/leg-fetch-member.out" 2>&1 &
LEG_N=$!
on_o "E2E_ENV_FILE=$GUEST_ENV bash $GUEST_TESTS/alpha-microvm-legs.sh fetch-owner $OD $OC $RELAY_URL" \
  >"$RUN/logs/leg-fetch-owner.out" 2>&1 &
LEG_O=$!
wait "$LEG_N" || die "fetch member leg failed (see logs/leg-fetch-member.out)"
wait "$LEG_O" || die "fetch owner leg failed (see logs/leg-fetch-owner.out)"
pass "blocking open, bounded EIO, and dedupe hold across hosts"

# --- phase 6: offline reopen --------------------------------------------
echo "=== microvm 9: offline reopen ==="
as_guest "$WYRD_BIN" device --identity-file "$MC/identity" --passphrase-file "$MC/passphrase" \
  "$MD" id >"$RUN/logs/reopen-n.out" 2>&1 || die "member-n drive does not reopen"
as_guest "$WYRD_BIN" device --identity-file "$RUN/creds/owner/identity" \
  --passphrase-file "$RUN/creds/owner/passphrase" "$RUN/drives/owner" id \
  >"$RUN/logs/reopen-o.out" 2>&1 || die "owner drive does not reopen"
pass "both drives reopen offline after unmount"
# Durability is the point of the reopen, not the `id` call: export
# both drives and assert the cross-host writes survived the restart.
# (Cleared first: export refuses populated destinations, and a
# non-fresh rerun would leave the previous run's trees behind.)
rm -rf "$RUN/export-owner" "$RUN/export-member"
as_guest "$WYRD_BIN" export \
  --identity-file "$RUN/creds/owner/identity" \
  --passphrase-file "$RUN/creds/owner/passphrase" \
  "$RUN/drives/owner" "$RUN/export-owner" >"$RUN/logs/export-o.out" 2>&1 \
  || die "owner drive does not export after reopen"
as_guest "$WYRD_BIN" export \
  --identity-file "$MC/identity" --passphrase-file "$MC/passphrase" \
  "$MD" "$RUN/export-member" >"$RUN/logs/export-m.out" 2>&1 \
  || die "member drive does not export after reopen"
[[ "$(cat "$RUN/export-owner/after-restart.txt")" == "after-restart" ]] \
  || die "owner export lost the post-restart write"
[[ "$(cat "$RUN/export-member/shared.txt")" == "owner-write-1" ]] \
  || die "member export lost the cross-host write"
pass "flush-committed state survives restart on both drives"

# Host-side leak check over every log the host wrote (guest logs
# are checked in-guest by each leg). All four credential secrets,
# matching the Lima step's coverage.
for f in "$RUN"/logs/*; do
  [[ -f "$f" ]] || continue
  for s in "$(cat "$MC/identity")" "$(cat "$MC/passphrase")" \
           "$(cat "$RUN/creds/owner/identity")" "$(cat "$RUN/creds/owner/passphrase")"; do
    grep -qF "$s" "$f" && die "secret leaked into $(basename "$f")"
  done
done
pass "no secrets in host logs"

echo "microvm: $PASS host checks passed (guest legs report their own totals above)"

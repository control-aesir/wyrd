#!/usr/bin/env bash
# tests/alpha-microvm.sh — host orchestrator for the microVM hardened
# gate. Runs on the Linux host (odin) as root; drives the two peers
# over ssh, runs offline ops locally. Never sources alpha-common.sh:
# its EXIT trap would reap guest pid files from the host pid
# namespace, so the host keeps its own minimal pass/die.
#
# Flow (issue: microvm.nix reproducible suite,
# nostr:nevent1qqsfe3tgav2h5xe0sdsj5508zxdpknamd9l48tr35fxyugda23df9dcpz9mhxue69uhkwunpwdczuap49eehgcy9luf
# for the conflict legs):
#   microvm 1-5. shared core steps 1-5 inside peer-o (unmodified
#      Lima script, E2E_ONLY_STEP prefix closure, relay untouched)
#   microvm 6. second member natively on peer-n (pair there,
#      invite+join here — invitation files are the portable artifact
#      by design)
#   microvm 7. cross-host convergence legs in parallel (guest legs,
#      done-file rendezvous on the shared state root) plus the
#      host-side relay opacity probe (addressed kind-1059 wraps
#      only, never cleartext)
#   microvm 8. serving-restart legs (fresh endpoint, route update,
#      no repair)
#   microvm 9. fetch-plane legs (blocking cold open, bounded EIO on
#      dead routes, recovery without remount after the owner returns
#      on a fresh endpoint, dedupe log with no double-append)
#   microvm 10. relay-partition conflict legs: rename-then-commit
#      StaleHandle, concurrent same-file commits under tap-r down,
#      ConflictedHeads write EIO with reads still serving, name@N
#      versions identical on both sides
#   microvm 11. offline reopen of both drives on the host (exports
#      now assert the conflict siblings too)
#
# Step selection (runner --step -> MICROVM_ONLY_STEP): phases build on
# each other, so the run set is the prefix closure of the selection —
# selecting phase N runs 1..N, never a lone dependent phase on stale
# state. Entries 1-5 are the shared-core Lima steps (phase 1 runs the
# 1..N prefix of those); 6-12 are the microvm phases below. Absent
# means all phases (the runner refuses an explicit empty value, so
# empty arriving here also means all).
#
# The relay is a VM service the host stops/starts per conflict leg
# via its tap (tap-r down/up); see nix/microvm/run-microvm.sh.
# Control-plane remainder closed here: NIP-44 wire interop is pinned
# by sealed_envelope_is_plain_nip44_v2_with_no_wrapper, the seen
# growth bound by the fetch-member dedupe proof plus unit compaction
# tests, and relay opacity by the convergence-phase probe above
# (addressed kind-1059 wraps only, never cleartext rumors).
# (The control-plane issue reference lives in the PR cover note;
# the Resolves: keyword goes on the merge commit, which is what the
# auto-resolve parser reads.)
set -euo pipefail

STATE_DIR="${STATE_DIR:-/var/lib/wyrd-microvm/state}"
RUN="$STATE_DIR/run"
SSH_KEY="$STATE_DIR/sshkey"
WYRD_BIN="${WYRD_BIN:?runner sets WYRD_BIN from the host build}"
NAK_BIN="${NAK_BIN:?runner sets NAK_BIN from the host build}"
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

ONLY_STEP="${MICROVM_ONLY_STEP:-}"
# Comma list (`--step 6,10`): phases build on each other, so the run
# set is the prefix closure of the selection — selecting phase N runs
# 1..N, never a lone dependent phase on stale state. Every entry must
# name a real phase, so `--step 99` fails instead of passing zero
# checks, and the highest entry decides the prefix.
MAX_STEP=0
if [[ -n "$ONLY_STEP" ]]; then
  # The grammar is a comma list; whitespace is not a separator.
  [[ "$ONLY_STEP" != *[[:space:]]* ]] \
    || die "--step: '$ONLY_STEP' is not a comma list (got whitespace)"
  # An empty entry (`,`, `4,,5`, `,4`) is a mistake, not "all phases":
  # without this it would run zero checks and pass.
  [[ ",$ONLY_STEP," != *,,* ]] \
    || die "--step: '$ONLY_STEP' has an empty entry (expected 1-12 entries)"
  # Split on commas into a quoted array: an unquoted expansion would
  # glob each entry against the working directory first, so `--step
  # '*'` could pathname-expand into a digit-named file and slip past
  # the grammar.
  _step_entries=()
  IFS=',' read -r -a _step_entries <<< "$ONLY_STEP"
  for _e in "${_step_entries[@]}"; do
    [[ "$_e" =~ ^([1-9]|1[012])$ ]] \
      || die "--step: '$_e' is not a step (expected a comma list of 1-12)"
    if (( _e > MAX_STEP )); then MAX_STEP="$_e"; fi
  done
  unset _step_entries _e
  (( MAX_STEP > 0 )) || die "--step: '$ONLY_STEP' names no step (expected a comma list of 1-12)"
fi
want_phase() { [[ -z "$ONLY_STEP" ]] || (( $1 <= MAX_STEP )); }
# Shared-core steps selected: the 1..N prefix truncated to the core
# range, as the comma list the Lima script already accepts. An absent
# selection means all five — identical to the previous hardcoded list.
CORE_MAX=5
if [[ -n "$ONLY_STEP" && "$MAX_STEP" -lt 5 ]]; then CORE_MAX="$MAX_STEP"; fi
CORE_ONLY="1"
for (( _c = 2; _c <= CORE_MAX; _c++ )); do CORE_ONLY="$CORE_ONLY,$_c"; done
unset _c

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
# Always runs: every prefix starts at 1. The selection only truncates
# the core depth (CORE_ONLY above).
echo "=== microvm 1-5: shared core on peer-o ==="
on_o "E2E_ENV_FILE=$GUEST_ENV E2E_ONLY_STEP=$CORE_ONLY bash $GUEST_TESTS/alpha-lima.sh" \
  || die "shared core steps ($CORE_ONLY) failed on peer-o"
pass "shared core steps ($CORE_ONLY) green on peer-o"

# --- phase 2: second member natively on peer-n --------------------------
if want_phase 6; then
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
fi # want_phase 6

# --- phase 3: cross-host convergence ------------------------------------
if want_phase 7; then
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
# Control-plane opacity: the relay must only ever carry kind-1059
# gift wraps — the 9501 rumor travels inside the NIP-59 seal+wrap
# (trust.md T16), never in cleartext. Observed on odin at the
# proving run: ~200 wraps with ephemeral authors and p-tag
# recipients, zero bare 9501s. nak comes pinned from the flake's
# nixpkgs channel (NAK_BIN); the runner already gated on relay
# readiness, so an empty answer is a failure, not connection
# flakiness. Both queries below are sample-relative at limit 500 —
# comfortable headroom at ~200 wraps, but a leak past the window
# would be invisible; raise the limit if mail volume grows.
# Stdin filter form (not -k/-l flags): the channel's nak answers
# flag-built filters with zero events on this relay while the stdin
# form reads fine — observed on odin, so pin the working form.
REQ1059='{"kinds":[1059],"limit":500}'
REQ9501='{"kinds":[9501],"limit":500}'
WRAPS="$(printf '%s' "$REQ1059" | timeout 30 "$NAK_BIN" req "$RELAY_URL" 2>"$RUN/logs/nak-1059.err" | grep '"kind":1059' || true)"
[[ -n "$WRAPS" ]] || die "no kind-1059 wraps on the relay: control plane never flowed (see logs/nak-1059.err)"
[[ -z "$(printf '%s\n' "$WRAPS" | grep -v '"p"' || true)" ]] \
  || die "gift wraps without recipient p tags on the relay (see logs/nak-1059.err)"
pass "control plane crossed the relay as addressed gift wraps only"
# Identity shape: the member device is addressed, and no wrap is
# signed by a device key — authors are discarded ephemeral keys
# (trust.md T16). No census: shared-core step 4 mints throwaway
# pairing devices that leave their own relay traces, so the p set
# legitimately holds more than this run's pair. Base64 ciphertext
# holds no quotes, so '"p","<hex>"' only matches relay JSON
# structure (tags are arrays, hence the comma).
P_HEX="$(printf '%s\n' "$WRAPS" | grep -oE '"p","[0-9a-f]{64}' | grep -oE '[0-9a-f]{64}' | sort -u || true)"
[[ -n "$P_HEX" ]] || die "no recipient p tags on the relay (see logs/nak-1059.err)"
printf '%s\n' "$P_HEX" | grep -qxF "$DEV" \
  || die "member device $DEV never addressed on the relay (see logs/nak-1059.err)"
AUTHORS_HEX="$(printf '%s\n' "$WRAPS" | grep -oE '"pubkey":"[0-9a-f]{64}"' | grep -oE '[0-9a-f]{64}' | sort -u || true)"
[[ -n "$AUTHORS_HEX" ]] || die "no wrap authors on the relay (see logs/nak-1059.err)"
# The member device must never author: of the two device keys the
# host provably holds one ($DEV), so this is the precise half of
# "no device key signs" — the owner half is not established here
# (its pubkey never appears as a proven p recipient), and the check
# stays on the 1059 layer only (the inner kind-13 seal is the
# sender's identity key by design, trust.md T16).
printf '%s\n' "$AUTHORS_HEX" | grep -qxF "$DEV" \
  && die "member device $DEV authored a gift wrap: authors must be ephemeral (see logs/nak-1059.err)"
pass "wraps address the member device and it never authors"
# Capture-then-assert (never grep -q in the pipeline): grep -q
# exits at the first match and SIGPIPEs nak, which under pipefail
# turns a real multi-event leak into a silent pass. Draining grep
# plus || true keeps the die reachable exactly when it matters.
nak_status=0
RUMORS="$( { printf '%s' "$REQ9501" | timeout 30 "$NAK_BIN" req "$RELAY_URL" \
  2>"$RUN/logs/nak-9501.err" || nak_status=$?; } | grep '"kind":9501' || true)"
# The leak query's real bound is the timeout above, not limit 500: a
# zero-result subscription depends on the relay terminating it, so
# "no rumor in thirty seconds" is what the pass below proves.
[[ "$nak_status" != 124 ]] || die "9501 query timed out: leak check inconclusive (see logs/nak-9501.err)"
[[ -z "$RUMORS" ]] || die "relay carries a bare kind-9501 rumor: control leaked in cleartext (see logs/nak-9501.err)"
pass "relay carries no cleartext control rumors"
fi # want_phase 7

# --- phase 4: serving restart -------------------------------------------
if want_phase 8; then
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
# Snapshot the member's dedupe log size: phase 5 asserts it grew
# across this restart (redelivery observed) and holds no duplicates.
# Missing file means no acks yet — record 0 rather than dying here;
# the leg fails on it if the log is still empty at the end.
wc -l < "$MD/mailbox.seen" > "$RUN/seen-after-restart" 2>/dev/null \
  || echo 0 > "$RUN/seen-after-restart"
fi # want_phase 8

# --- phase 5: fetch plane ---------------------------------------------
if want_phase 9; then
echo "=== microvm 9: fetch plane ==="
rm -f "$RUN/member-cold-done" "$RUN/member-listed-done" \
  "$RUN/member-scratch-done" "$RUN/owner-stopped" "$RUN/member-fetch-done" \
  "$RUN/member-probed-done" "$RUN/owner-converged-done" \
  "$RUN/cold-2.got" "$RUN/stale-1.err" "$RUN/stale-2.err" \
  "$RUN/never-announced.err" "$RUN/owner-back" \
  "$RUN/member-recovered-done" "$RUN/stale-2-recovered.got"
on_n "E2E_ENV_FILE=$GUEST_ENV bash $GUEST_TESTS/alpha-microvm-legs.sh fetch-member $GMD $GMC $RELAY_URL" \
  >"$RUN/logs/leg-fetch-member.out" 2>&1 &
LEG_N=$!
on_o "E2E_ENV_FILE=$GUEST_ENV bash $GUEST_TESTS/alpha-microvm-legs.sh fetch-owner $OD $OC $RELAY_URL" \
  >"$RUN/logs/leg-fetch-owner.out" 2>&1 &
LEG_O=$!
wait "$LEG_N" || die "fetch member leg failed (see logs/leg-fetch-member.out)"
wait "$LEG_O" || die "fetch owner leg failed (see logs/leg-fetch-owner.out)"
pass "blocking open, bounded EIO, recovery, and dedupe hold across hosts"
fi # want_phase 9

# --- phase: microvm 10 (relay-partition conflict) ---------------------
# Rename half runs pre-partition (it needs convergence); the host
# partitions only after both rename-done files land, then heals
# after both conflict writes. Partition is host-side tap surgery
# (tap-r is the relay's tap; see TAP_DEV in run-microvm.sh) — the
# orchestrator runs as root, so no privilege dance. Done-file
# rendezvous rides the shared state root, unaffected by the
# partition. No relay query witness: the in-leg @1/@2 reads cannot
# succeed unless the peer's announcement crossed the relay and its
# content crossed iroh, so a count would only re-prove what the
# legs already pin (and saturate at its query limit one day).
# A host EXIT trap re-ups tap-r: any die between down and up must
# not strand the relay unreachable in a --keep run.
if want_phase 10; then
echo "=== microvm 10: relay-partition conflict ==="
rm -f "$RUN"/conflict-rename-member-ready "$RUN"/conflict-rename-owner-done \
  "$RUN"/conflict-rename-member-done "$RUN"/conflict-partitioned \
  "$RUN"/conflict-owner-written "$RUN"/conflict-member-written \
  "$RUN"/conflict-healed "$RUN"/conflict-owner-done "$RUN"/conflict-member-done \
  "$RUN"/rename-stale.err "$RUN/logs"/conflict-eio-write-owner.stderr \
  "$RUN/logs"/conflict-eio-write-member.stderr \
  "$RUN/logs"/conflict-reread-owner-1.stderr \
  "$RUN/logs"/conflict-reread-owner-2.stderr \
  "$RUN/logs"/conflict-reread-member-1.stderr \
  "$RUN/logs"/conflict-reread-member-2.stderr
wait_conflict_file() { # <seconds> <file> <what> <leg-pid>
  local budget="$1" f="$2" what="$3" leg="$4" i
  for ((i = 0; i < budget * 2; i++)); do
    [[ -f "$f" ]] && return 0
    # A dead leg never touches its file: fail fast instead of burning
    # the whole budget on a corpse. The pid is per-file (the sibling
    # leg may already have finished fine); $what names the awaited
    # rendezvous and its leg log.
    kill -0 "$leg" 2>/dev/null || die "$what (leg exited early)"
    sleep 0.5
  done
  die "$what"
}
on_n "E2E_ENV_FILE=$GUEST_ENV bash $GUEST_TESTS/alpha-microvm-legs.sh conflict-member $GMD $GMC $RELAY_URL" \
  >"$RUN/logs/leg-conflict-member.out" 2>&1 &
LEG_N=$!
on_o "E2E_ENV_FILE=$GUEST_ENV bash $GUEST_TESTS/alpha-microvm-legs.sh conflict-owner $OD $OC $RELAY_URL" \
  >"$RUN/logs/leg-conflict-owner.out" 2>&1 &
LEG_O=$!
wait_conflict_file 300 "$RUN/conflict-rename-owner-done" \
  "owner rename leg never finished (see logs/leg-conflict-owner.out)" "$LEG_O"
wait_conflict_file 120 "$RUN/conflict-rename-member-done" \
  "member stale-handle probe never finished (see logs/leg-conflict-member.out)" "$LEG_N"
pass "rename breaks a held handle across hosts before the partition"
heal_tap() { ip link set tap-r up 2>/dev/null || true; }
trap heal_tap EXIT
ip link set tap-r down || die "host could not partition tap-r"
touch "$RUN/conflict-partitioned"
wait_conflict_file 180 "$RUN/conflict-owner-written" \
  "owner never committed under partition (see logs/leg-conflict-owner.out)" "$LEG_O"
wait_conflict_file 180 "$RUN/conflict-member-written" \
  "member never committed under partition (see logs/leg-conflict-member.out)" "$LEG_N"
pass "both sides commit the same path under partition"
ip link set tap-r up || die "host could not heal tap-r"
trap - EXIT
touch "$RUN/conflict-healed"
wait "$LEG_N" || die "conflict member leg failed (see logs/leg-conflict-member.out)"
wait "$LEG_O" || die "conflict owner leg failed (see logs/leg-conflict-owner.out)"
pass "conflict versions, EIO writes, and serving reads hold across hosts"
fi # want_phase 10

# --- phase: microvm 11 (offline reopen) ---------------------------------
# Depends on phase 5's delete (fetch-member removes stale-1.txt once
# the scratch write has localized the trees it needs): the export
# below fails closed on remote-only content, so without that delete
# this phase dies at the member export. Correct product behavior,
# coupled phases. (Prefix closure guarantees the dependency: phase 11
# never runs without phase 9.)
if want_phase 11; then
echo "=== microvm 11: offline reopen ==="
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
# The fetch phase pulled cold-2.txt over the network; the export
# proves the verified remote object survives process death.
[[ "$(cat "$RUN/export-member/cold-2.txt")" == "cold-bytes" ]] \
  || die "member export lost the fetched cold-2.txt"
pass "flush-committed state survives restart on both drives"
# Conflict siblings: the conflict legs localized both versions on
# both drives (cat of @1/@2 in-leg), so the offline export emits
# both takes as name@N siblings. Numbering is SnapshotId byte
# order — pinned nowhere, so compare the set, per drive.
for side in owner member; do
  for v in 1 2; do
    [[ -f "$RUN/export-$side/conflict-c.txt@$v" ]] \
      || die "$side export lost conflict-c.txt@$v"
  done
  got="$(printf '%s\n' "$(cat "$RUN/export-$side/conflict-c.txt@1")" "$(cat "$RUN/export-$side/conflict-c.txt@2")" | sort)"
  want="$(printf '%s\n' "owner-conflict-1" "member-conflict-1" | sort)"
  [[ "$got" == "$want" ]] \
    || die "$side export sibling set mismatch: [$got]"
done
pass "conflict versions export as name@N siblings on both drives"
fi # want_phase 11

# --- phase: microvm 12 (headless serving) --------------------------------
if want_phase 12; then
# Two headless peers exchange content with neither mounting
# (issue 23-headless-serving): the owner drive serves via
# `sync now --serve` while fresh devices join and converge with
# plain `sync now`, then read the bytes through a mount (headless
# reconciliation leaves file chunks RemoteOnly by policy, so the
# read faults them in over the serve route — the feature under
# review end to end).
# The dataset is a fresh single-author drive (init, one mount
# writing the targets, stop): v0 serving is author-bound and does
# not replicate serving authority for historical snapshots, so a
# deep multi-author closure is only convergent when every author
# has a live route — replication serving is deferred to v0.7. C
# proves the positive case; a KILL mid-residency plus restart
# proves the mirror rebuilds from the vault; D — admitted after
# the restart so its obligations are fresh for serve#3's route
# (re-announcement reseals pending obligations, never resurrects
# discharged ones) — proves pre-kill content still serves; both
# TERM stops prove the shutdown half. Drives are unmounted since
# phase 11, so the keystore is free for the offline invites.
echo "=== microvm 12: headless serving ==="
rm -f "$RUN/headless-setup-done" "$RUN/headless-serve-ready" "$RUN/headless-fetch-c-done" \
  "$RUN/headless-serve-stopped" "$RUN/headless-d-invited" \
  "$RUN/headless-serve3-ready" "$RUN/headless-fetch-d-done"
HO="$RUN/creds/headless-owner"
HF="$RUN/drives/headless-fresh"
GHO="$GUEST_RUN/creds/headless-owner"
GHF="$GUEST_RUN/drives/headless-fresh"
mkdir -p "$HO" "$HF"
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$HO/identity"
printf 'e2e-%s\n' "$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')" > "$HO/passphrase"
chmod 600 "$HO/identity" "$HO/passphrase"
chown -R 1000:1000 "$HO" "$HF"
as_guest "$WYRD_BIN" init --identity-file "$HO/identity" --passphrase-file "$HO/passphrase" \
  "$HF" >"$RUN/logs/init-hf.out" 2>"$RUN/logs/init-hf.stderr" \
  || die "headless fresh drive init failed"
pass "headless dataset drive initialized"
on_o "E2E_ENV_FILE=$GUEST_ENV bash $GUEST_TESTS/alpha-microvm-legs.sh headless-setup $GHF $GHO" \
  >"$RUN/logs/leg-headless-setup.out" 2>&1 &
LEG_HSETUP=$!
for ((i = 0; i < 300 * 2; i++)); do
  [[ -f "$RUN/headless-setup-done" ]] && break
  kill -0 "$LEG_HSETUP" 2>/dev/null || die "setup leg exited before writing the dataset (see logs/leg-headless-setup.out)"
  sleep 0.5
done
[[ -f "$RUN/headless-setup-done" ]] || die "setup leg never wrote the dataset"
wait "$LEG_HSETUP" || die "headless setup leg failed (see logs/leg-headless-setup.out)"
pass "single-author dataset written"
HC="$RUN/creds/headless-c"
HD="$RUN/drives/headless-c"
GHC="$GUEST_RUN/creds/headless-c"
GHD="$GUEST_RUN/drives/headless-c"
mkdir -p "$HC" "$HD"
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$HC/identity"
printf 'e2e-%s\n' "$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')" > "$HC/passphrase"
chmod 600 "$HC/identity" "$HC/passphrase"
chown -R 1000:1000 "$HC" "$HD"
as_guest "$WYRD_BIN" device --identity-file "$HC/identity" --passphrase-file "$HC/passphrase" \
  "$HD" pairing-request "$RUN/pairing-hc.txt" >"$RUN/logs/pairing-hc.out" 2>"$RUN/logs/pairing-hc.stderr" \
  || die "headless-c pairing-request failed"
DEV_C="$(grep '^device ' "$RUN/pairing-hc.txt" | cut -d' ' -f2)"
KEY_C="$(grep '^encryption-key ' "$RUN/pairing-hc.txt" | cut -d' ' -f2)"
[[ "${#DEV_C}" == 64 && "${#KEY_C}" == 64 ]] || die "headless-c pairing material malformed"
as_guest "$WYRD_BIN" member --identity-file "$HO/identity" \
  --passphrase-file "$HO/passphrase" "$HF" \
  invite "$DEV_C" "$KEY_C" "$RUN/invitation-hc" >"$RUN/logs/invite-hc.out" 2>"$RUN/logs/invite-hc.stderr" \
  || die "owner invite of headless-c failed"
as_guest "$WYRD_BIN" device --identity-file "$HC/identity" --passphrase-file "$HC/passphrase" \
  "$HD" join "$RUN/invitation-hc" >"$RUN/logs/join-hc.out" 2>"$RUN/logs/join-hc.stderr" \
  || die "headless-c join failed"
pass "headless-c joins from the owner invitation"
on_o "E2E_ENV_FILE=$GUEST_ENV bash $GUEST_TESTS/alpha-microvm-legs.sh headless-serve $GHF $GHO $RELAY_URL" \
  >"$RUN/logs/leg-headless-serve.out" 2>&1 &
LEG_HS=$!
on_n "E2E_ENV_FILE=$GUEST_ENV bash $GUEST_TESTS/alpha-microvm-legs.sh headless-fetch $GHD $GHC $RELAY_URL c headless-serve-ready headless-fetch-c-done" \
  >"$RUN/logs/leg-headless-fetch-c.out" 2>&1 &
LEG_HC=$!
# D is admitted mid-leg, after serve#2 stops and frees the owner
# drive: its obligations must be fresh for serve#3's route. The
# invite runs on the host (offline keystore op); the leg waits on
# headless-d-invited before starting serve#3.
for ((i = 0; i < 600 * 2; i++)); do
  [[ -f "$RUN/headless-serve-stopped" ]] && break
  kill -0 "$LEG_HS" 2>/dev/null || die "serve leg exited before stopping serve#2 (see logs/leg-headless-serve.out)"
  sleep 0.5
done
[[ -f "$RUN/headless-serve-stopped" ]] || die "serve leg never stopped serve#2"
HDD="$RUN/creds/headless-d"
HDDD="$RUN/drives/headless-d"
GHDD="$GUEST_RUN/creds/headless-d"
GHDDD="$GUEST_RUN/drives/headless-d"
mkdir -p "$HDD" "$HDDD"
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$HDD/identity"
printf 'e2e-%s\n' "$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')" > "$HDD/passphrase"
chmod 600 "$HDD/identity" "$HDD/passphrase"
chown -R 1000:1000 "$HDD" "$HDDD"
as_guest "$WYRD_BIN" device --identity-file "$HDD/identity" --passphrase-file "$HDD/passphrase" \
  "$HDDD" pairing-request "$RUN/pairing-hd.txt" >"$RUN/logs/pairing-hd.out" 2>"$RUN/logs/pairing-hd.stderr" \
  || die "headless-d pairing-request failed"
DEV_D="$(grep '^device ' "$RUN/pairing-hd.txt" | cut -d' ' -f2)"
KEY_D="$(grep '^encryption-key ' "$RUN/pairing-hd.txt" | cut -d' ' -f2)"
[[ "${#DEV_D}" == 64 && "${#KEY_D}" == 64 ]] || die "headless-d pairing material malformed"
as_guest "$WYRD_BIN" member --identity-file "$HO/identity" \
  --passphrase-file "$HO/passphrase" "$HF" \
  invite "$DEV_D" "$KEY_D" "$RUN/invitation-hd" >"$RUN/logs/invite-hd.out" 2>"$RUN/logs/invite-hd.stderr" \
  || die "owner invite of headless-d failed"
as_guest "$WYRD_BIN" device --identity-file "$HDD/identity" --passphrase-file "$HDD/passphrase" \
  "$HDDD" join "$RUN/invitation-hd" >"$RUN/logs/join-hd.out" 2>"$RUN/logs/join-hd.stderr" \
  || die "headless-d join failed"
touch "$RUN/headless-d-invited"
pass "headless-d joins after the serve restart"
on_n "E2E_ENV_FILE=$GUEST_ENV bash $GUEST_TESTS/alpha-microvm-legs.sh headless-fetch $GHDDD $GHDD $RELAY_URL d headless-serve3-ready headless-fetch-d-done" \
  >"$RUN/logs/leg-headless-fetch-d.out" 2>&1 &
LEG_HD=$!
wait "$LEG_HC" || die "headless fetch-c leg failed (see logs/leg-headless-fetch-c.out)"
wait "$LEG_HD" || die "headless fetch-d leg failed (see logs/leg-headless-fetch-d.out)"
wait "$LEG_HS" || die "headless serve leg failed (see logs/leg-headless-serve.out)"
pass "two headless peers exchange content with neither mounting"
fi # want_phase 12

# Host-side leak check over every log the host wrote (guest logs
# are checked in-guest by each leg). Owner secrets always exist past
# phase 1; member-n credentials exist only once phase 6 stages them,
# and the phase-12 headless credentials only once phase 12 stages
# them, so a prefix that stops earlier has nothing of theirs to
# check.
for f in "$RUN"/logs/*; do
  [[ -f "$f" ]] || continue
  for s in "$(cat "$RUN/creds/owner/identity")" "$(cat "$RUN/creds/owner/passphrase")"; do
    grep -qF "$s" "$f" && die "secret leaked into $(basename "$f")"
  done
  if want_phase 6; then
    for s in "$(cat "$MC/identity")" "$(cat "$MC/passphrase")"; do
      grep -qF "$s" "$f" && die "secret leaked into $(basename "$f")"
    done
  fi
  if want_phase 12; then
    for s in "$(cat "$HO/identity")" "$(cat "$HO/passphrase")" \
             "$(cat "$HC/identity")" "$(cat "$HC/passphrase")" \
             "$(cat "$HDD/identity")" "$(cat "$HDD/passphrase")"; do
      grep -qF "$s" "$f" && die "secret leaked into $(basename "$f")"
    done
  fi
done
pass "no secrets in host logs"
    grep -qF "$s" "$f" && die "secret leaked into $(basename "$f")"
  done
  if want_phase 6; then
    for s in "$(cat "$MC/identity")" "$(cat "$MC/passphrase")"; do
      grep -qF "$s" "$f" && die "secret leaked into $(basename "$f")"
    done
  fi
done
pass "no secrets in host logs"

echo "microvm: $PASS host checks passed (guest legs report their own totals above)"

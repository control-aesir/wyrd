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

# leg_fetch_owner <drive> <creds> <relay>: mount, publish the cold
# file, then the two stale files the member lists before the route
# dies, then stop: the stop IS the stale-route setup — no VM
# surgery, just an unmounted owner. After the member's dead-route
# probes, remount on a fresh endpoint and write a new file first:
# the new announcement carries the new route (which the member's
# later tree fetch needs) and the head advances singly — the member
# converges it before authoring scratch, so no fork. The member
# must recover the second stale identity over the new route
# without remounting.
leg_fetch_owner() {
  local d="$1" c="$2" relay="$3"
  step 9 "fetch-plane owner leg"
  start_mount xowner-f "$c" "$d" "$MNTS/xowner-f" --relay "$relay"
  echo "cold-bytes" > "$MNTS/xowner-f/cold-2.txt"
  poll_until 120 test -f "$E2E_ROOT/member-cold-done" \
    || die "member never completed the blocking cold open"
  pass "member's single open unblocked on the announcement"
  echo "stale-bytes" > "$MNTS/xowner-f/stale-1.txt"
  echo "stale-2-bytes" > "$MNTS/xowner-f/stale-2.txt"
  poll_until 120 test -f "$E2E_ROOT/member-listed-done" \
    || die "member never listed the stale files"
  # Stop before the member probes: the EIO probes below require the
  # route down — a live route would serve fetch-on-open and read rc
  # 0 instead of failing closed. The scratch write that localizes
  # trees for the later delete runs against the fresh endpoint
  # instead; same drive, same lineage, so nothing forks.
  stop_mount xowner-f INT
  check_no_leaks "$LOGDIR/mount-xowner-f.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
  touch "$E2E_ROOT/owner-stopped"
  poll_until 240 test -f "$E2E_ROOT/member-probed-done" \
    || die "member never finished the dead-route probes"
  pass "owner stayed down while the member probed the dead route"
  # Recovery setup: remount on a fresh endpoint (new iroh identity
  # over the same drive) and write a new file BEFORE the member
  # authors anything: the member converges this head first, so the
  # scratch and the delete extend the post-restart lineage instead
  # of forking it (the suite has no conflict legs). The new
  # announcement also carries the fresh route the member needs for
  # serving. File presence in the member's own view is the
  # self-synchronizing signal — no sleeps. Reading the scratch file
  # later also localizes its bytes: phase 6 exports this drive
  # offline and fails closed on remote-only content.
  start_mount xowner-f2 "$c" "$d" "$MNTS/xowner-f2" --relay "$relay"
  echo "owner-back" > "$MNTS/xowner-f2/owner-back-1.txt"
  touch "$E2E_ROOT/owner-back"
  # The member created its scratch file and deleted stale-1 on the
  # post-restart head; converge both before finishing, so the suite
  # never leaves a forked head behind.
  poll_until 180 test -f "$E2E_ROOT/member-scratch-done" \
    || die "member never created the scratch file"
  poll_until 120 converged "$MNTS/xowner-f2/scratch-del.txt" "scratch" \
    || die "owner never converged the scratch file's bytes"
  pass "owner converges the member's scratch write with bytes"
  poll_until 240 test -f "$E2E_ROOT/member-fetch-done" \
    || die "member never finished the delete"
  poll_until 120 bash -c "! test -e '$MNTS/xowner-f2/stale-1.txt'" \
    || die "owner never converged the member's offline delete"
  pass "owner converges the delete before finishing"
  # Convergence ack: the member must not shut down until its
  # announcements have arrived here — a fast member would otherwise
  # outrun its own outbox drain and this leg could never converge.
  touch "$E2E_ROOT/owner-converged-done"
  # Ten attempts bound the member's worst case near eleven minutes
  # (10 x (60s attempt + 5s sleep)), so this wait must clear it or
  # the owner's diagnostic masks the member's own.
  poll_until 700 test -f "$E2E_ROOT/member-recovered-done" \
    || die "member never recovered the stale identity"
  stop_mount xowner-f2 INT
  check_no_leaks "$LOGDIR/mount-xowner-f2.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
}

# leg_fetch_member <drive> <creds> <relay>: mount, wait for the cold
# file's announcement via listing, then prove open() blocks for the
# bytes with ONE cat (no retry loop). List both stale files for
# their manifests only, then probe the dead route right after the
# owner stops — before authoring anything, so no local write can
# fetch the probed identities first (fetch-on-open serves a live
# route with rc 0, which is correct serving but the wrong probe).
# The stale-1 probe exercises read-side chunk demand (the manifest
# is already local, so open succeeds and the bounded EIO comes from
# the read) with the errno to prove it; the never-announced path
# fails fast with ENOENT — open blocks for content after announce,
# not for announcements themselves. The recovery identity fails
# bounded here too, so its later success proves revival. Then the
# owner returns on a fresh endpoint: converge its head (and route)
# first, scratch-write to localize the trees the delete needs, and
# delete stale-1 — all on the post-restart lineage, no fork. Close
# with the dedupe proof over the step-8 restart's redelivery.
# Wall-clock envelope (whole guest run shares one 1-hour budget):
# probes ~130s worst case, owner convergence chain concurrent with
# the member's recovery, recovery loop 650s worst case, ack waits
# fail-fast (120s member-side). Typical green run: 4-6 minutes.
# Two matrix items are deliberately NOT e2e-legged here:
# timeout-then-completion (the waiter leaves with
# EIO while the fetch continues (unit-pinned by
# late_completion_caches_for_the_next_waiter in
# crates/wyrd-core/src/want.rs, no e2e leg).
# A third row is half-legged by construction: the stale probe pins
# fail-closed EIO but not "no invalid object committed", which is
# structurally guaranteed (verified ingest admits nothing invalid)
# and unobservable e2e — the member deletes stale-1.txt precisely
# because the export fails closed on remote-only content, so the
# export can never show that identity's absence.
# The recovery probe below is order-dependent, not a regression pin
# for decision 8 (fair share): candidate order is hash order, so a
# run where the live provider sorts first would pass without the
# fix. Read it as an end-to-end recovery smoke; the deterministic
# pin lives in-crate at
# runtime::plan::tests_execution::sliced_run_attempts_live_candidates_behind_a_dead_one,
# which builds the dead-first order explicitly.
leg_fetch_member() {
  local d="$1" c="$2" relay="$3"
  step 9 "fetch-plane member leg"
  start_mount xmember-f "$c" "$d" "$MNTS/xmember-f" --relay "$relay"
  # Announcement first (listing shows the new head), bytes second
  # (the single cat below): this split is what makes the cat a
  # blocking-open proof rather than a find-ready-bytes no-op.
  poll_until 120 bash -c "ls '$MNTS/xmember-f' | grep -qx 'cold-2.txt'" \
    || die "member never listed the cold file"
  timeout 120 cat "$MNTS/xmember-f/cold-2.txt" >"$E2E_ROOT/cold-2.got" \
    || die "blocking cold open failed (open did not wait for the bytes)"
  [[ "$(cat "$E2E_ROOT/cold-2.got")" == "cold-bytes" ]] \
    || die "cold open returned wrong bytes"
  pass "single open blocks until the announced bytes arrive"
  touch "$E2E_ROOT/member-cold-done"
  # Manifest-only convergence: readdir pulls the manifest chain
  # without opening contents, so the member holds the announcements
  # for both stale files while their chunks are still unfetched.
  poll_until 120 bash -c "ls '$MNTS/xmember-f' | grep -qx 'stale-1.txt'" \
    || die "member never listed stale-1.txt"
  poll_until 120 bash -c "ls '$MNTS/xmember-f' | grep -qx 'stale-2.txt'" \
    || die "member never listed stale-2.txt"
  touch "$E2E_ROOT/member-listed-done"
  poll_until 180 test -f "$E2E_ROOT/owner-stopped" \
    || die "owner never stopped for the dead-route probes"
  # Dead route, held manifest, nothing authored yet: the bytes are
  # announced but unfetchable, and no local write has had a chance
  # to demand them first. Each read must fail closed and bounded.
  local rc=0
  timeout 60 cat "$MNTS/xmember-f/stale-1.txt" >/dev/null 2>"$E2E_ROOT/stale-1.err" || rc=$?
  [[ "$rc" == 1 ]] || die "stale-manifest read returned rc $rc, want EIO (1)"
  grep -q "Input/output error" "$E2E_ROOT/stale-1.err" \
    || die "stale-manifest read was not EIO: $(cat "$E2E_ROOT/stale-1.err")"
  pass "announced-but-unfetchable read fails closed and bounded"
  # Never announced at all: resolve fails fast, no 30s wait for an
  # announcement that may never come. The 10s budget (well under the
  # 30s open deadline) is what makes "immediately" real: a regression
  # that blocked the full deadline before ENOENT would die here as
  # rc 124 instead of passing as rc 1.
  rc=0
  timeout 10 cat "$MNTS/xmember-f/never-announced.txt" >/dev/null 2>"$E2E_ROOT/never-announced.err" || rc=$?
  [[ "$rc" == 1 ]] || die "unknown-path open returned rc $rc, want ENOENT (1)"
  grep -q "No such file or directory" "$E2E_ROOT/never-announced.err" \
    || die "unknown-path open was not ENOENT: $(cat "$E2E_ROOT/never-announced.err")"
  pass "unknown-path open fails fast, never hangs for an announcement"
  # The recovery identity must FAIL first: bounded EIO against the
  # dead route, so the later success proves revival rather than a
  # first attempt that never saw trouble.
  rc=0
  timeout 60 cat "$MNTS/xmember-f/stale-2.txt" >/dev/null 2>"$E2E_ROOT/stale-2.err" || rc=$?
  [[ "$rc" == 1 ]] || die "stale-2 read returned rc $rc, want EIO (1)"
  grep -q "Input/output error" "$E2E_ROOT/stale-2.err" \
    || die "stale-2 read was not EIO: $(cat "$E2E_ROOT/stale-2.err")"
  pass "second stale identity fails closed and bounded"
  touch "$E2E_ROOT/member-probed-done"
  # The owner is back on a fresh endpoint with a new route (see
  # owner leg). Converge its head BEFORE authoring: the scratch and
  # the delete below must extend the post-restart lineage, and the
  # announcement carries the route the tree fetch needs.
  poll_until 120 test -f "$E2E_ROOT/owner-back" \
    || die "owner never came back after the dead-route probes"
  poll_until 120 bash -c "ls '$MNTS/xmember-f' | grep -qx 'owner-back-1.txt'" \
    || die "member never listed the post-restart write"
  pass "member converges on the post-restart head over the new route"
  # Scratch write against the live route: creating a file forces
  # the current head's tree object to materialize (reads never
  # fetch tree objects, only manifests and chunks), and the delete
  # below needs that tree local. Completion is the signal —
  # success means the trees are local, so no timing guess.
  echo "scratch" > "$MNTS/xmember-f/scratch-del.txt"
  poll_until 120 converged "$MNTS/xmember-f/scratch-del.txt" "scratch" \
    || die "scratch write never became readable"
  pass "scratch write forces tree materialization over the live route"
  touch "$E2E_ROOT/member-scratch-done"
  # Delete of stale-1: the scratch write above authored a head
  # whose tree object is local by construction, so this delete
  # needs nothing from the network — same local-first authorship
  # the green suite proved, now deterministic instead of
  # timing-lucky. The owner converges it (see owner leg), so no
  # head fork. stale-2 stays for the recovery probe below.
  timeout 60 rm "$MNTS/xmember-f/stale-1.txt" \
    || die "member cannot author the delete"
  pass "member authors the delete with trees local"
  touch "$E2E_ROOT/member-fetch-done"
  # Recovery without remount: the owner is back on a fresh endpoint
  # with a new route (see owner leg), and this mount never went
  # down. The stale-2 identity failed terminally against the dead
  # route; the live route must produce a new fetch attempt and the
  # open must eventually succeed. Each attempt is a fresh
  # bounded open (30s): the loop below is the retry, while the
  # fetch continues across attempts. Ten attempts bound the worst
  # case near eleven minutes; the live route should land it in the
  # first few. (The post-restart head converged before the scratch
  # above, so no second converge is needed here.)
  # Localize the post-restart file too: phase 6 exports this drive
  # offline and fails closed on remote-only content, so the export
  # needs every head file local — and reads need chunks only, never
  # tree objects, so this stays a pure fetch-plane assertion.
  poll_until 180 converged "$MNTS/xmember-f/owner-back-1.txt" "owner-back" \
    || die "member never fetched the post-restart bytes"
  pass "post-restart bytes land over the new route"
  local attempt=0
  while (( attempt < 10 )); do
    if timeout 60 cat "$MNTS/xmember-f/stale-2.txt" >"$E2E_ROOT/stale-2-recovered.got" 2>/dev/null \
      && [[ "$(cat "$E2E_ROOT/stale-2-recovered.got")" == "stale-2-bytes" ]]; then
      break
    fi
    attempt=$((attempt + 1))
    sleep 5
  done
  [[ "$attempt" -lt 10 ]] \
    || die "stale identity never recovered without remount after $attempt bounded opens"
  pass "failed fetch recovers after re-announcement without remount"
  # Stay up until the owner confirms convergence: shutting down
  # here would outrun the outbox drain and strand the scratch and
  # delete announcements this leg's owner polls wait for. Short
  # budget on purpose: in the normal case the owner acks while this
  # mount is still recovering, so this only ever costs minutes when
  # the owner is genuinely stuck.
  poll_until 120 test -f "$E2E_ROOT/owner-converged-done" \
    || die "owner never converged the scratch and delete"
  touch "$E2E_ROOT/member-recovered-done"
  stop_mount xmember-f TERM
  # Dedupe proof over the step-8 restart's redelivery, read after the
  # mount is down so no concurrent append can slip mid-read. Two
  # preconditions make the check real: the log is non-empty (an
  # empty log would pass trivially and means the member stopped
  # acking), and it grew past the phase-4 snapshot (the restart
  # redelivered, so "no duplicates" is observed, not vacuous).
  # Past the retention bound an evicted id may legitimately
  # re-append after redelivery (seen_store.rs:21-25), so the no-dup
  # half is a below-the-bound invariant; the bound itself is pinned
  # by unit tests at the 512 test bound.
  [[ -s "$d/mailbox.seen" ]] || die "member mailbox.seen empty: member stopped acking"
  [[ -f "$E2E_ROOT/seen-after-restart" ]] || die "phase-4 seen snapshot missing"
  [[ "$(wc -l < "$d/mailbox.seen")" -gt "$(cat "$E2E_ROOT/seen-after-restart")" ]] \
    || die "mailbox.seen did not grow across the restart: no redelivery observed"
  [[ -z "$(sort "$d/mailbox.seen" | uniq -d)" ]] \
    || die "mailbox.seen holds duplicate ids: redelivery double-appended"
  pass "redelivery grows the dedupe log without double-appending"
  # Growth-bound backstop (seen_store.rs:21-25): the durable file
  # never exceeds twice the 65,536 production retention bound,
  # regardless of lifetime history. Asserted in bytes, not lines: the
  # module's promise is a disk bound, and every record is exactly
  # MAX_RECORD_LEN (65) bytes, so 131072 * 65 fails closed on a
  # corrupt long line too. The suite generates ~100 acks, so this
  # pins the invariant in the hardened gate rather than exercising
  # compaction — that stays pinned by unit tests at the 512 test
  # bound. The literal below is a copy of MAX_SEEN_ENTRIES * 2;
  # update it if the production const moves.
  [[ "$(wc -c < "$d/mailbox.seen")" -le 8519680 ]] \
    || die "mailbox.seen exceeds the durable growth bound"
  pass "dedupe log stays within the durable growth bound"
  check_no_leaks "$LOGDIR/mount-xmember-f.err" "$(cat "$c/identity")" "$(cat "$c/passphrase")"
}

case "${1:-}" in
  converge-owner) leg_converge_owner "$2" "$3" "$4" ;;
  converge-member) leg_converge_member "$2" "$3" "$4" ;;
  restarted-owner) leg_restarted_owner "$2" "$3" "$4" ;;
  restart-member) leg_restart_member "$2" "$3" "$4" ;;
  fetch-owner) leg_fetch_owner "$2" "$3" "$4" ;;
  fetch-member) leg_fetch_member "$2" "$3" "$4" ;;
  *) echo "usage: $0 converge-owner|converge-member|restarted-owner|restart-member|fetch-owner|fetch-member <drive> <creds> <relay>" >&2; exit 2 ;;
esac
echo "legs: $PASS_COUNT checks passed"
